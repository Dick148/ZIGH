// ZIGH — Daemon mode: shared memory + socket listener + chain-based periodic locks

const std = @import("std");
const shm = @import("../ipc/shm.zig");
const mem = @import("../mem/mod.zig");
const types = @import("../mem/types.zig");
const socket = @import("../ipc/socket.zig");
const util = @import("../util.zig");
const linux = std.os.linux;

const MAX_CHAIN_LOCKS = 16;

const ChainLock = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    value: u64 = 0,
    tid: types.TypeId = .uint32,
    base: u64 = 0,
    module: [256]u8 = [_]u8{0} ** 256,
    rva: u64 = 0,
    offsets: [8]u32 = [_]u32{0} ** 8,
    layer_count: u32 = 0,
    interval_ms: u32 = 300,
    last_write_ms: u64 = 0,
    active: bool = false,
};

pub const Daemon = @This();

allocator: std.mem.Allocator,
shm_ptr: *align(4096) shm.SharedMemory,
shm_name: [:0]const u8,
pid: u32,
engine: u32,
mem_fd: ?linux.fd_t = null,
lock_names: [shm.MAX_CMD_SLOTS][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** shm.MAX_CMD_SLOTS,
chain_locks: [MAX_CHAIN_LOCKS]ChainLock = [_]ChainLock{.{}} ** MAX_CHAIN_LOCKS,
chain_thread: ?std.Thread = null,
chain_running: bool = false,

pub fn init(allocator: std.mem.Allocator, pid: u32, engine: u32) !Daemon {
    var name_buf: [64]u8 = undefined;
    const name = try shm.makeName(&name_buf, pid, engine);

    const shm_ptr = shm.create(name) catch |err| {
        if (err == error.ShmOpenFailed) {
            _ = std.c.shm_unlink(name);
            return init(allocator, pid, engine);
        }
        return err;
    };
    shm_ptr.engineType = engine;
    shm_ptr.initParams.targetPid = pid;
    if (mem.getModuleBase(allocator, pid, ".exe")) |maybe_base| {
        if (maybe_base) |base| shm_ptr.initParams.targetModuleBase = base;
    } else |_| {}

    const maybe_fd = mem.openProcMem(pid) catch null;

    const d = Daemon{
        .allocator = allocator,
        .shm_ptr = shm_ptr,
        .shm_name = name,
        .pid = pid,
        .engine = engine,
        .mem_fd = maybe_fd,
    };
    return d;
}

/// Wait for the injected agent to signal STATUS_RUNNING.
/// Returns error.AgentTimeout if the agent doesn't start within timeout_ms.
pub fn waitForAgent(self: *Daemon, timeout_ms: u32) !void {
    var waited: u32 = 0;
    while (waited < timeout_ms) : (waited += 10) {
        const status = @atomicLoad(u32, &self.shm_ptr.agentStatus, .acquire);
        if (status == shm.STATUS_RUNNING) return;
        if (status == shm.STATUS_ERROR) return error.AgentError;
        var req = linux.timespec{ .sec = 0, .nsec = 10_000_000 };
        _ = linux.nanosleep(&req, null);
    }
    return error.AgentTimeout;
}

pub fn deinit(self: *Daemon) void {
    self.chain_running = false;
    @atomicStore(u32, &self.shm_ptr.agentStatus, shm.STATUS_SHUTDOWN, .release);
    shm.bumpVersion(self.shm_ptr);
    if (self.mem_fd) |fd| _ = std.c.close(fd);
    var name_buf: [64]u8 = undefined;
    const name = shm.makeName(&name_buf, self.pid, self.engine) catch return;
    shm.destroy(self.shm_ptr, name);
}

pub fn startChainWorker(self: *Daemon) void {
    self.chain_running = true;
    self.chain_thread = std.Thread.spawn(.{}, chainWorkerLoop, .{self}) catch {
        self.chain_running = false;
        return;
    };
}

const CHAIN_TICK_NS: u64 = 50_000_000; // 50ms base tick rate

fn chainWorkerLoop(self: *Daemon) void {
    while (self.chain_running) {
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
        const now_ms = @as(u64, @intCast(@as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000)));
        self.tickChainLocks(now_ms);
        var req = linux.timespec{ .sec = 0, .nsec = CHAIN_TICK_NS };
        _ = linux.nanosleep(&req, null);
    }
}

fn tickChainLocks(self: *Daemon, now_ms: u64) void {
    for (&self.chain_locks) |*cl| {
        if (!cl.active) continue;
        if (now_ms < cl.last_write_ms + cl.interval_ms) continue;
        const mod_name: []const u8 = std.mem.sliceTo(&cl.module, 0);
        const addr = self.resolveChain(cl.base, mod_name, cl.rva, &cl.offsets, cl.layer_count) catch continue;
        self.writeOnce(addr, cl.value, cl.tid) catch continue;
        cl.last_write_ms = now_ms;
    }
}

pub fn resolveChain(self: *Daemon, base: u64, module: []const u8, rva: u64, offsets: []const u32, layer_count: u32) !usize {
    // layer_count==0 means direct address (no chain) — rva is the full absolute address
    if (layer_count == 0) return @intCast(rva);

    const fd = self.mem_fd orelse return error.NoMemAccess;

    var actual_base: u64 = base;
    if (actual_base == 0 and module.len > 0) {
        // Resolve base from module name (e.g. "GameAssembly.so")
        if (try mem.getModuleBase(self.allocator, self.pid, module)) |b| {
            actual_base = @intCast(b);
        } else {
            return error.ModuleNotFound;
        }
    }
    if (actual_base == 0) return error.NoBaseFound;

    if (layer_count > offsets.len) return error.InvalidChainLength;

    var ptr: u64 = try mem.readU64(fd, @intCast(actual_base + rva), .uint64);
    if (ptr == 0) return error.NullChain;

    var i: u32 = 0;
    while (i < layer_count - 1) : (i += 1) {
        ptr = try mem.readU64(fd, @intCast(ptr + offsets[i]), .uint64);
        if (ptr == 0) return error.NullChain;
    }
    return @intCast(ptr + offsets[layer_count - 1]);
}

pub fn setSlot(self: *Daemon, index: u32, mode: u32, tid: types.TypeId, value: u64, rva: u64, base: u64, offsets: []const u32, layer_count: u32) !void {
    if (index >= shm.MAX_CMD_SLOTS) return error.SlotOutOfRange;
    const slot = &self.shm_ptr.cmdSlots[index];
    slot.mode = mode;
    slot.valueType = @intFromEnum(tid);
    slot.layerCount = layer_count;
    slot.slotId = index + 1;
    slot.valueAsU64 = value;
    slot.rva = rva;
    slot.targetModuleBase = base;
    @memset(&slot.offsets, 0);
    if (offsets.len > 0 and offsets.len <= 8) @memcpy(slot.offsets[0..offsets.len], offsets);
}

pub fn writeOnce(self: *Daemon, addr: usize, value: u64, tid: types.TypeId) !void {
    const fd = self.mem_fd orelse return error.NoMemAccess;
    try mem.writeU64(fd, addr, value, tid);
}

pub fn readMem(self: *Daemon, addr: usize, tid: types.TypeId) !u64 {
    const fd = self.mem_fd orelse return error.NoMemAccess;
    return mem.readU64(fd, addr, tid);
}

fn addChainLock(self: *Daemon, name: []const u8, value: u64, tid: types.TypeId, rva: u64, base: u64, module: []const u8, offsets: []const u32, layer_count: u32, interval_ms: u32) !u32 {
    // Find free or matching slot
    for (&self.chain_locks, 0..) |*cl, i| {
        if (cl.active and std.mem.eql(u8, std.mem.sliceTo(&cl.name, 0), name)) {
            cl.value = value;
            cl.tid = tid;
            cl.base = base;
            cl.interval_ms = interval_ms;
            const max_mod = cl.module.len - 1;
            @memcpy(cl.module[0..@min(module.len, max_mod)], module[0..@min(module.len, max_mod)]);
            cl.module[@min(module.len, max_mod)] = 0;
            cl.rva = rva;
            cl.layer_count = layer_count;
            @memset(&cl.offsets, 0);
            if (offsets.len <= 8) @memcpy(cl.offsets[0..offsets.len], offsets);
            return @intCast(i);
        }
    }
    for (&self.chain_locks, 0..) |*cl, i| {
        if (!cl.active) {
            cl.active = true;
            @memcpy(cl.name[0..@min(name.len, 31)], name[0..@min(name.len, 31)]);
            cl.name[@min(name.len, 31)] = 0;
            cl.value = value;
            cl.tid = tid;
            cl.base = base;
            cl.interval_ms = interval_ms;
            const max_mod = cl.module.len - 1;
            @memcpy(cl.module[0..@min(module.len, max_mod)], module[0..@min(module.len, max_mod)]);
            cl.module[@min(module.len, max_mod)] = 0;
            cl.rva = rva;
            cl.layer_count = layer_count;
            @memset(&cl.offsets, 0);
            if (offsets.len <= 8) @memcpy(cl.offsets[0..offsets.len], offsets);
            return @intCast(i);
        }
    }
    return error.SlotsFull;
}

fn removeChainLock(self: *Daemon, name: []const u8) bool {
    for (&self.chain_locks) |*cl| {
        if (cl.active and std.mem.eql(u8, std.mem.sliceTo(&cl.name, 0), name)) {
            cl.active = false;
            return true;
        }
    }
    return false;
}

pub const ReadResult = struct { slotId: u32, value: u64, hasError: bool };

fn findFreeSlot(self: *Daemon) ?u32 {
    for (0..shm.MAX_CMD_SLOTS) |i| {
        if (self.shm_ptr.cmdSlots[i].mode & shm.MODE_ENABLED == 0) return @intCast(i);
    }
    return null;
}

fn findSlotByName(self: *Daemon, name: []const u8) ?u32 {
    for (0..shm.MAX_CMD_SLOTS) |i| {
        if (self.shm_ptr.cmdSlots[i].mode & shm.MODE_ENABLED != 0) {
            const n = std.mem.sliceTo(&self.lock_names[i], 0);
            if (std.mem.eql(u8, n, name)) return @intCast(i);
        }
    }
    return null;
}

fn clearSlot(self: *Daemon, index: u32) void {
    self.shm_ptr.cmdSlots[index].mode = 0;
    @memset(&self.lock_names[index], 0);
    var count: u32 = 0;
    for (0..shm.MAX_CMD_SLOTS) |i| {
        if (self.shm_ptr.cmdSlots[i].mode & shm.MODE_ENABLED != 0) count += 1;
    }
    self.shm_ptr.cmdCount = count;
    shm.bumpVersion(self.shm_ptr);
}

fn clearAllSlots(self: *Daemon) void {
    for (0..shm.MAX_CMD_SLOTS) |i| {
        self.shm_ptr.cmdSlots[i].mode = 0;
        @memset(&self.lock_names[i], 0);
    }
    self.shm_ptr.cmdCount = 0;
    shm.bumpVersion(self.shm_ptr);
}

pub const Handler = struct {
    daemon: *Daemon,

    pub fn handle(self: *Handler, allocator: std.mem.Allocator, msg_type: socket.MsgType, payload: []const u8) ![]u8 {
        switch (msg_type) {
            .req_status => return makeStatus(self.daemon, allocator),
            .req_lock_add => {
                const name = parseKVPayload(payload, "name") orelse return allocator.dupe(u8, "{\"err\":\"missing name\"}");
                const val_str = parseKVPayload(payload, "value") orelse return allocator.dupe(u8, "{\"err\":\"missing value\"}");
                const val = std.fmt.parseUnsigned(u64, val_str, 10) catch 0;
                const tid_str = parseKVPayload(payload, "type") orelse "u32";
                const tid = types.TypeId.fromString(tid_str) orelse .uint32;
                const addr_str = parseKVPayload(payload, "address") orelse "0";
                const rva = parseAddressRva(addr_str) catch 0;
                const base = self.daemon.shm_ptr.initParams.targetModuleBase;
                const chain_str = parseKVPayload(payload, "chain");

                const slot_idx = self.daemon.findSlotByName(name) orelse self.daemon.findFreeSlot() orelse
                    return allocator.dupe(u8, "{\"err\":\"no free slots\"}");

                var chain_buf: [8]u32 = [_]u32{0} ** 8;
                var chain_len: u32 = 0;
                if (chain_str) |cs| {
                    var it = std.mem.splitScalar(u8, cs, ',');
                    while (it.next()) |part| {
                        if (chain_len >= 8) break;
                        const t = std.mem.trim(u8, part, " []\t");
                        chain_buf[chain_len] = util.parseHexOrDec(u32, t) catch 0;
                        chain_len += 1;
                    }
                }

                self.daemon.setSlot(slot_idx, shm.MODE_ENABLED | shm.MODE_LOCK | shm.MODE_READBACK, tid, val, rva, base, chain_buf[0..chain_len], chain_len) catch {};
                @memcpy(self.daemon.lock_names[slot_idx][0..@min(name.len, 31)], name[0..@min(name.len, 31)]);
                var active: u32 = 0;
                for (0..shm.MAX_CMD_SLOTS) |j| {
                    if (self.daemon.shm_ptr.cmdSlots[j].mode & shm.MODE_ENABLED != 0) active += 1;
                }
                self.daemon.shm_ptr.cmdCount = active;
                shm.bumpVersion(self.daemon.shm_ptr);
                return std.fmt.allocPrint(allocator, "{{\"ok\":true,\"slot\":{d}}}", .{slot_idx});
            },
            .req_lock_remove => {
                const name = parseKVPayload(payload, "name") orelse return allocator.dupe(u8, "{\"err\":\"missing name\"}");
                if (self.daemon.findSlotByName(name)) |idx| {
                    self.daemon.clearSlot(idx);
                    return allocator.dupe(u8, "{\"ok\":true}");
                }
                return allocator.dupe(u8, "{\"err\":\"not found\"}");
            },
            .req_lock_list => return makeStatus(self.daemon, allocator),
            .req_write => {
                const addr_str = parseKVPayload(payload, "addr") orelse "0";
                const val_str = parseKVPayload(payload, "value") orelse return allocator.dupe(u8, "{\"err\":\"missing value\"}");
                const val = util.parseHexOrDec(u64, val_str) catch 0;
                const chain_str = parseKVPayload(payload, "chain");
                const base_str = parseKVPayload(payload, "base") orelse "0";
                const base = util.parseHexOrDec(u64, base_str) catch 0;

                const addr = if (chain_str) |cs| blk: {
                    if (cs.len == 0) {
                        // No chain — direct address
                        break :blk (util.parseHexOrDec(usize, addr_str) catch return allocator.dupe(u8, "{\"err\":\"invalid addr\"}"));
                    }
                    // Resolve chain before writing
                    var chain_buf: [8]u32 = [_]u32{0} ** 8;
                    var chain_len: u32 = 0;
                    var it = std.mem.splitScalar(u8, cs, ',');
                    while (it.next()) |part| {
                        if (chain_len >= 8) break;
                        const t = std.mem.trim(u8, part, " []\t");
                        chain_buf[chain_len] = util.parseHexOrDec(u32, t) catch 0;
                        chain_len += 1;
                    }
                    const rva = parseAddressRva(addr_str) catch @as(u64, 0);
                    const module = parseKVPayload(payload, "module") orelse "";
                    break :blk self.daemon.resolveChain(base, module, rva, chain_buf[0..chain_len], chain_len) catch return allocator.dupe(u8, "{\"err\":\"chain resolve failed\"}");
                } else util.parseHexOrDec(usize, addr_str) catch return allocator.dupe(u8, "{\"err\":\"invalid addr\"}");

                const tid_str = parseKVPayload(payload, "type") orelse "u32";
                const tid = types.TypeId.fromString(tid_str) orelse .uint32;
                self.daemon.writeOnce(addr, val, tid) catch return allocator.dupe(u8, "{\"err\":\"write failed\"}");
                return allocator.dupe(u8, "{\"ok\":true}");
            },
            .req_read => {
                if (parseKVPayload(payload, "addr")) |addr_str| {
                    const addr = util.parseHexOrDec(usize, addr_str) catch 0;
                    const val = self.daemon.readMem(addr, .uint32) catch 0;
                    return std.fmt.allocPrint(allocator, "{{\"value\":{d}}}", .{val});
                }
                return allocator.dupe(u8, "{\"err\":\"missing addr\"}");
            },
            .req_chain_lock => {
                const name = parseKVPayload(payload, "name") orelse return allocator.dupe(u8, "{\"err\":\"missing name\"}");
                const val_str = parseKVPayload(payload, "value") orelse return allocator.dupe(u8, "{\"err\":\"missing value\"}");
                const val = std.fmt.parseUnsigned(u64, val_str, 10) catch 0;
                const tid_str = parseKVPayload(payload, "type") orelse "u32";
                const tid = types.TypeId.fromString(tid_str) orelse .uint32;
                const addr_str = parseKVPayload(payload, "address") orelse "0";
                const rva = parseAddressRva(addr_str) catch 0;
                const base_str = parseKVPayload(payload, "base") orelse "0";
                const base = util.parseHexOrDec(u64, base_str) catch 0;
                const chain_str = parseKVPayload(payload, "chain") orelse "";
                const mod_name = parseKVPayload(payload, "module") orelse "";
                const interval_str = parseKVPayload(payload, "interval") orelse "300";
                const interval_ms: u32 = std.fmt.parseUnsigned(u32, interval_str, 10) catch 300;

                var chain_buf: [8]u32 = [_]u32{0} ** 8;
                var chain_len: u32 = 0;
                if (chain_str.len > 0) {
                    var it = std.mem.splitScalar(u8, chain_str, ',');
                    while (it.next()) |part| {
                        if (chain_len >= 8) break;
                        const t = std.mem.trim(u8, part, " []\t");
                        chain_buf[chain_len] = util.parseHexOrDec(u32, t) catch 0;
                        chain_len += 1;
                    }
                }

                _ = self.daemon.addChainLock(name, val, tid, rva, base, mod_name, chain_buf[0..chain_len], chain_len, interval_ms) catch
                    return allocator.dupe(u8, "{\"err\":\"slots full\"}");
                return allocator.dupe(u8, "{\"ok\":true}");
            },
            .req_chain_unlock => {
                const name = parseKVPayload(payload, "name") orelse return allocator.dupe(u8, "{\"err\":\"missing name\"}");
                if (self.daemon.removeChainLock(name))
                    return allocator.dupe(u8, "{\"ok\":true}");
                return allocator.dupe(u8, "{\"err\":\"not found\"}");
            },
            .req_cheat_start => {
                self.daemon.clearAllSlots();
                var pos: usize = 0;
                const p = payload;
                while (pos < p.len) {
                    const open = std.mem.indexOfScalarPos(u8, p, pos, '{') orelse break;
                    const close = std.mem.indexOfScalarPos(u8, p, open, '}') orelse break;
                    const obj = p[open .. close + 1];
                    pos = close + 1;
                    const lname = parseKVPayload(obj, "name") orelse continue;
                    const lval_str = parseKVPayload(obj, "value") orelse continue;
                    const lval = std.fmt.parseUnsigned(u64, lval_str, 10) catch 0;
                    const ltid_str = parseKVPayload(obj, "type") orelse "u32";
                    const ltid = types.TypeId.fromString(ltid_str) orelse .uint32;
                    const laddr_str = parseKVPayload(obj, "address") orelse "0";
                    const lrva = parseAddressRva(laddr_str) catch 0;
                    const lbase = self.daemon.shm_ptr.initParams.targetModuleBase;
                    const slot_idx = self.daemon.findFreeSlot() orelse break;
                    self.daemon.setSlot(slot_idx, shm.MODE_ENABLED | shm.MODE_LOCK | shm.MODE_READBACK, ltid, lval, lrva, lbase, &.{}, 0) catch continue;
                    @memcpy(self.daemon.lock_names[slot_idx][0..@min(lname.len, 31)], lname[0..@min(lname.len, 31)]);
                }
                var active: u32 = 0;
                for (0..shm.MAX_CMD_SLOTS) |j| {
                    if (self.daemon.shm_ptr.cmdSlots[j].mode & shm.MODE_ENABLED != 0) active += 1;
                }
                self.daemon.shm_ptr.cmdCount = active;
                shm.bumpVersion(self.daemon.shm_ptr);
                return std.fmt.allocPrint(allocator, "{{\"ok\":true,\"locks\":{d}}}", .{active});
            },
            .req_cheat_stop => {
                self.daemon.clearAllSlots();
                return allocator.dupe(u8, "{\"ok\":true}");
            },
            .req_ping => return allocator.dupe(u8, "{\"pong\":true}"),
            .req_call => {
                const addr_str = parseKVPayload(payload, "addr") orelse return allocator.dupe(u8, "{\"err\":\"missing addr\"}");
                const addr = util.parseHexOrDec(u64, addr_str) catch return allocator.dupe(u8, "{\"err\":\"invalid addr\"}");
                const args_str = parseKVPayload(payload, "args") orelse "";
                const call_req: *volatile shm.CallRequest = @ptrCast(@alignCast(&self.daemon.shm_ptr.engineExtData));
                call_req.status = 0;
                call_req.argc = 0;
                call_req.func_addr = 0;
                call_req.args = [_]u64{0} ** 6;
                call_req.result = 0;
                call_req.status = shm.CALL_PENDING;
                call_req.func_addr = addr;
                var argc: u32 = 0;
                if (args_str.len > 0) {
                    var it = std.mem.splitScalar(u8, args_str, ',');
                    while (it.next()) |part| {
                        if (argc >= 6) break;
                        const t = std.mem.trim(u8, part, " []\t\"'");
                        call_req.args[argc] = util.parseHexOrDec(u64, t) catch 0;
                        argc += 1;
                    }
                }
                call_req.argc = argc;
                @atomicStore(u32, &call_req.status, shm.CALL_PENDING, .release);
                shm.bumpVersion(self.daemon.shm_ptr);
                var timeout: u32 = 100;
                while (timeout > 0) : (timeout -= 1) {
                    const st = @atomicLoad(u32, &call_req.status, .acquire);
                    if (st == shm.CALL_DONE) return std.fmt.allocPrint(allocator, "{{\"ok\":true,\"result\":{d}}}", .{call_req.result});
                    if (st == shm.CALL_ERROR) return allocator.dupe(u8, "{\"err\":\"call failed\"}");
                    var req = linux.timespec{ .sec = 0, .nsec = 10_000_000 };
                    _ = linux.nanosleep(&req, null);
                }
                return allocator.dupe(u8, "{\"err\":\"timeout\"}");
            },
            .req_shutdown => return allocator.dupe(u8, "{\"ok\":true}"),
            else => return allocator.dupe(u8, "{\"err\":\"unknown command\"}"),
        }
    }
};

fn makeStatus(d: *Daemon, a: std.mem.Allocator) ![]u8 {
    var json: std.ArrayList(u8) = .empty;
    try json.appendSlice(a, "{\"pid\":");
    var pid_buf: [16]u8 = undefined;
    const pid_str = try std.fmt.bufPrint(&pid_buf, "{d}", .{d.pid});
    try json.appendSlice(a, pid_str);
    try json.appendSlice(a, ",\"locks\":[");
    var written: usize = 0;
    for (0..shm.MAX_CMD_SLOTS) |i| {
        if (d.shm_ptr.cmdSlots[i].mode & shm.MODE_ENABLED != 0) {
            if (written > 0) try json.append(a, ',');
            const name = std.mem.sliceTo(&d.lock_names[i], 0);
            var val_buf: [64]u8 = undefined;
            const val_str = try std.fmt.bufPrint(&val_buf, "{{\"slot\":{d},\"name\":\"{s}\"}}", .{ i, name });
            try json.appendSlice(a, val_str);
            written += 1;
        }
    }
    // Also show chain locks
    for (&d.chain_locks) |*cl| {
        if (!cl.active) continue;
        if (written > 0) try json.append(a, ',');
        const name = std.mem.sliceTo(&cl.name, 0);
        var val_buf: [128]u8 = undefined;
        const val_str = try std.fmt.bufPrint(&val_buf, "{{\"name\":\"{s}\",\"value\":{d},\"type\":\"chain\",\"rva\":\"0x{x}\"}}", .{ name, cl.value, cl.rva });
        try json.appendSlice(a, val_str);
        written += 1;
    }
    try json.appendSlice(a, "]}");
    return json.toOwnedSlice(a);
}

fn parseKVPayload(payload: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [64]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;
    const pos = std.mem.indexOf(u8, payload, search) orelse return null;
    const start = pos + search.len;
    var s = start;
    while (s < payload.len and (payload[s] == ' ' or payload[s] == '\t')) s += 1;
    if (s >= payload.len) return null;
    if (payload[s] == '"') {
        s += 1;
        const end = std.mem.indexOfScalarPos(u8, payload, s, '"') orelse return null;
        return payload[s..end];
    }
    const end = std.mem.indexOfAnyPos(u8, payload, s, ",}\n\r \t") orelse payload.len;
    return payload[s..end];
}

fn parseAddressRva(addr: []const u8) !u64 {
    if (std.mem.indexOfScalar(u8, addr, '+')) |plus| return util.parseHexOrDec(u64, addr[plus + 1 ..]);
    return util.parseHexOrDec(u64, addr);
}
