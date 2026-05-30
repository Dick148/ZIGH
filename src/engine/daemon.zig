// ZIGH — Daemon mode: shared memory + socket listener
// Handles commands from CLI via Unix socket, manages memory locks

const std = @import("std");
const shm = @import("../ipc/shm.zig");
const mem = @import("../mem/mod.zig");
const types = @import("../mem/types.zig");
const socket = @import("../ipc/socket.zig");
const linux = std.os.linux;

pub const Daemon = @This();

allocator: std.mem.Allocator,
shm_ptr: *align(4096) shm.SharedMemory,
shm_name: [:0]const u8,
pid: u32,
engine: u32,
mem_fd: ?linux.fd_t = null,

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

    return Daemon{
        .allocator = allocator,
        .shm_ptr = shm_ptr,
        .shm_name = name,
        .pid = pid,
        .engine = engine,
        .mem_fd = maybe_fd,
    };
}

pub fn deinit(self: *Daemon) void {
    @atomicStore(u32, &self.shm_ptr.agentStatus, shm.STATUS_SHUTDOWN, .release);
    shm.bumpVersion(self.shm_ptr);
    if (self.mem_fd) |fd| _ = std.c.close(fd);
    var name_buf: [64]u8 = undefined;
    const name = shm.makeName(&name_buf, self.pid, self.engine) catch return;
    shm.destroy(self.shm_ptr, name);
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

pub fn readBack(self: *Daemon, buf: []ReadResult) usize {
    var count: usize = 0;
    for (self.shm_ptr.readSlots[0..@intCast(shm.MAX_READ_SLOTS)], 0..) |rs, i| {
        _ = i;
        if (count >= buf.len) break;
        if (rs.flags & 1 != 0) {
            buf[count] = .{ .slotId = rs.slotId, .value = rs.valueAsU64, .hasError = (rs.flags & 0xE) != 0 };
            count += 1;
        }
    }
    return count;
}

pub const ReadResult = struct { slotId: u32, value: u64, hasError: bool };

// ─── Socket handler ─────────────────────────────────────────────────────

pub const Handler = struct {
    daemon: *Daemon,

    pub fn handle(self: *Handler, allocator: std.mem.Allocator, msg_type: socket.MsgType, payload: []const u8) ![]u8 {
        switch (msg_type) {
            .req_status => return makeStatus(self.daemon, allocator),
            .req_lock_add => {
                if (parseKVPayload(payload, "name")) |name| {
                    if (parseKVPayload(payload, "value")) |val_str| {
                        const val = std.fmt.parseUnsigned(u64, val_str, 10) catch 0;
                        const tid = if (parseKVPayload(payload, "type")) |t| types.TypeId.fromString(t) orelse .uint32 else .uint32;
                        const addr_str = parseKVPayload(payload, "address") orelse "0";
                        const rva = parseAddressRva(addr_str) catch 0;
                        _ = name; _ = val; _ = tid; _ = rva;
                        // TODO: actually add lock slot
                        return allocator.dupe(u8, "{\"ok\":true}");
                    }
                }
                return allocator.dupe(u8, "{\"err\":\"missing args\"}");
            },
            .req_lock_remove => return allocator.dupe(u8, "{\"ok\":true}"),
            .req_lock_list => return makeStatus(self.daemon, allocator),
            .req_write => {
                if (parseKVPayload(payload, "addr")) |addr_str| {
                    if (parseKVPayload(payload, "value")) |val_str| {
                        const addr = parseHexOrDec(usize, addr_str) catch 0;
                        const val = parseHexOrDec(u64, val_str) catch 0;
                        self.daemon.writeOnce(addr, val, .uint32) catch {};
                        return allocator.dupe(u8, "{\"ok\":true}");
                    }
                }
                return allocator.dupe(u8, "{\"err\":\"missing args\"}");
            },
            .req_read => {
                if (parseKVPayload(payload, "addr")) |addr_str| {
                    const addr = parseHexOrDec(usize, addr_str) catch 0;
                    const val = self.daemon.readMem(addr, .uint32) catch 0;
                    return std.fmt.allocPrint(allocator, "{{\"value\":{d}}}", .{val});
                }
                return allocator.dupe(u8, "{\"err\":\"missing addr\"}");
            },
            .req_ping => return allocator.dupe(u8, "{\"pong\":true}"),
            .req_shutdown => return allocator.dupe(u8, "{\"ok\":true}"),
            else => return allocator.dupe(u8, "{\"err\":\"unknown command\"}"),
        }
    }
};

fn makeStatus(d: *Daemon, a: std.mem.Allocator) ![]u8 {
    var results: [64]ReadResult = undefined;
    const count = d.readBack(&results);
    var json: std.ArrayList(u8) = .empty;
    try json.appendSlice(a, "{\"pid\":");
    var pid_buf: [16]u8 = undefined;
    const pid_str = try std.fmt.bufPrint(&pid_buf, "{d}", .{d.pid});
    try json.appendSlice(a, pid_str);
    try json.appendSlice(a, ",\"locks\":[");
    for (results[0..count], 0..) |r, i| {
        if (i > 0) try json.append(a, ',');
        var val_buf: [32]u8 = undefined;
        const val_str = try std.fmt.bufPrint(&val_buf, "{{\"slot\":{d},\"value\":{d}}}", .{ r.slotId, r.value });
        try json.appendSlice(a, val_str);
    }
    try json.appendSlice(a, "]}");
    return json.toOwnedSlice(a);
}

fn parseKVPayload(payload: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [64]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;
    const pos = std.mem.indexOf(u8, payload, search) orelse return null;
    const start = pos + search.len;
    // Skip whitespace
    var s = start;
    while (s < payload.len and (payload[s] == ' ' or payload[s] == '\t')) s += 1;
    if (s >= payload.len) return null;
    if (payload[s] == '"') {
        s += 1;
        const end = std.mem.indexOfScalarPos(u8, payload, s, '"') orelse return null;
        return payload[s..end];
    }
    // Number or unquoted
    const end = std.mem.indexOfAnyPos(u8, payload, s, ",}\n\r \t") orelse payload.len;
    return payload[s..end];
}

fn parseAddressRva(addr: []const u8) !u64 {
    if (std.mem.indexOfScalar(u8, addr, '+')) |plus| return parseHexOrDec(u64, addr[plus + 1 ..]);
    return parseHexOrDec(u64, addr);
}

fn parseHexOrDec(comptime T: type, s: []const u8) !T {
    const t = std.mem.trim(u8, s, " \t");
    if (std.mem.startsWith(u8, t, "0x") or std.mem.startsWith(u8, t, "0X")) return std.fmt.parseUnsigned(T, t[2..], 16);
    return std.fmt.parseUnsigned(T, t, 10);
}
