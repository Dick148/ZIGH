// ZIGH Agent — Worker-thread based (no hooks needed, pure Zig)
// Injected via ptrace. Creates its own worker thread that polls shm
// and writes values. On error, reports via readSlots.

const std = @import("std");
const linux = std.os.linux;

const SHM_SIZE = 4096;
const MAX_CMD_SLOTS = 16;
const MODE_ENABLED = @as(u32, 1 << 0);
const MODE_LOCK = @as(u32, 1 << 1);
const STATUS_UNINITIALIZED: u32 = 0;
const STATUS_RUNNING: u32 = 1;
const STATUS_ERROR: u32 = 2;
const STATUS_SHUTDOWN: u32 = 3;

// ReadSlot error flags
const RS_VALID = @as(u32, 1 << 0);
const RS_READ_ERR = @as(u32, 1 << 1);
const RS_WRITE_ERR = @as(u32, 1 << 2);
const RS_CHAIN_BROKEN = @as(u32, 1 << 3);

const SharedMemory = extern struct {
    version: u32, cmdCount: u32, lockIntervalMs: u32, engineType: u32,
    agentStatus: u32, reserved: u32, initParams: [48]u8,
    cmdSlots: [MAX_CMD_SLOTS]extern struct {
        mode: u32, valueType: u32, layerCount: u32, slotId: u32,
        valueAsU64: u64, rva: u64, targetModuleBase: u64,
        offsets: [8]u32, _reserved: [32]u8,
    },
    readSlots: [64]extern struct { valueAsU64: u64, slotId: u32, flags: u32 },
    engineExtData: [256]u8,
};

const CachedCmd = struct {
    addr: usize,
    value: u64,
    tid: u32,
    needsReResolve: bool,
    rva: u64,
    base: u64,
    offsets: [8]u32,
    layerCount: u32,
    slotId: u32,
};

var shm: *volatile SharedMemory = undefined;
var last_version: u32 = 0;
var lock_cmds: [MAX_CMD_SLOTS]CachedCmd = undefined;
var lock_count: u32 = 0;
var initialized: bool = false;
var worker_running: bool = false;

fn tryOpenShm(my_pid: u32, engine: u32) ?*volatile SharedMemory {
    var name_buf: [64]u8 = undefined;
    const name = std.fmt.bufPrintZ(&name_buf, "/dev/shm/zigh_{d}_{d}", .{ my_pid, engine }) catch return null;
    const fd = linux.open(name, linux.O{ .ACCMODE = .RDWR }, 0);
    if (@as(isize, @bitCast(fd)) < 0) return null;
    const ptr = linux.mmap(null, SHM_SIZE, linux.PROT{ .READ = true, .WRITE = true }, linux.MAP{ .TYPE = .SHARED }, @intCast(fd), 0);
    _ = std.c.close(@intCast(fd));
    if (@as(isize, @bitCast(ptr)) < 0) return null;
    return @ptrFromInt(@as(usize, @bitCast(ptr)));
}

fn resolveChain(base: usize, rva: u64, offsets: [*]const u32, layers: u32) usize {
    if (layers == 0) return base + rva;
    var ptr: usize = base + rva;
    var i: u32 = 0;
    while (i < layers - 1) : (i += 1) {
        ptr = @as(*usize, @ptrFromInt(ptr + offsets[i])).*;
        if (ptr == 0) return 0;
    }
    return ptr + offsets[layers - 1];
}

fn writeValue(addr: usize, value: u64, tid: u32) void {
    switch (tid) {
        0, 1 => @as(*u8, @ptrFromInt(addr)).* = @truncate(value),
        2, 3 => @as(*u16, @ptrFromInt(addr)).* = @truncate(value),
        4, 5, 8 => @as(*u32, @ptrFromInt(addr)).* = @truncate(value),
        else => @as(*u64, @ptrFromInt(addr)).* = value,
    }
}

/// Write error info to the corresponding readSlot.
fn reportSlotError(slot_id: u32, flags: u32, value: u64) void {
    if (slot_id == 0 or slot_id > 64) return;
    const rs = &shm.readSlots[slot_id - 1];
    rs.valueAsU64 = value;
    rs.slotId = slot_id;
    rs.flags = flags;
}

/// Clear any previous error on the readSlot for this command.
fn clearSlotError(slot_id: u32) void {
    if (slot_id == 0 or slot_id > 64) return;
    shm.readSlots[slot_id - 1].flags = 0;
}

fn rebuildCommands() void {
    lock_count = 0;
    const count = @atomicLoad(u32, &shm.cmdCount, .acquire);
    var i: u32 = 0;
    while (i < count and i < MAX_CMD_SLOTS) : (i += 1) {
        const slot = &shm.cmdSlots[i];
        if (slot.mode & MODE_ENABLED == 0) continue;
        if (slot.mode & MODE_LOCK == 0) continue;

        const addr = resolveChain(slot.targetModuleBase, slot.rva, @volatileCast(@ptrCast(&slot.offsets)), slot.layerCount);
        lock_cmds[lock_count] = .{
            .addr = addr,
            .value = slot.valueAsU64,
            .tid = slot.valueType,
            .needsReResolve = (slot.mode & (1 << 4)) != 0,
            .rva = slot.rva,
            .base = slot.targetModuleBase,
            .offsets = slot.offsets,
            .layerCount = slot.layerCount,
            .slotId = slot.slotId,
        };
        lock_count += 1;
    }
}

fn executeLocks() void {
    var i: u32 = 0;
    while (i < lock_count) : (i += 1) {
        const cmd = &lock_cmds[i];

        // Resolve chain address
        var addr = cmd.addr;
        if (cmd.needsReResolve or addr == 0) {
            addr = resolveChain(cmd.base, cmd.rva, &cmd.offsets, cmd.layerCount);
            cmd.addr = addr;
        }

        if (addr == 0) {
            reportSlotError(cmd.slotId, RS_CHAIN_BROKEN, cmd.value);
            continue;
        }

        // Perform the write
        // In an injected agent, writing to an invalid address causes SIGSEGV.
        // We can't catch that from user mode, so we trust the addr is valid.
        // The /proc/PID/mem path (daemon-side) does proper error checking.
        writeValue(addr, cmd.value, cmd.tid);

        // Clear any previous error — success is silent
        if (shm.readSlots[cmd.slotId - 1].flags != 0) {
            clearSlotError(cmd.slotId);
        }
    }
}

/// Worker thread: polls shared memory, executes locks, sleeps.
fn agentWorker() void {
    while (worker_running) {
        const status = @atomicLoad(u32, &shm.agentStatus, .acquire);
        if (status == STATUS_SHUTDOWN) {
            worker_running = false;
            return;
        }

        // Check for version change (new/modified commands)
        const ver = @atomicLoad(u32, &shm.version, .acquire);
        if (ver != last_version) {
            rebuildCommands();
            last_version = ver;
        }

        // Execute lock commands
        if (lock_count > 0) {
            executeLocks();
        }

        // Sleep for lockIntervalMs (default 250ms), read from daemon-controlled shm header
        const interval = @atomicLoad(u32, &shm.lockIntervalMs, .acquire);
        const sleep_ms: u64 = if (interval > 0) @min(interval, 5000) else 250;
        var req = linux.timespec{ .sec = @intCast(sleep_ms / 1000), .nsec = @intCast((sleep_ms % 1000) * 1_000_000) };
        _ = linux.nanosleep(&req, null);
    }
}

export fn agent_init() void {
    const my_pid: u32 = @intCast(linux.getpid());
    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        if (tryOpenShm(my_pid, 0)) |s| {
            shm = s;
            const engine = @atomicLoad(u32, &shm.engineType, .acquire);
            if (engine != 0) {
                if (tryOpenShm(my_pid, engine)) |s2| {
                    shm = s2;
                } else {
                    continue;
                }
            }
            initialized = true;

            // Spawn the worker thread (detached — runs independently)
            worker_running = true;
            const thread = std.Thread.spawn(.{}, agentWorker, .{}) catch {
                @atomicStore(u32, &shm.agentStatus, STATUS_ERROR, .release);
                return;
            };
            thread.detach();

            @atomicStore(u32, &shm.agentStatus, STATUS_RUNNING, .release);
            return;
        }
        // Sleep 100ms between retries (up to 60s total)
        var req = linux.timespec{ .sec = 0, .nsec = 100_000_000 };
        _ = linux.nanosleep(&req, null);
    }
}

// Legacy export: agent_tick for backward compat with hook-based injection.
// No longer the primary execution path — use agent_init + worker thread instead.
export fn agent_tick() callconv(.c) void {
    if (!initialized) return;
    const ver = @atomicLoad(u32, &shm.version, .acquire);
    if (ver != last_version) {
        rebuildCommands();
        last_version = ver;
    }
    if (lock_count > 0) {
        executeLocks();
    }
}

// Reserved space for hook trampoline (may be written by injector at runtime)
export var _trampoline_space: [128]u8 align(16) = [_]u8{0xcc} ** 128;
