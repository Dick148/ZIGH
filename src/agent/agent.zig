// ZIGH Agent — Injected .so for zero-syscall memory locking
// Runs inside the game process, reads shared memory, writes directly

const std = @import("std");
const linux = std.os.linux;

// ─── Shared memory layout (must match ipc/shm.zig) ──────────────────────

const SHM_SIZE = 4096;
const MAX_CMD_SLOTS = 16;
const MODE_ENABLED = @as(u32, 1 << 0);
const MODE_LOCK = @as(u32, 1 << 1);
const MODE_READBACK = @as(u32, 1 << 2);
const STATUS_RUNNING = @as(u32, 1);
const STATUS_SHUTDOWN = @as(u32, 3);

const CmdSlot = extern struct {
    mode: u32,
    valueType: u32,
    layerCount: u32,
    slotId: u32,
    valueAsU64: u64,
    rva: u64,
    targetModuleBase: u64,
    offsets: [8]u32,
    _reserved: [32]u8,
};

const ReadSlot = extern struct {
    valueAsU64: u64,
    slotId: u32,
    flags: u32,
};

const SharedMemory = extern struct {
    version: u32,
    cmdCount: u32,
    lockIntervalMs: u32,
    engineType: u32,
    agentStatus: u32,
    _reserved: u32,
    _initParams: [48]u8,
    cmdSlots: [MAX_CMD_SLOTS]CmdSlot,
    readSlots: [64]ReadSlot,
    _ext: [256]u8,
};

const CachedCmd = struct {
    addr: usize,
    value: u64,
    tid: u32,
    slotId: u32,
    needsReadback: bool,
    needsReResolve: bool,
    rva: u64,
    base: u64,
    offsets: [8]u32,
    layerCount: u32,
};

// ─── Globals ─────────────────────────────────────────────────────────────

var shm: *volatile SharedMemory = undefined;
var last_version: u32 = 0;
var lock_cmds: [MAX_CMD_SLOTS]CachedCmd = undefined;
var lock_count: u32 = 0;

// ─── Helper: nanosleep via syscall ───────────────────────────────────────

fn sleepMs(ms: u32) void {
    const ns: u64 = @as(u64, ms) * 1_000_000;
    var req = linux.timespec{ .sec = @intCast(ns / 1_000_000_000), .nsec = @intCast(ns % 1_000_000_000) };
    _ = linux.nanosleep(&req, null);
}

// ─── Pointer chain resolution ────────────────────────────────────────────

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

// ─── Direct memory write (no syscall!) ───────────────────────────────────

fn writeValue(addr: usize, value: u64, tid: u32) void {
    const p = @as([*]u8, @ptrFromInt(addr));
    switch (tid) {
        0, 1 => p[0] = @truncate(value), // int8/uint8
        2, 3 => {
            const v16: u16 = @truncate(value);
            @as(*u16, @ptrFromInt(addr)).* = v16;
        },
        4, 5, 8 => {
            const v32: u32 = @truncate(value);
            @as(*u32, @ptrFromInt(addr)).* = v32;
        },
        6, 7, 9, 10, 11 => {
            @as(*u64, @ptrFromInt(addr)).* = value;
        },
        else => {},
    }
}

fn readValue(addr: usize, tid: u32) u64 {
    switch (tid) {
        0 => return @bitCast(@as(i64, @as(i8, @bitCast(@as(u8, @truncate(@as(*u8, @ptrFromInt(addr)).*)))))),
        1 => return @as(*u8, @ptrFromInt(addr)).*,
        2 => return @bitCast(@as(i64, @as(i16, @bitCast(@as(*u16, @ptrFromInt(addr)).*)))),
        3 => return @as(*u16, @ptrFromInt(addr)).*,
        4 => return @bitCast(@as(i64, @as(i32, @bitCast(@as(*u32, @ptrFromInt(addr)).*)))),
        5, 8 => return @as(*u32, @ptrFromInt(addr)).*,
        6 => return @bitCast(@as(i64, @bitCast(@as(*u64, @ptrFromInt(addr)).*))),
        7, 9, 10, 11 => return @as(*u64, @ptrFromInt(addr)).*,
        else => return 0,
    }
}

// ─── Rebuild cached command list ─────────────────────────────────────────

fn rebuildCommands() void {
    lock_count = 0;
    const count = @atomicLoad(u32, &shm.cmdCount, .acquire);
    var i: u32 = 0;
    while (i < count and i < MAX_CMD_SLOTS) : (i += 1) {
        const slot = &shm.cmdSlots[i];
        if (slot.mode & MODE_ENABLED == 0) continue;
        if (slot.mode & MODE_LOCK == 0) continue;

        const addr = resolveChain(slot.targetModuleBase, slot.rva, @volatileCast(@ptrCast(&slot.offsets)), slot.layerCount);
        lock_cmds[lock_count] = CachedCmd{
            .addr = addr,
            .value = slot.valueAsU64,
            .tid = slot.valueType,
            .slotId = slot.slotId,
            .needsReadback = (slot.mode & MODE_READBACK) != 0,
            .needsReResolve = (slot.mode & (1 << 4)) != 0,
            .rva = slot.rva,
            .base = slot.targetModuleBase,
            .offsets = slot.offsets,
            .layerCount = slot.layerCount,
        };
        lock_count += 1;
    }
}

// ─── Main lock loop ──────────────────────────────────────────────────────

fn workerLoop() void {
    while (true) {
        const status = @atomicLoad(u32, &shm.agentStatus, .acquire);
        if (status == STATUS_SHUTDOWN) break;

        const ver = @atomicLoad(u32, &shm.version, .acquire);
        if (ver != last_version) {
            rebuildCommands();
            last_version = ver;
        }

        // Execute all lock commands
        var i: u32 = 0;
        while (i < lock_count) : (i += 1) {
            const cmd = &lock_cmds[i];
            if (cmd.addr == 0) continue;

            if (cmd.needsReResolve) {
                cmd.addr = resolveChain(cmd.base, cmd.rva, &cmd.offsets, cmd.layerCount);
                if (cmd.addr == 0) continue;
            }

            writeValue(cmd.addr, cmd.value, cmd.tid);

            if (cmd.needsReadback) {
                const actual = readValue(cmd.addr, cmd.tid);
                // Find matching readSlot by slotId
                var ri: u32 = 0;
                while (ri < 64) : (ri += 1) {
                    if (shm.readSlots[ri].slotId == cmd.slotId) {
                        shm.readSlots[ri].valueAsU64 = actual;
                        shm.readSlots[ri].flags = 1; // VALID
                        break;
                    }
                }
            }
        }

        const interval = @atomicLoad(u32, &shm.lockIntervalMs, .acquire);
        sleepMs(if (interval > 0) interval else 16);
    }
}

// ─── Constructor — called when .so is loaded ─────────────────────────────

fn openShm(name: [:0]const u8) ?*volatile SharedMemory {
    const fd = std.c.shm_open(name, @bitCast(linux.O{ .ACCMODE = .RDWR }), 0);
    if (fd == -1) return null;
    const ptr = linux.mmap(null, SHM_SIZE, linux.PROT{ .READ = true, .WRITE = true }, linux.MAP{ .TYPE = .SHARED }, @intCast(fd), 0);
    _ = std.c.close(fd);
    if (@as(isize, @bitCast(ptr)) < 0) return null;
    return @ptrFromInt(@as(usize, @bitCast(ptr)));
}

export fn agent_init() void {
    // Get own PID
    const my_pid = linux.getpid();

    // Try to open shared memory (try engine=0 first = generic)
    var name_buf: [64]u8 = undefined;
    const name = std.fmt.bufPrintZ(&name_buf, "/zigh_{d}_0", .{my_pid}) catch return;
    shm = openShm(name) orelse return;

    // Read engine type from shm
    const engine = @atomicLoad(u32, &shm.engineType, .acquire);

    // If engine != 0, reopen with correct name
    if (engine != 0) {
        const name2 = std.fmt.bufPrintZ(&name_buf, "/zigh_{d}_{d}", .{ my_pid, engine }) catch return;
        shm = openShm(name2) orelse return;
    }

    // Mark as running
    @atomicStore(u32, &shm.agentStatus, STATUS_RUNNING, .release);

    // Start worker
    workerLoop();
}

// Dummy main for shared library
export fn _start() void {}
