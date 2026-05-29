// ZIGH — Shared memory IPC (Linux POSIX shm)
// Implements the wire-compatible protocol layout from docs/ipc-protocol-linux.md

const std = @import("std");
const posix = std.posix;
const c = std.c;
const types = @import("../mem/types.zig");

// ─── Constants (protocol v2) ────────────────────────────────────────────
pub const SHM_SIZE = 4096;

pub const MAX_CMD_SLOTS: u32 = 16;
pub const CMD_SLOT_SIZE: u32 = 80;
pub const MAX_READ_SLOTS: u32 = 64;
pub const READ_SLOT_SIZE: u32 = 16;

pub const OFFSET_VERSION: u32 = 0x0000;
pub const OFFSET_CMD_COUNT: u32 = 0x0004;
pub const OFFSET_LOCK_INTERVAL: u32 = 0x0008;
pub const OFFSET_ENGINE_TYPE: u32 = 0x000C;
pub const OFFSET_AGENT_STATUS: u32 = 0x0010;
pub const OFFSET_INIT_PARAMS: u32 = 0x0018;
pub const OFFSET_CMD_AREA: u32 = 0x0048;
pub const OFFSET_READ_AREA: u32 = 0x0548;
pub const OFFSET_EXT_AREA: u32 = 0x0948;

pub const MODE_ENABLED: u32 = 1 << 0;
pub const MODE_LOCK: u32 = 1 << 1;
pub const MODE_READBACK: u32 = 1 << 2;
pub const MODE_ENGINE_CALL: u32 = 1 << 3;
pub const MODE_NEED_CHAIN_RESOLVE: u32 = 1 << 4;

pub const STATUS_UNINITIALIZED: u32 = 0;
pub const STATUS_RUNNING: u32 = 1;
pub const STATUS_ERROR: u32 = 2;
pub const STATUS_SHUTDOWN: u32 = 3;

// ─── Layout structs (packed for wire compatibility) ─────────────────────

pub const CmdSlot = extern struct {
    mode: u32 align(4) = 0,
    valueType: u32 = 0,
    layerCount: u32 = 0,
    slotId: u32 = 0,
    valueAsU64: u64 = 0,
    rva: u64 = 0,
    targetModuleBase: u64 = 0,
    offsets: [8]u32 = [_]u32{0} ** 8,
    reserved: [32]u8 = [_]u8{0} ** 32,
};

pub const ReadSlot = extern struct {
    valueAsU64: u64 = 0,
    slotId: u32 = 0,
    flags: u32 = 0,
};

pub const InitParams = extern struct {
    targetModuleBase: u64 = 0,
    targetPid: u32 = 0,
    targetBit: u32 = 0,
    socketPath: [32]u8 = [_]u8{0} ** 32,
};

pub const SharedMemory = extern struct {
    version: u32 = 0,
    cmdCount: u32 = 0,
    lockIntervalMs: u32 = 16,
    engineType: u32 = 0,
    agentStatus: u32 = 0,
    reserved: u32 = 0,
    initParams: InitParams = .{},
    cmdSlots: [MAX_CMD_SLOTS]CmdSlot = [_]CmdSlot{.{}} ** MAX_CMD_SLOTS,
    readSlots: [MAX_READ_SLOTS]ReadSlot = [_]ReadSlot{.{}} ** MAX_READ_SLOTS,
    engineExtData: [256]u8 = [_]u8{0} ** 256,
};

// ─── Operations ─────────────────────────────────────────────────────────

/// Create + mmap a POSIX shared memory region. Returns aligned pointer.
pub fn create(name: [:0]const u8) !*align(4096) SharedMemory {
    const fd = c.shm_open(name, @bitCast(posix.O{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true }), 0o600);
    if (fd == -1) return error.ShmOpenFailed;
    _ = c.ftruncate(fd, SHM_SIZE);
    const slice = try posix.mmap(null, SHM_SIZE, posix.PROT{ .READ = true, .WRITE = true }, posix.MAP{ .TYPE = .SHARED }, @intCast(fd), 0);
    posix.close(@intCast(fd));
    const ptr: *align(4096) SharedMemory = @ptrCast(@alignCast(slice.ptr));
    @memset(@as([*]u8, @ptrCast(ptr))[0..SHM_SIZE], 0);
    return ptr;
}

/// Open an existing POSIX shared memory region (read/write).
pub fn open(name: [:0]const u8) !*align(4096) SharedMemory {
    const fd = c.shm_open(name, @bitCast(posix.O{ .ACCMODE = .RDWR }), 0);
    if (fd == -1) return error.ShmOpenFailed;
    const slice = try posix.mmap(null, SHM_SIZE, posix.PROT{ .READ = true, .WRITE = true }, posix.MAP{ .TYPE = .SHARED }, @intCast(fd), 0);
    posix.close(@intCast(fd));
    return @ptrCast(@alignCast(slice.ptr));
}

/// Unmap + unlink shared memory.
pub fn destroy(shm_ptr: *align(4096) SharedMemory, name: [:0]const u8) void {
    const ptr: [*]align(std.mem.page_size) u8 = @ptrCast(@alignCast(shm_ptr));
    posix.munmap(ptr[0..SHM_SIZE]);
    _ = c.shm_unlink(name);
}

/// Atomically increment the version field to signal agent.
pub fn bumpVersion(shm_ptr: *SharedMemory) void {
    _ = @atomicRmw(u32, &shm_ptr.version, .Add, 1, .release);
}

/// Build a shared memory name path for a given PID and engine type.
pub fn makeName(buf: []u8, pid: u32, engine: u32) ![:0]u8 {
    return try std.fmt.bufPrintZ(buf, "/zigh_{d}_{d}", .{ pid, engine });
}
