// ZIGH — Daemon mode: lock loop + socket listener
// Manages shared memory command dispatch and client socket connections.

const std = @import("std");
const shm = @import("../ipc/shm.zig");
const mem = @import("../mem/mod.zig");
const types = @import("../mem/types.zig");
const posix = std.posix;

pub const Daemon = @This();

allocator: std.mem.Allocator,
shm_ptr: *align(4096) shm.SharedMemory,
shm_name: [:0]const u8,
pid: u32,
engine: u32,
mem_file: ?posix.fd_t = null, // /proc/PID/mem fd for non-injected mode

pub fn init(
    allocator: std.mem.Allocator,
    pid: u32,
    engine: u32,
) !Daemon {
    var name_buf: [64]u8 = undefined;
    const name = try shm.makeName(&name_buf, pid, engine);

    const shm_ptr = shm.create(name) catch |err| {
        if (err == error.ShmOpenFailed) {
            // Stale shared memory — try to unlink and recreate
            _ = std.c.shm_unlink(name);
            return init(allocator, pid, engine);
        }
        return err;
    };

    // Fill init params
    shm_ptr.engineType = engine;
    shm_ptr.initParams.targetPid = pid;

    // Try to find module base
    if (mem.getModuleBase(allocator, pid, ".exe")) |maybe_base| {
        if (maybe_base) |base| {
            shm_ptr.initParams.targetModuleBase = base;
            std.debug.print("[daemon] Module base: 0x{x}\n", .{base});
        }
    } else |_| {}

    // Open /proc/PID/mem for direct memory ops (non-injected mode)
    const maybe_fd = mem.openProcMem(pid) catch null;

    return Daemon{
        .allocator = allocator,
        .shm_ptr = shm_ptr,
        .shm_name = name,
        .pid = pid,
        .engine = engine,
        .mem_file = maybe_fd,
    };
}

pub fn deinit(self: *Daemon) void {
    // Signal shutdown to agent
    @atomicStore(u32, &self.shm_ptr.agentStatus, shm.STATUS_SHUTDOWN, .release);
    shm.bumpVersion(self.shm_ptr);

    if (self.mem_file) |fd| _ = std.c.close(fd);

    // Unlink needs the name. Since we own the allocation of the name buffer,
    // we just pass what we have. But shm_name points into a stack buffer from init...
    // For now, reconstruct the name:
    var name_buf: [64]u8 = undefined;
    const name = shm.makeName(&name_buf, self.pid, self.engine) catch return;
    shm.destroy(self.shm_ptr, name);
}

/// Write a value to a specific slot. Call bumpVersion() after modifying slots.
pub fn setSlot(self: *Daemon, index: u32, mode: u32, tid: types.TypeId, value: u64, rva: u64, base: u64, offsets: []const u32, layer_count: u32) !void {
    if (index >= shm.MAX_CMD_SLOTS) return error.SlotOutOfRange;

    const slot = &self.shm_ptr.cmdSlots[index];
    slot.mode = mode;
    slot.valueType = @intFromEnum(tid);
    slot.layerCount = layer_count;
    slot.slotId = index + 1; // 1-based slot ID
    slot.valueAsU64 = value;
    slot.rva = rva;
    slot.targetModuleBase = base;

    @memset(&slot.offsets, 0);
    if (offsets.len > 0 and offsets.len <= 8) {
        @memcpy(slot.offsets[0..offsets.len], offsets);
    }
}

/// Issue a one-shot write via /proc/PID/mem (no shared memory needed).
pub fn writeOnce(self: *Daemon, addr: usize, value: u64, tid: types.TypeId) !void {
    const file = self.mem_file orelse return error.NoMemAccess;
    try mem.writeU64(file, addr, value, tid);
}

/// Read a value via /proc/PID/mem.
pub fn readMem(self: *Daemon, addr: usize, tid: types.TypeId) !u64 {
    const file = self.mem_file orelse return error.NoMemAccess;
    return mem.readU64(file, addr, tid);
}

/// Resolve address from a cheat's module+offset+chain description.
pub fn resolveAddr(self: *Daemon, module_base: usize, rva: u64, chain: []const u32) !usize {
    const file = self.mem_file orelse return error.NoMemAccess;
    return mem.resolveChain(file, module_base, rva, chain, @intCast(chain.len));
}

/// Push all pending commands to shared memory and signal agent.
pub fn commit(self: *Daemon) void {
    shm.bumpVersion(self.shm_ptr);
}

/// Read back values from the readSlots area.
pub fn readBack(self: *Daemon, buf: []ReadResult) usize {
    var count: usize = 0;
    for (self.shm_ptr.readSlots[0..@intCast(shm.MAX_READ_SLOTS)], 0..) |rs, i| {
        _ = i;
        if (count >= buf.len) break;
        if (rs.flags & 1 != 0) { // VALID flag
            buf[count] = .{
                .slotId = rs.slotId,
                .value = rs.valueAsU64,
                .hasError = (rs.flags & 0xE) != 0,
            };
            count += 1;
        }
    }
    return count;
}

pub const ReadResult = struct {
    slotId: u32,
    value: u64,
    hasError: bool,
};
