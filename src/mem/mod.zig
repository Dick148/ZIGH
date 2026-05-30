// ZIGH — Process memory operations
// /proc/PID/mem access via raw Linux syscalls (fd + pread/pwrite)

const std = @import("std");
const types = @import("types.zig");
const linux = std.os.linux;

/// Open a handle to a process's memory via /proc/PID/mem.
/// Returns raw fd — caller must close with std.c.close().
pub fn openProcMem(pid: u32) !linux.fd_t {
    var buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&buf, "/proc/{d}/mem", .{pid});
    const raw = linux.open(path, linux.O{ .ACCMODE = .RDWR }, 0);
    const fd_signed: isize = @bitCast(raw);
    if (fd_signed < 0) return error.OpenFailed;
    return @intCast(fd_signed);
}

/// Read raw bytes from a process's memory at a given address.
pub fn readRaw(fd: linux.fd_t, addr: usize, buf: []u8) void {
    _ = linux.pread(fd, buf.ptr, buf.len, @intCast(addr));
}

/// Write raw bytes to a process's memory at a given address.
pub fn writeRaw(fd: linux.fd_t, addr: usize, buf: []const u8) void {
    _ = linux.pwrite(fd, buf.ptr, buf.len, @intCast(addr));
}

/// Read a typed value. Returns the raw u64 (protocol wire format).
pub fn readU64(fd: linux.fd_t, addr: usize, tid: types.TypeId) !u64 {
    var buf: [8]u8 = [_]u8{0} ** 8;
    const sz = tid.size();
    readRaw(fd, addr, buf[0..sz]);
    return switch (sz) {
        1 => @as(u64, buf[0]),
        2 => @as(u64, std.mem.readInt(u16, buf[0..2], .little)),
        4 => @as(u64, std.mem.readInt(u32, buf[0..4], .little)),
        8 => std.mem.readInt(u64, buf[0..8], .little),
        else => error.UnsupportedSize,
    };
}

/// Write a typed value.
pub fn writeU64(fd: linux.fd_t, addr: usize, value: u64, tid: types.TypeId) !void {
    var buf: [8]u8 = undefined;
    const sz = tid.size();
    switch (sz) {
        1 => buf[0] = @truncate(value),
        2 => std.mem.writeInt(u16, buf[0..2], @truncate(value), .little),
        4 => std.mem.writeInt(u32, buf[0..4], @truncate(value), .little),
        8 => std.mem.writeInt(u64, buf[0..8], value, .little),
        else => return error.UnsupportedSize,
    }
    writeRaw(fd, addr, buf[0..sz]);
}

/// Resolve a pointer chain.
pub fn resolveChain(fd: linux.fd_t, base: usize, rva: u64, offsets: []const u32, layer_count: u32) !usize {
    if (layer_count == 0) return base + rva;

    var ptr: usize = base + rva;
    for (offsets[0 .. layer_count - 1]) |off| {
        ptr = try readU64(fd, ptr + off, .pointer);
        if (ptr == 0) return error.NullPointerInChain;
    }
    return ptr + offsets[layer_count - 1];
}

/// Get the base address of a module in a process via /proc/PID/maps.
pub fn getModuleBase(allocator: std.mem.Allocator, pid: u32, module_name: []const u8) !?usize {
    var buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&buf, "/proc/{d}/maps", .{pid});

    const raw = linux.open(path, linux.O{}, 0);
    if (@as(isize, @bitCast(raw)) < 0) return error.OpenFailed;
    defer _ = std.c.close(@intCast(raw));

    const content = try readAllFd(@intCast(raw), allocator, 1 << 20);
    defer allocator.free(content);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, module_name) != null) {
            const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
            return std.fmt.parseUnsigned(usize, line[0..dash], 16) catch continue;
        }
    }
    return null;
}

/// Simple read-all from fd to allocated buffer.
fn readAllFd(fd: linux.fd_t, allocator: std.mem.Allocator, max_size: usize) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = linux.read(fd, &buf, buf.len);
        if (n == 0) break;
        if (list.items.len + n > max_size) return error.TooLarge;
        try list.appendSlice(allocator, buf[0..n]);
    }
    return try list.toOwnedSlice(allocator);
}

/// Find PID by process name.
pub fn findPid(name: []const u8) !?u32 {
    var pid: u32 = 1;
    while (pid < 65535) : (pid += 1) {
        var comm_buf: [128]u8 = undefined;
        const comm_path = std.fmt.bufPrintZ(&comm_buf, "/proc/{d}/comm", .{pid}) catch continue;
        const raw = linux.open(comm_path, linux.O{}, 0);
        if (@as(isize, @bitCast(raw)) < 0) continue;
        const n = linux.read(@intCast(raw), &comm_buf, comm_buf.len);
        _ = std.c.close(@intCast(raw));
        if (n > 0) {
            const trimmed = std.mem.trimRight(u8, comm_buf[0..@intCast(n)], "\n");
            if (std.mem.eql(u8, trimmed, name)) return pid;
        }
    }
    return null;
}
