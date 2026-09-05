// ZIGH — Process memory operations
// /proc/PID/mem access via raw Linux syscalls (fd + pread/pwrite)

const std = @import("std");
const types = @import("types.zig");
const util = @import("../util.zig");
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
/// Returns error on failed or short reads.
pub fn readRaw(fd: linux.fd_t, addr: usize, buf: []u8) !void {
    const n = linux.pread(fd, buf.ptr, buf.len, @intCast(addr));
    if (@as(isize, @bitCast(n)) < 0) return error.ReadFailed;
}

/// Write raw bytes to a process's memory at a given address.
/// Returns error on failed writes.
pub fn writeRaw(fd: linux.fd_t, addr: usize, buf: []const u8) !void {
    const n = linux.pwrite(fd, buf.ptr, buf.len, @intCast(addr));
    if (@as(isize, @bitCast(n)) < 0) return error.WriteFailed;
}

/// Read from remote process via process_vm_readv (no /proc/PID/mem fd needed).
pub fn readvRaw(pid: u32, addr: usize, buf: []u8) !void {
    const local = [_]std.os.iovec{.{ .iov_base = buf.ptr, .iov_len = buf.len }};
    const remote = [_]std.os.iovec_const{.{ .iov_base = @ptrFromInt(addr), .iov_len = buf.len }};
    const n = linux.process_vm_readv(@intCast(pid), &local, &remote, 0);
    if (n != buf.len) return error.ReadFailed;
}

/// Write to remote process via process_vm_writev (no /proc/PID/mem fd needed).
pub fn writevRaw(pid: u32, addr: usize, buf: []const u8) !void {
    const local = [_]std.os.iovec_const{.{ .iov_base = @constCast(buf.ptr), .iov_len = buf.len }};
    const remote = [_]std.os.iovec_const{.{ .iov_base = @ptrFromInt(addr), .iov_len = buf.len }};
    const n = linux.process_vm_writev(@intCast(pid), &local, &remote, 0);
    if (n != buf.len) return error.WriteFailed;
}

/// Read a typed value. Returns the raw u64 (protocol wire format).
pub fn readU64(fd: linux.fd_t, addr: usize, tid: types.TypeId) !u64 {
    var buf: [8]u8 = [_]u8{0} ** 8;
    const sz = tid.size();
    readRaw(fd, addr, buf[0..sz]) catch return 0;
    return switch (sz) {
        1 => @as(u64, buf[0]),
        2 => @as(u64, std.mem.readInt(u16, buf[0..2], .little)),
        4 => @as(u64, std.mem.readInt(u32, buf[0..4], .little)),
        8 => std.mem.readInt(u64, buf[0..8], .little),
        else => error.UnsupportedSize,
    };
}

/// Write a typed value via /proc/PID/mem.
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
    writeRaw(fd, addr, buf[0..sz]) catch return error.WriteFailed;
}

/// Write a typed value via process_vm_writev (no fd needed).
pub fn writevU64(pid: u32, addr: usize, value: u64, tid: types.TypeId) !void {
    var buf: [8]u8 = undefined;
    const sz = tid.size();
    switch (sz) {
        1 => buf[0] = @truncate(value),
        2 => std.mem.writeInt(u16, buf[0..2], @truncate(value), .little),
        4 => std.mem.writeInt(u32, buf[0..4], @truncate(value), .little),
        8 => std.mem.writeInt(u64, buf[0..8], value, .little),
        else => return error.UnsupportedSize,
    }
    try writevRaw(pid, addr, buf[0..sz]);
}

/// Resolve a pointer chain. Returns error if offsets slice is too short
/// for the specified layer_count.
pub fn resolveChain(fd: linux.fd_t, base: usize, rva: u64, offsets: []const u32, layer_count: u32) !usize {
    if (layer_count == 0) return base + rva;
    if (layer_count > offsets.len) return error.InvalidChainLength;

    var ptr: usize = base + rva;
    for (offsets[0 .. layer_count - 1]) |off| {
        ptr = try readU64(fd, ptr + off, .pointer);
        if (ptr == 0) return error.NullPointerInChain;
    }
    return ptr + offsets[layer_count - 1];
}

/// Get the base address of a module in a process via /proc/PID/maps.
/// module_name can be:
///   - an absolute path (starts with '/'): exact match on the mapping's pathname
///   - a suffix (e.g. ".exe", "GameAssembly.so", "libc.so.6"): matched against
///     the mapping's pathname via endsWith
pub fn getModuleBase(allocator: std.mem.Allocator, pid: u32, module_name: []const u8) !?usize {
    var buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&buf, "/proc/{d}/maps", .{pid});

    const raw = linux.open(path, linux.O{}, 0);
    if (@as(isize, @bitCast(raw)) < 0) return error.OpenFailed;
    defer _ = std.c.close(@intCast(raw));

    const content = try util.readAllFd(@intCast(raw), allocator, 1 << 20);
    defer allocator.free(content);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;

        // /proc/PID/maps format:
        //   address           perms offset   dev   inode   pathname
        //   7f1234-7f5678     r-xp  00000000 08:01 1234567 /usr/lib/foo.so
        // Extract pathname column: find the 5th space (fields: addr perms offset dev inode pathname)
        var space_count: u32 = 0;
        var path_start: ?usize = null;
        for (line, 0..) |c, i| {
            if (c == ' ') {
                space_count += 1;
                if (space_count == 5) {
                    path_start = i + 1;
                    break;
                }
            }
        }
        const pathname = if (path_start) |ps| blk: {
            // Skip leading spaces in pathname
            var s: usize = ps;
            while (s < line.len and (line[s] == ' ' or line[s] == '\t')) s += 1;
            break :blk line[s..];
        } else continue;

        // Match in the pathname column only:
        //   - absolute path (starts with '/'): exact equality
        //   - relative/suffix: endsWith (handles ".exe", "GameAssembly.so", "libc.so.6")
        const matched = if (module_name.len > 0 and module_name[0] == '/')
            std.mem.eql(u8, pathname, module_name)
        else
            std.mem.endsWith(u8, pathname, module_name);

        if (matched) {
            const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
            return std.fmt.parseUnsigned(usize, line[0..dash], 16) catch continue;
        }
    }
    return null;
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
            const trimmed = std.mem.trimEnd(u8, comm_buf[0..@intCast(n)], "\n");
            if (std.mem.eql(u8, trimmed, name)) return pid;
        }
    }
    return null;
}
