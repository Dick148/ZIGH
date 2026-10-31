// ZIGH — Shared utilities
// Avoids code duplication across modules.

const std = @import("std");
const linux = std.os.linux;

/// Read entire file descriptor into allocated buffer.
/// Returns error.TooLarge if content exceeds max_size.
pub fn readAllFd(fd: linux.fd_t, allocator: std.mem.Allocator, max_size: usize) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = linux.read(fd, &buf, buf.len);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        if (n == 0) break;
        if (list.items.len + n > max_size) return error.TooLarge;
        try list.appendSlice(allocator, buf[0..@intCast(n)]);
    }
    return try list.toOwnedSlice(allocator);
}

/// Write the whole buffer, retrying short writes and EINTR.
pub fn writeAll(fd: linux.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = linux.write(fd, bytes.ptr + off, bytes.len - off);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.WriteFailed,
        }
        if (n == 0) return error.WriteFailed;
        off += n;
    }
}

/// Write the whole buffer at an absolute offset, retrying short writes.
pub fn pwriteAll(fd: linux.fd_t, bytes: []const u8, offset: u64) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = linux.pwrite(fd, bytes.ptr + off, bytes.len - off, @intCast(offset + off));
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.WriteFailed,
        }
        if (n == 0) return error.WriteFailed;
        off += n;
    }
}

/// Read exactly `buf.len` bytes at an absolute offset. Short reads and EOF are
/// reported as errors so callers never operate on stale buffer contents.
pub fn preadAll(fd: linux.fd_t, buf: []u8, offset: u64) !void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = linux.pread(fd, buf.ptr + off, buf.len - off, @intCast(offset + off));
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        if (n == 0) return error.ReadFailed;
        off += n;
    }
}

/// Parse a hex (0x-prefixed) or decimal integer.
pub fn parseHexOrDec(comptime T: type, s: []const u8) !T {
    const t = std.mem.trim(u8, s, " \t");
    if (std.mem.startsWith(u8, t, "0x") or std.mem.startsWith(u8, t, "0X"))
        return std.fmt.parseUnsigned(T, t[2..], 16);
    return std.fmt.parseUnsigned(T, t, 10);
}

/// Get monotonic timestamp in milliseconds.
pub fn timestampMs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(@as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000)));
}
