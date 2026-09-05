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
        if (n == 0) break;
        if (list.items.len + n > max_size) return error.TooLarge;
        try list.appendSlice(allocator, buf[0..@intCast(n)]);
    }
    return try list.toOwnedSlice(allocator);
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
