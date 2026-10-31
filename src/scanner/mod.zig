// ZIGH — Scanner module public API
// High-level interface for memory scanning from CLI or scripts.

const std = @import("std");
const mem_types = @import("../mem/types.zig");
const mem_mod = @import("../mem/mod.zig");
pub const types = @import("types.zig");
const engine = @import("engine.zig");

/// Persistent scan session. Manages work directory and scan state across
/// multiple scan rounds (first scan → next scan → next scan → ...).
pub const ScanSession = struct {
    allocator: std.mem.Allocator,
    cfg: types.ScanConfig,
    work_dir: []const u8,
    /// True after first scan has completed
    first_done: bool = false,
    /// True if first scan used CE-style memory snapshot
    used_snapshot: bool = false,
    /// Most recent scan's result count
    last_count: u32 = 0,
    /// Most recent scan's bytes scanned
    last_scanned: u64 = 0,

    const Self = @This();

    /// Create a new scan session. Creates temp directory under /tmp/.
    pub fn init(allocator: std.mem.Allocator, pid: u32) !Self {
        var buf: [128]u8 = undefined;
        const wd = try std.fmt.bufPrintZ(&buf, "/tmp/zigh_scan_{d}", .{pid});
        _ = std.os.linux.mkdir(wd, 0o700);

        return Self{
            .allocator = allocator,
            .cfg = types.ScanConfig{ .pid = pid, .scan_option = .exact, .value_type = .uint32 },
            .work_dir = try allocator.dupe(u8, wd),
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.work_dir);
    }

    /// Run a first scan (exact value, unknown, bigger_than, etc.)
    /// Returns merged results. Caller owns via the provided arena.
    pub fn firstScan(self: *Self, arena: std.mem.Allocator, opt: types.ScanOption, value_type: mem_types.TypeId, value1: u64, value2: u64) ![]types.ScanResult {
        self.cfg.scan_option = opt;
        self.cfg.value_type = value_type;
        self.cfg.value1 = value1;
        self.cfg.value2 = value2;
        self.cfg.work_dir = self.work_dir;
        // Enable snapshot for unknown scans (CE-style MEMORY.TMP)
        self.cfg.snapshot_memory = (opt == .unknown);

        var eng = try engine.ScanEngine.init(self.allocator, self.cfg, true);
        defer eng.deinit();

        try eng.runFirstScan();
        self.first_done = true;
        self.last_count = eng.total_found;
        self.last_scanned = eng.total_scanned;
        self.used_snapshot = eng.used_snapshot;

        if (eng.used_snapshot) {
            // Snapshot mode: return a representative result (the scan covered all memory).
            // The first next scan will do a full memory re-scan against the snapshot.
            // For now, return a small sample of results.
            const max_records = if (self.cfg.max_memory_mb > 0)
                (@as(usize, self.cfg.max_memory_mb) * 1024 * 1024) / @sizeOf(types.ScanResult)
            else
                10000; // small cap for snapshot mode — user knows there are zillions of addresses
            return try eng.mergeResults(arena, max_records);
        }

        const max_records = if (self.cfg.max_memory_mb > 0)
            (@as(usize, self.cfg.max_memory_mb) * 1024 * 1024) / @sizeOf(types.ScanResult)
        else
            0;

        return try eng.mergeResults(arena, max_records);
    }

    /// Run a next scan on top of previous results.
    pub fn nextScan(self: *Self, arena: std.mem.Allocator, opt: types.ScanOption, value1: u64, value2: u64) ![]types.ScanResult {
        if (!self.first_done) return error.NoFirstScan;
        if (opt == .unknown) return error.InvalidOptionForNextScan;

        self.cfg.scan_option = opt;
        self.cfg.value1 = value1;
        self.cfg.value2 = value2;
        self.cfg.work_dir = self.work_dir;

        var eng = try engine.ScanEngine.init(self.allocator, self.cfg, false);
        defer eng.deinit();

        try eng.runNextScan();
        self.last_count = eng.total_found;

        const max_records = if (self.cfg.max_memory_mb > 0)
            (@as(usize, self.cfg.max_memory_mb) * 1024 * 1024) / @sizeOf(types.ScanResult)
        else
            0;

        return try eng.mergeResults(arena, max_records);
    }

    /// Clean up temp files
    pub fn cleanup(self: *const Self) void {
        var wd_buf: [256]u8 = undefined;
        const wd_z = std.fmt.bufPrintZ(&wd_buf, "{s}", .{self.work_dir}) catch return;

        var buf: [256]u8 = undefined;
        // Remove all scan_*.tmp / next_*.tmp files by trying indices up to a liberal max
        var ti: u32 = 0;
        while (ti < 256) : (ti += 1) {
            const path = std.fmt.bufPrintZ(&buf, "{s}/scan_{d}.tmp", .{ self.work_dir, ti }) catch break;
            _ = std.os.linux.unlink(path);
        }
        ti = 0;
        while (ti < 256) : (ti += 1) {
            const path = std.fmt.bufPrintZ(&buf, "{s}/next_{d}.tmp", .{ self.work_dir, ti }) catch break;
            _ = std.os.linux.unlink(path);
        }
        const snap = std.fmt.bufPrintZ(&buf, "{s}/MEMORY.TMP", .{self.work_dir}) catch return;
        _ = std.os.linux.unlink(snap);
        const lock_path = std.fmt.bufPrintZ(&buf, "{s}/lock", .{self.work_dir}) catch return;
        _ = std.os.linux.unlink(lock_path);
        _ = std.os.linux.rmdir(wd_z);
    }
};

// ─── Integration tests ──────────────────────────────────────────────────
// These fork a small target process with a known value mapped at a known
// address and exercise the real scanner end to end.

const TestTarget = struct {
    pid: u32,
    addr: usize,
};

fn spawnTestTarget() !TestTarget {
    const linux = std.os.linux;

    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) return error.SkipZigTest;

    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        const addr = linux.mmap(
            null,
            4096,
            .{ .READ = true, .WRITE = true },
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        );
        if (linux.errno(addr) != .SUCCESS) linux.exit_group(1);

        const p: *u32 = @ptrFromInt(addr);
        p.* = 0xDEADBEEF;

        var abuf: [8]u8 = undefined;
        std.mem.writeInt(u64, abuf[0..8], addr, .little);
        _ = linux.write(fds[1], &abuf, 8);
        _ = linux.close(fds[1]);

        var ts = linux.timespec{ .sec = 60, .nsec = 0 };
        _ = linux.nanosleep(&ts, null);
        linux.exit_group(0);
    }

    _ = linux.close(fds[1]);

    var abuf: [8]u8 = undefined;
    var got: usize = 0;
    while (got < abuf.len) {
        const n = linux.read(fds[0], abuf[got..].ptr, abuf.len - got);
        if (linux.errno(n) != .SUCCESS or n == 0) {
            _ = linux.kill(@intCast(fork_rc), linux.SIG.KILL);
            return error.SkipZigTest;
        }
        got += n;
    }
    _ = linux.close(fds[0]);

    return .{
        .pid = @intCast(fork_rc),
        .addr = @intCast(std.mem.readInt(u64, abuf[0..8], .little)),
    };
}

fn stopTestTarget(pid: u32) void {
    const linux = std.os.linux;
    _ = linux.kill(@intCast(pid), linux.SIG.KILL);
    var status: u32 = 0;
    _ = linux.wait4(@intCast(pid), &status, 0, null);
}

fn writeChildU32(pid: u32, addr: usize, val: u32) !void {
    const fd = try mem_mod.openProcMem(pid);
    defer _ = std.c.close(fd);
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], val, .little);
    try mem_mod.writeRaw(fd, addr, &buf);
}

fn containsAddress(results: []const types.ScanResult, addr: usize) bool {
    for (results) |r| {
        if (r.address == addr) return true;
    }
    return false;
}

test "first scan and next scans against a live target" {
    const target = try spawnTestTarget();
    defer stopTestTarget(target.pid);

    const alloc = std.testing.allocator;
    var session = try ScanSession.init(alloc, target.pid);
    defer {
        session.cleanup();
        session.deinit();
    }

    var arena_inst = std.heap.ArenaAllocator.init(alloc);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const r1 = try session.firstScan(arena, .exact, .uint32, 0xDEADBEEF, 0);
    try std.testing.expect(containsAddress(r1, target.addr));

    try writeChildU32(target.pid, target.addr, 0xCAFEBABE);
    const r2 = try session.nextScan(arena, .exact, 0xCAFEBABE, 0);
    try std.testing.expect(containsAddress(r2, target.addr));

    try writeChildU32(target.pid, target.addr, 0xCAFEBABF);
    const r3 = try session.nextScan(arena, .changed, 0, 0);
    try std.testing.expect(containsAddress(r3, target.addr));

    const r4 = try session.nextScan(arena, .between, 0xCAFEBAB0, 0xCAFEC000);
    try std.testing.expect(containsAddress(r4, target.addr));
}

test "signed values are decoded with sign extension" {
    const target = try spawnTestTarget();
    defer stopTestTarget(target.pid);

    const alloc = std.testing.allocator;
    var session = try ScanSession.init(alloc, target.pid);
    defer {
        session.cleanup();
        session.deinit();
    }

    var arena_inst = std.heap.ArenaAllocator.init(alloc);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // -1 as i32
    try writeChildU32(target.pid, target.addr, 0xFFFFFFFF);
    const neg_one: u64 = @bitCast(@as(i64, -1));
    const r1 = try session.firstScan(arena, .exact, .int32, neg_one, 0);
    try std.testing.expect(containsAddress(r1, target.addr));

    // -1 -> 0 is an increase.
    try writeChildU32(target.pid, target.addr, 0);
    const r2 = try session.nextScan(arena, .increased, 0, 0);
    try std.testing.expect(containsAddress(r2, target.addr));
}

test "unknown snapshot scan and bounded next scan" {
    const target = try spawnTestTarget();
    defer stopTestTarget(target.pid);

    const alloc = std.testing.allocator;
    var session = try ScanSession.init(alloc, target.pid);
    defer {
        session.cleanup();
        session.deinit();
    }

    var arena_inst = std.heap.ArenaAllocator.init(alloc);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    _ = try session.firstScan(arena, .unknown, .uint32, 0, 0);
    try std.testing.expect(session.used_snapshot);

    try writeChildU32(target.pid, target.addr, 12345);
    const r = try session.nextScan(arena, .between, 100, 20000);
    try std.testing.expect(containsAddress(r, target.addr));
}
