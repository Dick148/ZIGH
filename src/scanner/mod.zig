// ZIGH — Scanner module public API
// High-level interface for memory scanning from CLI or scripts.

const std = @import("std");
const mem_types = @import("../mem/types.zig");
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
        _ = std.os.linux.mkdir(wd, 0o755);

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
    pub fn nextScan(self: *Self, arena: std.mem.Allocator, opt: types.ScanOption, value1: u64) ![]types.ScanResult {
        if (!self.first_done) return error.NoFirstScan;

        self.cfg.scan_option = opt;
        self.cfg.value1 = value1;
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
        var buf: [256]u8 = undefined;
        const wd_z = std.fmt.bufPrintZ(&buf, "{s}", .{self.work_dir}) catch return;
        // Remove all scan_*.tmp files by trying indices up to a generous max
        var ti: u32 = 0;
        while (ti < 256) : (ti += 1) {
            const path = std.fmt.bufPrintZ(&buf, "{s}/scan_{d}.tmp", .{ self.work_dir, ti }) catch break;
            _ = std.os.linux.unlink(path);
        }
        _ = std.os.linux.rmdir(wd_z);
    }
};
