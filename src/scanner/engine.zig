// ZIGH — Scan engine
// Multi-threaded memory scanner orchestrator.
// Enumerates regions, builds fixed-size jobs, spawns workers, merges results.

const std = @import("std");
const linux = std.os.linux;
const types = @import("types.zig");
const worker = @import("worker.zig");
const value = @import("value.zig");
const mem_mod = @import("../mem/mod.zig");
const util = @import("../util.zig");

const CHUNK_SIZE = 256 * 1024; // 256KB read chunks (shared with worker)
const FLUSH_THRESHOLD = 1024; // flush results to file every N matches
const JOB_SIZE = 4 * 1024 * 1024; // 4MB work units for dynamic scheduling
const MAPS_MAX_BYTES = 64 * 1024 * 1024; // hard sanity cap for /proc/PID/maps

// Snapshot file format: 8-byte magic + u32 version + u32 region count +
// count * {u64 base, u64 size, u64 data_offset}, followed by the data.
const SNAP_MAGIC = "ZIGSNAP1";
const SNAP_VERSION: u32 = 1;
const SNAP_HEADER_SIZE = 16;
const SNAP_ENTRY_SIZE = 24;
const SNAP_MAX_REGIONS = 1_000_000;

// flock(2) operations (not exposed by std.os.linux).
const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;

const SnapEntry = struct {
    base: u64,
    size: u64,
    offset: u64,
};

/// Orchestrates a complete scan across multiple threads.
pub const ScanEngine = struct {
    allocator: std.mem.Allocator,
    cfg: types.ScanConfig,
    work_dir: []const u8,
    /// Thread count (1 or cpu count)
    thread_count: u32,
    /// All readable memory regions
    regions: []types.MemoryRegion = &.{},
    /// Fixed-size work units (sub-slices of regions)
    jobs: []types.Job = &.{},
    /// Per-thread result file paths
    result_paths: [][:0]u8 = &.{},
    /// Total results across all threads
    total_found: u32 = 0,
    /// Total bytes scanned
    total_scanned: u64 = 0,
    /// Is this a first scan or next scan?
    is_first: bool,
    /// CE-style memory snapshot: path to MEMORY.TMP (for unknown initial value)
    snapshot_path: ?[:0]u8 = null,
    /// Whether this first scan used snapshot mode
    used_snapshot: bool = false,
    /// Advisory lock held for the lifetime of the scan (prevents two scans for
    /// the same pid from clobbering each other's temp files). -1 = not held.
    lock_fd: linux.fd_t = -1,

    const Self = @This();

    /// Initialize a scan engine. Creates work directory for temp files.
    pub fn init(allocator: std.mem.Allocator, cfg: types.ScanConfig, is_first: bool) !Self {
        // Determine work directory
        var wd_buf: [128]u8 = undefined;
        const wd_z = if (cfg.work_dir) |d| blk: {
            break :blk try std.fmt.bufPrintZ(&wd_buf, "{s}", .{d});
        } else blk: {
            break :blk try std.fmt.bufPrintZ(&wd_buf, "/tmp/zigh_scan_{d}", .{cfg.pid});
        };

        // Create work directory if it doesn't exist
        const raw_mkdir = linux.mkdir(wd_z, 0o700);
        _ = raw_mkdir; // ignore EEXIST

        // Serialize scans on the same work directory.
        var lock_fd: linux.fd_t = -1;
        var lock_buf: [160]u8 = undefined;
        if (std.fmt.bufPrintZ(&lock_buf, "{s}/lock", .{wd_z}) catch null) |lock_path| {
            const raw_lock = linux.open(lock_path, linux.O{
                .ACCMODE = .RDWR,
                .CREAT = true,
                .NOFOLLOW = true,
            }, 0o600);
            if (@as(isize, @bitCast(raw_lock)) >= 0) {
                const fd: linux.fd_t = @intCast(raw_lock);
                const rc = linux.flock(fd, LOCK_EX | LOCK_NB);
                if (linux.errno(rc) != .SUCCESS) {
                    _ = std.c.close(fd);
                    return error.ScanInProgress;
                }
                lock_fd = fd;
            }
        }

        // Determine thread count
        const tc: u32 = if (cfg.thread_count > 0) cfg.thread_count else blk: {
            const cc = std.Thread.getCpuCount() catch 4;
            break :blk @as(u32, @intCast(cc));
        };

        return Self{
            .allocator = allocator,
            .cfg = cfg,
            .work_dir = try allocator.dupe(u8, wd_z),
            .thread_count = tc,
            .is_first = is_first,
            .lock_fd = lock_fd,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.lock_fd >= 0) _ = std.c.close(self.lock_fd);
        self.allocator.free(self.work_dir);
        if (self.snapshot_path) |sp| self.allocator.free(sp);
        if (self.result_paths.len > 0) {
            for (self.result_paths) |p| self.allocator.free(p);
            self.allocator.free(self.result_paths);
        }
        if (self.regions.len > 0) self.allocator.free(self.regions);
        if (self.jobs.len > 0) self.allocator.free(self.jobs);
    }

    /// Enumerate all readable memory regions from /proc/PID/maps.
    /// Streams the file (with a generous sanity cap) and keeps every readable
    /// region, including large heaps / anonymous mappings.
    pub fn enumerateRegions(self: *Self) !void {
        if (self.regions.len > 0) {
            self.allocator.free(self.regions);
            self.regions = &.{};
        }

        var path_buf: [64]u8 = undefined;
        const maps_path = try std.fmt.bufPrintZ(&path_buf, "/proc/{d}/maps", .{self.cfg.pid});

        const raw = linux.open(maps_path, linux.O{}, 0);
        if (@as(isize, @bitCast(raw)) < 0) return error.OpenMapsFailed;
        defer _ = std.c.close(@intCast(raw));

        const content = try util.readAllFd(@intCast(raw), self.allocator, MAPS_MAX_BYTES);
        defer self.allocator.free(content);

        var regions: std.ArrayList(types.MemoryRegion) = .empty;
        defer regions.deinit(self.allocator);

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;

            // Format: START-END FLAGS ...
            const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
            const space = std.mem.indexOfScalarPos(u8, line, dash + 1, ' ') orelse continue;

            const flags_start = space + 1;
            if (flags_start >= line.len) continue;
            if (line[flags_start] != 'r') continue;
            // Default: writable regions only (heap/data), like Cheat Engine.
            if (self.cfg.writable_only) {
                if (flags_start + 1 >= line.len or line[flags_start + 1] != 'w') continue;
            }

            // These cannot be read via /proc/PID/mem.
            if (std.mem.indexOf(u8, line, "[vvar]") != null) continue;
            if (std.mem.indexOf(u8, line, "[vdso]") != null) continue;
            if (std.mem.indexOf(u8, line, "[vsyscall]") != null) continue;

            const start = std.fmt.parseUnsigned(usize, line[0..dash], 16) catch continue;
            const end = std.fmt.parseUnsigned(usize, line[dash + 1 .. space], 16) catch continue;
            if (end <= start) continue;

            try regions.append(self.allocator, .{
                .base = start,
                .size = end - start,
                .mirror_offset = 0,
            });
        }

        self.regions = try regions.toOwnedSlice(self.allocator);
    }

    /// Split every region into fixed-size jobs. Jobs are page-aligned because
    /// regions are page-aligned and JOB_SIZE is a multiple of the page size.
    fn buildJobs(self: *Self) !void {
        if (self.jobs.len > 0) {
            self.allocator.free(self.jobs);
            self.jobs = &.{};
        }

        var jobs: std.ArrayList(types.Job) = .empty;
        defer jobs.deinit(self.allocator);

        for (self.regions) |region| {
            var off: usize = 0;
            while (off < region.size) {
                const size = @min(JOB_SIZE, region.size - off);
                try jobs.append(self.allocator, .{
                    .base = region.base + off,
                    .size = size,
                    .snapshot_offset = region.mirror_offset + @as(u64, off),
                });
                off += size;
            }
        }

        self.jobs = try jobs.toOwnedSlice(self.allocator);
    }

    /// Run a first scan (exact value, unknown, bigger_than, etc.)
    /// For unknown scans with snapshot_memory=true: saves a MEMORY.TMP snapshot
    /// of all scanned memory (like Cheat Engine) instead of per-address records.
    pub fn runFirstScan(self: *Self) !void {
        if (self.regions.len == 0) try self.enumerateRegions();
        if (self.regions.len == 0) return;

        const use_snapshot = self.cfg.snapshot_memory and self.cfg.scan_option == .unknown;
        if (use_snapshot) return self.runSnapshotScan();

        try self.buildJobs();
        try self.buildResultPaths("scan_");

        const outcomes = try self.allocator.alloc(types.ThreadOutcome, self.thread_count);
        defer self.allocator.free(outcomes);
        @memset(outcomes, .{});

        const threads = try self.allocator.alloc(std.Thread, self.thread_count);
        defer self.allocator.free(threads);

        var counter = std.atomic.Value(usize).init(0);
        var spawned: u32 = 0;
        errdefer {
            var j: u32 = 0;
            while (j < spawned) : (j += 1) threads[j].join();
        }

        var ti: u32 = 0;
        while (ti < self.thread_count) : (ti += 1) {
            const idx = ti;
            threads[idx] = try std.Thread.spawn(.{}, struct {
                fn run(
                    pid: u32,
                    jobs: []const types.Job,
                    ctr: *std.atomic.Value(usize),
                    c: types.ScanConfig,
                    rp: [:0]const u8,
                    out: *types.ThreadOutcome,
                ) void {
                    var w = worker.ScanWorker.init(pid, jobs, ctr, c, rp) catch |e| {
                        out.err = e;
                        return;
                    };
                    defer w.deinit();
                    out.found = w.run() catch |e| {
                        out.err = e;
                        return;
                    };
                    out.scanned = w.scanned;
                }
            }.run, .{
                self.cfg.pid,
                self.jobs,
                &counter,
                self.cfg,
                self.result_paths[idx],
                &outcomes[idx],
            });
            spawned += 1;
        }

        ti = 0;
        while (ti < self.thread_count) : (ti += 1) threads[ti].join();

        try self.collectOutcomes(outcomes);
    }

    /// CE-style snapshot scan: save all readable memory to MEMORY.TMP.
    /// Each job writes its data at the correct file offset.
    fn runSnapshotScan(self: *Self) !void {
        self.used_snapshot = true;
        if (self.regions.len > SNAP_MAX_REGIONS) return error.TooManyRegions;

        var snap_buf: [128]u8 = undefined;
        const snap_path = try std.fmt.bufPrintZ(&snap_buf, "{s}/MEMORY.TMP", .{self.work_dir});
        self.snapshot_path = try self.allocator.dupeZ(u8, snap_path);

        // Compute per-region file offsets, starting after the manifest header.
        const data_start = SNAP_HEADER_SIZE + self.regions.len * SNAP_ENTRY_SIZE;
        var current_offset: u64 = data_start;
        for (self.regions) |*region| {
            region.mirror_offset = current_offset;
            current_offset += region.size;
        }
        const total_size = current_offset;

        if (total_size > std.math.maxInt(i64)) return error.SnapshotTooLarge;
        {
            const raw = linux.open(snap_path, linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true }, 0o600);
            if (@as(isize, @bitCast(raw)) < 0) return error.OpenSnapshotFailed;
            const fd: linux.fd_t = @intCast(raw);
            defer _ = std.c.close(fd);
            const trunc_rc = linux.ftruncate(fd, @intCast(total_size));
            if (linux.errno(trunc_rc) != .SUCCESS) return error.SnapshotTruncateFailed;
            try self.writeSnapshotHeader(fd);
        }

        try self.buildJobs();

        const outcomes = try self.allocator.alloc(types.ThreadOutcome, self.thread_count);
        defer self.allocator.free(outcomes);
        @memset(outcomes, .{});

        const threads = try self.allocator.alloc(std.Thread, self.thread_count);
        defer self.allocator.free(threads);

        var counter = std.atomic.Value(usize).init(0);
        var spawned: u32 = 0;
        errdefer {
            var j: u32 = 0;
            while (j < spawned) : (j += 1) threads[j].join();
        }

        var ti: u32 = 0;
        while (ti < self.thread_count) : (ti += 1) {
            const idx = ti;
            threads[idx] = try std.Thread.spawn(.{}, struct {
                fn run(
                    pid: u32,
                    jobs: []const types.Job,
                    ctr: *std.atomic.Value(usize),
                    sp: [:0]const u8,
                    out: *types.ThreadOutcome,
                ) void {
                    const mem_fd = mem_mod.openProcMem(pid) catch |e| {
                        out.err = e;
                        return;
                    };
                    defer _ = std.c.close(mem_fd);

                    const raw = linux.open(sp, linux.O{ .ACCMODE = .WRONLY, .NOFOLLOW = true }, 0);
                    if (@as(isize, @bitCast(raw)) < 0) {
                        out.err = error.OpenSnapshotFailed;
                        return;
                    }
                    const snap_fd: linux.fd_t = @intCast(raw);
                    defer _ = std.c.close(snap_fd);

                    const chunk = std.heap.page_allocator.alloc(u8, CHUNK_SIZE) catch |e| {
                        out.err = e;
                        return;
                    };
                    defer std.heap.page_allocator.free(chunk);

                    while (true) {
                        const idx2 = ctr.fetchAdd(1, .monotonic);
                        if (idx2 >= jobs.len) break;
                        const job = jobs[idx2];

                        var off: usize = 0;
                        while (off < job.size) {
                            const to_read = @min(job.size - off, CHUNK_SIZE);
                            mem_mod.readRaw(mem_fd, job.base + off, chunk[0..to_read]) catch {
                                out.scanned += to_read;
                                off += to_read;
                                continue;
                            };
                            util.pwriteAll(snap_fd, chunk[0..to_read], job.snapshot_offset + @as(u64, off)) catch |e| {
                                out.err = e;
                                return;
                            };
                            out.scanned += to_read;
                            off += to_read;
                        }
                    }
                }
            }.run, .{
                self.cfg.pid,
                self.jobs,
                &counter,
                snap_path,
                &outcomes[idx],
            });
            spawned += 1;
        }

        ti = 0;
        while (ti < self.thread_count) : (ti += 1) threads[ti].join();

        try self.collectOutcomes(outcomes);

        // Sentinel tells the next scan that MEMORY.TMP exists.
        {
            var sbuf: [128]u8 = undefined;
            const sentinel_path = try std.fmt.bufPrintZ(&sbuf, "{s}/scan_0.tmp", .{self.work_dir});
            const raw_s = linux.open(sentinel_path, linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true }, 0o600);
            if (@as(isize, @bitCast(raw_s)) < 0) return error.OpenSentinelFailed;
            const fd: linux.fd_t = @intCast(raw_s);
            defer _ = std.c.close(fd);
            try util.writeAll(fd, "SNAPv1");
        }

        try self.buildResultPaths("scan_");
        const approx_found = self.total_scanned / self.cfg.value_type.size();
        self.total_found = @intCast(@min(approx_found, std.math.maxInt(u32)));
    }

    fn writeSnapshotHeader(self: *Self, fd: linux.fd_t) !void {
        const header_size = SNAP_HEADER_SIZE + self.regions.len * SNAP_ENTRY_SIZE;
        const hdr = try self.allocator.alloc(u8, header_size);
        defer self.allocator.free(hdr);

        @memcpy(hdr[0..8], SNAP_MAGIC);
        std.mem.writeInt(u32, hdr[8..12], SNAP_VERSION, .little);
        std.mem.writeInt(u32, hdr[12..16], @intCast(self.regions.len), .little);

        var p: usize = SNAP_HEADER_SIZE;
        for (self.regions) |r| {
            std.mem.writeInt(u64, hdr[p..][0..8], @intCast(r.base), .little);
            std.mem.writeInt(u64, hdr[p + 8 ..][0..8], @intCast(r.size), .little);
            std.mem.writeInt(u64, hdr[p + 16 ..][0..8], r.mirror_offset, .little);
            p += SNAP_ENTRY_SIZE;
        }

        try util.pwriteAll(fd, hdr, 0);
    }

    fn readSnapshotHeader(self: *Self, fd: linux.fd_t) ![]SnapEntry {
        var hdr: [SNAP_HEADER_SIZE]u8 = undefined;
        try util.preadAll(fd, &hdr, 0);

        if (!std.mem.eql(u8, hdr[0..8], SNAP_MAGIC)) return error.SnapshotFormatUnsupported;
        const version = std.mem.readInt(u32, hdr[8..12], .little);
        if (version != SNAP_VERSION) return error.SnapshotFormatUnsupported;
        const count = std.mem.readInt(u32, hdr[12..16], .little);
        if (count > SNAP_MAX_REGIONS) return error.SnapshotCorrupt;

        const entries: []SnapEntry = if (count == 0) &.{} else try self.allocator.alloc(SnapEntry, count);

        if (count > 0) {
            errdefer self.allocator.free(entries);
            const raw = try self.allocator.alloc(u8, @as(usize, count) * SNAP_ENTRY_SIZE);
            defer self.allocator.free(raw);
            try util.preadAll(fd, raw, SNAP_HEADER_SIZE);
            for (entries, 0..) |*e, i| {
                const p = i * SNAP_ENTRY_SIZE;
                e.* = .{
                    .base = std.mem.readInt(u64, raw[p..][0..8], .little),
                    .size = std.mem.readInt(u64, raw[p + 8 ..][0..8], .little),
                    .offset = std.mem.readInt(u64, raw[p + 16 ..][0..8], .little),
                };
            }
        }

        return entries;
    }

    /// Run a next scan (changed, unchanged, increased, etc.)
    pub fn runNextScan(self: *Self) !void {
        if (self.isSnapshotMode()) {
            return self.runSnapshotNextScan();
        }

        try self.buildResultPaths("next_");

        // Previous result paths must outlive the threads.
        const prev_paths = try self.allocator.alloc([:0]u8, self.thread_count);
        defer {
            for (prev_paths) |p| self.allocator.free(p);
            self.allocator.free(prev_paths);
        }

        const outcomes = try self.allocator.alloc(types.ThreadOutcome, self.thread_count);
        defer self.allocator.free(outcomes);
        @memset(outcomes, .{});

        const threads = try self.allocator.alloc(std.Thread, self.thread_count);
        defer self.allocator.free(threads);

        var spawned: u32 = 0;
        errdefer {
            var j: u32 = 0;
            while (j < spawned) : (j += 1) threads[j].join();
        }

        var ti: u32 = 0;
        while (ti < self.thread_count) : (ti += 1) {
            const idx = ti;

            var prev_buf: [128]u8 = undefined;
            const prev_path_blk = try std.fmt.bufPrintZ(&prev_buf, "{s}/scan_{d}.tmp", .{ self.work_dir, idx });
            prev_paths[idx] = try self.allocator.dupeZ(u8, prev_path_blk);

            threads[idx] = try std.Thread.spawn(.{}, struct {
                fn run(
                    pid: u32,
                    c: types.ScanConfig,
                    rp: [:0]const u8,
                    pp: [:0]const u8,
                    out: *types.ThreadOutcome,
                ) void {
                    var w = worker.NextScanWorker.init(pid, c, rp, pp) catch |e| {
                        out.err = e;
                        return;
                    };
                    defer w.deinit();
                    out.found = w.run() catch |e| {
                        out.err = e;
                        return;
                    };
                    out.scanned = w.scanned;
                }
            }.run, .{
                self.cfg.pid,
                self.cfg,
                self.result_paths[idx],
                prev_paths[idx],
                &outcomes[idx],
            });
            spawned += 1;
        }

        ti = 0;
        while (ti < self.thread_count) : (ti += 1) threads[ti].join();

        try self.collectOutcomes(outcomes);

        // Swap new results over old ones: next_*.tmp → scan_*.tmp
        for (0..self.result_paths.len) |i| {
            var next_buf: [256]u8 = undefined;
            var scan_buf: [256]u8 = undefined;
            const next_path = std.fmt.bufPrintZ(&next_buf, "{s}/next_{d}.tmp", .{ self.work_dir, @as(u32, @intCast(i)) }) catch continue;
            const scan_path = std.fmt.bufPrintZ(&scan_buf, "{s}/scan_{d}.tmp", .{ self.work_dir, @as(u32, @intCast(i)) }) catch continue;
            try renameResult(next_path, scan_path);
        }

        for (self.result_paths) |p| self.allocator.free(p);
        self.allocator.free(self.result_paths);
        self.result_paths = &.{};
        try self.buildResultPaths("scan_");
    }

    /// Merge all per-thread result files into one slice, stopping once
    /// `max_records` is reached (0 = unlimited). Streams the files instead of
    /// loading them whole, so a large result set cannot abort the scan.
    pub fn mergeResults(self: *Self, arena: std.mem.Allocator, max_records: usize) ![]types.ScanResult {
        var all: std.ArrayList(types.ScanResult) = .empty;
        const hard_cap: usize = if (max_records == 0) std.math.maxInt(usize) else max_records;

        for (self.result_paths) |rpath| {
            if (all.items.len >= hard_cap) break;

            const raw = linux.open(rpath, linux.O{ .NOFOLLOW = true }, 0);
            if (@as(isize, @bitCast(raw)) < 0) continue;
            const fd: linux.fd_t = @intCast(raw);
            defer _ = std.c.close(fd);

            var chunk_buf: [64 * 1024]u8 = undefined;
            var tail: [16]u8 = undefined;
            var tail_len: usize = 0;

            while (all.items.len < hard_cap) {
                const n = linux.read(fd, &chunk_buf, chunk_buf.len);
                switch (linux.errno(n)) {
                    .SUCCESS => {},
                    .INTR => continue,
                    else => return error.ReadFailed,
                }
                if (n == 0) break;

                var bytes: []const u8 = chunk_buf[0..n];

                if (tail_len > 0) {
                    const need = 16 - tail_len;
                    if (bytes.len < need) {
                        @memcpy(tail[tail_len..][0..bytes.len], bytes);
                        tail_len += bytes.len;
                        continue;
                    }
                    @memcpy(tail[tail_len..][0..need], bytes[0..need]);
                    try appendRecord(&all, arena, tail[0..16]);
                    tail_len = 0;
                    bytes = bytes[need..];
                }

                const count = bytes.len / 16;
                var i: usize = 0;
                while (i < count and all.items.len < hard_cap) : (i += 1) {
                    try appendRecord(&all, arena, bytes[i * 16 ..][0..16]);
                }
                if (all.items.len >= hard_cap) break;

                const consumed = count * 16;
                const rem = bytes.len - consumed;
                if (rem > 0) {
                    @memcpy(tail[0..rem], bytes[consumed..]);
                    tail_len = rem;
                }
            }
        }

        return all.items;
    }

    /// Check if first scan used snapshot mode by reading scan_0.tmp sentinel.
    fn isSnapshotMode(self: *const Self) bool {
        var sbuf: [128]u8 = undefined;
        const path = std.fmt.bufPrintZ(&sbuf, "{s}/scan_0.tmp", .{self.work_dir}) catch return false;
        const raw = linux.open(path, linux.O{ .NOFOLLOW = true }, 0);
        if (@as(isize, @bitCast(raw)) < 0) return false;
        const fd: linux.fd_t = @intCast(raw);
        defer _ = std.c.close(fd);

        var magic: [6]u8 = undefined;
        const n = linux.read(fd, &magic, 6);
        return n == 6 and std.mem.eql(u8, &magic, "SNAPv1");
    }

    /// CE-style firstnextscan: read MEMORY.TMP snapshot, compare against current
    /// process memory, and produce standard scan_*.tmp result files.
    fn runSnapshotNextScan(self: *Self) !void {
        var snap_buf: [128]u8 = undefined;
        const snap_path = try std.fmt.bufPrintZ(&snap_buf, "{s}/MEMORY.TMP", .{self.work_dir});
        const raw_snap = linux.open(snap_path, linux.O{ .NOFOLLOW = true }, 0);
        if (@as(isize, @bitCast(raw_snap)) < 0) return error.OpenSnapshotFailed;
        const snap_fd: linux.fd_t = @intCast(raw_snap);
        defer _ = std.c.close(snap_fd);

        // The snapshot manifest defines the scope; always enumerate all
        // readable regions, then match them against the recorded entries.
        if (self.regions.len == 0) {
            const saved_writable_only = self.cfg.writable_only;
            self.cfg.writable_only = false;
            defer self.cfg.writable_only = saved_writable_only;
            try self.enumerateRegions();
        }

        const entries = try self.readSnapshotHeader(snap_fd);
        defer self.allocator.free(entries);

        // Match current regions to the snapshot by base address. This keeps the
        // comparison aligned even if the target's memory map changed between
        // the two scans.
        if (self.jobs.len > 0) {
            self.allocator.free(self.jobs);
            self.jobs = &.{};
        }
        var jobs: std.ArrayList(types.Job) = .empty;
        defer jobs.deinit(self.allocator);
        for (self.regions) |region| {
            const entry = findSnapEntry(entries, region.base) orelse continue;
            const snap_size: usize = std.math.cast(usize, entry.size) orelse continue;
            const cmp_size = @min(region.size, snap_size);
            var off: usize = 0;
            while (off < cmp_size) {
                const size = @min(JOB_SIZE, cmp_size - off);
                try jobs.append(self.allocator, .{
                    .base = region.base + off,
                    .size = size,
                    .snapshot_offset = entry.offset + @as(u64, off),
                });
                off += size;
            }
        }
        self.jobs = try jobs.toOwnedSlice(self.allocator);

        try self.buildResultPaths("next_");

        const outcomes = try self.allocator.alloc(types.ThreadOutcome, self.thread_count);
        defer self.allocator.free(outcomes);
        @memset(outcomes, .{});

        const threads = try self.allocator.alloc(std.Thread, self.thread_count);
        defer self.allocator.free(threads);

        var counter = std.atomic.Value(usize).init(0);
        var spawned: u32 = 0;
        errdefer {
            var j: u32 = 0;
            while (j < spawned) : (j += 1) threads[j].join();
        }

        var ti: u32 = 0;
        while (ti < self.thread_count) : (ti += 1) {
            const idx = ti;
            threads[idx] = try std.Thread.spawn(.{}, struct {
                fn run(
                    pid: u32,
                    jobs2: []const types.Job,
                    ctr: *std.atomic.Value(usize),
                    sf: linux.fd_t,
                    c: types.ScanConfig,
                    rp: [:0]const u8,
                    out: *types.ThreadOutcome,
                ) void {
                    const mem_fd = mem_mod.openProcMem(pid) catch |e| {
                        out.err = e;
                        return;
                    };
                    defer _ = std.c.close(mem_fd);

                    const raw_r = linux.open(rp, linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true }, 0o600);
                    if (@as(isize, @bitCast(raw_r)) < 0) {
                        out.err = error.OpenResultFileFailed;
                        return;
                    }
                    const result_fd: linux.fd_t = @intCast(raw_r);
                    defer _ = std.c.close(result_fd);

                    const alloc = std.heap.page_allocator;
                    const chunk = alloc.alloc(u8, CHUNK_SIZE) catch |e| {
                        out.err = e;
                        return;
                    };
                    defer alloc.free(chunk);
                    const old_chunk = alloc.alloc(u8, CHUNK_SIZE) catch |e| {
                        out.err = e;
                        return;
                    };
                    defer alloc.free(old_chunk);

                    var result_buf: std.ArrayList(u8) = .empty;
                    defer result_buf.deinit(alloc);
                    result_buf.ensureTotalCapacity(alloc, FLUSH_THRESHOLD * 16) catch |e| {
                        out.err = e;
                        return;
                    };

                    const tid = c.value_type;
                    const tsz = tid.size();

                    while (true) {
                        const idx2 = ctr.fetchAdd(1, .monotonic);
                        if (idx2 >= jobs2.len) break;
                        const job = jobs2[idx2];

                        var off: usize = 0;
                        while (off < job.size) {
                            const to_cmp = @min(job.size - off, CHUNK_SIZE);

                            mem_mod.readRaw(mem_fd, job.base + off, chunk[0..to_cmp]) catch {
                                out.scanned += to_cmp;
                                off += to_cmp;
                                continue;
                            };
                            util.preadAll(sf, old_chunk[0..to_cmp], job.snapshot_offset + @as(u64, off)) catch {
                                out.scanned += to_cmp;
                                off += to_cmp;
                                continue;
                            };

                            if (to_cmp >= tsz) {
                                const end = to_cmp - tsz;
                                var pos: usize = 0;
                                while (pos <= end) : (pos += tsz) {
                                    const cur_val = value.decode(chunk[pos..], tid);
                                    const old_val = value.decode(old_chunk[pos..], tid);

                                    if (value.matchesNext(c.scan_option, cur_val, old_val, tid, c.value1, c.value2, c.epsilon)) {
                                        out.found += 1;
                                        var rec: [16]u8 = undefined;
                                        std.mem.writeInt(u64, rec[0..8], @intCast(job.base + off + pos), .little);
                                        std.mem.writeInt(u64, rec[8..16], cur_val, .little);
                                        result_buf.appendSlice(alloc, &rec) catch |e| {
                                            out.err = e;
                                            return;
                                        };
                                        if (out.found % FLUSH_THRESHOLD == 0) {
                                            util.writeAll(result_fd, result_buf.items) catch |e| {
                                                out.err = e;
                                                return;
                                            };
                                            result_buf.clearRetainingCapacity();
                                        }
                                    }
                                }
                            }

                            out.scanned += to_cmp;
                            off += to_cmp;
                        }
                    }

                    if (result_buf.items.len > 0) {
                        util.writeAll(result_fd, result_buf.items) catch |e| {
                            out.err = e;
                            return;
                        };
                    }
                }
            }.run, .{
                self.cfg.pid,
                self.jobs,
                &counter,
                snap_fd,
                self.cfg,
                self.result_paths[idx],
                &outcomes[idx],
            });
            spawned += 1;
        }

        ti = 0;
        while (ti < self.thread_count) : (ti += 1) threads[ti].join();

        try self.collectOutcomes(outcomes);

        // Only now that the scan succeeded may we discard the snapshot.
        for (0..self.result_paths.len) |i| {
            var next_buf: [256]u8 = undefined;
            var scan_buf: [256]u8 = undefined;
            const next_path = std.fmt.bufPrintZ(&next_buf, "{s}/next_{d}.tmp", .{ self.work_dir, @as(u32, @intCast(i)) }) catch continue;
            const scan_path = std.fmt.bufPrintZ(&scan_buf, "{s}/scan_{d}.tmp", .{ self.work_dir, @as(u32, @intCast(i)) }) catch continue;
            _ = linux.unlink(scan_path); // remove SNAPv1 sentinel
            try renameResult(next_path, scan_path);
        }

        for (self.result_paths) |p| self.allocator.free(p);
        self.allocator.free(self.result_paths);
        self.result_paths = &.{};
        try self.buildResultPaths("scan_");

        _ = linux.unlink(snap_path);
    }

    fn collectOutcomes(self: *Self, outcomes: []const types.ThreadOutcome) !void {
        var first_err: ?anyerror = null;
        for (outcomes) |o| {
            self.total_found += o.found;
            self.total_scanned += o.scanned;
            if (o.err) |e| {
                if (first_err == null) first_err = e;
            }
        }
        if (first_err) |e| return e;
    }

    /// Clean up temp files
    pub fn cleanup(self: *const Self) void {
        for (self.result_paths) |rp| {
            _ = linux.unlink(rp);
        }
        if (self.snapshot_path) |sp| {
            _ = linux.unlink(sp);
        }
        var lock_buf: [160]u8 = undefined;
        if (std.fmt.bufPrintZ(&lock_buf, "{s}/lock", .{self.work_dir}) catch null) |lp| {
            _ = linux.unlink(lp);
        }
        var rmdir_buf: [128]u8 = undefined;
        const wd_z = std.fmt.bufPrintZ(&rmdir_buf, "{s}", .{self.work_dir}) catch return;
        _ = linux.rmdir(wd_z);
    }

    // ─── Internal helpers ────────────────────────────────────────────────

    fn buildResultPaths(self: *Self, prefix: []const u8) !void {
        var paths: std.ArrayList([:0]u8) = .empty;
        defer paths.deinit(self.allocator);
        var ti: u32 = 0;
        while (ti < self.thread_count) : (ti += 1) {
            var buf: [128]u8 = undefined;
            const path = try std.fmt.bufPrintZ(&buf, "{s}/{s}{d}.tmp", .{ self.work_dir, prefix, ti });
            try paths.append(self.allocator, try self.allocator.dupeZ(u8, path));
        }
        self.result_paths = try paths.toOwnedSlice(self.allocator);
    }
};

// ─── Free functions ──────────────────────────────────────────────────────

fn appendRecord(
    all: *std.ArrayList(types.ScanResult),
    arena: std.mem.Allocator,
    rec: []const u8,
) !void {
    const addr: usize = @intCast(std.mem.readInt(u64, rec[0..8], .little));
    const val: u64 = std.mem.readInt(u64, rec[8..16], .little);
    try all.append(arena, .{ .address = addr, .value = val });
}

fn findSnapEntry(entries: []const SnapEntry, base: usize) ?SnapEntry {
    for (entries) |e| {
        if (e.base == base) return e;
    }
    return null;
}

fn renameResult(from: [:0]const u8, to: [:0]const u8) !void {
    const rc = linux.rename(from, to);
    if (linux.errno(rc) != .SUCCESS) return error.RenameResultFailed;
}
