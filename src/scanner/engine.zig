// ZIGH — Scan engine
// Multi-threaded memory scanner orchestrator.
// Enumerates regions, spawns workers, merges results.

const std = @import("std");
const linux = std.os.linux;
const types = @import("types.zig");
const worker = @import("worker.zig");
const mem_mod = @import("../mem/mod.zig");
const mem_types = @import("../mem/types.zig");
const util = @import("../util.zig");

const MAX_REGIONS = 256;
const CHUNK_SIZE = 256 * 1024; // 256KB read chunks (shared with worker)
const FLUSH_THRESHOLD = 1024; // flush results to file every N matches

/// Orchestrates a complete scan across multiple threads.
pub const ScanEngine = struct {
    allocator: std.mem.Allocator,
    cfg: types.ScanConfig,
    work_dir: []const u8,
    /// Thread count (1 or cpu count)
    thread_count: u32,
    /// All memory regions
    regions: [MAX_REGIONS]types.MemoryRegion = undefined,
    region_count: usize = 0,
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
        const raw_mkdir = linux.mkdir(wd_z, 0o755);
        _ = raw_mkdir; // ignore EEXIST

        // Determine thread count
        const tc: u32 = if (cfg.thread_count > 0) cfg.thread_count else blk: {
            // Use CPU count
            const cc = std.Thread.getCpuCount() catch 4;
            break :blk @as(u32, @intCast(cc));
        };

        return Self{
            .allocator = allocator,
            .cfg = cfg,
            .work_dir = try allocator.dupe(u8, wd_z),
            .thread_count = tc,
            .is_first = is_first,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.work_dir);
        if (self.snapshot_path) |sp| self.allocator.free(sp);
        if (self.result_paths.len > 0) {
            for (self.result_paths) |p| self.allocator.free(p);
            self.allocator.free(self.result_paths);
        }
    }

    /// Enumerate all readable memory regions from /proc/PID/maps
    pub fn enumerateRegions(self: *Self) !void {
        var path_buf: [64]u8 = undefined;
        const maps_path = try std.fmt.bufPrintZ(&path_buf, "/proc/{d}/maps", .{self.cfg.pid});

        const raw = linux.open(maps_path, linux.O{}, 0);
        if (@as(isize, @bitCast(raw)) < 0) return error.OpenMapsFailed;
        defer _ = std.c.close(@intCast(raw));

        const content = try util.readAllFd(@intCast(raw), self.allocator, 1 << 20);
        defer self.allocator.free(content);

        // Parse /proc/PID/maps to extract readable regions
        self.region_count = 0;
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (self.region_count >= MAX_REGIONS) break;

            // Format: START-END FLAGS ... — we need 'r' in flags
            const dash = std.mem.indexOfScalar(u8, line, '-') orelse continue;
            const space = std.mem.indexOfScalarPos(u8, line, dash + 1, ' ') orelse continue;

            // Check for readable flag (4th char after space is 'r')
            const flags_start = space + 1;
            if (flags_start + 4 > line.len) continue;
            if (line[flags_start] != 'r') continue;

            // Skip [vvar], [vdso], [vsyscall] — these can't be read via /proc/PID/mem
            if (std.mem.indexOf(u8, line, "[vvar]") != null) continue;
            if (std.mem.indexOf(u8, line, "[vdso]") != null) continue;
            if (std.mem.indexOf(u8, line, "[vsyscall]") != null) continue;

            const start = std.fmt.parseUnsigned(usize, line[0..dash], 16) catch continue;
            const end = std.fmt.parseUnsigned(usize, line[dash + 1 .. space], 16) catch continue;

            if (end <= start) continue;
            if (end - start > 512 * 1024 * 1024) continue; // skip >512MB regions (e.g. GPU maps)

            self.regions[self.region_count] = types.MemoryRegion{
                .base = start,
                .size = end - start,
                .mirror_offset = 0,
            };
            self.region_count += 1;
        }
    }

    /// Run a first scan (exact value, unknown, bigger_than, etc.)
    /// For unknown scans with snapshot_memory=true: saves a MEMORY.TMP snapshot
    /// of all scanned memory (like Cheat Engine) instead of per-address records.
    /// This is far more disk-efficient: 1 byte per byte scanned vs 16 bytes per address.
    pub fn runFirstScan(self: *Self) !void {
        if (self.region_count == 0) try self.enumerateRegions();
        if (self.region_count == 0) return;

        // Check if we should use CE-style snapshot mode
        const use_snapshot = self.cfg.snapshot_memory and self.cfg.scan_option == .unknown;

        if (use_snapshot) {
            return self.runSnapshotScan();
        }

        // Standard first scan: produce per-thread result files
        // Build per-thread result paths
        try self.buildResultPaths("scan_");

        // Split regions evenly across threads
        const regions_per_thread = try self.splitRegionsEvenly();

        var threads = try self.allocator.alloc(std.Thread, self.thread_count);
        defer self.allocator.free(threads);
        var thread_results = try self.allocator.alloc(u32, self.thread_count);
        defer self.allocator.free(thread_results);
        var thread_scanned = try self.allocator.alloc(u64, self.thread_count);
        defer self.allocator.free(thread_scanned);
        @memset(thread_results, 0);
        @memset(thread_scanned, 0);

        var ti: u32 = 0;
        while (ti < self.thread_count) : (ti += 1) {
            const idx = ti;
            const t_regions = regions_per_thread[idx];

            const alloc_cpy = self.allocator;
            const cfg_cpy = self.cfg;
            const pid_cpy = self.cfg.pid;
            const rpath = self.result_paths[idx];

            threads[idx] = try std.Thread.spawn(.{}, struct {
                fn run(a: std.mem.Allocator, pid2: u32, regs: []const types.MemoryRegion, c: types.ScanConfig, rp: [:0]const u8, res: *u32, sc: *u64) !void {
                    var w = try worker.ScanWorker.init(a, pid2, regs, c, rp);
                    defer w.deinit();
                    res.* = try w.run();
                    sc.* = w.scanned;
                }
            }.run, .{ alloc_cpy, pid_cpy, t_regions, cfg_cpy, rpath, &thread_results[idx], &thread_scanned[idx] });
        }

        // Wait for all threads
        ti = 0;
        while (ti < self.thread_count) : (ti += 1) {
            threads[ti].join();
            self.total_found += thread_results[ti];
            self.total_scanned += thread_scanned[ti];
        }
    }

    /// CE-style snapshot scan: save all readable memory to MEMORY.TMP.
    /// Each thread writes its regions' data at the correct file offset.
    fn runSnapshotScan(self: *Self) !void {
        self.used_snapshot = true;

        // Create MEMORY.TMP path
        var snap_buf: [128]u8 = undefined;
        const snap_path = try std.fmt.bufPrintZ(&snap_buf, "{s}/MEMORY.TMP", .{self.work_dir});
        self.snapshot_path = try self.allocator.dupeZ(u8, snap_path);

        // Compute per-region file offsets (sequential)
        var current_offset: u64 = 0;
        for (self.regions[0..self.region_count]) |*region| {
            region.mirror_offset = current_offset;
            current_offset += region.size;
        }

        // Pre-allocate file to total size (like CE does)
        const total_size = current_offset;
        {
            const raw = linux.open(snap_path, linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
            if (@as(isize, @bitCast(raw)) < 0) return error.OpenSnapshotFailed;
            _ = linux.ftruncate(@intCast(raw), @intCast(total_size));
            _ = std.c.close(@intCast(raw));
        }

        // Split regions across threads
        const regions_per_thread = try self.splitRegionsEvenly();

        var threads = try self.allocator.alloc(std.Thread, self.thread_count);
        defer self.allocator.free(threads);
        var thread_scanned = try self.allocator.alloc(u64, self.thread_count);
        defer self.allocator.free(thread_scanned);
        @memset(thread_scanned, 0);

        var ti: u32 = 0;
        while (ti < self.thread_count) : (ti += 1) {
            const idx = ti;
            const t_regions = regions_per_thread[idx];
            const pid_cpy = self.cfg.pid;
            const sp_cpy = snap_path;

            threads[idx] = try std.Thread.spawn(.{}, struct {
                fn run(pid2: u32, regs: []const types.MemoryRegion, sp: [:0]const u8, sc: *u64) !void {
                    const mem_fd = try mem_mod.openProcMem(pid2);
                    defer _ = std.c.close(mem_fd);

                    const raw = linux.open(sp, linux.O{ .ACCMODE = .WRONLY }, 0);
                    if (@as(isize, @bitCast(raw)) < 0) return error.OpenSnapshotFailed;
                    const snap_fd: linux.fd_t = @intCast(raw);
                    defer _ = std.c.close(snap_fd);

                    const chunk_buf = try std.heap.page_allocator.alloc(u8, CHUNK_SIZE);
                    defer std.heap.page_allocator.free(chunk_buf);

                    for (regs) |region| {
                        var offset: usize = 0;
                        const file_base = region.mirror_offset;
                        while (offset < region.size) {
                            const remaining = region.size - offset;
                            const to_read = if (remaining < CHUNK_SIZE) remaining else CHUNK_SIZE;

                            mem_mod.readRaw(mem_fd, region.base + offset, chunk_buf[0..to_read]) catch {
                                offset += to_read;
                                sc.* += to_read;
                                continue;
                            };

                            _ = linux.pwrite(snap_fd, chunk_buf.ptr, to_read, @intCast(file_base + offset));
                            sc.* += to_read;
                            offset += to_read;
                        }
                    }
                }
            }.run, .{ pid_cpy, t_regions, sp_cpy, &thread_scanned[idx] });
        }

        // Wait for all threads
        ti = 0;
        while (ti < self.thread_count) : (ti += 1) {
            threads[ti].join();
            self.total_scanned += thread_scanned[ti];
        }

        // Mark all scanned addresses as "found" (like CE — unknown first scan finds everything)
        // We don't write individual address records; instead, we create a sentinel
        // scan_0.tmp that next scans can detect to know a snapshot exists.
        {
            var sbuf: [128]u8 = undefined;
            const sentinel_path = try std.fmt.bufPrintZ(&sbuf, "{s}/scan_0.tmp", .{self.work_dir});
            const raw_s = linux.open(sentinel_path, linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
            if (@as(isize, @bitCast(raw_s)) < 0) return error.OpenSentinelFailed;
            const magic: [6]u8 = "SNAPv1".*;
            _ = linux.write(@intCast(raw_s), &magic, 6);
            _ = std.c.close(@intCast(raw_s));
        }

        try self.buildResultPaths("scan_");
        self.total_found = @intCast(self.total_scanned / self.cfg.value_type.size());
    }

    /// Run a next scan (changed, unchanged, increased, etc.)
    /// Requires first scan to have been completed first.
    /// Automatically detects snapshot mode and uses firstnextscan if needed.
    pub fn runNextScan(self: *Self) !void {
        // Check if first scan used snapshot mode (SNAPv1 sentinel in scan_0.tmp)
        if (self.isSnapshotMode()) {
            return self.runSnapshotNextScan();
        }

        // Standard next scan: read previous address records, re-read memory, compare
        // Build result and previous file paths
        try self.buildResultPaths("next_");

        var threads = try self.allocator.alloc(std.Thread, self.thread_count);
        defer self.allocator.free(threads);
        var thread_results = try self.allocator.alloc(u32, self.thread_count);
        defer self.allocator.free(thread_results);
        @memset(thread_results, 0);

        var ti: u32 = 0;
        while (ti < self.thread_count) : (ti += 1) {
            const idx = ti;

            // Previous result file path (from first scan or previous next scan)
            // MUST duplicate to heap — prev_buf on stack is reused across loop iterations
            var prev_buf: [128]u8 = undefined;
            const prev_path_blk = try std.fmt.bufPrintZ(&prev_buf, "{s}/scan_{d}.tmp", .{ self.work_dir, idx });
            const prev_path = try self.allocator.dupeZ(u8, prev_path_blk);

            const alloc_cpy = self.allocator;
            const cfg_cpy = self.cfg;
            const pid_cpy = self.cfg.pid;
            const rpath = self.result_paths[idx];

            threads[idx] = try std.Thread.spawn(.{}, struct {
                fn run(a: std.mem.Allocator, pid2: u32, c: types.ScanConfig, rp: [:0]const u8, pp: [:0]const u8, res: *u32) !void {
                    var w = try worker.NextScanWorker.init(a, pid2, c, rp, pp);
                    defer w.deinit();
                    res.* = try w.run();
                }
            }.run, .{ alloc_cpy, pid_cpy, cfg_cpy, rpath, prev_path, &thread_results[idx] });
        }

        // Wait for all threads
        ti = 0;
        while (ti < self.thread_count) : (ti += 1) {
            threads[ti].join();
            self.total_found += thread_results[ti];
        }

        // Swap new results over old ones: next_*.tmp → scan_*.tmp
        // This way subsequent next scans read the latest results.
        for (0..self.result_paths.len) |i| {
            var next_buf: [256]u8 = undefined;
            var scan_buf: [256]u8 = undefined;
            const next_path = std.fmt.bufPrintZ(&next_buf, "{s}/next_{d}.tmp", .{ self.work_dir, @as(u32, @intCast(i)) }) catch continue;
            const scan_path = std.fmt.bufPrintZ(&scan_buf, "{s}/scan_{d}.tmp", .{ self.work_dir, @as(u32, @intCast(i)) }) catch continue;
            _ = linux.rename(next_path, scan_path);
        }

        // Update result_paths to point at scan_*.tmp (where the renamed files live now)
        // Free old next_* paths, allocate new scan_* paths
        for (self.result_paths) |p| self.allocator.free(p);
        self.allocator.free(self.result_paths);
        try self.buildResultPaths("scan_");
    }

    /// Merge all per-thread result files and write combined output.
    /// Returns a slice of ScanResult (caller owns via arena allocator).
    /// max_records caps the total records loaded into RAM (0 = unlimited).
    pub fn mergeResults(self: *Self, arena: std.mem.Allocator, max_records: usize) ![]types.ScanResult {
        var all: std.ArrayList(types.ScanResult) = .empty;

        // Distribute memory budget across per-thread files
        const per_file_max: usize = if (max_records > 0 and self.result_paths.len > 0) blk: {
            const per_file = (max_records / self.result_paths.len) * 16;
            // Use at least 16MB per file for snapshot next scans
            break :blk @max(per_file, 16 * 1024 * 1024);
        } else 256 * 1024 * 1024; // unbounded: 256MB per file fallback

        for (self.result_paths) |rpath| {
            if (max_records > 0 and all.items.len >= max_records) break;

            const raw = linux.open(rpath, linux.O{}, 0);
            if (@as(isize, @bitCast(raw)) < 0) continue;

            const data = try util.readAllFd(@intCast(raw), self.allocator, per_file_max);
            defer self.allocator.free(data);
            _ = std.c.close(@intCast(raw));

            const rec_count = data.len / 16;
            const records: [][16]u8 align(1) = @as([*][16]u8, @ptrCast(data.ptr))[0..rec_count];

            for (records) |rec| {
                if (max_records > 0 and all.items.len >= max_records) break;
                const addr: usize = @intCast(std.mem.readInt(u64, rec[0..8], .little));
                const val: u64 = std.mem.readInt(u64, rec[8..16], .little);
                try all.append(arena, types.ScanResult{ .address = addr, .value = val });
            }
        }

        return all.items;
    }

    /// Check if first scan used snapshot mode by reading scan_0.tmp sentinel.
    fn isSnapshotMode(self: *const Self) bool {
        var sbuf: [128]u8 = undefined;
        const path = std.fmt.bufPrintZ(&sbuf, "{s}/scan_0.tmp", .{self.work_dir}) catch return false;
        const raw = linux.open(path, linux.O{}, 0);
        if (@as(isize, @bitCast(raw)) < 0) return false;
        defer _ = std.c.close(@intCast(raw));

        var magic: [6]u8 = undefined;
        const n = linux.read(@intCast(raw), &magic, 6);
        return n >= 6 and std.mem.eql(u8, &magic, "SNAPv1");
    }

    /// CE-style firstnextscan: read MEMORY.TMP snapshot, compare against current
    /// process memory, and produce standard scan_*.tmp result files.
    /// After this completes, subsequent next scans use normal nextnextscan.
    fn runSnapshotNextScan(self: *Self) !void {
        // Open MEMORY.TMP snapshot
        var snap_buf: [128]u8 = undefined;
        const snap_path = try std.fmt.bufPrintZ(&snap_buf, "{s}/MEMORY.TMP", .{self.work_dir});
        const raw_snap = linux.open(snap_path, linux.O{}, 0);
        if (@as(isize, @bitCast(raw_snap)) < 0) return error.OpenSnapshotFailed;
        const snap_fd: linux.fd_t = @intCast(raw_snap);
        defer _ = std.c.close(snap_fd);

        // Get total snapshot size via lseek
        const snap_size: usize = @intCast(linux.lseek(snap_fd, 0, linux.SEEK.END));

        // Build output paths
        try self.buildResultPaths("next_");

        // Re-read current memory regions and compare against snapshot
        const step = self.cfg.value_type.size();
        const type_size = step;

        var thread_results = try self.allocator.alloc(u32, self.thread_count);
        defer self.allocator.free(thread_results);
        var thread_scanned = try self.allocator.alloc(u64, self.thread_count);
        defer self.allocator.free(thread_scanned);
        @memset(thread_results, 0);
        @memset(thread_scanned, 0);

        // Re-enumerate regions if needed (they may have changed)
        if (self.region_count == 0) try self.enumerateRegions();

        // Compute per-region snapshot offsets
        var snap_offset: u64 = 0;
        for (self.regions[0..self.region_count]) |*r| {
            r.mirror_offset = snap_offset;
            snap_offset += r.size;
        }
        // Note: snap_offset may differ from snap_size if regions changed.
        // We use min(region.size, remaining_snap) to handle this gracefully.

        const regions_per_thread = try self.splitRegionsEvenly();

        var threads = try self.allocator.alloc(std.Thread, self.thread_count);
        defer self.allocator.free(threads);

        var ti: u32 = 0;
        while (ti < self.thread_count) : (ti += 1) {
            const idx = ti;
            const t_regions = regions_per_thread[idx];
            const pid_cpy = self.cfg.pid;
            const rpath = self.result_paths[idx];
            const opt = self.cfg.scan_option;
            const v1 = self.cfg.value1;

            threads[idx] = try std.Thread.spawn(.{}, struct {
                fn run(pid2: u32, regs: []const types.MemoryRegion, rp: [:0]const u8,
                    scan_opt: types.ScanOption, val1: u64, res: *u32, sc: *u64,
                    sf: linux.fd_t, ts: usize, tsz: u32) !void {
                    const mem_fd = try mem_mod.openProcMem(pid2);
                    defer _ = std.c.close(mem_fd);

                    const raw_r = linux.open(rp, linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
                    if (@as(isize, @bitCast(raw_r)) < 0) return error.OpenResultFileFailed;
                    const result_fd: linux.fd_t = @intCast(raw_r);
                    defer _ = std.c.close(result_fd);

                    const chunk = try std.heap.page_allocator.alloc(u8, CHUNK_SIZE);
                    defer std.heap.page_allocator.free(chunk);
                    const old_chunk = try std.heap.page_allocator.alloc(u8, CHUNK_SIZE);
                    defer std.heap.page_allocator.free(old_chunk);

                    var result_buf: std.ArrayList(u8) = .empty;
                    defer result_buf.deinit(std.heap.page_allocator);
                    try result_buf.ensureTotalCapacity(std.heap.page_allocator, FLUSH_THRESHOLD * 16);

                    var found: u32 = 0;
                    var scanned: u64 = 0;

                    for (regs) |region| {
                        const file_base = region.mirror_offset;
                        var offset: usize = 0;
                        while (offset < region.size) {
                            const remaining = region.size - offset;
                            const file_remaining = if (file_base + offset < ts)
                                ts - (file_base + offset)
                            else
                                0;
                            const to_cmp = @min(@min(remaining, file_remaining), CHUNK_SIZE);

                            if (to_cmp == 0) {
                                offset += remaining;
                                scanned += remaining;
                                break;
                            }

                            // Read current memory
                            mem_mod.readRaw(mem_fd, region.base + offset, chunk[0..to_cmp]) catch {
                                offset += to_cmp;
                                scanned += to_cmp;
                                continue;
                            };

                            // Read old snapshot at this offset
                            const old_read = linux.pread(sf, old_chunk.ptr, to_cmp, @intCast(file_base + offset));
                            if (@as(isize, @bitCast(old_read)) < 0) {
                                offset += to_cmp;
                                scanned += to_cmp;
                                continue;
                            }
                            const old_bytes = old_chunk[0..@intCast(old_read)];

                            // Compare and record matches
                            const end = if (to_cmp >= tsz) to_cmp - tsz + 1 else 0;
                            var pos: usize = 0;
                            while (pos < end) : (pos += tsz) {
                                if (pos + tsz > old_bytes.len) break;
                                const old_val = readValue(old_bytes[pos..], tsz);
                                const cur_val = readValue(chunk[pos..], tsz);

                                if (checkNextMatch(scan_opt, cur_val, old_val, val1)) {
                                    found += 1;
                                    var rec: [16]u8 = undefined;
                                    std.mem.writeInt(u64, rec[0..8], @intCast(region.base + offset + pos), .little);
                                    std.mem.writeInt(u64, rec[8..16], cur_val, .little);
                                    result_buf.appendSlice(std.heap.page_allocator, &rec) catch break;
                                    if (found % FLUSH_THRESHOLD == 0) {
                                        _ = linux.write(result_fd, result_buf.items.ptr, result_buf.items.len);
                                        result_buf.clearRetainingCapacity();
                                    }
                                }
                            }

                            scanned += to_cmp;
                            offset += to_cmp;
                        }
                    }

                    // Final flush
                    if (result_buf.items.len > 0) {
                        _ = linux.write(result_fd, result_buf.items.ptr, result_buf.items.len);
                    }

                    res.* = found;
                    sc.* = scanned;
                }
            }.run, .{ pid_cpy, t_regions, rpath, opt, v1, &thread_results[idx], &thread_scanned[idx], snap_fd, snap_size, @as(u32, @intCast(type_size)) });
        }

        // Wait for all threads
        ti = 0;
        while (ti < self.thread_count) : (ti += 1) {
            threads[ti].join();
            self.total_found += thread_results[ti];
            self.total_scanned += thread_scanned[ti];
        }

        // Replace SNAPv1 sentinel with the first next scan result path
        // Rename next_*.tmp → scan_*.tmp so subsequent scans use normal nextnextscan
        for (0..self.result_paths.len) |i| {
            var next_buf: [256]u8 = undefined;
            var scan_buf: [256]u8 = undefined;
            const next_path = std.fmt.bufPrintZ(&next_buf, "{s}/next_{d}.tmp", .{ self.work_dir, @as(u32, @intCast(i)) }) catch continue;
            const scan_path = std.fmt.bufPrintZ(&scan_buf, "{s}/scan_{d}.tmp", .{ self.work_dir, @as(u32, @intCast(i)) }) catch continue;
            _ = linux.unlink(scan_path); // remove SNAPv1 sentinel
            _ = linux.rename(next_path, scan_path);
        }

        // Update result_paths to point at scan_*.tmp
        for (self.result_paths) |p| self.allocator.free(p);
        self.allocator.free(self.result_paths);
        try self.buildResultPaths("scan_");

        // Remove MEMORY.TMP — no longer needed after first next scan
        _ = linux.unlink(snap_path);
    }

    /// Clean up temp files
    pub fn cleanup(self: *const Self) void {
        for (self.result_paths) |rp| {
            _ = linux.unlink(rp);
        }
        if (self.snapshot_path) |sp| {
            _ = linux.unlink(sp);
        }
        var rmdir_buf: [128]u8 = undefined;
        const wd_z = std.fmt.bufPrintZ(&rmdir_buf, "{s}", .{self.work_dir}) catch return;
        _ = linux.rmdir(wd_z);
    }

    // ─── Internal helpers ────────────────────────────────────────────────

    /// Build per-thread result file paths.
    /// prefix controls the filename prefix ("scan_" for first, "next_" for next).
    fn buildResultPaths(self: *Self, prefix: []const u8) !void {
        var paths: std.ArrayList([:0]u8) = .empty;
        var ti: u32 = 0;
        while (ti < self.thread_count) : (ti += 1) {
            var buf: [128]u8 = undefined;
            const path = try std.fmt.bufPrintZ(&buf, "{s}/{s}{d}.tmp", .{ self.work_dir, prefix, ti });
            try paths.append(self.allocator, try self.allocator.dupeZ(u8, path));
        }
        self.result_paths = try paths.toOwnedSlice(self.allocator);
    }

    /// Split self.regions evenly across self.thread_count threads.
    /// Returns an array of slices into self.regions.
    fn splitRegionsEvenly(self: *const Self) ![]const []const types.MemoryRegion {
        var result: std.ArrayList([]const types.MemoryRegion) = .empty;

        if (self.region_count <= self.thread_count) {
            // Each thread gets up to 1 region
            for (0..self.thread_count) |ti| {
                if (ti < self.region_count) {
                    try result.append(self.allocator, self.regions[ti..ti+1]);
                } else {
                    try result.append(self.allocator, self.regions[0..0]);
                }
            }
        } else {
            // Round-robin distribution so threads get roughly equal total size
            var thread_sizes = try self.allocator.alloc(usize, self.thread_count);
            defer self.allocator.free(thread_sizes);
            var thread_counts = try self.allocator.alloc(usize, self.thread_count);
            defer self.allocator.free(thread_counts);
            @memset(thread_sizes, 0);
            @memset(thread_counts, 0);

            // First pass: assign each region to the thread with smallest total so far
            for (self.regions[0..self.region_count]) |region| {
                var min_idx: u32 = 0;
                var min_size: usize = std.math.maxInt(usize);
                for (0..self.thread_count) |ti| {
                    if (thread_sizes[ti] < min_size) {
                        min_size = thread_sizes[ti];
                        min_idx = @intCast(ti);
                    }
                }
                thread_sizes[min_idx] += region.size;
                thread_counts[min_idx] += 1;
            }

            // Second pass: allocate slices
            var region_ptr: usize = 0;
            for (0..self.thread_count) |ti| {
                if (thread_counts[ti] == 0) {
                    try result.append(self.allocator, self.regions[0..0]);
                    continue;
                }
                try result.append(self.allocator, self.regions[region_ptr .. region_ptr + thread_counts[ti]]);
                region_ptr += thread_counts[ti];
            }
        }

        return try result.toOwnedSlice(self.allocator);
    }
};

// ─── Free functions (used by spawned threads) ───────────────────────────

/// Read a typed u64 value from a byte slice.
fn readValue(buf: []const u8, type_size: u32) u64 {
    return switch (type_size) {
        1 => @as(u64, buf[0]),
        2 => @as(u64, std.mem.readInt(u16, buf[0..2], .little)),
        4 => @as(u64, std.mem.readInt(u32, buf[0..4], .little)),
        8 => std.mem.readInt(u64, buf[0..8], .little),
        else => 0,
    };
}

/// Check if current vs old value matches scan option (for next scans).
fn checkNextMatch(opt: types.ScanOption, current: u64, old: u64, val1: u64) bool {
    return switch (opt) {
        .exact => current == val1,
        .unknown => true,
        .changed => current != old,
        .unchanged => current == old,
        .increased => @as(i64, @bitCast(current)) > @as(i64, @bitCast(old)),
        .decreased => @as(i64, @bitCast(current)) < @as(i64, @bitCast(old)),
        .increased_by => @as(i64, @bitCast(current)) - @as(i64, @bitCast(old)) == @as(i64, @bitCast(val1)),
        .decreased_by => @as(i64, @bitCast(old)) - @as(i64, @bitCast(current)) == @as(i64, @bitCast(val1)),
        .bigger_than => current > val1,
        .smaller_than => current < val1,
        .between => current >= val1 and current <= val1, // val1 is min in snapshot context
    };
}
