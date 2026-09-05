// ZIGH — Scanner worker thread
// Each worker scans its assigned memory regions independently.
// Results written to per-thread temp files; merged by the engine.

const std = @import("std");
const linux = std.os.linux;
const types = @import("types.zig");
const mem_types = @import("../mem/types.zig");
const mem_mod = @import("../mem/mod.zig");
const util = @import("../util.zig");

const CHUNK_SIZE = 256 * 1024; // 256KB read chunks
const FLUSH_THRESHOLD = 1024; // flush results to file every N matches

/// A single-threaded scanner that processes assigned memory regions.
pub const ScanWorker = struct {
    allocator: std.mem.Allocator,
    pid: u32,
    mem_fd: linux.fd_t,
    /// Regions assigned to this worker (slice into engine-owned array)
    regions: []const types.MemoryRegion,
    /// Scan parameters
    cfg: types.ScanConfig,
    /// Temp file fd for results (address,value pairs)
    result_fd: linux.fd_t,
    /// Accumulated result count
    found: u32 = 0,
    /// Accumulated byte count scanned
    scanned: u64 = 0,

    const Self = @This();

    /// Initialize a worker. Opens its own /proc/PID/mem fd.
    pub fn init(allocator: std.mem.Allocator, pid: u32, regions: []const types.MemoryRegion, cfg: types.ScanConfig, result_path: [:0]const u8) !Self {
        const raw = linux.open(result_path, linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        if (@as(isize, @bitCast(raw)) < 0) return error.OpenResultFileFailed;

        const mem_fd = try mem_mod.openProcMem(pid);
        errdefer _ = std.c.close(mem_fd);

        return Self{
            .allocator = allocator,
            .pid = pid,
            .mem_fd = mem_fd,
            .regions = regions,
            .cfg = cfg,
            .result_fd = @intCast(raw),
        };
    }

    pub fn deinit(self: *Self) void {
        _ = std.c.close(self.mem_fd);
        _ = std.c.close(self.result_fd);
    }

    /// Run the scan over assigned regions. Returns total results found.
    pub fn run(self: *Self) !u32 {
        // Allocate scan buffer once (reused across reads)
        const buf = try self.allocator.alloc(u8, CHUNK_SIZE + self.cfg.value_type.size());
        defer self.allocator.free(buf);

        // Result accumulation buffer (flush to file periodically)
        var result_buf: std.ArrayList(u8) = .empty;
        defer result_buf.deinit(self.allocator);

        // Ensure result_buf has enough capacity for FLUSH_THRESHOLD records
        try result_buf.ensureTotalCapacity(self.allocator, FLUSH_THRESHOLD * 16);

        for (self.regions) |region| {
            var offset: usize = 0;
            while (offset < region.size) {
                const remaining = region.size - offset;
                const to_read = if (remaining < CHUNK_SIZE) remaining else CHUNK_SIZE;

                mem_mod.readRaw(self.mem_fd, region.base + offset, buf[0..to_read]) catch {
                    offset += to_read;
                    self.scanned += to_read;
                    continue;
                };
                self.scanned += to_read;

                try self.scanBuffer(
                    buf[0..to_read],
                    region.base + offset,
                    &result_buf,
                );

                offset += to_read;
            }

            // Flush after each region
            if (result_buf.items.len > 0) {
                _ = linux.write(self.result_fd, result_buf.items.ptr, result_buf.items.len);
                result_buf.clearRetainingCapacity();
            }
        }

        return self.found;
    }

    /// Scan a memory buffer, appending results to result_buf
    fn scanBuffer(self: *Self, buf: []u8, base_addr: usize, result_buf: *std.ArrayList(u8)) !void {
        const type_size = self.cfg.value_type.size();
        if (buf.len < type_size) return;

        const step: usize = if (self.cfg.fast_scan) type_size else 1;
        const end = buf.len - type_size;

        var pos: usize = 0;
        while (pos <= end) : (pos += step) {
            const addr = base_addr + pos;
            const current = readValue(buf[pos..], self.cfg.value_type);

            if (self.checkMatch(current)) {
                self.found += 1;

                // Append to result buffer (binary: 8 bytes addr + 8 bytes value)
                var record: [16]u8 = undefined;
                std.mem.writeInt(u64, record[0..8], @intCast(addr), .little);
                std.mem.writeInt(u64, record[8..16], current, .little);
                try result_buf.appendSlice(self.allocator, &record);

                // Flush when buffer is full
                if (self.found % FLUSH_THRESHOLD == 0) {
                    _ = linux.write(self.result_fd, result_buf.items.ptr, result_buf.items.len);
                    result_buf.clearRetainingCapacity();
                }
            }
        }
    }

    /// Check if a value matches the scan option
    fn checkMatch(self: *const Self, value: u64) bool {
        return switch (self.cfg.scan_option) {
            .exact => value == self.cfg.value1,
            .bigger_than => value > self.cfg.value1,
            .smaller_than => value < self.cfg.value1,
            .between => value >= self.cfg.value1 and value <= self.cfg.value2,
            .unknown => true,
            .changed, .unchanged, .increased, .decreased, .increased_by, .decreased_by => false,
        };
    }
};

/// A worker for next scans — compares current value against previous scan results.
pub const NextScanWorker = struct {
    allocator: std.mem.Allocator,
    pid: u32,
    mem_fd: linux.fd_t,
    cfg: types.ScanConfig,
    result_fd: linux.fd_t,
    prev_fd: linux.fd_t,
    found: u32 = 0,
    scanned: u64 = 0,

    const Self2 = @This();

    pub fn init(allocator: std.mem.Allocator, pid: u32, cfg: types.ScanConfig, result_path: [:0]const u8, prev_path: [:0]const u8) !Self2 {
        const raw_res = linux.open(result_path, linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        if (@as(isize, @bitCast(raw_res)) < 0) return error.OpenResultFileFailed;

        const raw_prev = linux.open(prev_path, linux.O{}, 0);
        if (@as(isize, @bitCast(raw_prev)) < 0) return error.OpenPrevFileFailed;

        const mem_fd = try mem_mod.openProcMem(pid);
        errdefer _ = std.c.close(mem_fd);

        return Self2{
            .allocator = allocator,
            .pid = pid,
            .mem_fd = mem_fd,
            .cfg = cfg,
            .result_fd = @intCast(raw_res),
            .prev_fd = @intCast(raw_prev),
        };
    }

    pub fn deinit(self: *Self2) void {
        _ = std.c.close(self.mem_fd);
        _ = std.c.close(self.result_fd);
        _ = std.c.close(self.prev_fd);
    }

    const STREAM_CHUNK_BYTES = 64 * 1024; // 64KB chunks = 4096 records per read

    /// Read previous scan results, re-read memory for each address, compare, write matching ones.
    pub fn run(self: *Self2) !u32 {
        var result_buf: std.ArrayList(u8) = .empty;
        defer result_buf.deinit(self.allocator);
        try result_buf.ensureTotalCapacity(self.allocator, FLUSH_THRESHOLD * 16);

        const type_size = self.cfg.value_type.size();
        var val_buf: [8]u8 = [_]u8{0} ** 8;

        // Stream previous results in chunks instead of loading all into RAM at once
        const chunk = try self.allocator.alloc(u8, STREAM_CHUNK_BYTES);
        defer self.allocator.free(chunk);

        while (true) {
            const n = linux.read(self.prev_fd, chunk.ptr, chunk.len);
            if (n <= 0) break;
            const bytes = chunk[0..@as(usize, @intCast(n))];
            const rec_count = bytes.len / 16;
            const records: [][16]u8 align(1) = @as([*][16]u8, @ptrCast(bytes.ptr))[0..rec_count];

            for (records) |rec| {
                const addr: usize = @intCast(std.mem.readInt(u64, rec[0..8], .little));
                const old_val: u64 = std.mem.readInt(u64, rec[8..16], .little);

                // Re-read current value from process
                mem_mod.readRaw(self.mem_fd, addr, val_buf[0..type_size]) catch continue;
                const current = readValue(val_buf[0..], self.cfg.value_type);
                self.scanned += 1;

                if (self.checkNextMatch(current, old_val)) {
                    self.found += 1;

                    var record: [16]u8 = undefined;
                    std.mem.writeInt(u64, record[0..8], @intCast(addr), .little);
                    std.mem.writeInt(u64, record[8..16], current, .little);
                    try result_buf.appendSlice(self.allocator, &record);

                    if (self.found % FLUSH_THRESHOLD == 0) {
                        _ = linux.write(self.result_fd, result_buf.items.ptr, result_buf.items.len);
                        result_buf.clearRetainingCapacity();
                    }
                }
            }
        }

        if (result_buf.items.len > 0) {
            _ = linux.write(self.result_fd, result_buf.items.ptr, result_buf.items.len);
        }

        return self.found;
    }

    fn checkNextMatch(self: *const Self2, current: u64, old: u64) bool {
        return switch (self.cfg.scan_option) {
            .exact => current == self.cfg.value1,
            .unknown => true,
            .changed => current != old,
            .unchanged => current == old,
            .increased => @as(i64, @bitCast(current)) > @as(i64, @bitCast(old)),
            .decreased => @as(i64, @bitCast(current)) < @as(i64, @bitCast(old)),
            .increased_by => @as(i64, @bitCast(current)) - @as(i64, @bitCast(old)) == @as(i64, @bitCast(self.cfg.value1)),
            .decreased_by => @as(i64, @bitCast(old)) - @as(i64, @bitCast(current)) == @as(i64, @bitCast(self.cfg.value1)),
            .bigger_than => current > self.cfg.value1,
            .smaller_than => current < self.cfg.value1,
            .between => current >= self.cfg.value1 and current <= self.cfg.value2,
        };
    }
};

/// Read a typed value from a byte slice at offset 0
fn readValue(buf: []const u8, tid: mem_types.TypeId) u64 {
    const sz = tid.size();
    return switch (sz) {
        1 => @as(u64, buf[0]),
        2 => @as(u64, std.mem.readInt(u16, buf[0..2], .little)),
        4 => @as(u64, std.mem.readInt(u32, buf[0..4], .little)),
        8 => std.mem.readInt(u64, buf[0..8], .little),
        else => 0,
    };
}
