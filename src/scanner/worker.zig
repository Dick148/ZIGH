// ZIGH — Scanner worker thread
// Each worker pulls fixed-size jobs from a shared atomic queue, reads the
// target's memory in chunks, compares typed values and writes 16-byte result
// records to its own temp file. The engine merges the files.

const std = @import("std");
const linux = std.os.linux;
const types = @import("types.zig");
const mem_types = @import("../mem/types.zig");
const mem_mod = @import("../mem/mod.zig");
const util = @import("../util.zig");
const value = @import("value.zig");

const CHUNK_SIZE = 256 * 1024; // 256KB read chunks
const FLUSH_THRESHOLD = 1024; // flush results to file every N matches

/// A single-threaded scanner that processes jobs pulled from a shared queue.
pub const ScanWorker = struct {
    pid: u32,
    mem_fd: linux.fd_t,
    jobs: []const types.Job,
    counter: *std.atomic.Value(usize),
    cfg: types.ScanConfig,
    result_fd: linux.fd_t,
    found: u32 = 0,
    scanned: u64 = 0,

    const Self = @This();

    pub fn init(
        pid: u32,
        jobs: []const types.Job,
        counter: *std.atomic.Value(usize),
        cfg: types.ScanConfig,
        result_path: [:0]const u8,
    ) !Self {
        const raw = linux.open(result_path, linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true }, 0o600);
        if (@as(isize, @bitCast(raw)) < 0) return error.OpenResultFileFailed;

        const mem_fd = mem_mod.openProcMem(pid) catch |e| {
            _ = std.c.close(@intCast(raw));
            return e;
        };

        return Self{
            .pid = pid,
            .mem_fd = mem_fd,
            .jobs = jobs,
            .counter = counter,
            .cfg = cfg,
            .result_fd = @intCast(raw),
        };
    }

    pub fn deinit(self: *Self) void {
        _ = std.c.close(self.mem_fd);
        _ = std.c.close(self.result_fd);
    }

    /// Run until the shared job queue is exhausted. Returns total results.
    pub fn run(self: *Self) !u32 {
        const alloc = std.heap.page_allocator;
        const buf = try alloc.alloc(u8, CHUNK_SIZE);
        defer alloc.free(buf);

        var result_buf: std.ArrayList(u8) = .empty;
        defer result_buf.deinit(alloc);
        try result_buf.ensureTotalCapacity(alloc, FLUSH_THRESHOLD * 16);

        while (true) {
            const idx = self.counter.fetchAdd(1, .monotonic);
            if (idx >= self.jobs.len) break;
            try self.scanJob(self.jobs[idx], buf, &result_buf);
        }

        try self.flush(&result_buf);
        return self.found;
    }

    fn flush(self: *Self, result_buf: *std.ArrayList(u8)) !void {
        if (result_buf.items.len == 0) return;
        try util.writeAll(self.result_fd, result_buf.items);
        result_buf.clearRetainingCapacity();
    }

    fn scanJob(self: *Self, job: types.Job, buf: []u8, result_buf: *std.ArrayList(u8)) !void {
        const tid = self.cfg.value_type;
        const type_size = tid.size();
        if (job.size < type_size) return;

        const step: usize = if (self.cfg.fast_scan) type_size else 1;
        // Unaligned scans need the last (type_size - 1) bytes carried into the
        // next read so values straddling a chunk boundary are not missed.
        const overlap: usize = if (step == 1) type_size - 1 else 0;

        var offset: usize = 0;
        while (offset < job.size) {
            const remaining = job.size - offset;
            const to_read = @min(remaining, CHUNK_SIZE);

            mem_mod.readRaw(self.mem_fd, job.base + offset, buf[0..to_read]) catch {
                self.scanned += to_read;
                offset += to_read;
                continue;
            };
            self.scanned += to_read;

            if (to_read >= type_size) {
                const end = to_read - type_size;
                var pos: usize = 0;
                while (pos <= end) : (pos += step) {
                    const current = value.decode(buf[pos..], tid);
                    if (value.matchesFirst(
                        self.cfg.scan_option,
                        current,
                        tid,
                        self.cfg.value1,
                        self.cfg.value2,
                        self.cfg.epsilon,
                    )) {
                        self.found += 1;
                        var record: [16]u8 = undefined;
                        std.mem.writeInt(u64, record[0..8], @intCast(job.base + offset + pos), .little);
                        std.mem.writeInt(u64, record[8..16], current, .little);
                        try result_buf.appendSlice(std.heap.page_allocator, &record);

                        if (self.found % FLUSH_THRESHOLD == 0) try self.flush(result_buf);
                    }
                }
            }

            if (overlap > 0 and to_read > overlap and offset + to_read < job.size) {
                offset += to_read - overlap;
            } else {
                offset += to_read;
            }
        }
    }
};

/// A worker for next scans. Previous-scan records are streamed from disk and
/// grouped by 64KB window, then current memory is read once per window (with a
/// per-page fallback) instead of once per record.
pub const NextScanWorker = struct {
    pid: u32,
    mem_fd: linux.fd_t,
    cfg: types.ScanConfig,
    result_fd: linux.fd_t,
    prev_fd: linux.fd_t,
    found: u32 = 0,
    scanned: u64 = 0,

    const Self2 = @This();

    pub fn init(
        pid: u32,
        cfg: types.ScanConfig,
        result_path: [:0]const u8,
        prev_path: [:0]const u8,
    ) !Self2 {
        const raw_res = linux.open(result_path, linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true }, 0o600);
        if (@as(isize, @bitCast(raw_res)) < 0) return error.OpenResultFileFailed;

        const raw_prev = linux.open(prev_path, linux.O{ .NOFOLLOW = true }, 0);
        if (@as(isize, @bitCast(raw_prev)) < 0) {
            _ = std.c.close(@intCast(raw_res));
            return error.OpenPrevFileFailed;
        }

        const mem_fd = mem_mod.openProcMem(pid) catch |e| {
            _ = std.c.close(@intCast(raw_res));
            _ = std.c.close(@intCast(raw_prev));
            return e;
        };

        return Self2{
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

    const STREAM_CHUNK_BYTES = 64 * 1024; // 64KB of records per file read
    const WINDOW_SHIFT = 16; // batch records by 64KB address window
    const WINDOW_SIZE = 1 << WINDOW_SHIFT;
    const PAGE_SIZE: usize = 4096;
    const PAGE_MASK: usize = PAGE_SIZE - 1;
    const MAX_PENDING_RECORDS = 16384;

    /// Records buffered for the current 64KB window.
    const Batch = struct {
        addrs: std.ArrayList(usize) = .empty,
        vals: std.ArrayList(u64) = .empty,
        window: usize = std.math.maxInt(usize),

        fn deinit(self: *Batch, alloc: std.mem.Allocator) void {
            self.addrs.deinit(alloc);
            self.vals.deinit(alloc);
        }

        fn clear(self: *Batch) void {
            self.addrs.clearRetainingCapacity();
            self.vals.clearRetainingCapacity();
            self.window = std.math.maxInt(usize);
        }

        fn count(self: *const Batch) usize {
            return self.addrs.items.len;
        }
    };

    pub fn run(self: *Self2) !u32 {
        const alloc = std.heap.page_allocator;

        var result_buf: std.ArrayList(u8) = .empty;
        defer result_buf.deinit(alloc);
        try result_buf.ensureTotalCapacity(alloc, FLUSH_THRESHOLD * 16);

        var batch: Batch = .{};
        defer batch.deinit(alloc);
        try batch.addrs.ensureTotalCapacity(alloc, MAX_PENDING_RECORDS);
        try batch.vals.ensureTotalCapacity(alloc, MAX_PENDING_RECORDS);

        const chunk = try alloc.alloc(u8, STREAM_CHUNK_BYTES);
        defer alloc.free(chunk);
        const window_buf = try alloc.alloc(u8, WINDOW_SIZE);
        defer alloc.free(window_buf);
        const page_buf = try alloc.alloc(u8, PAGE_SIZE);
        defer alloc.free(page_buf);

        // Records are streamed in 16-byte units; carry a partial record across
        // reads so a short read cannot desynchronize the stream.
        var tail: [16]u8 = undefined;
        var tail_len: usize = 0;

        while (true) {
            const n = linux.read(self.prev_fd, chunk.ptr, chunk.len);
            switch (linux.errno(n)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return error.ReadPrevFailed,
            }
            if (n == 0) break;

            var bytes: []const u8 = chunk[0..n];

            if (tail_len > 0) {
                const need = 16 - tail_len;
                if (bytes.len < need) {
                    @memcpy(tail[tail_len..][0..bytes.len], bytes);
                    tail_len += bytes.len;
                    continue;
                }
                @memcpy(tail[tail_len..][0..need], bytes[0..need]);
                try self.addRecord(tail[0..], &batch, window_buf, page_buf, &result_buf);
                tail_len = 0;
                bytes = bytes[need..];
            }

            const rec_count = bytes.len / 16;
            const records: []const [16]u8 align(1) = @as([*]const [16]u8, @ptrCast(bytes.ptr))[0..rec_count];
            for (records) |rec| {
                try self.addRecord(rec[0..], &batch, window_buf, page_buf, &result_buf);
            }

            const consumed = rec_count * 16;
            const rem = bytes.len - consumed;
            if (rem > 0) {
                @memcpy(tail[0..rem], bytes[consumed..]);
                tail_len = rem;
            }
        }

        try self.flushBatch(&batch, window_buf, page_buf, &result_buf);

        if (result_buf.items.len > 0) {
            try util.writeAll(self.result_fd, result_buf.items);
        }

        return self.found;
    }

    fn addRecord(
        self: *Self2,
        rec: []const u8,
        batch: *Batch,
        window_buf: []u8,
        page_buf: []u8,
        result_buf: *std.ArrayList(u8),
    ) !void {
        const addr: usize = @intCast(std.mem.readInt(u64, rec[0..8], .little));
        const old_val: u64 = std.mem.readInt(u64, rec[8..16], .little);
        const window = addr >> WINDOW_SHIFT;

        if (batch.count() > 0 and (batch.window != window or batch.count() >= MAX_PENDING_RECORDS)) {
            try self.flushBatch(batch, window_buf, page_buf, result_buf);
        }

        batch.window = window;
        try batch.addrs.append(std.heap.page_allocator, addr);
        try batch.vals.append(std.heap.page_allocator, old_val);
    }

    fn flushBatch(
        self: *Self2,
        batch: *Batch,
        window_buf: []u8,
        page_buf: []u8,
        result_buf: *std.ArrayList(u8),
    ) !void {
        const n = batch.count();
        if (n == 0) return;
        defer batch.clear();

        const tid = self.cfg.value_type;
        const tsz = tid.size();
        const addrs = batch.addrs.items;
        const vals = batch.vals.items;

        // Read only the pages spanned by these records (at most one 64KB
        // window). If the span crosses an unmapped page the read fails and we
        // fall back to one read per page, then to one read per record.
        const read_base = addrs[0] & ~PAGE_MASK;
        const read_end = (addrs[n - 1] & ~PAGE_MASK) + PAGE_SIZE;
        const read_len = read_end - read_base;

        const window_ok = blk: {
            if (read_len > window_buf.len) break :blk false;
            mem_mod.readRaw(self.mem_fd, read_base, window_buf[0..read_len]) catch break :blk false;
            break :blk true;
        };

        if (window_ok) {
            for (addrs, vals) |addr, old_val| {
                const off = addr - read_base;
                if (off + tsz <= read_len) {
                    self.scanned += 1;
                    const current = value.decode(window_buf[off..], tid);
                    try self.compareAndEmit(addr, current, old_val, result_buf);
                } else {
                    try self.processDirect(addr, old_val, result_buf);
                }
            }
            return;
        }

        var cur_page: usize = std.math.maxInt(usize);
        var page_ok = false;
        for (addrs, vals) |addr, old_val| {
            const page = addr & ~PAGE_MASK;
            if (page != cur_page) {
                cur_page = page;
                page_ok = blk: {
                    mem_mod.readRaw(self.mem_fd, page, page_buf[0..PAGE_SIZE]) catch break :blk false;
                    break :blk true;
                };
            }

            if (page_ok) {
                const off = addr - page;
                if (off + tsz <= PAGE_SIZE) {
                    self.scanned += 1;
                    const current = value.decode(page_buf[off..], tid);
                    try self.compareAndEmit(addr, current, old_val, result_buf);
                    continue;
                }
            }

            try self.processDirect(addr, old_val, result_buf);
        }
    }

    fn processDirect(self: *Self2, addr: usize, old_val: u64, result_buf: *std.ArrayList(u8)) !void {
        const tid = self.cfg.value_type;
        var val_buf: [8]u8 = undefined;
        mem_mod.readRaw(self.mem_fd, addr, val_buf[0..tid.size()]) catch return;
        self.scanned += 1;
        const current = value.decode(val_buf[0..], tid);
        try self.compareAndEmit(addr, current, old_val, result_buf);
    }

    fn compareAndEmit(
        self: *Self2,
        addr: usize,
        current: u64,
        old_val: u64,
        result_buf: *std.ArrayList(u8),
    ) !void {
        if (!value.matchesNext(
            self.cfg.scan_option,
            current,
            old_val,
            self.cfg.value_type,
            self.cfg.value1,
            self.cfg.value2,
            self.cfg.epsilon,
        )) return;

        self.found += 1;

        var record: [16]u8 = undefined;
        std.mem.writeInt(u64, record[0..8], @intCast(addr), .little);
        std.mem.writeInt(u64, record[8..16], current, .little);
        try result_buf.appendSlice(std.heap.page_allocator, &record);

        if (self.found % FLUSH_THRESHOLD == 0) {
            try util.writeAll(self.result_fd, result_buf.items);
            result_buf.clearRetainingCapacity();
        }
    }
};
