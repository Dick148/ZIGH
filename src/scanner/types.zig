// ZIGH — Scanner types
// Scan options, region descriptors, result records

const std = @import("std");
const mem_types = @import("../mem/types.zig");

/// How to compare during a scan
pub const ScanOption = enum {
    exact,          // value matches exactly
    unknown,        // unknown initial value (first scan only)
    bigger_than,
    smaller_than,
    between,        // value1 <= x <= value2
    changed,        // value changed since last scan
    unchanged,      // value unchanged since last scan
    increased,      // value increased since last scan
    decreased,      // value decreased since last scan
    increased_by,   // value increased by exactly N
    decreased_by,   // value decreased by exactly N

    pub fn isFirstOnly(self: ScanOption) bool {
        return switch (self) {
            .unknown, .exact, .bigger_than, .smaller_than, .between => true,
            else => false,
        };
    }

    pub fn isNextOnly(self: ScanOption) bool {
        return switch (self) {
            .changed, .unchanged, .increased, .decreased, .increased_by, .decreased_by => true,
            .unknown => true, // unknown implies first scan
            else => false,
        };
    }

    pub fn parse(s: []const u8) ?ScanOption {
        if (std.mem.eql(u8, s, "exact")) return .exact;
        if (std.mem.eql(u8, s, "unknown")) return .unknown;
        if (std.mem.eql(u8, s, "bigger_than")) return .bigger_than;
        if (std.mem.eql(u8, s, "smaller_than")) return .smaller_than;
        if (std.mem.eql(u8, s, "between")) return .between;
        if (std.mem.eql(u8, s, "changed")) return .changed;
        if (std.mem.eql(u8, s, "unchanged")) return .unchanged;
        if (std.mem.eql(u8, s, "increased")) return .increased;
        if (std.mem.eql(u8, s, "decreased")) return .decreased;
        if (std.mem.eql(u8, s, "increased_by")) return .increased_by;
        if (std.mem.eql(u8, s, "decreased_by")) return .decreased_by;
        return null;
    }
};

/// A contiguous memory region to scan
pub const MemoryRegion = struct {
    base: usize,
    size: usize,
    /// Offset into the previous scan's mirror file (used for next scans)
    mirror_offset: u64,
};

/// A single scan result
pub const ScanResult = struct {
    address: usize,
    value: u64, // wire format (packed)

    pub fn format(
        self: ScanResult,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("0x{x}: {d}", .{ self.address, self.value });
    }
};

/// Scanner configuration for a scan run
pub const ScanConfig = struct {
    pid: u32,
    scan_option: ScanOption,
    value_type: mem_types.TypeId,
    /// First scan value (exact / bigger_than / smaller_than / between_lower)
    value1: u64 = 0,
    /// Second value (between_upper / increased_by / decreased_by)
    value2: u64 = 0,
    /// Scan directory for temp files (default: /tmp/zigh_scan_<pid>/)
    work_dir: ?[]const u8 = null,
    /// Max number of worker threads (0 = auto = CPU count)
    thread_count: u32 = 0,
    /// Use fast aligned scanning (skip align bytes)
    fast_scan: bool = true,
    /// Max memory (MB) to use for keeping scan results in RAM.
    /// Beyond this, results stay disk-only and are read in chunks.
    /// 0 = unlimited (default 256 MB).
    max_memory_mb: u32 = 256,
    /// CE-style: for unknown initial value scans, save a MEMORY.TMP snapshot
    /// of all scanned memory instead of individual address records.
    /// This is far more disk-efficient (1 byte per byte scanned vs 16 bytes).
    /// Subsequent next scans read current memory and compare against this snapshot.
    snapshot_memory: bool = false,
};

const SENTINEL = "SCANv1";

/// Result index header (written at top of combined results file)
pub const ResultHeader = struct {
    magic: [6]u8 = SENTINEL.*,
    count: u32 = 0,
    value_type: mem_types.TypeId = .uint32,
    _pad: u16 = 0,
};
