// ZIGH — Value types and conversion
// Maps type IDs to Zig types + serialization, compatible with IPC protocol v2

const std = @import("std");

pub const TypeId = enum(u32) {
    int8 = 0,
    uint8 = 1,
    int16 = 2,
    uint16 = 3,
    int32 = 4,
    uint32 = 5,
    int64 = 6,
    uint64 = 7,
    float32 = 8,
    float64 = 9,
    bytes8 = 10,
    pointer = 11,

    pub fn size(self: TypeId) usize {
        return switch (self) {
            .int8, .uint8 => 1,
            .int16, .uint16 => 2,
            .int32, .uint32, .float32 => 4,
            .int64, .uint64, .float64, .bytes8, .pointer => 8,
        };
    }

    pub fn fromU32(v: u32) ?TypeId {
        return if (v <= 11) @enumFromInt(v) else null;
    }

    pub fn fromString(s: []const u8) ?TypeId {
        for (std.meta.tags(TypeId)) |tag| {
            if (std.mem.eql(u8, s, @tagName(tag))) return tag;
        }
        return null;
    }
};

/// Pack a Zig value into its u64 wire representation (for shared memory)
pub fn packU64(value: anytype, tid: TypeId) u64 {
    return switch (tid) {
        .int8 => @as(u64, @bitCast(@as(i64, @as(i8, @intCast(value))))),
        .uint8 => @as(u64, @as(u8, @intCast(value))),
        .int16 => @as(u64, @bitCast(@as(i64, @as(i16, @intCast(value))))),
        .uint16 => @as(u64, @as(u16, @intCast(value))),
        .int32 => @as(u64, @bitCast(@as(i64, @as(i32, @intCast(value))))),
        .uint32 => @as(u64, @as(u32, @intCast(value))),
        .int64 => @bitCast(@as(i64, @intCast(value))),
        .uint64 => @as(u64, @intCast(value)),
        .float32 => @as(u64, @bitCast(@as(u32, @bitCast(@as(f32, @floatCast(value)))))),
        .float64 => @bitCast(@as(f64, @floatCast(value))),
        .bytes8 => @as(u64, @bitCast(value)),
        .pointer => @as(u64, @intCast(@intFromPtr(value))),
    };
}

/// Format a u64 wire value back to a human-readable string.
/// Caller owns the returned slice (uses provided allocator).
pub fn formatU64(v: u64, tid: TypeId, allocator: std.mem.Allocator) ![]u8 {
    return switch (tid) {
        .int8 => std.fmt.allocPrint(allocator, "{d}", .{@as(i8, @bitCast(@as(u8, @truncate(v))))}),
        .uint8 => std.fmt.allocPrint(allocator, "{d}", .{@as(u8, @truncate(v))}),
        .int16 => std.fmt.allocPrint(allocator, "{d}", .{@as(i16, @bitCast(@as(u16, @truncate(v))))}),
        .uint16 => std.fmt.allocPrint(allocator, "{d}", .{@as(u16, @truncate(v))}),
        .int32 => std.fmt.allocPrint(allocator, "{d}", .{@as(i32, @bitCast(@as(u32, @truncate(v))))}),
        .uint32 => std.fmt.allocPrint(allocator, "{d}", .{@as(u32, @truncate(v))}),
        .int64 => std.fmt.allocPrint(allocator, "{d}", .{@as(i64, @bitCast(v))}),
        .uint64 => std.fmt.allocPrint(allocator, "{d}", .{v}),
        .float32 => std.fmt.allocPrint(allocator, "{d:.3}", .{@as(f32, @bitCast(@as(u32, @truncate(v))))}),
        .float64 => std.fmt.allocPrint(allocator, "{d:.3}", .{@as(f64, @bitCast(v))}),
        .bytes8 => std.fmt.allocPrint(allocator, "{x:0>16}", .{v}),
        .pointer => std.fmt.allocPrint(allocator, "0x{x}", .{v}),
    };
}
