// ZIGH — Scanner value decoding & comparison
// Single source of truth for turning raw bytes into wire u64 values and for
// evaluating scan options. Type-aware: signed integers are sign-extended and
// floats are compared numerically.

const std = @import("std");
const mem_types = @import("../mem/types.zig");
const types = @import("types.zig");

/// Decode a typed value from a byte slice into the wire u64 representation.
/// - signed int8/16/32 are sign-extended to 64 bits
/// - unsigned ints are zero-extended
/// - floats keep their IEEE-754 bit pattern (low 32 bits for f32)
pub fn decode(buf: []const u8, tid: mem_types.TypeId) u64 {
    return switch (tid) {
        .uint8 => @as(u64, buf[0]),
        .int8 => signExtend(@as(i64, @as(i8, @bitCast(buf[0])))),
        .uint16 => @as(u64, read(u16, buf)),
        .int16 => signExtend(@as(i64, @as(i16, @bitCast(read(u16, buf))))),
        .uint32, .float32 => @as(u64, read(u32, buf)),
        .int32 => signExtend(@as(i64, @as(i32, @bitCast(read(u32, buf))))),
        .int64 => read(u64, buf),
        .uint64, .float64, .bytes8, .pointer => read(u64, buf),
    };
}

fn read(comptime T: type, buf: []const u8) T {
    return std.mem.readInt(T, buf[0..@sizeOf(T)], .little);
}

fn signExtend(v: i64) u64 {
    return @bitCast(v);
}

pub fn isSigned(tid: mem_types.TypeId) bool {
    return switch (tid) {
        .int8, .int16, .int32, .int64 => true,
        else => false,
    };
}

pub fn isFloat(tid: mem_types.TypeId) bool {
    return tid == .float32 or tid == .float64;
}

/// First-scan match.
pub fn matchesFirst(
    opt: types.ScanOption,
    cur: u64,
    tid: mem_types.TypeId,
    v1: u64,
    v2: u64,
    epsilon: f64,
) bool {
    return switch (opt) {
        .exact => eql(cur, v1, tid, epsilon),
        .bigger_than => greater(cur, v1, tid),
        .smaller_than => less(cur, v1, tid),
        .between => greaterEq(cur, v1, tid, epsilon) and lessEq(cur, v2, tid, epsilon),
        .unknown => true,
        // Next-scan-only options never match during a first scan.
        else => false,
    };
}

/// Next-scan match against the previous value.
pub fn matchesNext(
    opt: types.ScanOption,
    cur: u64,
    old: u64,
    tid: mem_types.TypeId,
    v1: u64,
    v2: u64,
    epsilon: f64,
) bool {
    return switch (opt) {
        .exact => eql(cur, v1, tid, epsilon),
        .changed => cur != old,
        .unchanged => cur == old,
        .increased => greater(cur, old, tid),
        .decreased => less(cur, old, tid),
        .increased_by => deltaEq(cur, old, v1, tid, epsilon),
        .decreased_by => deltaEq(old, cur, v1, tid, epsilon),
        .bigger_than => greater(cur, v1, tid),
        .smaller_than => less(cur, v1, tid),
        .between => greaterEq(cur, v1, tid, epsilon) and lessEq(cur, v2, tid, epsilon),
        .unknown => true,
    };
}

fn eql(a: u64, b: u64, tid: mem_types.TypeId, epsilon: f64) bool {
    if (isFloat(tid)) {
        if (epsilon > 0) {
            const x = asF64(a, tid);
            const y = asF64(b, tid);
            return @abs(x - y) <= epsilon;
        }
        // Exact float scans compare the bit pattern, like CE's default.
        return a == b;
    }
    return a == b;
}

fn greater(a: u64, b: u64, tid: mem_types.TypeId) bool {
    if (isFloat(tid)) return asF64(a, tid) > asF64(b, tid);
    if (isSigned(tid)) return @as(i64, @bitCast(a)) > @as(i64, @bitCast(b));
    return a > b;
}

fn less(a: u64, b: u64, tid: mem_types.TypeId) bool {
    if (isFloat(tid)) return asF64(a, tid) < asF64(b, tid);
    if (isSigned(tid)) return @as(i64, @bitCast(a)) < @as(i64, @bitCast(b));
    return a < b;
}

fn greaterEq(a: u64, b: u64, tid: mem_types.TypeId, epsilon: f64) bool {
    return greater(a, b, tid) or eql(a, b, tid, epsilon);
}

fn lessEq(a: u64, b: u64, tid: mem_types.TypeId, epsilon: f64) bool {
    return less(a, b, tid) or eql(a, b, tid, epsilon);
}

/// `cur - old == delta` in the type's natural semantics (wrapping for ints).
fn deltaEq(cur: u64, old: u64, delta: u64, tid: mem_types.TypeId, epsilon: f64) bool {
    if (isFloat(tid)) {
        const d = asF64(cur, tid) - asF64(old, tid);
        const want = asF64(delta, tid);
        if (epsilon > 0) return @abs(d - want) <= epsilon;
        return d == want;
    }
    if (isSigned(tid)) {
        const d = @as(i64, @bitCast(cur)) -% @as(i64, @bitCast(old));
        return d == @as(i64, @bitCast(delta));
    }
    return (cur -% old) == delta;
}

fn asF64(v: u64, tid: mem_types.TypeId) f64 {
    return switch (tid) {
        .float32 => @as(f32, @bitCast(@as(u32, @truncate(v)))),
        .float64 => @as(f64, @bitCast(v)),
        else => @floatFromInt(v),
    };
}

// ─── Tests ───────────────────────────────────────────────────────────────

test "decode sign-extends signed integers" {
    const t = std.testing;
    try t.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), decode(&[_]u8{0xFF}, .int8));
    try t.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFE), decode(&[_]u8{0xFE}, .int8));
    try t.expectEqual(@as(u64, 255), decode(&[_]u8{0xFF}, .uint8));
    try t.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFD), decode(&[_]u8{ 0xFD, 0xFF }, .int16));
    try t.expectEqual(@as(u64, 65533), decode(&[_]u8{ 0xFD, 0xFF }, .uint16));
    try t.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), decode(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }, .int32));
    try t.expectEqual(@as(u64, 0xFFFF_FFFF), decode(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }, .uint32));
    try t.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), decode(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, .int64));
}

test "signed exact match with negative value" {
    const t = std.testing;
    const neg_one = decode(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }, .int32);
    const v1: u64 = @bitCast(@as(i64, -1));
    try t.expect(matchesFirst(.exact, neg_one, .int32, v1, 0, 0));
}

test "signed increased/decreased" {
    const t = std.testing;
    const neg_one = decode(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }, .int32);
    const zero = decode(&[_]u8{ 0, 0, 0, 0 }, .int32);
    // -1 -> 0 is an increase; the old zero-extended implementation got this wrong.
    try t.expect(matchesNext(.increased, zero, neg_one, .int32, 0, 0, 0));
    try t.expect(!matchesNext(.decreased, zero, neg_one, .int32, 0, 0, 0));
    try t.expect(matchesNext(.increased_by, zero, neg_one, .int32, 1, 0, 0));
    try t.expect(matchesNext(.decreased_by, neg_one, zero, .int32, 1, 0, 0));
}

test "unsigned comparisons stay unsigned" {
    const t = std.testing;
    const big = decode(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, .uint64);
    try t.expect(matchesFirst(.bigger_than, big, .uint64, 1, 0, 0));
    try t.expect(!matchesFirst(.smaller_than, big, .uint64, 1, 0, 0));
}

test "float ordering is numeric, not bitwise" {
    const t = std.testing;
    const neg: f32 = -2.0;
    const pos: f32 = 1.0;
    const neg_bits: u64 = @as(u32, @bitCast(neg));
    const pos_bits: u64 = @as(u32, @bitCast(pos));
    // Bitwise i64 compare would say neg_bits > pos_bits; numeric says -2 < 1.
    try t.expect(matchesFirst(.smaller_than, neg_bits, .float32, pos_bits, 0, 0));
    try t.expect(matchesFirst(.bigger_than, pos_bits, .float32, neg_bits, 0, 0));
    try t.expect(matchesFirst(.between, neg_bits, .float32, neg_bits, pos_bits, 0));
}

test "between uses both bounds" {
    const t = std.testing;
    const five: u64 = 5;
    try t.expect(matchesFirst(.between, five, .uint32, 1, 10, 0));
    try t.expect(!matchesFirst(.between, five, .uint32, 6, 10, 0));
    try t.expect(matchesNext(.between, five, five, .uint32, 1, 10, 0));
}

test "float epsilon" {
    const t = std.testing;
    const a: f32 = 1.0;
    const b: f32 = 1.0001;
    const ab: u64 = @as(u32, @bitCast(a));
    const bb: u64 = @as(u32, @bitCast(b));
    try t.expect(!matchesFirst(.exact, bb, .float32, ab, 0, 0));
    try t.expect(matchesFirst(.exact, bb, .float32, ab, 0, 0.001));
}
