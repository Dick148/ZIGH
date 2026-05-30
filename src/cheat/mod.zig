// ZIGH — Simple line-by-line cheat file parser
// Format: YAML subset — key: value, lists with -, inline arrays [a,b]

const std = @import("std");
const types = @import("../mem/types.zig");

pub const LockDef = struct {
    name: []const u8 = "",
    address: []const u8 = "",
    chain: []u32 = &.{},
    type: types.TypeId = .uint32,
    default: u64 = 0,
};

pub const RemoteCallDef = struct {
    name: []const u8 = "",
    address: []const u8 = "",
    args: []types.TypeId = &.{},
};

pub const CheatFile = struct {
    game: []const u8 = "",
    engine: []const u8 = "generic",
    process: []const u8 = "",
    locks: []LockDef = &.{},
    remote_calls: []RemoteCallDef = &.{},

    pub fn deinit(self: *CheatFile, a: std.mem.Allocator) void {
        if (self.game.len > 0) a.free(self.game);
        if (self.engine.len > 0) a.free(self.engine);
        if (self.process.len > 0) a.free(self.process);
        for (self.locks) |l| { a.free(l.name); a.free(l.address); if (l.chain.len > 0) a.free(l.chain); }
        if (self.locks.len > 0) a.free(self.locks);
        for (self.remote_calls) |r| { a.free(r.name); a.free(r.address); if (r.args.len > 0) a.free(r.args); }
        if (self.remote_calls.len > 0) a.free(self.remote_calls);
    }
};

pub fn loadFile(allocator: std.mem.Allocator, path: []const u8) !CheatFile {
    var path_buf: [4096]u8 = undefined;
    const path_z = std.fmt.bufPrintZ(&path_buf, "{s}", .{path}) catch return error.ReadError;
    const raw = std.os.linux.open(path_z, std.os.linux.O{}, 0);
    if (@as(isize, @bitCast(raw)) < 0) return error.FileNotFound;
    const content = readAlloc(allocator, @intCast(raw), 1 << 20) catch |e| { _ = std.c.close(@intCast(raw)); return e; };
    _ = std.c.close(@intCast(raw));
    defer allocator.free(content);
    return parse(allocator, content);
}

fn readAlloc(a: std.mem.Allocator, fd: std.os.linux.fd_t, max: usize) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = std.os.linux.read(fd, &buf, buf.len);
        if (n == 0) break;
        if (list.items.len + n > max) return error.ReadError;
        try list.appendSlice(a, buf[0..n]);
    }
    return try list.toOwnedSlice(a);
}

/// Full top-down parse — caller owns returned CheatFile; must call deinit()
fn parse(a: std.mem.Allocator, src: []const u8) !CheatFile {
    var cf: CheatFile = .{};
    var locks: std.ArrayList(LockDef) = .empty;
    var calls: std.ArrayList(RemoteCallDef) = .empty;
    var in_section: enum { none, locks, calls } = .none;
    var current_lock: ?LockDef = null;
    var current_call: ?RemoteCallDef = null;
    var prev_indent: u32 = 0;

    var lines = std.mem.splitScalar(u8, src, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimStart(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        const indent: u32 = @intCast(countIndent(raw_line));
        // Section transitions: if indent drops, commit current item
        if (indent <= prev_indent and indent <= 2) {
            if (in_section == .locks and current_lock != null) {
                try locks.append(a, current_lock.?);
                current_lock = null;
            }
            if (in_section == .calls and current_call != null) {
                try calls.append(a, current_call.?);
                current_call = null;
            }
        }
        prev_indent = indent;

        if (std.mem.eql(u8, line, "locks:")) {
            in_section = .locks; continue;
        }
        if (std.mem.eql(u8, line, "remote_calls:")) {
            in_section = .calls; continue;
        }

        if (in_section == .none) {
            // Top-level key: value
            if (parseKV(line)) |kv| {
                if (std.mem.eql(u8, kv.key, "game")) { cf.game = try a.dupe(u8, kv.value); }
                if (std.mem.eql(u8, kv.key, "engine")) { cf.engine = try a.dupe(u8, kv.value); }
                if (std.mem.eql(u8, kv.key, "process")) { cf.process = try a.dupe(u8, kv.value); }
            }
            continue;
        }

        if (in_section == .locks) {
            if (std.mem.startsWith(u8, line, "- ")) {
                // Commit previous
                if (current_lock) |l| try locks.append(a, l);
                current_lock = .{};
                // Parse inline key:value after "- "
                if (parseKV(line[2..])) |kv| {
                    fillLock(a, &current_lock.?, kv.key, kv.value);
                }
            } else if (parseKV(line)) |kv| {
                if (current_lock == null) current_lock = .{};
                fillLock(a, &current_lock.?, kv.key, kv.value);
            }
            continue;
        }

        if (in_section == .calls) {
            if (std.mem.startsWith(u8, line, "- ")) {
                if (current_call) |c| try calls.append(a, c);
                current_call = .{};
                if (parseKV(line[2..])) |kv| {
                    fillCall(a, &current_call.?, kv.key, kv.value);
                }
            } else if (parseKV(line)) |kv| {
                if (current_call == null) current_call = .{};
                fillCall(a, &current_call.?, kv.key, kv.value);
            }
        }
    }
    // Commit final items
    if (current_lock) |l| try locks.append(a, l);
    if (current_call) |c| try calls.append(a, c);

    if (locks.items.len > 0) cf.locks = try locks.toOwnedSlice(a);
    if (calls.items.len > 0) cf.remote_calls = try calls.toOwnedSlice(a);
    return cf;
}

const KV = struct { key: []const u8, value: []const u8 };

fn parseKV(line: []const u8) ?KV {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    const key = std.mem.trimEnd(u8, line[0..colon], " \t");
    if (key.len == 0) return null;
    var value = std.mem.trimStart(u8, line[colon + 1 ..], " \t");
    // Strip trailing comment
    if (std.mem.indexOfScalar(u8, value, '#')) |ci| {
        value = std.mem.trimEnd(u8, value[0..ci], " \t");
    }
    // Unquote
    if (value.len >= 2 and (value[0] == '"' or value[0] == '\'')) {
        value = value[1 .. value.len - 1];
    }
    return .{ .key = key, .value = value };
}

fn countIndent(line: []const u8) usize {
    var n: usize = 0;
    for (line) |c| {
        if (c == ' ') n += 1 else if (c == '\t') n += 2 else break;
    }
    return n;
}

fn fillLock(a: std.mem.Allocator, lock: *LockDef, key: []const u8, value: []const u8) void {
    if (std.mem.eql(u8, key, "name")) lock.name = a.dupe(u8, value) catch value;
    if (std.mem.eql(u8, key, "address")) lock.address = a.dupe(u8, value) catch value;
    if (std.mem.eql(u8, key, "type")) { if (types.TypeId.fromString(value)) |t| lock.type = t; }
    if (std.mem.eql(u8, key, "default")) lock.default = parseHexOrDec(u64, value) catch 0;
}

fn fillCall(a: std.mem.Allocator, call: *RemoteCallDef, key: []const u8, value: []const u8) void {
    if (std.mem.eql(u8, key, "name")) call.name = value;
    if (std.mem.eql(u8, key, "address")) call.address = value;
    if (std.mem.eql(u8, key, "args")) {
        // Parse [type1, type2] format
        var list: std.ArrayList(types.TypeId) = .empty;
        const s = std.mem.trim(u8, value, " []");
        var it = std.mem.splitScalar(u8, s, ',');
        while (it.next()) |part| {
            const t = std.mem.trim(u8, part, " \t");
            if (types.TypeId.fromString(t)) |tid| list.append(a, tid) catch {};
        }
        if (list.items.len > 0) call.args = list.toOwnedSlice(a) catch &.{};
    }
}

fn parseHexOrDec(comptime T: type, s: []const u8) !T {
    const t = std.mem.trim(u8, s, " \t");
    if (std.mem.startsWith(u8, t, "0x") or std.mem.startsWith(u8, t, "0X")) return std.fmt.parseUnsigned(T, t[2..], 16);
    return std.fmt.parseUnsigned(T, t, 10);
}
