// ZIGH — ZIGH Is Game Hacker
// Entry point: CLI routing → daemon / one-shot / status

const std = @import("std");
const cli = @import("cli/parser.zig");
const types = @import("mem/types.zig");
const mem = @import("mem/mod.zig");
const daemon_mod = @import("engine/daemon.zig");

var gpa_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
const alloc = gpa_instance.allocator();

pub fn main(init: std.process.Init) !void {
    defer gpa_instance.deinit();
    const args_slice = try init.minimal.args.toSlice(alloc);
    // Convert [:0]const u8 → []const u8 for the parser
    var args: [][]const u8 = undefined;
    args = alloc.alloc([]const u8, args_slice.len) catch {
        cli.printHelp();
        return;
    };
    for (args_slice, 0..) |a, i| args[i] = a;

    if (args.len < 2) {
        cli.printHelp();
        return;
    }

    const parsed = cli.parseArgs(alloc, args) catch |err| {
        std.debug.print("Error parsing arguments: {}\n", .{err});
        return;
    };
    if (parsed == null) {
        std.debug.print("Unknown command: {s}\n", .{args[1]});
        cli.printHelp();
        return;
    }
    var pa = parsed.?;
    defer pa.deinit();

    switch (pa.cmd) {
        .help => cli.printHelp(),
        .version => printVersion(),
        .daemon => try cmdDaemon(&pa),
        .status => try cmdStatus(&pa),
        .@"lock-add" => try cmdLockAdd(&pa),
        .@"lock-remove" => try cmdLockRemove(&pa),
        .@"lock-list" => try cmdLockList(&pa),
        .write => try cmdWrite(&pa),
        .read => try cmdRead(&pa),
        .@"cheat-load" => try cmdCheatLoad(&pa),
        .@"cheat-start" => try cmdCheatStart(&pa),
        .@"cheat-stop" => try cmdCheatStop(&pa),
        .inject => std.debug.print("inject: not yet implemented\n", .{}),
        .call => std.debug.print("call: not yet implemented\n", .{}),
    }
}

fn printVersion() void {
    std.debug.print("ZIGH v0.1.0 — ZIGH Is Game Hacker\nBuilt with Zig {s}\nTarget: Linux x86_64\n", .{"0.16.0"});
}

// ─── Command implementations ────────────────────────────────────────────

var active_daemon: ?*daemon_mod.Daemon = null;

fn getDaemon() !*daemon_mod.Daemon {
    if (active_daemon) |d| return d;
    std.debug.print("No active daemon. Run 'zigh daemon --pid <id>' first.\n", .{});
    return error.NoDaemon;
}

fn cmdDaemon(pa: *const cli.ParsedArgs) !void {
    const pid_str = pa.getOpt("pid") orelse {
        if (pa.positional.items.len > 0) {
            _ = pa.positional.items[0];
        }
        std.debug.print("Usage: zigh daemon --pid <pid>\n", .{});
        return;
    };
    const pid = std.fmt.parseUnsigned(u32, pid_str, 10) catch {
        std.debug.print("Invalid PID: {s}\n", .{pid_str});
        return;
    };

    const daemon_ptr = try alloc.create(daemon_mod.Daemon);
    daemon_ptr.* = try daemon_mod.Daemon.init(alloc, pid, 0); // engine=0 (generic)
    active_daemon = daemon_ptr;

    std.debug.print("[zigh] Daemon attached to PID {d}\n", .{pid});
    std.debug.print("[zigh] Shared memory: /dev/shm/zigh_{d}_0\n", .{pid});
    std.debug.print("[zigh] Ready for commands.\n", .{});
}

fn cmdStatus(pa: *const cli.ParsedArgs) !void {
    _ = pa;
    const d = try getDaemon();
    var results: [64]daemon_mod.Daemon.ReadResult = undefined;
    const count = d.readBack(&results);
    std.debug.print("┌──── ZIGH Status ──────────────────────\n", .{});
    std.debug.print("│ PID:  {d}\n", .{d.pid});
    std.debug.print("│ Engine: {d} (generic)\n", .{d.engine});
    std.debug.print("│ Active locks: {d}\n", .{count});
    if (count > 0) {
        std.debug.print("│\n", .{});
        for (results[0..count]) |r| {
            if (r.hasError) {
                std.debug.print("│  slot{d}: [ERROR]\n", .{r.slotId});
            } else {
                std.debug.print("│  slot{d}: 0x{x:0>16}\n", .{ r.slotId, r.value });
            }
        }
    }
    std.debug.print("└────────────────────────────────────────\n", .{});
}

fn cmdLockAdd(pa: *const cli.ParsedArgs) !void {
    if (pa.positional.items.len < 2) {
        std.debug.print("Usage: zigh lock-add <name> <value> [--type f32] [--addr 0x...] [--chain 0x10,0x20]\n", .{});
        return;
    }
    std.debug.print("[lock-add] '{s}' = {s} — daemon required, not yet wired\n", .{ pa.positional.items[0], pa.positional.items[1] });
}

fn cmdLockRemove(pa: *const cli.ParsedArgs) !void {
    if (pa.positional.items.len < 1) {
        std.debug.print("Usage: zigh lock-remove <name>\n", .{});
        return;
    }
    std.debug.print("[lock-remove] '{s}' — daemon required, not yet wired\n", .{pa.positional.items[0]});
}

fn cmdLockList(pa: *const cli.ParsedArgs) !void {
    _ = pa;
    const d = try getDaemon();
    var results: [64]daemon_mod.Daemon.ReadResult = undefined;
    const count = d.readBack(&results);
    if (count == 0) {
        std.debug.print("No active locks.\n", .{});
        return;
    }
    for (results[0..count]) |r| {
        std.debug.print("  lock slot{d}: 0x{x:0>16} {s}\n", .{ r.slotId, r.value, if (r.hasError) "[ERR]" else "" });
    }
}

fn cmdWrite(pa: *const cli.ParsedArgs) !void {
    if (pa.positional.items.len < 2) {
        std.debug.print("Usage: zigh write <addr> <value> [--type f32]\n", .{});
        return;
    }
    const addr_str = pa.positional.items[0];
    const val_str = pa.positional.items[1];
    const tid_str = pa.getOpt("type") orelse "u32";

    const addr = parseHexOrDec(usize, addr_str) catch {
        std.debug.print("Invalid address: {s}\n", .{addr_str});
        return;
    };
    const tid = types.TypeId.fromString(tid_str) orelse {
        std.debug.print("Unknown type: {s}\n", .{tid_str});
        return;
    };

    const d = try getDaemon();
    const value: u64 = switch (tid) {
        .float32, .float64 => {
            const f = std.fmt.parseFloat(f64, val_str) catch {
                std.debug.print("Invalid float: {s}\n", .{val_str});
                return;
            };
            @as(u64, @bitCast(@as(f64, f)));
        },
        else => parseHexOrDec(u64, val_str) catch {
            std.debug.print("Invalid value: {s}\n", .{val_str});
            return;
        },
    };

    try d.writeOnce(addr, value, tid);
    std.debug.print("Wrote 0x{x} → 0x{x} ({s})\n", .{ value, addr, @tagName(tid) });
}

fn cmdRead(pa: *const cli.ParsedArgs) !void {
    if (pa.positional.items.len < 1) {
        std.debug.print("Usage: zigh read <addr> [--type f32]\n", .{});
        return;
    }
    const addr_str = pa.positional.items[0];
    const tid_str = pa.getOpt("type") orelse "u32";

    const addr = parseHexOrDec(usize, addr_str) catch {
        std.debug.print("Invalid address: {s}\n", .{addr_str});
        return;
    };
    const tid = types.TypeId.fromString(tid_str) orelse {
        std.debug.print("Unknown type: {s}\n", .{tid_str});
        return;
    };

    const d = try getDaemon();
    const value = try d.readMem(addr, tid);
    const formatted = try types.formatU64(value, tid, alloc);
    defer alloc.free(formatted);
    std.debug.print("0x{x}: {s}\n", .{ addr, formatted });
}

fn cmdCheatLoad(pa: *const cli.ParsedArgs) !void {
    if (pa.positional.items.len < 1) {
        std.debug.print("Usage: zigh cheat-load <file.yaml>\n", .{});
        return;
    }
    std.debug.print("[cheat-load] '{s}' — YAML parser not yet implemented\n", .{pa.positional.items[0]});
}

fn cmdCheatStart(pa: *const cli.ParsedArgs) !void {
    _ = pa;
    std.debug.print("[cheat-start] Not yet implemented.\n", .{});
}

fn cmdCheatStop(pa: *const cli.ParsedArgs) !void {
    _ = pa;
    std.debug.print("[cheat-stop] Not yet implemented.\n", .{});
}

// ─── Utilities ──────────────────────────────────────────────────────────

fn parseHexOrDec(comptime T: type, s: []const u8) !T {
    if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) {
        return std.fmt.parseUnsigned(T, s[2..], 16);
    }
    return std.fmt.parseUnsigned(T, s, 10);
}
