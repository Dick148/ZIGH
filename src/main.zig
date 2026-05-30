// ZIGH — ZIGH Is Game Hacker
// CLI → Unix socket → Daemon

const std = @import("std");
const cli = @import("cli/parser.zig");
const types = @import("mem/types.zig");
const cheat = @import("cheat/mod.zig");
const socket = @import("ipc/socket.zig");
const daemon_mod = @import("engine/daemon.zig");
const injector = @import("agent/inject.zig");
const linux = std.os.linux;

var gpa_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
const alloc = gpa_instance.allocator();


const PID_FILE = "/tmp/zigh_daemon.pid";

pub fn main(init: std.process.Init) !void {
    defer gpa_instance.deinit();
    const args_slice = try init.minimal.args.toSlice(alloc);
    var args: [][]const u8 = undefined;
    args = alloc.alloc([]const u8, args_slice.len) catch { cli.printHelp(); return; };
    for (args_slice, 0..) |a, i| args[i] = a;

    if (args.len < 2) { cli.printHelp(); return; }
    const parsed = cli.parseArgs(alloc, args) catch |err| { std.debug.print("Error: {}\n", .{err}); return; };
    if (parsed == null) { std.debug.print("Unknown: {s}\n", .{args[1]}); cli.printHelp(); return; }
    var pa = parsed.?;
    defer pa.deinit();

    switch (pa.cmd) {
        .help => cli.printHelp(),
        .version => printVersion(),
        .daemon => try cmdDaemon(&pa),
        .inject => try cmdInject(&pa),
        else => try cmdViaSocket(&pa),
    }
}

fn printVersion() void {
    std.debug.print("ZIGH v0.2.0 — ZIGH Is Game Hacker\n", .{});
}

// ─── Daemon mode ────────────────────────────────────────────────────────

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

    var d = try daemon_mod.Daemon.init(alloc, pid, 0);
    defer d.deinit();

    // Write PID file
    var pid_buf: [32]u8 = undefined;
    const pid_content = try std.fmt.bufPrintZ(&pid_buf, "{d}\n", .{pid});
    const fd = linux.open(PID_FILE, linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (@as(isize, @bitCast(fd)) < 0) { std.debug.print("Cannot write PID file\n", .{}); return; }
    _ = linux.write(@intCast(fd), pid_content.ptr, pid_content.len);
    _ = linux.close(@intCast(fd));

    // Socket path
    var sock_buf: [64]u8 = undefined;
    const sock_path = try std.fmt.bufPrintZ(&sock_buf, "/tmp/zigh_{d}.sock", .{pid});

    const handler = daemon_mod.Handler{ .daemon = &d };
    var server = try socket.Server(daemon_mod.Handler).init(alloc, sock_path, handler);
    defer server.deinit();

    std.debug.print("[zigh] Daemon on {s} for PID {d}\n", .{ sock_path, pid });

    // Block serving
    server.serve() catch |err| {
        std.debug.print("[zigh] Daemon stopped: {}\n", .{err});
    };
}

fn cmdInject(pa: *const cli.ParsedArgs) !void {
    if (pa.positional.items.len < 2) {
        std.debug.print("Usage: zigh inject <pid> <agent.so>\n", .{});
        std.debug.print("  Injects the agent shared library into the target process.\n", .{});
        std.debug.print("  The agent.so is built alongside zigh (zig-out/lib/libzigh_agent.so)\n", .{});
        return;
    }
    const pid = std.fmt.parseUnsigned(u32, pa.positional.items[0], 10) catch {
        std.debug.print("Invalid PID: {s}\n", .{pa.positional.items[0]});
        return;
    };
    const so_path = pa.positional.items[1];
    var path_buf: [512]u8 = undefined;
    const path_z = std.fmt.bufPrintZ(&path_buf, "{s}", .{so_path}) catch {
        std.debug.print("Path too long\n", .{});
        return;
    };
    std.debug.print("Injecting {s} into PID {d}...\n", .{ path_z, pid });
    injector.inject(pid, path_z) catch |err| {
        std.debug.print("Injection failed: {}\n", .{err});
        return;
    };
    std.debug.print("Injection successful!\n", .{});
}

// ─── Socket client commands ──────────────────────────────────────────────

fn getPid() !u32 {
    const fd = linux.open(PID_FILE, linux.O{}, 0);
    if (@as(isize, @bitCast(fd)) < 0) return error.NoDaemon;
    defer _ = linux.close(@intCast(fd));
    var buf: [32]u8 = undefined;
    const n = linux.read(@intCast(fd), &buf, buf.len);
    if (n == 0) return error.NoDaemon;
    return std.fmt.parseUnsigned(u32, std.mem.trimEnd(u8, buf[0..n], "\n\r"), 10) catch error.NoDaemon;
}

fn connect() !socket.Client {
    const pid = try getPid();
    var buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&buf, "/tmp/zigh_{d}.sock", .{pid});
    return socket.Client.connect(path);
}

fn cmdViaSocket(pa: *const cli.ParsedArgs) !void {
    var client = connect() catch |err| {
        std.debug.print("Cannot connect to daemon: {}\n", .{err});
        return;
    };
    defer client.deinit();

    switch (pa.cmd) {
        .status => {
            const resp = try client.send(alloc, .req_status, "");
            defer alloc.free(resp);
            std.debug.print("{s}\n", .{resp});
        },
        .@"lock-add" => {
            if (pa.positional.items.len < 2) { std.debug.print("Usage: zigh lock-add <name> <value> [--type f32] [--addr 0x...] [--chain 0x10,0x20]\n", .{}); return; }
            const tid = pa.getOpt("type") orelse "u32";
            const addr = pa.getOpt("addr") orelse "0";
            const chain = pa.getOpt("chain") orelse "";
            const payload = try std.fmt.allocPrint(alloc, "{{\"name\":\"{s}\",\"value\":\"{s}\",\"type\":\"{s}\",\"address\":\"{s}\",\"chain\":\"{s}\"}}", .{ pa.positional.items[0], pa.positional.items[1], tid, addr, chain });
            defer alloc.free(payload);
            const resp = try client.send(alloc, .req_lock_add, payload);
            defer alloc.free(resp);
            std.debug.print("{s}\n", .{resp});
        },
        .@"lock-remove" => {
            if (pa.positional.items.len < 1) { std.debug.print("Usage: zigh lock-remove <name>\n", .{}); return; }
            const payload = try std.fmt.allocPrint(alloc, "{{\"name\":\"{s}\"}}", .{pa.positional.items[0]});
            defer alloc.free(payload);
            const resp = try client.send(alloc, .req_lock_remove, payload);
            defer alloc.free(resp);
            std.debug.print("{s}\n", .{resp});
        },
        .@"lock-list" => {
            const resp = try client.send(alloc, .req_lock_list, "");
            defer alloc.free(resp);
            std.debug.print("{s}\n", .{resp});
        },
        .write => {
            if (pa.positional.items.len < 2) { std.debug.print("Usage: zigh write <addr> <value>\n", .{}); return; }
            const payload = try std.fmt.allocPrint(alloc, "{{\"addr\":\"{s}\",\"value\":\"{s}\"}}", .{ pa.positional.items[0], pa.positional.items[1] });
            defer alloc.free(payload);
            const resp = try client.send(alloc, .req_write, payload);
            defer alloc.free(resp);
            std.debug.print("{s}\n", .{resp});
        },
        .read => {
            if (pa.positional.items.len < 1) { std.debug.print("Usage: zigh read <addr>\n", .{}); return; }
            const payload = try std.fmt.allocPrint(alloc, "{{\"addr\":\"{s}\"}}", .{pa.positional.items[0]});
            defer alloc.free(payload);
            const resp = try client.send(alloc, .req_read, payload);
            defer alloc.free(resp);
            std.debug.print("{s}\n", .{resp});
        },
        .@"cheat-load" => {
            if (pa.positional.items.len < 1) { std.debug.print("Usage: zigh cheat-load <file>\n", .{}); return; }
            var cf = cheat.loadFile(alloc, pa.positional.items[0]) catch |e| { std.debug.print("Load error: {}\n", .{e}); return; };
            std.debug.print("Loaded: {s} ({s}), {d} locks\n", .{ cf.game, cf.process, cf.locks.len });
            for (cf.locks) |l| std.debug.print("  {s}: {s} type={s}\n", .{ l.name, l.address, @tagName(l.type) });

            // Send to daemon immediately
            var json: std.ArrayList(u8) = .empty;
            try json.appendSlice(alloc, "[");
            for (cf.locks, 0..) |lock, i| {
                if (i > 0) try json.append(alloc, ',');
                var buf: [256]u8 = undefined;
                const entry = try std.fmt.bufPrint(&buf, "{{\"name\":\"{s}\",\"value\":\"{d}\",\"type\":\"{s}\",\"address\":\"{s}\"}}", .{ lock.name, lock.default, @tagName(lock.type), lock.address });
                try json.appendSlice(alloc, entry);
            }
            try json.appendSlice(alloc, "]");
            defer json.deinit(alloc);
            const resp = try client.send(alloc, .req_cheat_start, json.items);
            defer alloc.free(resp);
            std.debug.print("{s}\n", .{resp});
            cf.deinit(alloc);
        },
        .@"cheat-start" => {
            // Re-send if loaded_cheat set (same process only), or just show status
            const resp = try client.send(alloc, .req_status, "");
            defer alloc.free(resp);
            std.debug.print("{s}\n", .{resp});
        },
        .@"cheat-stop" => {
            const resp = try client.send(alloc, .req_cheat_stop, "");
            defer alloc.free(resp);
            std.debug.print("{s}\n", .{resp});
        },
        .call => {
            if (pa.positional.items.len < 1) { std.debug.print("Usage: zigh call <addr> [--args 1,2,3]\n", .{}); return; }
            const args = pa.getOpt("args") orelse "";
            const payload = try std.fmt.allocPrint(alloc, "{{\"addr\":\"{s}\",\"args\":\"{s}\"}}", .{ pa.positional.items[0], args });
            defer alloc.free(payload);
            const resp = try client.send(alloc, .req_call, payload);
            defer alloc.free(resp);
            std.debug.print("{s}\n", .{resp});
        },
        .inject => std.debug.print("inject: handled standalone\n", .{}),
        else => unreachable,
    }
}
