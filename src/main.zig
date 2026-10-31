// ZIGH — ZIGH Is Game Hacker
// CLI → Unix socket → Daemon

const std = @import("std");
const cli = @import("cli/parser.zig");
const types = @import("mem/types.zig");
const mem_types = @import("mem/types.zig");
const cheat = @import("cheat/mod.zig");
const socket = @import("ipc/socket.zig");
const daemon_mod = @import("engine/daemon.zig");
const injector = @import("agent/inject.zig");
const linject = @import("injector/linject.zig");
const scanner = @import("scanner/mod.zig");
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
        .scan => try cmdScan(&pa),
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
        std.debug.print("Usage: zigh daemon --pid <pid> [--inject] [--so <agent.so>]\n", .{});
        return;
    };
    const pid = std.fmt.parseUnsigned(u32, pid_str, 10) catch {
        std.debug.print("Invalid PID: {s}\n", .{pid_str});
        return;
    };

    var d = try daemon_mod.Daemon.init(alloc, pid, 0);
    defer d.deinit();
    d.startChainWorker();

    // Write PID file
    var pid_buf: [32]u8 = undefined;
    const pid_content = try std.fmt.bufPrintZ(&pid_buf, "{d}\n", .{pid});
    const fd = linux.open(PID_FILE, linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (@as(isize, @bitCast(fd)) < 0) { std.debug.print("Cannot write PID file\n", .{}); return; }
    _ = linux.write(@intCast(fd), pid_content.ptr, pid_content.len);
    _ = linux.close(@intCast(fd));

    // Auto-inject agent if --inject is specified
    const do_inject = pa.opts.contains("inject");
    if (do_inject) {
        const so_path = pa.getOpt("so") orelse "./zig-out/lib/libzigh_agent.so";
        std.debug.print("[zigh] Injecting agent: {s}...\n", .{so_path});
        var path_buf: [512]u8 = undefined;
        const path_z = try std.fmt.bufPrintZ(&path_buf, "{s}", .{so_path});
        injector.inject(alloc, pid, path_z, null) catch |err| {
            std.debug.print("[zigh] Inject failed: {}\n", .{err});
            return;
        };
        std.debug.print("[zigh] Waiting for agent to start...\n", .{});
        d.waitForAgent(5000) catch |err| {
            std.debug.print("[zigh] Agent not ready: {}\n", .{err});
            return;
        };
        std.debug.print("[zigh] Agent is running!\n", .{});
    }

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
        std.debug.print("Usage: zigh inject <pid> <agent.so> [--hook <addr>] [--method linject]\n", .{});
        std.debug.print("  Methods:\n", .{});
        std.debug.print("    ptrace (default) — ptrace-based dlopen injection\n", .{});
        std.debug.print("    linject         — function-hijack injection (no ptrace, works alongside GDB)\n", .{});
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

    const method = pa.getOpt("method") orelse "ptrace";

    if (std.mem.eql(u8, method, "linject")) {
        std.debug.print("[linject] Injecting {s} into PID {d} (function-hijack method)...\n", .{ path_z, pid });
        // Default alloc_len: 64KB for small agents, override with --alloc-len <bytes>
        const alloc_len_str = pa.getOpt("alloc-len") orelse "65536";
        const alloc_len = std.fmt.parseUnsigned(u32, alloc_len_str, 10) catch @as(u32, 65536);
        linject.injectSo(alloc, pid, path_z, alloc_len) catch |err| {
            std.debug.print("[linject] Injection failed: {}\n", .{err});
            return;
        };
        std.debug.print("[linject] Injection successful!\n", .{});
        return;
    }

    // Default: ptrace method
    std.debug.print("Injecting {s} into PID {d}...\n", .{ path_z, pid });
    const hook_str = pa.getOpt("hook");
    const hook_addr: ?usize = if (hook_str) |hs| blk: {
        break :blk std.fmt.parseUnsigned(usize, hs, 0) catch null;
    } else null;
    injector.inject(alloc, pid, path_z, hook_addr) catch |err| {
        std.debug.print("Injection failed: {}\n", .{err});
        return;
    };
    std.debug.print("Injection successful!\n", .{});
}

// ─── Scan command ────────────────────────────────────────────────────────

fn cmdScan(pa: *const cli.ParsedArgs) !void {
    const pid_str = pa.getOpt("pid") orelse {
        // Try to get PID from running daemon
        const pid = getPid() catch {
            std.debug.print("Usage: zigh scan --pid <pid> --value <n> [--type <t>] [--option <opt>]\n", .{});
            std.debug.print("  Options: exact, unknown, bigger_than, smaller_than, between\n", .{});
            std.debug.print("  Next scan: --next --option changed|unchanged|increased|decreased\n", .{});
            return;
        };
        return runScan(pid, pa);
    };

    const pid = std.fmt.parseUnsigned(u32, pid_str, 10) catch {
        std.debug.print("Invalid PID: {s}\n", .{pid_str});
        return;
    };
    try runScan(pid, pa);
}

fn runScan(pid: u32, pa: *const cli.ParsedArgs) !void {
    const is_next = pa.opts.contains("next");
    const opt_str = pa.getOpt("option") orelse if (is_next) "changed" else "exact";

    const opt = scanner.types.ScanOption.parse(opt_str) orelse {
        std.debug.print("Unknown scan option: {s}\n", .{opt_str});
        return;
    };

    const type_str = pa.getOpt("type") orelse "u32";
    const value_type = mem_types.TypeId.fromString(type_str) orelse {
        std.debug.print("Unknown type: {s}\n", .{type_str});
        return;
    };

    const max_mem_str = pa.getOpt("max-memory");
    const max_mem: u32 = if (max_mem_str) |s| std.fmt.parseUnsigned(u32, s, 10) catch 256 else 256;

    const value1: u64 = blk: {
        if (pa.getOpt("value")) |v| {
            break :blk parseScanValue(v, value_type) catch {
                std.debug.print("Invalid value: {s}\n", .{v});
                return;
            };
        }
        break :blk 0;
    };

    const value2: u64 = blk: {
        if (pa.getOpt("value2")) |v| {
            break :blk parseScanValue(v, value_type) catch {
                std.debug.print("Invalid value2: {s}\n", .{v});
                return;
            };
        }
        break :blk 0;
    };

    const epsilon: f64 = blk: {
        if (pa.getOpt("epsilon")) |v| {
            break :blk std.fmt.parseFloat(f64, v) catch {
                std.debug.print("Invalid epsilon: {s}\n", .{v});
                return;
            };
        }
        break :blk 0;
    };

    if (!is_next and opt.isNextOnly()) {
        std.debug.print("Option '{s}' can only be used with --next\n", .{opt_str});
        return;
    }
    if (is_next and opt == .unknown) {
        std.debug.print("Option 'unknown' is only valid for a first scan\n", .{});
        return;
    }

    var session = try scanner.ScanSession.init(alloc, pid);
    defer session.deinit();
    session.cfg.epsilon = epsilon;
    session.cfg.writable_only = !pa.opts.contains("all");

    // Check if a first scan was previously done (temp files exist)
    var scan0_buf: [128]u8 = undefined;
    const scan0_path = std.fmt.bufPrintZ(&scan0_buf, "/tmp/zigh_scan_{d}/scan_0.tmp", .{pid}) catch {
        session.first_done = false;
        return runScanImpl(pid, pa, &session, opt, value_type, value1, value2, is_next, max_mem) catch {};
    };

    const raw0 = linux.open(scan0_path, linux.O{}, 0);
    if (@as(isize, @bitCast(raw0)) < 0) {
        session.first_done = false;
    } else {
        _ = std.c.close(@intCast(raw0));
        session.first_done = true;
    }

    try runScanImpl(pid, pa, &session, opt, value_type, value1, value2, is_next, max_mem);
}

fn runScanImpl(pid: u32, pa: *const cli.ParsedArgs, session: *scanner.ScanSession, opt: scanner.types.ScanOption, value_type: mem_types.TypeId, value1: u64, value2: u64, is_next: bool, max_mem: u32) !void {
    _ = pa;
    session.cfg.max_memory_mb = max_mem;

    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    if (is_next) {
        if (!session.first_done) {
            std.debug.print("No first scan found. Run a first scan first.\n", .{});
            return;
        }
        std.debug.print("Next scan: {s}...\n", .{@tagName(opt)});
        const results = try session.nextScan(arena, opt, value1, value2);
        std.debug.print("Found {d} results.\n", .{results.len});
        const show = @min(results.len, 100);
        for (results[0..show]) |r| {
            const val_str = mem_types.formatU64(r.value, value_type, arena) catch "?";
            std.debug.print("  0x{x}: {s}\n", .{ r.address, val_str });
        }
        if (results.len > 100) {
            std.debug.print("  ... and {d} more\n", .{results.len - 100});
        }
    } else {
        std.debug.print("First scan: {s}...\n", .{@tagName(opt)});
        const results = try session.firstScan(arena, opt, value_type, value1, value2);
        if (session.used_snapshot) {
            std.debug.print("Snapshot saved: {d} bytes scanned.\n", .{session.last_scanned});
            std.debug.print("Run a next scan to narrow the results, e.g.:\n", .{});
            std.debug.print("  zigh scan --pid {d} --next --option changed\n", .{pid});
            return;
        }
        std.debug.print("Found {d} results.\n", .{results.len});
        const show = @min(results.len, 100);
        for (results[0..show]) |r| {
            const val_str = mem_types.formatU64(r.value, value_type, arena) catch "?";
            std.debug.print("  0x{x}: {s}\n", .{ r.address, val_str });
        }
        if (results.len > 100) {
            std.debug.print("  ... and {d} more\n", .{results.len - 100});
        }
    }
}

fn parseScanValue(s: []const u8, tid: mem_types.TypeId) !u64 {
    return switch (tid) {
        .float32 => blk: {
            const f: f32 = try std.fmt.parseFloat(f32, s);
            break :blk @as(u64, @as(u32, @bitCast(f)));
        },
        .float64 => @as(u64, @bitCast(try std.fmt.parseFloat(f64, s))),
        .int8, .int16, .int32, .int64 => @bitCast(try std.fmt.parseInt(i64, s, 0)),
        else => try std.fmt.parseUnsigned(u64, s, 0),
    };
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
        .@"chain-lock" => {
            if (pa.positional.items.len < 2) { std.debug.print("Usage: zigh chain-lock <name> <val> --addr <rva> --chain <offs> [--module <name>] [--interval <ms>]\n", .{}); return; }
            const ctid = pa.getOpt("type") orelse "u32";
            const caddr = pa.getOpt("addr") orelse "0";
            const cchain = pa.getOpt("chain") orelse "";
            const cbase = pa.getOpt("base") orelse "0";
            const cmodule = pa.getOpt("module") orelse "";
            const cinterval = pa.getOpt("interval") orelse "300";
            const cpayload = try std.fmt.allocPrint(alloc, "{{\"name\":\"{s}\",\"value\":\"{s}\",\"type\":\"{s}\",\"address\":\"{s}\",\"chain\":\"{s}\",\"base\":\"{s}\",\"module\":\"{s}\",\"interval\":\"{s}\"}}", .{ pa.positional.items[0], pa.positional.items[1], ctid, caddr, cchain, cbase, cmodule, cinterval });
            defer alloc.free(cpayload);
            const cresp = try client.send(alloc, .req_chain_lock, cpayload);
            defer alloc.free(cresp);
            std.debug.print("{s}\n", .{cresp});
        },
        .@"chain-unlock" => {
            if (pa.positional.items.len < 1) { std.debug.print("Usage: zigh chain-unlock <name>\n", .{}); return; }
            const upayload = try std.fmt.allocPrint(alloc, "{{\"name\":\"{s}\"}}", .{pa.positional.items[0]});
            defer alloc.free(upayload);
            const uresp = try client.send(alloc, .req_chain_unlock, upayload);
            defer alloc.free(uresp);
            std.debug.print("{s}\n", .{uresp});
        },
        .write => {
            if (pa.positional.items.len < 2) { std.debug.print("Usage: zigh write <addr> <value> [--type t] [--chain offs] [--base 0x...]\n", .{}); return; }
            const tid = pa.getOpt("type") orelse "u32";
            const chain = pa.getOpt("chain") orelse "";
            const base = pa.getOpt("base") orelse "0";
            const payload = try std.fmt.allocPrint(alloc, "{{\"addr\":\"{s}\",\"value\":\"{s}\",\"type\":\"{s}\",\"chain\":\"{s}\",\"base\":\"{s}\"}}", .{ pa.positional.items[0], pa.positional.items[1], tid, chain, base });
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
        .scan => std.debug.print("scan: handled standalone\n", .{}),
        else => unreachable,
    }
}

test {
    _ = @import("scanner/value.zig");
    _ = @import("scanner/mod.zig");
}
