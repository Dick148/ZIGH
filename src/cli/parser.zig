// ZIGH — Builtin CLI command parser
// Zero dependencies, simple linear scan for <15 commands.

const std = @import("std");

pub const Command = enum {
    help,
    version,
    daemon,
    status,
    @"lock-add",
    @"lock-remove",
    @"lock-list",
    write,
    read,
    call,
    @"cheat-load",
    @"cheat-start",
    @"cheat-stop",
    inject,

    pub fn parse(name: []const u8) ?Command {
        if (std.mem.eql(u8, name, "help")) return .help;
        if (std.mem.eql(u8, name, "version")) return .version;
        if (std.mem.eql(u8, name, "daemon")) return .daemon;
        if (std.mem.eql(u8, name, "status")) return .status;
        if (std.mem.eql(u8, name, "lock-add")) return .@"lock-add";
        if (std.mem.eql(u8, name, "lock-remove")) return .@"lock-remove";
        if (std.mem.eql(u8, name, "lock-list")) return .@"lock-list";
        if (std.mem.eql(u8, name, "write")) return .write;
        if (std.mem.eql(u8, name, "read")) return .read;
        if (std.mem.eql(u8, name, "call")) return .call;
        if (std.mem.eql(u8, name, "cheat-load")) return .@"cheat-load";
        if (std.mem.eql(u8, name, "cheat-start")) return .@"cheat-start";
        if (std.mem.eql(u8, name, "cheat-stop")) return .@"cheat-stop";
        if (std.mem.eql(u8, name, "inject")) return .inject;
        return null;
    }

    pub fn usage(self: Command) []const u8 {
        return switch (self) {
            .help => "zigh help                         — Show this help",
            .version => "zigh version                      — Show version info",
            .daemon => "zigh daemon [--pid <id>]          — Start daemon for a game process",
            .status => "zigh status                       — Show active locks & daemon status",
            .@"lock-add" => "zigh lock-add <name> <value> [--type <t>]  — Add a memory lock",
            .@"lock-remove" => "zigh lock-remove <name>            — Remove a memory lock",
            .@"lock-list" => "zigh lock-list                     — List all active locks",
            .write => "zigh write <addr> <value> [--type <t>]    — One-shot memory write",
            .read => "zigh read <addr> [--type <t>]            — One-shot memory read",
            .call => "zigh call <func> [args...]         — Remote function call",
            .@"cheat-load" => "zigh cheat-load <file.yaml>        — Load a cheat definition",
            .@"cheat-start" => "zigh cheat-start [<name>]          — Activate cheats",
            .@"cheat-stop" => "zigh cheat-stop                    — Deactivate all cheats",
            .inject => "zigh inject <pid> <agent.so>       — Inject agent into process",
        };
    }
};

pub const ParsedArgs = struct {
    cmd: Command,
    positional: std.ArrayList([]const u8),
    opts: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ParsedArgs) void {
        self.positional.deinit(self.allocator);
        self.opts.deinit();
    }

    pub fn getOpt(self: ParsedArgs, name: []const u8) ?[]const u8 {
        return self.opts.get(name);
    }
};

pub fn parseArgs(allocator: std.mem.Allocator, args: [][]const u8) !?ParsedArgs {
    if (args.len < 2) return null;

    const cmd = Command.parse(args[1]) orelse return null;

    var positional: std.ArrayList([]const u8) = .empty;
    var opts = std.StringHashMap([]const u8).init(allocator);

    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.startsWith(u8, arg, "--")) {
            const eq = std.mem.indexOfScalar(u8, arg, '=');
            if (eq) |pos| {
                try opts.put(arg[2..pos], arg[pos + 1 ..]);
            } else if (i + 1 < args.len and !std.mem.startsWith(u8, args[i + 1], "-")) {
                try opts.put(arg[2..], args[i + 1]);
                i += 1;
            } else {
                try opts.put(arg[2..], "true");
            }
        } else if (std.mem.startsWith(u8, arg, "-")) {
            if (arg.len > 2) {
                try opts.put(arg[1..2], arg[2..]);
            } else if (i + 1 < args.len) {
                try opts.put(arg[1..2], args[i + 1]);
                i += 1;
            }
        } else {
            try positional.append(allocator, arg);
        }
    }

    return ParsedArgs{
        .cmd = cmd,
        .positional = positional,
        .opts = opts,
        .allocator = allocator,
    };
}

pub fn printHelp() void {
    std.debug.print(
        \\ZIGH — ZIGH Is Game Hacker
        \\Builtin CLI trainer & memory editor for Linux/Wine
        \\
        \\COMMANDS:
        \\
    , .{});
    const cmds = [_]Command{
        .help, .version, .daemon, .status,
        .@"lock-add", .@"lock-remove", .@"lock-list",
        .write, .read, .call,
        .@"cheat-load", .@"cheat-start", .@"cheat-stop",
        .inject,
    };
    for (cmds) |cmd| {
        std.debug.print("  {s}\n", .{cmd.usage()});
    }
    std.debug.print(
        \\
        \\TYPE OPTIONS (for --type flag):
        \\  u8 u16 u32 u64  i8 i16 i32 i64  f32 f64  ptr bytes
        \\
        \\EXAMPLES:
        \\  zigh daemon --pid 12345
        \\  zigh lock-add hp 100 --type f32
        \\  zigh cheat-load ~/.config/zigh/cheats/nier.yaml
        \\
    , .{});
}
