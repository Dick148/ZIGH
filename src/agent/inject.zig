// ZIGH — Agent injector (stub)
// Full ptrace injection blocked by Zig 0.16 API churn on user_regs_struct.
// Use LD_PRELOAD for now: LD_PRELOAD=zig-out/lib/libzigh_agent.so wine game.exe

const std = @import("std");

pub fn inject(pid: u32, so_path: [:0]const u8) !void {
    _ = pid;
    _ = so_path;
    std.debug.print(
        \\ptrace-based injection not yet available (Zig 0.16 ptrace API changes).
        \\Use LD_PRELOAD instead:
        \\
        \\  LD_PRELOAD=zig-out/lib/libzigh_agent.so wine game.exe
        \\
        \\Or build with kernel module / eBPF for post-start injection.
        \\
    , .{});
}
