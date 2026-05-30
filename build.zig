const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const exe = b.addExecutable(.{
        .name = "zigh",
        .root_module = root_mod,
    });

    b.installArtifact(exe);

    // Agent shared library
    const agent_mod = b.createModule(.{
        .root_source_file = b.path("src/agent/agent.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const agent = b.addLibrary(.{
        .name = "zigh_agent",
        .root_module = agent_mod,
        .linkage = .dynamic,
    });
    b.installArtifact(agent);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run ZIGH");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}
