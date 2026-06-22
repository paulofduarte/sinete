// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── libsinete: the cross-platform core (a reusable module + static library) ──
    const lib_mod = b.addModule("sinete", .{
        .root_source_file = b.path("lib/sinete.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "sinete",
        .root_module = lib_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    // ── the sinete executable: a thin CLI + wiring layer over libsinete ──
    const exe = b.addExecutable(.{
        .name = "sinete",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "sinete", .module = lib_mod }},
        }),
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| run.addArgs(args);
    const run_step = b.step("run", "Build and run sinete");
    run_step.dependOn(&run.step);

    // ── tests: the portable core runs with no hardware ──
    const lib_tests = b.addTest(.{ .root_module = lib_mod });
    const run_lib_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_tests.step);
}
