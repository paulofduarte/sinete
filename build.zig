// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // libsinete: the cross-platform core, a reusable module plus a static library.
    const lib_mod = b.addModule("sinete", .{
        .root_source_file = b.path("lib/sinete.zig"),
        .target = target,
        .optimize = optimize,
    });

    // A static archive of the core, installed as a build artifact. The sinete executable below
    // does not link it; it imports the module and compiles the core in. (No C ABI is exported
    // yet, so this archive is for Zig consumers; a C-callable surface can be added later.)
    const lib = b.addLibrary(.{
        .name = "sinete",
        .root_module = lib_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    // the sinete executable: a thin CLI and wiring layer that imports the libsinete module.
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

    // tests: the portable core runs with no hardware.
    const lib_tests = b.addTest(.{ .root_module = lib_mod });
    const run_lib_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_tests.step);

    // coverage: build kcov via the Zig build system (a dwarf-zig fork that reads DWARF
    // line tables with std.debug.Dwarf, so the self-hosted backend's output is read
    // correctly) and run the test binary under it, writing kcov-out/. The dependency is
    // lazy, so a normal `zig build` or `zig build test` neither fetches nor builds kcov.
    //
    // The include pattern is our absolute source directories, so kcov reports only our
    // files and not the standard library (which lives under the Zig installation prefix).
    const cov_step = b.step("coverage", "Run unit tests under kcov (writes kcov-out/)");
    // On a headless CI runner kcov's task_for_pid blocks forever in the taskgated
    // authorization path, even with the cs.debugger entitlement and developer mode enabled.
    // Running kcov as root bypasses taskgated entirely; gate it so local runs are untouched.
    const kcov_sudo = b.option(bool, "kcov-sudo", "Run kcov under sudo -n (needed on macOS CI)") orelse false;
    // Zig 0.16's self-hosted Mach-O linker corrupts ~16 bytes of a function
    // prologue in the large x86_64-macOS kcov link; only Debug codegen dodges it
    // (Release{Fast,Safe,Small} all fault on entry to collectStmtAddrs). Build
    // that one target as Debug; a coverage tool needs correctness, not speed.
    const kcov_optimize: std.builtin.OptimizeMode =
        if (target.result.os.tag.isDarwin() and target.result.cpu.arch == .x86_64)
            .Debug
        else
            .ReleaseFast;
    if (b.lazyDependency("kcov", .{ .target = target, .optimize = kcov_optimize })) |kcov_dep| {
        const kcov_exe = kcov_dep.artifact("kcov");
        const is_darwin = target.result.os.tag.isDarwin();

        const kcov = if (kcov_sudo) sudo: {
            const sudo_run = std.Build.Step.Run.create(b, "run kcov coverage (sudo)");
            sudo_run.addArgs(&.{ "sudo", "-n" });
            sudo_run.addArtifactArg(kcov_exe);
            break :sudo sudo_run;
        } else b.addRunArtifact(kcov_exe);
        kcov.addArg("--clean");
        kcov.addArg(b.fmt("--include-pattern={s},{s}", .{ b.pathFromRoot("lib"), b.pathFromRoot("src") }));
        kcov.addArg("kcov-out");
        kcov.addArtifactArg(lib_tests);

        // macOS: kcov's mach engine calls task_for_pid, which needs the cs.debugger
        // entitlement; ad-hoc sign the built binary before running it. (--verbose so the
        // codesign outcome is visible in the CI log.)
        if (is_darwin) {
            const entitlements = b.addWriteFiles().add("kcov-entitlements.plist",
                \\<?xml version="1.0" encoding="UTF-8"?>
                \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                \\<plist version="1.0">
                \\<dict>
                \\    <key>com.apple.security.cs.debugger</key>
                \\    <true/>
                \\</dict>
                \\</plist>
                \\
            );
            const sign = b.addSystemCommand(&.{ "codesign", "-s", "-", "--verbose", "--entitlements" });
            sign.addFileArg(entitlements);
            sign.addArg("-f");
            sign.addArtifactArg(kcov_exe);
            kcov.step.dependOn(&sign.step);
        }

        cov_step.dependOn(&kcov.step);
    }
}
