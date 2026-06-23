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
    if (b.lazyDependency("kcov", .{ .target = target, .optimize = .ReleaseFast })) |kcov_dep| {
        const kcov_exe = kcov_dep.artifact("kcov");
        const include = b.fmt("--include-pattern={s},{s}", .{ b.pathFromRoot("lib"), b.pathFromRoot("src") });

        if (target.result.os.tag.isDarwin()) {
            // kcov's mach engine calls task_for_pid, which needs the cs.debugger entitlement,
            // so ad-hoc sign kcov. Sign a fresh copy rather than the build artifact in place: a
            // re-sign cannot clear the SIP-protected com.apple.provenance xattr that makes
            // AppleSystemPolicy stall a binary's first exec on a headless CI runner, but plain
            // cp drops the xattr while preserving the embedded signature. Copy the test binary
            // the same way so its launch under kcov is not stalled either.
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

            const copy_kcov = b.addSystemCommand(&.{"cp"});
            copy_kcov.addArtifactArg(kcov_exe);
            const kcov_bin = copy_kcov.addOutputFileArg("kcov");

            const sign = b.addSystemCommand(&.{ "codesign", "--force", "--sign", "-", "--timestamp=none", "--verbose", "--entitlements" });
            sign.addFileArg(entitlements);
            sign.addFileArg(kcov_bin);

            const copy_tests = b.addSystemCommand(&.{"cp"});
            copy_tests.addArtifactArg(lib_tests);
            const tests_bin = copy_tests.addOutputFileArg("kcov-tests");

            const kcov = std.Build.Step.Run.create(b, "run kcov coverage");
            kcov.addFileArg(kcov_bin);
            kcov.step.dependOn(&sign.step);
            kcov.addArgs(&.{ "--clean", include, "kcov-out" });
            kcov.addFileArg(tests_bin);
            cov_step.dependOn(&kcov.step);
        } else {
            const kcov = b.addRunArtifact(kcov_exe);
            kcov.addArgs(&.{ "--clean", include, "kcov-out" });
            kcov.addArtifactArg(lib_tests);
            cov_step.dependOn(&kcov.step);
        }
    }
}
