// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! sinete — hardware-backed SSH key store + agent (Zig rewrite).
//! This is the develop-zig scaffolding: the CLI dispatch skeleton only; the
//! backends (TPM/Secure Enclave, agent, presence, broker) land in later phases.

const std = @import("std");

const version = "0.0.0-dev";

const usage =
    \\sinete — hardware-backed SSH key store + agent (Zig rewrite, scaffolding)
    \\
    \\usage: sinete <command> [args]
    \\
    \\commands:
    \\  version            print the version
    \\  help               show this help
    \\  agent              run the ssh-agent          (not implemented)
    \\  generate <name>    create a hardware key       (not implemented)
    \\  list               list keys                   (not implemented)
    \\
;

// Zig 0.16 entry point: `init` carries the Io interface, the process arena, and
// the command-line args (the post-"Writergate" explicit-Io model).
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const cmd = if (args.len > 1) args[1] else "help";

    const stdout = std.Io.File.stdout();
    if (std.mem.eql(u8, cmd, "version")) {
        try stdout.writeStreamingAll(init.io, "sinete " ++ version ++ "\n");
    } else if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "--help")) {
        try stdout.writeStreamingAll(init.io, usage);
    } else {
        try std.Io.File.stderr().writeStreamingAll(init.io, "sinete: '");
        try std.Io.File.stderr().writeStreamingAll(init.io, cmd);
        try std.Io.File.stderr().writeStreamingAll(init.io, "' is not implemented yet (Zig rewrite in progress)\n");
        std.process.exit(2);
    }
}

test "version is the dev placeholder" {
    try std.testing.expectEqualStrings("0.0.0-dev", version);
}

test "usage mentions the agent" {
    try std.testing.expect(std.mem.indexOf(u8, usage, "agent") != null);
}
