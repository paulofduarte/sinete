// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The `sinete` executable: a thin CLI that dispatches to libsinete + the platform backend.
//! The portable logic lives in the `sinete` module (lib/); this file only parses argv and
//! routes. Hardware-backed commands (generate/sign/agent) arrive in later Z-phases.

const std = @import("std");
const sinete = @import("sinete");

const usage =
    \\sinete — hardware-backed SSH key manager + agent
    \\
    \\usage: sinete <command> [args]
    \\
    \\commands:
    \\  version    print the version
    \\  help       show this help
    \\
;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const cmd = if (args.len >= 2) args[1] else "help";

    if (std.mem.eql(u8, cmd, "version")) {
        try out(init, "sinete " ++ sinete.version ++ "\n");
    } else if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "--help")) {
        try out(init, usage);
    } else {
        // Unknown command is an error: usage goes to stderr so stdout stays clean for pipes.
        try err(init, usage);
        std.process.exit(2);
    }
}

fn out(init: std.process.Init, bytes: []const u8) !void {
    try std.Io.File.stdout().writeStreamingAll(init.io, bytes);
}

fn err(init: std.process.Init, bytes: []const u8) !void {
    try std.Io.File.stderr().writeStreamingAll(init.io, bytes);
}
