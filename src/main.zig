// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The `sinete` executable: a thin CLI that dispatches to libsinete + the platform backend.
//! The portable logic lives in the `sinete` module (lib/); this file only parses argv, routes,
//! and owns the executable-side glue (the libxev transport). Hardware-backed key generation and
//! the real Secure Enclave/TPM backends arrive in later Z-phases; `agent` here runs the protocol
//! over a fake backend so `ssh-add -l` works end-to-end with no hardware.

const std = @import("std");
const builtin = @import("builtin");
const sinete = @import("sinete");
const transport = @import("transport.zig");

const usage =
    \\sinete - hardware-backed SSH key manager + agent
    \\
    \\usage: sinete <command> [args]
    \\
    \\commands:
    \\  agent [--sock PATH]   serve the ssh-agent protocol on a unix socket (Z2: fake backend)
    \\  version               print the version
    \\  help                  show this help
    \\
;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const cmd = if (args.len >= 2) args[1] else "help";

    if (std.mem.eql(u8, cmd, "version")) {
        try out(init, "sinete " ++ sinete.version ++ "\n");
    } else if (std.mem.eql(u8, cmd, "agent")) {
        try runAgent(init);
    } else if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "--help")) {
        try out(init, usage);
    } else {
        // Unknown command is an error: usage goes to stderr so stdout stays clean for pipes.
        try err(init, usage);
        std.process.exit(2);
    }
}

/// Run the agent loop: a fake-backed `Agent` served over the libxev unix-socket transport. The
/// fake advertises one real ecdsa-sha2-nistp256 identity, so a client's `ssh-add -l` lists it.
fn runAgent(init: std.process.Init) !void {
    const arena = init.arena.allocator(); // process-lifetime: argv + the demo key blob

    const args = try init.minimal.args.toSlice(arena);
    var sock_override: ?[]const u8 = null;
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--sock")) {
            if (i + 1 >= args.len) {
                try err(init, "error: --sock needs a path\n");
                std.process.exit(2);
            }
            sock_override = args[i + 1];
            i += 1;
        }
    }

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock = sock_override orelse try defaultSockPath(init.io, init.environ_map, &path_buf);

    const blob = try demoEcdsaBlob(init.io, arena);
    const keys = [_]sinete.crypto.KeyInfo{.{ .blob = blob, .comment = "sinete demo (z2 fake)" }};
    var cp = sinete.crypto.Fake{ .keys = &keys };
    var az = sinete.authz.Fake{};

    // A reclaiming allocator for the agent's window cache and the transport's per-connection state.
    // An arena would never free a closed connection's buffers, so repeated connect/disconnect would
    // grow RSS without bound; the process-lifetime arena above is only for argv + the demo blob.
    var conn_alloc: std.heap.DebugAllocator(.{}) = .init;
    defer _ = conn_alloc.deinit();
    const gpa = conn_alloc.allocator();

    var agent = sinete.Agent.init(gpa, cp.processor(), az.authorizer(), .{
        .idle_ms = 300_000, // 5 min idle TTL (moot: the fake authorizer never prompts)
        .max_ms = 3_600_000, // 1 h absolute cap
    });
    defer agent.deinit();

    var msg_buf: [std.fs.max_path_bytes + 64]u8 = undefined;
    try err(init, try std.fmt.bufPrint(&msg_buf, "sinete agent listening on {s}\n", .{sock}));

    try transport.serve(gpa, init.io, &agent, sock, .{});
}

/// Per-OS default socket path, creating its parent directory. macOS: ~/Library/Caches/sinete;
/// Linux/BSD: $XDG_RUNTIME_DIR/sinete, falling back to ~/.cache/sinete. The result is written into
/// `buf`; the socket file itself is created by the transport.
fn defaultSockPath(io: std.Io, env: *std.process.Environ.Map, buf: []u8) ![]const u8 {
    const home = env.get("HOME");
    var basebuf: [std.fs.max_path_bytes]u8 = undefined;
    const base = if (builtin.os.tag.isDarwin())
        try std.fmt.bufPrint(&basebuf, "{s}/Library/Caches", .{home orelse return error.NoHomeDir})
    else if (env.get("XDG_RUNTIME_DIR")) |x|
        x
    else
        try std.fmt.bufPrint(&basebuf, "{s}/.cache", .{home orelse return error.NoHomeDir});

    var dirbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dirbuf, "{s}/sinete", .{base});
    std.Io.Dir.cwd().createDirPath(io, dir) catch {}; // best-effort; a real failure surfaces at bind
    return std.fmt.bufPrint(buf, "{s}/agent.sock", .{dir});
}

/// Build a real ecdsa-sha2-nistp256 SSH public-key blob from a fresh P-256 key, so the advertised
/// identity parses in `ssh-add -l`. The blob is: string("ecdsa-sha2-nistp256") || string("nistp256")
/// || string(0x04 || X || Y). Owned by `gpa`.
fn demoEcdsaBlob(io: std.Io, gpa: std.mem.Allocator) ![]const u8 {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const kp = Ecdsa.KeyPair.generate(io);
    const point = kp.public_key.toUncompressedSec1(); // [65]u8: 0x04 || X || Y

    var enc = sinete.wire.Encoder.init(gpa);
    defer enc.deinit();
    try enc.string("ecdsa-sha2-nistp256");
    try enc.string("nistp256");
    try enc.string(&point);
    return gpa.dupe(u8, enc.bytes());
}

fn out(init: std.process.Init, bytes: []const u8) !void {
    try std.Io.File.stdout().writeStreamingAll(init.io, bytes);
}

fn err(init: std.process.Init, bytes: []const u8) !void {
    try std.Io.File.stderr().writeStreamingAll(init.io, bytes);
}
