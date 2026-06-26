// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The `sinete` executable: a thin CLI that dispatches to libsinete + the platform backend. The
//! portable logic lives in the `sinete` module (lib/); this file parses argv (via zig-cli), routes,
//! and owns the executable-side glue (the libxev transport and the macOS Secure Enclave backend).
//! On macOS the agent serves real enclave keys gated by Touch ID; elsewhere it runs a fake backend
//! so `ssh-add -l` works end-to-end with no hardware.

const std = @import("std");
const builtin = @import("builtin");
const sinete = @import("sinete");
const cli = @import("cli");
const transport = @import("transport.zig");

// The Secure Enclave backend exists only on macOS; elsewhere the agent runs the fake backend and
// the key-management verbs report that they need macOS. Gating the import keeps Linux/CI builds
// free of the Apple-framework shim.
const darwin = if (builtin.os.tag == .macos) @import("backend/darwin.zig") else struct {};

// zig-cli action callbacks are bare `fn() !void`, so the process context and the parsed argument
// values live in file scope (the same pattern as zig-cli's own examples).
var g_io: std.Io = undefined;
var g_gpa: std.mem.Allocator = undefined;
var g_env: *const std.process.Environ.Map = undefined;

var opt_sock: []const u8 = ""; // agent --sock; empty means the per-OS default
var arg_name: []const u8 = ""; // the <name> positional for generate/export/remove

pub fn main(init: std.process.Init) !void {
    g_io = init.io;
    g_gpa = init.gpa;
    g_env = init.environ_map;

    var r = cli.AppRunner.init(&init);
    defer r.deinit();

    const app = cli.App{
        .version = sinete.version,
        .command = .{
            .name = "sinete",
            .description = .{ .one_line = "hardware-backed SSH key manager + agent" },
            .target = .{ .subcommands = try r.allocCommands(&.{
                .{
                    .name = "agent",
                    .description = .{ .one_line = "serve the ssh-agent protocol on a unix socket" },
                    .options = try r.allocOptions(&.{.{
                        .long_name = "sock",
                        .help = "socket path (default: the per-OS cache directory)",
                        .value_ref = r.mkRef(&opt_sock),
                        .value_name = "PATH",
                    }}),
                    .target = .{ .action = .{ .exec = cmdAgent } },
                },
                try nameCmd(&r, "generate", "create a Secure Enclave key and print its public key", cmdGenerate),
                .{
                    .name = "list",
                    .description = .{ .one_line = "list the enclave keys" },
                    .target = .{ .action = .{ .exec = cmdList } },
                },
                try nameCmd(&r, "export", "print a key's public key in authorized_keys form", cmdExport),
                try nameCmd(&r, "remove", "delete an enclave key", cmdRemove),
                .{
                    .name = "version",
                    .description = .{ .one_line = "print the version" },
                    .target = .{ .action = .{ .exec = cmdVersion } },
                },
            }) },
        },
    };
    return r.run(&app);
}

/// A subcommand taking a single required `<name>` positional bound to `arg_name`.
fn nameCmd(r: *cli.AppRunner, name: []const u8, one_line: []const u8, exec: cli.ExecFn) !cli.Command {
    return .{
        .name = name,
        .description = .{ .one_line = one_line },
        .target = .{ .action = .{
            .positional_args = .{ .required = try r.allocPositionalArgs(&.{.{
                .name = "name",
                .value_ref = r.mkRef(&arg_name),
            }}) },
            .exec = exec,
        } },
    };
}

// --- actions ---

fn cmdAgent() !void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock = if (opt_sock.len > 0) opt_sock else try defaultSockPath(g_io, g_env, &path_buf);

    if (builtin.os.tag == .macos) {
        var be = darwin.Darwin{};
        try serveAgent(sock, be.processor(), be.authorizer());
    } else {
        // No secure element: advertise one freshly generated identity so the protocol path works.
        var arena = std.heap.ArenaAllocator.init(g_gpa);
        defer arena.deinit();
        const blob = try demoEcdsaBlob(g_io, arena.allocator());
        const keys = [_]sinete.crypto.KeyInfo{.{ .blob = blob, .comment = "sinete demo (fake backend)" }};
        var cp = sinete.crypto.Fake{ .keys = &keys };
        var az = sinete.authz.Fake{};
        try serveAgent(sock, cp.processor(), az.authorizer());
    }
}

/// Wire a Cryptoprocessor + Authorizer into an Agent and serve it over the libxev transport until
/// the loop ends. A reclaiming allocator backs the per-connection state (leak-detecting in safe
/// builds, the fast smp_allocator in release); an arena would grow RSS without bound.
fn serveAgent(sock: []const u8, cp: sinete.crypto.Cryptoprocessor, az: sinete.authz.Authorizer) !void {
    var debug_alloc: std.heap.DebugAllocator(.{}) = .init;
    const gpa, const debug_gpa = switch (builtin.mode) {
        .Debug, .ReleaseSafe => .{ debug_alloc.allocator(), true },
        .ReleaseFast, .ReleaseSmall => .{ std.heap.smp_allocator, false },
    };
    defer if (debug_gpa) {
        _ = debug_alloc.deinit();
    };

    var agent = sinete.Agent.init(gpa, cp, az, .{
        .idle_ms = 300_000, // 5 min idle TTL
        .max_ms = 3_600_000, // 1 h absolute cap
    });
    defer agent.deinit();

    var msg_buf: [std.fs.max_path_bytes + 64]u8 = undefined;
    try stderrWrite(try std.fmt.bufPrint(&msg_buf, "sinete agent listening on {s}\n", .{sock}));

    try transport.serve(gpa, g_io, &agent, sock, .{});
}

/// Build the `sinete-<name>` enclave label for `arg_name`, rejecting a name so long that the
/// backend's 128-byte label buffer would truncate it (which would orphan the key: export/remove
/// rebuild the full name and could never match the truncated enumerated comment).
fn keyLabel(buf: []u8) ![:0]const u8 {
    const max = 120; // 128-byte label buffer (incl NUL) minus the "sinete-" prefix
    if (arg_name.len > max) {
        var e: [96]u8 = undefined;
        try stderrWrite(try std.fmt.bufPrint(&e, "error: name too long (max {d} bytes)\n", .{max}));
        std.process.exit(2);
    }
    return std.fmt.bufPrintZ(buf, "sinete-{s}", .{arg_name});
}

fn cmdGenerate() !void {
    if (builtin.os.tag == .macos) {
        var lbl_buf: [128]u8 = undefined;
        const label = try keyLabel(&lbl_buf);
        var be = darwin.Darwin{};
        var point: [65]u8 = undefined;
        try be.generate(label, &point);

        var arena = std.heap.ArenaAllocator.init(g_gpa);
        defer arena.deinit();
        var enc = sinete.wire.Encoder.init(arena.allocator());
        try sinete.ecdsa_key.writePubBlob(&enc, &point);
        try printAuthKeys(enc.bytes(), label);
    } else return macosOnly("generate");
}

fn cmdList() !void {
    if (builtin.os.tag == .macos) {
        var be = darwin.Darwin{};
        var arena = std.heap.ArenaAllocator.init(g_gpa);
        defer arena.deinit();
        const keys = try be.processor().enumerate(arena.allocator());
        for (keys) |k| try printListEntry(k.blob, k.comment);
    } else return macosOnly("list");
}

fn cmdExport() !void {
    if (builtin.os.tag == .macos) {
        var be = darwin.Darwin{};
        var arena = std.heap.ArenaAllocator.init(g_gpa);
        defer arena.deinit();
        var want_buf: [128]u8 = undefined;
        const want = try keyLabel(&want_buf);
        const keys = try be.processor().enumerate(arena.allocator());
        for (keys) |k| {
            if (std.mem.eql(u8, k.comment, want)) return printAuthKeys(k.blob, k.comment);
        }
        try notFound(arg_name);
    } else return macosOnly("export");
}

fn cmdRemove() !void {
    if (builtin.os.tag == .macos) {
        var be = darwin.Darwin{};
        var arena = std.heap.ArenaAllocator.init(g_gpa);
        defer arena.deinit();
        var want_buf: [128]u8 = undefined;
        const want = try keyLabel(&want_buf);
        const keys = try be.processor().enumerate(arena.allocator());
        for (keys) |k| {
            if (!std.mem.eql(u8, k.comment, want)) continue;
            const point = try sinete.ecdsa_key.pointFromPubBlob(k.blob);
            try be.remove(point);
            var msg: [192]u8 = undefined;
            return stdoutWrite(try std.fmt.bufPrint(&msg, "removed {s}\n", .{want}));
        }
        try notFound(arg_name);
    } else return macosOnly("remove");
}

fn cmdVersion() !void {
    try stdoutWrite("sinete " ++ sinete.version ++ "\n");
}

// --- output helpers ---

fn stdoutWrite(bytes: []const u8) !void {
    try std.Io.File.stdout().writeStreamingAll(g_io, bytes);
}
fn stderrWrite(bytes: []const u8) !void {
    try std.Io.File.stderr().writeStreamingAll(g_io, bytes);
}

/// Print an authorized_keys line: `ecdsa-sha2-nistp256 <base64(blob)> <comment>`.
fn printAuthKeys(blob: []const u8, comment: []const u8) !void {
    var b64_buf: [256]u8 = undefined;
    const b64 = std.base64.standard.Encoder.encode(&b64_buf, blob);
    var line: [512]u8 = undefined;
    try stdoutWrite(try std.fmt.bufPrint(&line, "{s} {s} {s}\n", .{ sinete.ecdsa_key.key_type, b64, comment }));
}

/// Print an `ssh-add -l` style line: `256 SHA256:<b64> <comment> (ECDSA)`.
fn printListEntry(blob: []const u8, comment: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(blob, &digest, .{});
    var fp_buf: [44]u8 = undefined;
    const fp = std.base64.standard_no_pad.Encoder.encode(&fp_buf, &digest);
    var line: [256]u8 = undefined;
    try stdoutWrite(try std.fmt.bufPrint(&line, "256 SHA256:{s} {s} (ECDSA)\n", .{ fp, comment }));
}

fn notFound(name: []const u8) !void {
    var buf: [192]u8 = undefined;
    try stderrWrite(try std.fmt.bufPrint(&buf, "error: no key named '{s}'\n", .{name}));
    std.process.exit(1);
}

fn macosOnly(verb: []const u8) !void {
    var buf: [160]u8 = undefined;
    try stderrWrite(try std.fmt.bufPrint(&buf, "error: '{s}' needs the Secure Enclave and is only supported on macOS\n", .{verb}));
    std.process.exit(2);
}

/// Per-OS default socket path (creating its parent directory). macOS:
/// ~/Library/Caches/sinete/agent.sock; Linux: $XDG_RUNTIME_DIR/sinete/agent.sock, falling back to
/// ~/.cache/sinete/agent.sock. The result is written into `buf`; the socket file itself is created
/// by the transport.
fn defaultSockPath(io: std.Io, env: *const std.process.Environ.Map, buf: []u8) ![]const u8 {
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
    // Keep the agent directory owner-only (0700) as defense in depth. The socket itself is already
    // created 0600 (umask around bind, plus an explicit chmod, in the transport); a private parent
    // dir additionally stops other local users from listing or replacing the socket path.
    std.Io.Dir.cwd().setFilePermissions(io, dir, @enumFromInt(0o700), .{ .follow_symlinks = false }) catch {};
    return std.fmt.bufPrint(buf, "{s}/agent.sock", .{dir});
}

/// Build a real ecdsa-sha2-nistp256 SSH public-key blob from a fresh P-256 key, so the fake agent
/// advertises an identity that parses in `ssh-add -l`. Owned by `gpa`.
fn demoEcdsaBlob(io: std.Io, gpa: std.mem.Allocator) ![]const u8 {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const kp = Ecdsa.KeyPair.generate(io);
    const point = kp.public_key.toUncompressedSec1(); // [65]u8: 0x04 || X || Y

    var enc = sinete.wire.Encoder.init(gpa);
    defer enc.deinit();
    try sinete.ecdsa_key.writePubBlob(&enc, &point);
    return gpa.dupe(u8, enc.bytes());
}
