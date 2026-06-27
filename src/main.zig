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
const linux = if (builtin.os.tag == .linux) @import("backend/linux.zig") else struct {};
// Linux presence: the fprintd fingerprint Authorizer and the logind remote-session gate, both over
// the pure-Zig D-Bus client. Gated so non-Linux builds don't pull in the Linux-only socket code.
const fprintd = if (builtin.os.tag == .linux) @import("backend/fprintd.zig") else struct {};
const authorizer_linux = if (builtin.os.tag == .linux) @import("backend/authorizer_linux.zig") else struct {};
const logind = if (builtin.os.tag == .linux) @import("backend/logind.zig") else struct {};
const dbus_conn = if (builtin.os.tag == .linux) @import("backend/dbus_conn.zig") else struct {};
// Cross-platform log-only presenter: records every refusal/failure reason to the agent log until the
// real channel presenters (pinentry / modal / tty) land.
const presenter_log = @import("backend/presenter_log.zig");
// The pinentry presenter is pure std + the sinete lib (no OS-specific syscalls), so it is imported
// unconditionally -- the _pinentry-selftest diagnostic runs anywhere a pinentry binary exists.
const pinentry = @import("backend/pinentry.zig").Pinentry;

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
                try nameCmd(&r, "generate", "create a hardware-backed key and print its public key", cmdGenerate),
                .{
                    .name = "list",
                    .description = .{ .one_line = "list the hardware-backed keys" },
                    .target = .{ .action = .{ .exec = cmdList } },
                },
                try nameCmd(&r, "export", "print a key's public key in authorized_keys form", cmdExport),
                try nameCmd(&r, "remove", "delete a hardware-backed key", cmdRemove),
                .{
                    .name = "version",
                    .description = .{ .one_line = "print the version" },
                    .target = .{ .action = .{ .exec = cmdVersion } },
                },
                .{
                    .name = "_tpm-selftest",
                    .description = .{ .one_line = "diagnostic: exercise the TPM path (Linux; SINETE_TPM=<swtpm sock>)" },
                    .target = .{ .action = .{ .exec = cmdTpmSelftest } },
                },
                .{
                    .name = "_dbus-selftest",
                    .description = .{ .one_line = "diagnostic: connect to the system D-Bus and Hello (Linux)" },
                    .target = .{ .action = .{ .exec = cmdDbusSelftest } },
                },
                .{
                    .name = "_tpm-policy-selftest",
                    .description = .{ .one_line = "diagnostic: exercise the TPM policy binding (Linux; SINETE_TPM=<sock>)" },
                    .target = .{ .action = .{ .exec = cmdTpmPolicySelftest } },
                },
                .{
                    .name = "_pinentry-selftest",
                    .description = .{ .one_line = "diagnostic: spawn pinentry, Assuan greeting + BYE (SINETE_PINENTRY=<path>)" },
                    .target = .{ .action = .{ .exec = cmdPinentrySelftest } },
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
        var lp = presenter_log.LogPresenter{ .io = g_io };
        var be = darwin.Darwin{};
        try serveAgent(sock, be.processor(), be.authorizer(), null, lp.presenter());
    } else if (builtin.os.tag == .linux) {
        var kbuf: [std.fs.max_path_bytes]u8 = undefined;
        var be = linuxBackend(try linuxKeyDir(&kbuf));
        // The orchestrator is both the Authorizer (fingerprint or a typed confirm) and the Presenter
        // (refusal/failure messages on the peer's terminal; it owns its own log fallback). Remote/SSH
        // sessions are refused via logind.
        var fp = fprintd.Fprintd{ .io = g_io, .gpa = g_gpa };
        var lg = logind.Logind{ .io = g_io, .gpa = g_gpa, .self_uid = std.os.linux.getuid() };
        const display = g_env.get("DISPLAY") orelse "";
        var xauth_buf: [std.fs.max_path_bytes]u8 = undefined;
        const xauth = xauthPath(&xauth_buf);
        var orch = authorizer_linux.Authorizer.init(g_io, g_gpa, &fp, &lg, display, xauth);
        try serveAgent(sock, be.processor(), orch.authorizer(), lg.localSession(), orch.presenter());
    } else {
        // No secure element: advertise one freshly generated identity so the protocol path works.
        var lp = presenter_log.LogPresenter{ .io = g_io };
        var arena = std.heap.ArenaAllocator.init(g_gpa);
        defer arena.deinit();
        const blob = try demoEcdsaBlob(g_io, arena.allocator());
        const keys = [_]sinete.crypto.KeyInfo{.{ .blob = blob, .comment = "sinete demo (fake backend)" }};
        var cp = sinete.crypto.Fake{ .keys = &keys };
        var az = sinete.authz.Fake{};
        try serveAgent(sock, cp.processor(), az.authorizer(), null, lp.presenter());
    }
}

/// Wire a Cryptoprocessor + Authorizer into an Agent and serve it over the libxev transport until
/// the loop ends. A reclaiming allocator backs the per-connection state (leak-detecting in safe
/// builds, the fast smp_allocator in release); an arena would grow RSS without bound.
fn serveAgent(sock: []const u8, cp: sinete.crypto.Cryptoprocessor, az: sinete.authz.Authorizer, session: ?sinete.session.LocalSession, present: ?sinete.presenter.Presenter) !void {
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
    agent.session = session; // remote-session gate (Linux); null elsewhere leaves it inactive
    agent.presenter = present; // user-facing refusal/failure messages (log-only for now)
    defer agent.deinit();

    var msg_buf: [std.fs.max_path_bytes + 64]u8 = undefined;
    try stderrWrite(try std.fmt.bufPrint(&msg_buf, "sinete agent listening on {s}\n", .{sock}));

    try transport.serve(gpa, g_io, &agent, sock, .{});
}

/// Strip a leading "sinete-" so a name copy-pasted from `list` (which prints the full label) works
/// the same as the bare name, instead of becoming "sinete-sinete-...".
fn bareName() []const u8 {
    return if (std.mem.startsWith(u8, arg_name, "sinete-")) arg_name["sinete-".len..] else arg_name;
}

/// Build the `sinete-<name>` enclave label for a new key (the `generate` path only), validating the
/// name. Rejects: empty, or longer than 120 bytes (the backend's 128-byte label buffer minus
/// "sinete-"; a longer name would be truncated on enumeration); the reserved `_master` (its label
/// is hidden from enumeration); and bytes outside [A-Za-z0-9._@+-] (whitespace, NUL, control,
/// non-ASCII) -- invalid UTF-8 would make a nil kSecAttrLabel in the shim, and the name must be one
/// unambiguous token since list/export/remove treat it as a single identifier.
fn keyLabel(buf: []u8) ![:0]const u8 {
    const name = bareName();
    if (!validName(name)) try invalidName();
    return std.fmt.bufPrintZ(buf, "sinete-{s}", .{name});
}

/// Whether `name` is acceptable for a new key: 1-120 bytes, [A-Za-z0-9._@+-] only (a clean
/// single-token identifier, a safe filename, and a valid SSH comment), not the reserved `_master`,
/// and not the special path components `.` / `..` (which would name the key directory or its parent).
fn validName(name: []const u8) bool {
    return name.len > 0 and name.len <= 120 and
        !std.mem.eql(u8, name, "_master") and
        !std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..") and
        validNameChars(name);
}

fn invalidName() !void {
    try stderrWrite("error: invalid name (1-120 chars from [A-Za-z0-9._@+-], not '_master', '.' or '..')\n");
    std.process.exit(2);
}

/// Whether an enumerated key `comment` is the one the user asked for: an exact match, or — when the
/// argument carries the optional leading "sinete-" — a match on the stripped remainder. Exact-first
/// keeps a key whose real name literally starts with "sinete-" targetable on Linux.
fn nameMatches(comment: []const u8, typed: []const u8) bool {
    if (std.mem.eql(u8, comment, typed)) return true;
    if (std.mem.startsWith(u8, typed, "sinete-")) return std.mem.eql(u8, comment, typed["sinete-".len..]);
    return false;
}

/// Build the lookup label for export/remove. Unlike keyLabel (create) this does not re-apply the
/// create-time validation: any enumerated key must be targetable, even one made outside this CLI,
/// so we only build the comparison string. Returns null only if the name is too long to be a real
/// label (so it can never match), which the caller reports as not-found.
fn matchLabel(buf: []u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, "sinete-{s}", .{bareName()}) catch null;
}

fn validNameChars(name: []const u8) bool {
    for (name) |ch| switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '_', '@', '+', '-' => {},
        else => return false,
    };
    return true;
}

/// The Linux TPM key directory ($XDG_DATA_HOME/sinete/keys, else ~/.local/share/sinete/keys),
/// written into `buf`.
fn linuxKeyDir(buf: []u8) ![]const u8 {
    // envValue treats an empty value as unset for both, so neither XDG_DATA_HOME= nor HOME= builds a
    // path off the filesystem root.
    if (envValue("XDG_DATA_HOME")) |x| return std.fmt.bufPrint(buf, "{s}/sinete/keys", .{x});
    const home = envValue("HOME") orelse return error.NoHomeDir;
    return std.fmt.bufPrint(buf, "{s}/.local/share/sinete/keys", .{home});
}

/// An environment variable's value, treating an empty string as unset (matches the XDG convention and
/// avoids building a path off "" -- e.g. an empty SINETE_TPM must not select an empty socket path).
fn envValue(name: []const u8) ?[]const u8 {
    const v = g_env.get(name) orelse return null;
    return if (v.len > 0) v else null;
}

/// Build the Linux TPM backend over `keydir` and the device (SINETE_TPM swtpm socket, else
/// /dev/tpmrm0). `keydir` must outlive the returned value.
fn linuxBackend(keydir: []const u8) linux.Linux {
    const sock = envValue("SINETE_TPM"); // empty -> unset: fall back to the kernel device
    // The master secret is loaded lazily on the first policy-bound sign (Linux.ensureMasterLoaded),
    // so an agent that started before the first generate still picks it up.
    return .{
        .io = g_io,
        .gpa = g_gpa,
        .keydir = keydir,
        .tpm_path = sock orelse "/dev/tpmrm0",
        .tpm_is_socket = sock != null,
    };
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
        defer enc.deinit();
        try sinete.ecdsa_key.writePubBlob(&enc, &point);
        try printAuthKeys(enc.bytes(), label);
    } else if (builtin.os.tag == .linux) {
        const name = bareName(); // treat a leading "sinete-" as optional, same as macOS
        if (!validName(name)) try invalidName();
        var kbuf: [std.fs.max_path_bytes]u8 = undefined;
        var be = linuxBackend(try linuxKeyDir(&kbuf));
        var point = be.generate(name) catch |e| switch (e) {
            error.KeyExists => {
                var m: [192]u8 = undefined;
                try stderrWrite(try std.fmt.bufPrint(&m, "error: key '{s}' already exists (remove it first to regenerate)\n", .{name}));
                std.process.exit(2);
            },
            else => return e,
        };

        var arena = std.heap.ArenaAllocator.init(g_gpa);
        defer arena.deinit();
        var enc = sinete.wire.Encoder.init(arena.allocator());
        defer enc.deinit();
        try sinete.ecdsa_key.writePubBlob(&enc, &point);
        try printAuthKeys(enc.bytes(), name);
    } else return noSecureElement("generate");
}

fn cmdList() !void {
    if (builtin.os.tag == .macos) {
        var be = darwin.Darwin{};
        var arena = std.heap.ArenaAllocator.init(g_gpa);
        defer arena.deinit();
        const keys = try be.processor().enumerate(arena.allocator());
        for (keys) |k| try printListEntry(k.blob, k.comment);
    } else if (builtin.os.tag == .linux) {
        var kbuf: [std.fs.max_path_bytes]u8 = undefined;
        var be = linuxBackend(try linuxKeyDir(&kbuf));
        var arena = std.heap.ArenaAllocator.init(g_gpa);
        defer arena.deinit();
        const keys = try be.processor().enumerate(arena.allocator());
        for (keys) |k| try printListEntry(k.blob, k.comment);
    } else return noSecureElement("list");
}

fn cmdExport() !void {
    if (builtin.os.tag == .macos) {
        var be = darwin.Darwin{};
        var arena = std.heap.ArenaAllocator.init(g_gpa);
        defer arena.deinit();
        var want_buf: [256]u8 = undefined;
        const want = matchLabel(&want_buf) orelse return notFound(arg_name);
        const keys = try be.processor().enumerate(arena.allocator());
        for (keys) |k| {
            if (std.mem.eql(u8, k.comment, want)) return printAuthKeys(k.blob, k.comment);
        }
        try notFound(arg_name);
    } else if (builtin.os.tag == .linux) {
        var kbuf: [std.fs.max_path_bytes]u8 = undefined;
        var be = linuxBackend(try linuxKeyDir(&kbuf));
        var arena = std.heap.ArenaAllocator.init(g_gpa);
        defer arena.deinit();
        const keys = try be.processor().enumerate(arena.allocator());
        for (keys) |k| {
            if (nameMatches(k.comment, arg_name)) return printAuthKeys(k.blob, k.comment);
        }
        try notFound(arg_name);
    } else return noSecureElement("export");
}

fn cmdRemove() !void {
    if (builtin.os.tag == .macos) {
        var be = darwin.Darwin{};
        var arena = std.heap.ArenaAllocator.init(g_gpa);
        defer arena.deinit();
        var want_buf: [256]u8 = undefined;
        const want = matchLabel(&want_buf) orelse return notFound(arg_name);
        const keys = try be.processor().enumerate(arena.allocator());
        for (keys) |k| {
            if (!std.mem.eql(u8, k.comment, want)) continue;
            const point = try sinete.ecdsa_key.pointFromPubBlob(k.blob);
            try be.remove(point);
            var msg: [192]u8 = undefined;
            return stdoutWrite(try std.fmt.bufPrint(&msg, "removed {s}\n", .{want}));
        }
        try notFound(arg_name);
    } else if (builtin.os.tag == .linux) {
        var kbuf: [std.fs.max_path_bytes]u8 = undefined;
        var be = linuxBackend(try linuxKeyDir(&kbuf));
        var arena = std.heap.ArenaAllocator.init(g_gpa);
        defer arena.deinit();
        // Delete by a name that enumeration actually returned, so arg_name is never used as a path
        // directly (a raw "../x" would otherwise escape the key directory). Mirrors export/macOS.
        const keys = try be.processor().enumerate(arena.allocator());
        for (keys) |k| {
            if (!nameMatches(k.comment, arg_name)) continue;
            try be.remove(k.comment);
            var msg: [192]u8 = undefined;
            return stdoutWrite(try std.fmt.bufPrint(&msg, "removed {s}\n", .{k.comment}));
        }
        try notFound(arg_name);
    } else return noSecureElement("remove");
}

fn cmdVersion() !void {
    try stdoutWrite("sinete " ++ sinete.version ++ "\n");
}

fn cmdTpmSelftest() !void {
    if (builtin.os.tag == .linux) {
        const sock = envValue("SINETE_TPM"); // a swtpm unix socket (empty -> unset); else the kernel device
        try linux.selftest(g_io, sock orelse "/dev/tpmrm0", sock != null);
    } else {
        try stderrWrite("error: _tpm-selftest is only supported on Linux\n");
        std.process.exit(2);
    }
}

fn cmdDbusSelftest() !void {
    if (builtin.os.tag == .linux) {
        try dbus_conn.Conn.selftest(g_io, g_gpa);
        try stdoutWrite("DBUS SELFTEST PASS\n");
    } else {
        try stderrWrite("error: _dbus-selftest is only supported on Linux\n");
        std.process.exit(2);
    }
}

fn cmdTpmPolicySelftest() !void {
    if (builtin.os.tag == .linux) {
        const sock = envValue("SINETE_TPM");
        try linux.policySelftest(g_io, sock orelse "/dev/tpmrm0", sock != null);
    } else {
        try stderrWrite("error: _tpm-policy-selftest is only supported on Linux\n");
        std.process.exit(2);
    }
}

/// The Xauthority file for the built-in X11 modal: $XAUTHORITY, else $HOME/.Xauthority. Returns ""
/// when neither is resolvable (the modal then connects without a cookie and likely fails closed).
fn xauthPath(buf: []u8) []const u8 {
    if (g_env.get("XAUTHORITY")) |x| {
        if (x.len > 0 and x.len <= buf.len) {
            @memcpy(buf[0..x.len], x);
            return buf[0..x.len];
        }
    }
    const home = g_env.get("HOME") orelse "";
    if (home.len == 0) return ""; // unset or empty HOME -> no path (avoid a bare "/.Xauthority")
    const suffix = "/.Xauthority";
    if (home.len + suffix.len > buf.len) return "";
    @memcpy(buf[0..home.len], home);
    @memcpy(buf[home.len..][0..suffix.len], suffix);
    return buf[0 .. home.len + suffix.len];
}

fn cmdPinentrySelftest() !void {
    const program = envValue("SINETE_PINENTRY") orelse "pinentry";
    pinentry.selftest(g_io, g_gpa, program) catch |e| {
        var buf: [160]u8 = undefined;
        try stderrWrite(try std.fmt.bufPrint(&buf, "PINENTRY SELFTEST FAIL: {s} (program: {s})\n", .{ @errorName(e), program }));
        std.process.exit(2);
    };
    try stdoutWrite("PINENTRY SELFTEST PASS\n");
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

fn noSecureElement(verb: []const u8) !void {
    var buf: [160]u8 = undefined;
    try stderrWrite(try std.fmt.bufPrint(&buf, "error: '{s}' needs a secure element (macOS Secure Enclave or Linux TPM)\n", .{verb}));
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
