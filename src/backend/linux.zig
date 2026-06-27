// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The Linux TPM 2.0 backend: drives the pure command marshaling (sinete.tpm_commands) over the
//! device (tpm_device.zig). Mirrors the macOS darwin backend behind the same vtable seams. Impure
//! (real TPM I/O) so it is verified against swtpm by the integration selftest, not unit tests; the
//! marshaling it calls is unit-tested in lib/tpm. v1 keys are presence-less (Z5 adds the gesture).

const std = @import("std");
const sinete = @import("sinete");
const cmd = sinete.tpm_commands;
const ecdsa_sig = sinete.ecdsa_sig;
const ecdsa_key = sinete.ecdsa_key;
const wire = sinete.wire;
const keyfile = sinete.tpm_keyfile;
const crypto = sinete.crypto;
const device = @import("tpm_device.zig");

/// The largest TSS2 key file we read (PEM); a P-256 loadable key is a few hundred bytes.
const max_keyfile = 8192;

/// A TPM session: the device plus scratch buffers for one command and its response. The response
/// slice is invalidated by the next transact, so callers copy out anything they need to keep.
pub const Tpm = struct {
    dev: device.Device,
    cmdbuf: [1024]u8 = undefined,
    respbuf: [4096]u8 = undefined,

    pub fn open(io: std.Io, path: []const u8, is_socket: bool) !Tpm {
        return .{ .dev = try device.Device.open(io, path, is_socket) };
    }
    pub fn close(self: *Tpm) void {
        self.dev.close();
    }
    const rc_retry: u32 = 0x922; // TPM_RC_RETRY: the TPM is busy (e.g. background self-test); re-send

    fn transact(self: *Tpm, command: []const u8) ![]const u8 {
        var tries: u8 = 0;
        while (true) : (tries += 1) {
            const resp = try self.dev.transact(command, &self.respbuf);
            if (resp.len >= 10 and tries < 100 and std.mem.readInt(u32, resp[6..10], .big) == rc_retry) {
                // Back off ~1ms between retries so a busy TPM (or swtpm running its self-test) is not
                // hammered in a tight CPU-spinning loop; <=100ms total before we give up and return.
                self.dev.io.sleep(.fromMilliseconds(1), .awake) catch {};
                continue;
            }
            return resp;
        }
    }
};

/// A freshly created or loaded ECDSA P-256 key's persisted material + its public point.
pub const KeyBlobs = struct {
    private: [256]u8 = undefined,
    private_len: usize = 0,
    public: [256]u8 = undefined,
    public_len: usize = 0,
    point: [65]u8 = undefined,

    pub const Error = error{BlobTooLarge};

    pub fn priv(self: *const KeyBlobs) []const u8 {
        return self.private[0..self.private_len];
    }
    pub fn pub_blob(self: *const KeyBlobs) []const u8 {
        return self.public[0..self.public_len];
    }

    /// Copy a TPM2B_PRIVATE blob in, rejecting anything that would overflow the fixed buffer (a
    /// well-formed P-256 key is well under 256 bytes; this fails closed on a malformed/oversized one).
    fn setPrivate(self: *KeyBlobs, b: []const u8) Error!void {
        if (b.len > self.private.len) return Error.BlobTooLarge;
        @memcpy(self.private[0..b.len], b);
        self.private_len = b.len;
    }
    /// Copy a TPM2B_PUBLIC blob in, with the same overflow guard as setPrivate.
    fn setPublic(self: *KeyBlobs, b: []const u8) Error!void {
        if (b.len > self.public.len) return Error.BlobTooLarge;
        @memcpy(self.public[0..b.len], b);
        self.public_len = b.len;
    }
};

/// Best-effort flush of a transient TPM object, so primaries and loaded keys do not accumulate on a
/// raw TPM (swtpm) across operations.
fn flush(t: *Tpm, handle: u32) void {
    const c = cmd.flushContext(&t.cmdbuf, handle) catch return;
    _ = t.transact(c) catch {};
}

/// Set the process umask, returning the previous value (raw Linux syscall; this file is linux-only).
fn osUmask(mode: std.posix.mode_t) std.posix.mode_t {
    return @intCast(std.os.linux.syscall1(.umask, mode));
}

/// Fill `buf` with kernel CSPRNG bytes via the getrandom syscall (std.crypto.random is gone in 0.16;
/// this file is linux-only). Used for the master secret and TPM session nonces.
fn randomBytes(buf: []u8) error{Getrandom}!void {
    var off: usize = 0;
    while (off < buf.len) {
        const rc = std.os.linux.getrandom(buf[off..].ptr, buf.len - off, 0);
        const n: isize = @bitCast(rc);
        if (n <= 0) return error.Getrandom;
        off += @intCast(n);
    }
}

/// Whether a key filename is safe to surface as a single-line SSH key comment. A name with a newline
/// or carriage return (valid on a Linux filesystem) could split list/export output into multiple
/// records (e.g. injecting an extra authorized_keys line), so such files are ignored everywhere.
fn safeKeyName(name: []const u8) bool {
    return std.mem.indexOfAny(u8, name, "\n\r") == null;
}

/// CreatePrimary under the owner hierarchy: a deterministic ECC P-256 storage parent. Returns the
/// transient handle (valid until the TPM is reset). Re-derived per session.
fn createPrimary(t: *Tpm) !u32 {
    const c = try cmd.createPrimary(&t.cmdbuf);
    return cmd.createPrimaryHandle(try t.transact(c));
}

/// Create a new ECDSA P-256 signing key under `parent`, copying its (private, public) blobs and
/// public point into `out`.
fn createKey(t: *Tpm, parent: u32, out: *KeyBlobs) !void {
    const c = try cmd.create(&t.cmdbuf, parent);
    const blobs = try cmd.createKeyBlobs(try t.transact(c));
    try out.setPrivate(blobs.private);
    try out.setPublic(blobs.public);
    try cmd.pointFromPublic(out.pub_blob(), &out.point);
}

/// Create an ECDSA P-256 signing key bound to `auth_policy` (no password), copying its blobs + point.
fn createPolicyKeyBlobs(t: *Tpm, parent: u32, auth_policy: []const u8, out: *KeyBlobs) !void {
    const c = try cmd.createPolicyKey(&t.cmdbuf, parent, auth_policy);
    const blobs = try cmd.createKeyBlobs(try t.transact(c));
    try out.setPrivate(blobs.private);
    try out.setPublic(blobs.public);
    try cmd.pointFromPublic(out.pub_blob(), &out.point);
}

/// Load a saved key under `parent`, returning its transient handle.
fn loadKey(t: *Tpm, parent: u32, k: *const KeyBlobs) !u32 {
    const c = try cmd.load(&t.cmdbuf, parent, k.priv(), k.pub_blob());
    return cmd.loadHandle(try t.transact(c));
}

/// Sign a 32-byte SHA-256 digest with the loaded key, writing the SSH signature blob into `out`.
fn signDigest(t: *Tpm, key: u32, digest: []const u8, out: []u8) !usize {
    const c = try cmd.sign(&t.cmdbuf, key, digest);
    const sig = try cmd.signResult(try t.transact(c));
    return ecdsa_sig.rawRsToSshBlob(sig.r, sig.s, out);
}

// --- Z5b: the master NV index and the policy-bound sign path ---

const master_index: u32 = 0x018E7E7F; // sibling of the epoch index; holds the PolicySecret authValue S
const master_secret_file = "master.secret";

/// Ensure the master NV index exists (define + write-once to set WRITTEN) with authValue `secret`,
/// then return the PolicySecret authPolicy digest computed from its current Name. The Name aliases
/// the response buffer, so the digest is computed before any further transact.
fn masterPolicy(t: *Tpm, secret: []const u8) ![32]u8 {
    const def = try cmd.nvDefineMaster(&t.cmdbuf, master_index, secret);
    if (try cmd.checkOrDefined(try t.transact(def)) == .ok) {
        const w = try cmd.nvWrite(&t.cmdbuf, master_index, secret, &[_]u8{0}); // any write sets WRITTEN
        try cmd.expectOk(try t.transact(w));
    }
    const rp = try cmd.nvReadPublic(&t.cmdbuf, master_index);
    const name = try cmd.nvReadPublicName(try t.transact(rp));
    return cmd.policySecretDigest(name);
}

/// Sign a digest with a policy-bound key: open a policy session, satisfy its PolicySecret by proving
/// the master secret `S`, then Sign authorized by that session (empty HMAC). The session auto-flushes
/// on the Sign (continueSession=0); flush defensively in case an earlier step failed.
fn signDigestPolicy(t: *Tpm, key: u32, digest: []const u8, secret: []const u8, out: []u8) !usize {
    var nonce: [32]u8 = undefined;
    try randomBytes(&nonce);
    const sa = try cmd.startAuthSession(&t.cmdbuf, cmd.se_policy, &nonce);
    const sess = try cmd.startAuthSessionResult(try t.transact(sa));
    errdefer flush(t, sess.handle);

    const ps = try cmd.policySecret(&t.cmdbuf, master_index, sess.handle, secret, sess.nonce_tpm, 0);
    try cmd.expectOk(try t.transact(ps));

    var nonce2: [32]u8 = undefined;
    try randomBytes(&nonce2);
    const sg = try cmd.signPolicy(&t.cmdbuf, key, digest, sess.handle, &nonce2);
    const sig = try cmd.signResult(try t.transact(sg));
    return ecdsa_sig.rawRsToSshBlob(sig.r, sig.s, out);
}

// --- the Cryptoprocessor backend: file-backed TPM keys ---

/// The Linux TPM backend. Keys live as TSS2 key files in `keydir`, loaded into the TPM on demand;
/// the device is /dev/tpmrm0 or a swtpm socket. The Cryptoprocessor only; presence is the separate
/// fprintd Authorizer (Z5a). Policy-bound keys (Z5b) also need the master secret S, loaded from
/// `keydir/master.secret` when present; `master.secret` absent means no policy keys can be signed.
pub const Linux = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    keydir: []const u8,
    tpm_path: []const u8,
    tpm_is_socket: bool,
    master_secret: [32]u8 = undefined,
    has_master: bool = false,

    pub fn processor(self: *Linux) crypto.Cryptoprocessor {
        return .{ .ptr = self, .vtable = &cp_vt };
    }

    const cp_vt = crypto.Cryptoprocessor.VTable{ .enumerate = enumerate, .sign = sign };

    fn enumerate(ptr: *anyopaque, arena: std.mem.Allocator) anyerror![]const crypto.KeyInfo {
        const self: *Linux = @ptrCast(@alignCast(ptr));
        // Only a missing key directory means "no keys"; surface AccessDenied/I/O errors so the agent
        // doesn't silently behave as if the user has no keys.
        var dir = std.Io.Dir.cwd().openDir(self.io, self.keydir, .{ .iterate = true }) catch |e| switch (e) {
            error.FileNotFound => return &.{},
            else => return e,
        };
        defer dir.close(self.io);

        var list: std.ArrayList(crypto.KeyInfo) = .empty;
        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (entry.kind != .file) continue;
            if (!safeKeyName(entry.name)) continue; // never emit a multi-line key record
            // A file racing deletion mid-iteration is fine to skip; AccessDenied/I/O is surfaced.
            const pem = dir.readFileAlloc(self.io, entry.name, arena, .limited(max_keyfile)) catch |e| switch (e) {
                error.FileNotFound => continue,
                else => return e,
            };
            var scratch: [max_keyfile]u8 = undefined;
            const blobs = keyfile.decode(pem, &scratch) catch continue; // not a valid key file: skip
            var point: [65]u8 = undefined;
            cmd.pointFromPublic(blobs.public, &point) catch continue;
            var enc = wire.Encoder.init(arena);
            defer enc.deinit();
            ecdsa_key.writePubBlob(&enc, &point) catch continue;
            try list.append(arena, .{
                .blob = try arena.dupe(u8, enc.bytes()),
                .comment = try arena.dupe(u8, entry.name),
            });
        }
        return list.toOwnedSlice(arena);
    }

    fn sign(ptr: *anyopaque, key_id: []const u8, data: []const u8, out: []u8) anyerror!usize {
        const self: *Linux = @ptrCast(@alignCast(ptr));
        const want = try ecdsa_key.pointFromPubBlob(key_id);
        var key: KeyBlobs = .{};
        if (!try self.findKey(want, &key)) return error.UnknownKey;

        var t = try Tpm.open(self.io, self.tpm_path, self.tpm_is_socket);
        defer t.close();
        const primary = try createPrimary(&t);
        const handle = try loadKey(&t, primary, &key);
        defer flush(&t, handle);
        flush(&t, primary); // the parent is only needed to load; free its slot before the sign/session
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});

        // A policy-bound key (Z5b) signs only via a policy session proving the master secret; a
        // legacy Z4 empty-auth key signs directly. They coexist in one key directory.
        if (try cmd.hasAuthPolicy(key.pub_blob())) {
            if (!self.has_master) return error.NoMaster; // a copied key file without the secret cannot sign
            return signDigestPolicy(&t, handle, &digest, &self.master_secret, out);
        }
        return signDigest(&t, handle, &digest, out);
    }

    /// Find the key file whose public point equals `want`, copying its blobs into `out`.
    fn findKey(self: *Linux, want: *const [65]u8, out: *KeyBlobs) !bool {
        var dir = std.Io.Dir.cwd().openDir(self.io, self.keydir, .{ .iterate = true }) catch |e| switch (e) {
            error.FileNotFound => return false,
            else => return e,
        };
        defer dir.close(self.io);
        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (entry.kind != .file) continue;
            if (!safeKeyName(entry.name)) continue; // ignore uniformly with enumerate
            // A file racing deletion mid-iteration is fine to skip; AccessDenied/I/O is surfaced.
            const pem = dir.readFileAlloc(self.io, entry.name, self.gpa, .limited(max_keyfile)) catch |e| switch (e) {
                error.FileNotFound => continue,
                else => return e,
            };
            defer self.gpa.free(pem);
            var scratch: [max_keyfile]u8 = undefined;
            const blobs = keyfile.decode(pem, &scratch) catch continue;
            var point: [65]u8 = undefined;
            cmd.pointFromPublic(blobs.public, &point) catch continue;
            if (!std.mem.eql(u8, &point, want)) continue;
            try out.setPublic(blobs.public);
            try out.setPrivate(blobs.private);
            @memcpy(&out.point, &point);
            return true;
        }
        return false;
    }

    /// Load the master secret S from keydir/master.secret (0600) if present, so policy keys can sign.
    /// Best-effort: a missing/short file just leaves has_master false (no policy keys can be signed).
    pub fn loadMasterSecret(self: *Linux) void {
        var dir = std.Io.Dir.cwd().openDir(self.io, self.keydir, .{}) catch return;
        defer dir.close(self.io);
        const data = dir.readFileAlloc(self.io, master_secret_file, self.gpa, .limited(64)) catch return;
        defer self.gpa.free(data);
        if (data.len != 32) return;
        @memcpy(&self.master_secret, data);
        self.has_master = true;
    }

    /// Return the master secret S, generating + persisting it (0600) on first use so the policy
    /// binding is on by default with no separate enroll step.
    fn ensureMasterSecret(self: *Linux) ![32]u8 {
        if (self.has_master) return self.master_secret;
        var s: [32]u8 = undefined;
        try randomBytes(&s);
        const old_umask = osUmask(0o077);
        defer _ = osUmask(old_umask);
        try std.Io.Dir.cwd().createDirPath(self.io, self.keydir);
        try std.Io.Dir.cwd().setFilePermissions(self.io, self.keydir, @enumFromInt(0o700), .{ .follow_symlinks = false });
        var dir = try std.Io.Dir.cwd().openDir(self.io, self.keydir, .{});
        defer dir.close(self.io);
        var file = try dir.createFile(self.io, master_secret_file, .{ .exclusive = true });
        errdefer dir.deleteFile(self.io, master_secret_file) catch {};
        defer file.close(self.io);
        try file.writeStreamingAll(self.io, &s);
        try dir.setFilePermissions(self.io, master_secret_file, @enumFromInt(0o600), .{ .follow_symlinks = false });
        self.master_secret = s;
        self.has_master = true;
        return s;
    }

    /// Generate a new policy-bound ECDSA P-256 key, persist it as a TSS2 key file named `name`, and
    /// return its public point. The key is bound to the master via a TPM authPolicy, so signing it
    /// later requires proving the master secret (after the presence gesture).
    pub fn generate(self: *Linux, name: []const u8) ![65]u8 {
        var t = try Tpm.open(self.io, self.tpm_path, self.tpm_is_socket);
        defer t.close();
        const secret = try self.ensureMasterSecret();
        const policy = try masterPolicy(&t, &secret);
        const primary = try createPrimary(&t);
        defer flush(&t, primary);
        var key: KeyBlobs = .{};
        try createPolicyKeyBlobs(&t, primary, &policy, &key);

        var pem_buf: [max_keyfile]u8 = undefined;
        const pem = try keyfile.encode(&pem_buf, key.pub_blob(), key.priv());

        // Owner-only from birth: a restrictive umask means the directory and key file are never even
        // momentarily group/world-readable (the file holds TPM-wrapped private material). Restored on
        // every path; the CLI generate flow is single-threaded. The explicit chmods below still pin the
        // mode regardless of the inherited umask, and on a failed lock-down the file is removed rather
        // than left behind with default permissions.
        const old_umask = osUmask(0o077);
        defer _ = osUmask(old_umask);
        // Fail fast if the key directory can't be created or locked to 0700: it governs who can list
        // and replace key files, so a masked AccessDenied (or a left-permissive dir) is not acceptable.
        // createDirPath is idempotent, so an already-present directory is not an error.
        try std.Io.Dir.cwd().createDirPath(self.io, self.keydir);
        try std.Io.Dir.cwd().setFilePermissions(self.io, self.keydir, @enumFromInt(0o700), .{ .follow_symlinks = false });
        var dir = try std.Io.Dir.cwd().openDir(self.io, self.keydir, .{});
        defer dir.close(self.io);
        // Exclusive create: never silently overwrite an existing key file. Clobbering a live key would
        // break that key's auth/signing; the caller must `remove` it first to regenerate under the name.
        var file = dir.createFile(self.io, name, .{ .exclusive = true }) catch |e| switch (e) {
            error.PathAlreadyExists => return error.KeyExists,
            else => return e,
        };
        errdefer dir.deleteFile(self.io, name) catch {};
        defer file.close(self.io);
        try file.writeStreamingAll(self.io, pem);
        try dir.setFilePermissions(self.io, name, @enumFromInt(0o600), .{ .follow_symlinks = false });
        return key.point;
    }

    /// Delete the key file named `name`.
    pub fn remove(self: *Linux, name: []const u8) !void {
        var dir = try std.Io.Dir.cwd().openDir(self.io, self.keydir, .{});
        defer dir.close(self.io);
        try dir.deleteFile(self.io, name);
    }
};

/// A self-test exercising the whole TPM path against a real (or software) TPM: create a key, sign a
/// known message, verify the signature with std.crypto, and round-trip the NV epoch counter. Prints
/// progress and returns an error on the first failure. Run against swtpm in CI/Docker.
pub fn selftest(io: std.Io, path: []const u8, is_socket: bool) !void {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var t = try Tpm.open(io, path, is_socket);
    defer t.close();

    var log_buf: [128]u8 = undefined;
    const out = std.Io.File.stdout();
    const note = struct {
        fn p(o: std.Io.File, i: std.Io, b: *[128]u8, comptime f: []const u8, a: anytype) void {
            o.writeStreamingAll(i, std.fmt.bufPrint(b, f ++ "\n", a) catch return) catch {};
        }
    }.p;

    const primary = try createPrimary(&t);
    defer flush(&t, primary);
    note(out, io, &log_buf, "createPrimary -> handle 0x{x}", .{primary});

    var key: KeyBlobs = .{};
    try createKey(&t, primary, &key);
    note(out, io, &log_buf, "create -> {d}-byte priv, {d}-byte pub, point 0x{x:0>2}...", .{ key.private_len, key.public_len, key.point[1] });

    const handle = try loadKey(&t, primary, &key);
    defer flush(&t, handle);
    note(out, io, &log_buf, "load -> handle 0x{x}", .{handle});

    const msg = "sinete z4 tpm selftest";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
    var sshsig: [256]u8 = undefined;
    const n = try signDigest(&t, handle, &digest, &sshsig);
    note(out, io, &log_buf, "sign -> {d}-byte SSH signature blob", .{n});

    // Verify with std.crypto: decode the SSH blob back to r||s and check against the public point.
    var dec = sinete.wire.Decoder{ .data = sshsig[0..n] };
    _ = try dec.string(); // "ecdsa-sha2-nistp256"
    var inner = sinete.wire.Decoder{ .data = try dec.string() };
    const r = try inner.string();
    const s = try inner.string();
    var rs: [64]u8 = undefined;
    @memset(&rs, 0);
    copyRight(rs[0..32], r);
    copyRight(rs[32..64], s);
    const pk = try Ecdsa.PublicKey.fromSec1(&key.point);
    const sig = Ecdsa.Signature.fromBytes(rs);
    try sig.verify(msg, pk);
    note(out, io, &log_buf, "verify -> OK (signature valid for the TPM public key)", .{});

    // NV epoch: ensure -> read -> increment -> read (+1).
    try ensureEpoch(&t);
    const e0 = try readEpoch(&t);
    const e1 = try incrementEpoch(&t);
    if (e1 != e0 + 1) return error.EpochNotMonotonic;
    note(out, io, &log_buf, "epoch -> {d} then {d} (+1)", .{ e0, e1 });
    note(out, io, &log_buf, "SELFTEST PASS", .{});
}

/// Verify an SSH ecdsa-sha2-nistp256 signature blob against a public point, for the selftests.
fn verifySshSig(sshsig: []const u8, msg: []const u8, point: *const [65]u8) !void {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var dec = sinete.wire.Decoder{ .data = sshsig };
    _ = try dec.string(); // "ecdsa-sha2-nistp256"
    var inner = sinete.wire.Decoder{ .data = try dec.string() };
    var rs: [64]u8 = undefined;
    @memset(&rs, 0);
    copyRight(rs[0..32], try inner.string());
    copyRight(rs[32..64], try inner.string());
    try Ecdsa.Signature.fromBytes(rs).verify(msg, try Ecdsa.PublicKey.fromSec1(point));
}

/// Exercise the Z5b policy binding against a TPM: enroll a master, create a policy-bound key, prove
/// the binding (an empty-auth Sign on it MUST fail), then sign via the policy session and verify.
pub fn policySelftest(io: std.Io, path: []const u8, is_socket: bool) !void {
    var t = try Tpm.open(io, path, is_socket);
    defer t.close();
    var log_buf: [128]u8 = undefined;
    const out = std.Io.File.stdout();
    const note = struct {
        fn p(o: std.Io.File, i: std.Io, b: *[128]u8, comptime f: []const u8, a: anytype) void {
            o.writeStreamingAll(i, std.fmt.bufPrint(b, f ++ "\n", a) catch return) catch {};
        }
    }.p;

    const secret = [_]u8{0x5A} ** 32;
    const policy = try masterPolicy(&t, &secret);
    note(out, io, &log_buf, "masterPolicy -> 0x{x:0>2}{x:0>2}...", .{ policy[0], policy[1] });

    const primary = try createPrimary(&t);
    var key: KeyBlobs = .{};
    try createPolicyKeyBlobs(&t, primary, &policy, &key);
    const handle = try loadKey(&t, primary, &key);
    defer flush(&t, handle);
    flush(&t, primary);
    note(out, io, &log_buf, "policy key created + loaded", .{});

    const msg = "sinete z5b policy selftest";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});

    // Negative: an empty-password Sign on the policy key must be rejected by the TPM.
    var sbuf: [256]u8 = undefined;
    if (signDigest(&t, handle, &digest, &sbuf)) |_| {
        return error.PolicyBindingBypassed; // empty-auth signed a policy key -> the binding is broken
    } else |_| {
        note(out, io, &log_buf, "negative -> empty-auth sign rejected (binding holds)", .{});
    }

    // Positive: sign via the policy session, then verify the signature.
    const n = try signDigestPolicy(&t, handle, &digest, &secret, &sbuf);
    try verifySshSig(sbuf[0..n], msg, &key.point);
    note(out, io, &log_buf, "positive -> policy-session sign verifies", .{});
    note(out, io, &log_buf, "POLICY SELFTEST PASS", .{});
}

fn copyRight(dst: []u8, src: []const u8) void {
    // Place an SSH mpint into a fixed field: drop a leading 0x00 sign pad (src longer than dst), or
    // right-align a short magnitude.
    if (src.len >= dst.len) {
        @memcpy(dst, src[src.len - dst.len ..]);
    } else {
        @memcpy(dst[dst.len - src.len ..], src);
    }
}

// --- NV epoch counter ---

const epoch_index: u32 = 0x018E7E7E;

fn ensureEpoch(t: *Tpm) !void {
    // Define-if-absent, then a first increment to initialize the WRITTEN bit. Both are idempotent:
    // a define on an existing index returns NV_DEFINED, an increment is always valid once defined.
    const def = try cmd.nvDefineCounter(&t.cmdbuf, epoch_index);
    const r = try cmd.checkOrDefined(try t.transact(def));
    if (r == .defined) {
        // already exists; ensure it has been written at least once
        _ = incrementEpoch(t) catch {};
        return;
    }
    _ = try incrementEpoch(t); // initialize a freshly defined counter
}

fn readEpoch(t: *Tpm) !u64 {
    const c = try cmd.nvRead(&t.cmdbuf, epoch_index, 8, 0);
    return cmd.nvReadU64(try t.transact(c));
}

fn incrementEpoch(t: *Tpm) !u64 {
    const c = try cmd.nvIncrement(&t.cmdbuf, epoch_index);
    try cmd.expectOk(try t.transact(c));
    return readEpoch(t);
}
