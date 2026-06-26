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
const device = @import("tpm_device.zig");

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
            if (resp.len >= 10 and tries < 100 and std.mem.readInt(u32, resp[6..10], .big) == rc_retry) continue;
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

    pub fn priv(self: *const KeyBlobs) []const u8 {
        return self.private[0..self.private_len];
    }
    pub fn pub_blob(self: *const KeyBlobs) []const u8 {
        return self.public[0..self.public_len];
    }
};

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
    out.private_len = blobs.private.len;
    out.public_len = blobs.public.len;
    @memcpy(out.private[0..blobs.private.len], blobs.private);
    @memcpy(out.public[0..blobs.public.len], blobs.public);
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
    note(out, io, &log_buf, "createPrimary -> handle 0x{x}", .{primary});

    var key: KeyBlobs = .{};
    try createKey(&t, primary, &key);
    note(out, io, &log_buf, "create -> {d}-byte priv, {d}-byte pub, point 0x{x:0>2}...", .{ key.private_len, key.public_len, key.point[1] });

    const handle = try loadKey(&t, primary, &key);
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
