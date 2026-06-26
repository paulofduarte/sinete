// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! macOS Secure Enclave + Touch ID backend: the Zig side of the Cryptoprocessor and Authorizer
//! seams, wrapping the Security.framework / LocalAuthentication shims (darwin_se.m,
//! darwin_presence.m). It lives in the executable (not lib/) because it links Apple frameworks;
//! the pure byte logic it leans on (ecdsa_key, ecdsa_sig) is in the coverage-gated core.

const std = @import("std");
const sinete = @import("sinete");
const crypto = sinete.crypto;
const authz = sinete.authz;
const wire = sinete.wire;
const ecdsa_key = sinete.ecdsa_key;
const ecdsa_sig = sinete.ecdsa_sig;

/// Mirrors the C `sinete_se_key` in darwin_se.m: an uncompressed point and a NUL-terminated label.
const SeKey = extern struct {
    pub_point: [65]u8,
    label: [128]u8,
};

extern fn sinete_se_enumerate(out: [*]SeKey, max: i32) i32;
extern fn sinete_se_sign(point: [*]const u8, data: [*]const u8, len: usize, der_out: [*]u8, cap: usize) i32;
extern fn sinete_se_generate(label: [*:0]const u8, pub_out: [*]u8) i32;
extern fn sinete_se_remove(point: [*]const u8) i32;
extern fn sinete_authenticate(reason: [*:0]const u8, err: *?[*:0]u8) c_int;

pub const Error = error{ UnknownKey, MissingEntitlement, PresenceDeclined, BackendError };

/// The most keys we read in one enumeration. A personal agent holds a handful; extra keys beyond
/// this are simply not advertised (the shim stops at `max`).
pub const max_keys = 64;

/// Map a negative OSStatus from a shim to a Zig error. Distinct codes get distinct errors so the
/// CLI can explain them; the agent core collapses them to BackendError on the wire.
fn mapStatus(code: i32) Error {
    return switch (code) {
        -25300 => Error.UnknownKey, // errSecItemNotFound
        -34018 => Error.MissingEntitlement, // errSecMissingEntitlement: unsigned or wrong access group
        -128 => Error.PresenceDeclined, // errSecUserCanceled
        else => Error.BackendError,
    };
}

/// The Secure Enclave backend. Stateless: every call goes straight to the keychain, so the same
/// value can back the Cryptoprocessor and Authorizer seams at once.
pub const Darwin = struct {
    pub fn processor(self: *Darwin) crypto.Cryptoprocessor {
        return .{ .ptr = self, .vtable = &cp_vt };
    }
    pub fn authorizer(self: *Darwin) authz.Authorizer {
        return .{ .ptr = self, .vtable = &az_vt };
    }

    const cp_vt = crypto.Cryptoprocessor.VTable{ .enumerate = enumerate, .sign = sign };
    const az_vt = authz.Authorizer.VTable{ .authorize = authorize };

    fn enumerate(ptr: *anyopaque, arena: std.mem.Allocator) anyerror![]const crypto.KeyInfo {
        _ = ptr;
        var buf: [max_keys]SeKey = undefined;
        const n = sinete_se_enumerate(&buf, max_keys);
        if (n < 0) return mapStatus(n);
        const count: usize = @intCast(n);
        const out = try arena.alloc(crypto.KeyInfo, count);
        for (buf[0..count], 0..) |k, i| {
            var enc = wire.Encoder.init(arena);
            try ecdsa_key.writePubBlob(&enc, &k.pub_point);
            out[i] = .{
                .blob = try arena.dupe(u8, enc.bytes()),
                .comment = try arena.dupe(u8, std.mem.sliceTo(&k.label, 0)),
            };
        }
        return out;
    }

    fn sign(ptr: *anyopaque, key_id: []const u8, data: []const u8, out: []u8) anyerror!usize {
        _ = ptr;
        const point = try ecdsa_key.pointFromPubBlob(key_id);
        var der: [80]u8 = undefined; // a P-256 DER ECDSA-Sig-Value is <= 72 bytes
        const dn = sinete_se_sign(point, data.ptr, data.len, &der, der.len);
        if (dn < 0) return mapStatus(dn);
        return ecdsa_sig.derP256ToSshBlob(der[0..@intCast(dn)], out);
    }

    fn authorize(ptr: *anyopaque, key_id: []const u8, reason: []const u8) anyerror!void {
        _ = ptr;
        _ = key_id; // the gesture is presence-only; the entitlement wall binds key use
        var rbuf: [256]u8 = undefined;
        const r: [:0]const u8 = std.fmt.bufPrintZ(&rbuf, "{s}", .{reason}) catch "authenticate to use a sinete key";
        var err_msg: ?[*:0]u8 = null;
        if (sinete_authenticate(r.ptr, &err_msg) == 1) return;
        if (err_msg) |m| std.c.free(m);
        return Error.PresenceDeclined;
    }

    /// Create a new presence-less Secure Enclave key, writing its uncompressed point to point_out.
    pub fn generate(self: *Darwin, label: [*:0]const u8, point_out: *[65]u8) !void {
        _ = self;
        const code = sinete_se_generate(label, point_out);
        if (code != 0) return mapStatus(code);
    }

    /// Delete the Secure Enclave key whose public point is `point`.
    pub fn remove(self: *Darwin, point: *const [65]u8) !void {
        _ = self;
        const code = sinete_se_remove(point);
        if (code != 0) return mapStatus(code);
    }
};
