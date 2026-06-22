// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The cross-platform key-authorization seam (see KEY-AUTHZ-DESIGN.md): an `Authorizer`
//! performs the presence gesture + per-key unlock and returns a `Grant` — an authorized,
//! time-bounded signer. Runtime-polymorphic (std.mem.Allocator-style vtable) so the agent
//! core is generic over the backend (macOS SE / Touch ID, Linux TPM ticket, or a fake).

const std = @import("std");

/// An authorized, time-bounded signer. The backend hides whether signing goes through the
/// macOS Secure Enclave, a Linux TPM policy-session ticket, or a test fake.
pub const Grant = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Sign `data`, writing the signature into `out`; returns the byte count.
        sign: *const fn (ptr: *anyopaque, data: []const u8, out: []u8) anyerror!usize,
        /// Whether this grant's window has lapsed (hardware-enforced where available).
        expired: *const fn (ptr: *anyopaque) bool,
    };

    pub fn sign(self: Grant, data: []const u8, out: []u8) !usize {
        return self.vtable.sign(self.ptr, data, out);
    }
    pub fn expired(self: Grant) bool {
        return self.vtable.expired(self.ptr);
    }
};

/// Performs the human presence gesture (and any per-key unlock) for `key_id`, returning a
/// `Grant`. Called by the agent only when a key's presence window is cold; an error means
/// refuse the signature.
pub const Authorizer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        authorize: *const fn (ptr: *anyopaque, key_id: []const u8, reason: []const u8) anyerror!Grant,
    };

    pub fn authorize(self: Authorizer, key_id: []const u8, reason: []const u8) !Grant {
        return self.vtable.authorize(self.ptr, key_id, reason);
    }
};

/// A fake authorizer for unit tests and the early agent (before any TPM/SE backend exists).
/// Counts authorizations; its grants never expire and produce a deterministic 1-byte tag.
pub const Fake = struct {
    granted: usize = 0,
    declines: bool = false,

    pub fn authorizer(self: *Fake) Authorizer {
        return .{ .ptr = self, .vtable = &.{ .authorize = authorize } };
    }
    fn authorize(ptr: *anyopaque, key_id: []const u8, reason: []const u8) !Grant {
        _ = key_id;
        _ = reason;
        const self: *Fake = @ptrCast(@alignCast(ptr));
        if (self.declines) return error.PresenceDeclined;
        self.granted += 1;
        return .{ .ptr = self, .vtable = &grant_vt };
    }
    const grant_vt = Grant.VTable{ .sign = sign, .expired = expired };
    fn sign(ptr: *anyopaque, data: []const u8, out: []u8) !usize {
        _ = ptr;
        if (out.len < 1) return error.NoSpace;
        out[0] = @truncate(data.len);
        return 1;
    }
    fn expired(ptr: *anyopaque) bool {
        _ = ptr;
        return false;
    }
};

test "fake authorizer grants and signs through the vtable seam" {
    var fake = Fake{};
    const az = fake.authorizer();
    const g = try az.authorize("key-1", "sign");
    try std.testing.expect(!g.expired());
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try g.sign("hello", &buf));
    try std.testing.expectEqual(@as(u8, 5), buf[0]);
    try std.testing.expectEqual(@as(usize, 1), fake.granted);
}

test "fake authorizer can decline (refusal path)" {
    var fake = Fake{ .declines = true };
    const az = fake.authorizer();
    try std.testing.expectError(error.PresenceDeclined, az.authorize("k", "r"));
}
