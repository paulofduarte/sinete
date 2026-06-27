// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The presence-authorization interface. An Authorizer performs the human-presence gesture,
//! and any per-key unlock, for a key and returns success or refusal. It is a gate, not a
//! signer: the signature itself is computed by the Cryptoprocessor (crypto.zig) after the gate
//! passes. On macOS the gesture is Touch ID and signing uses the Secure Enclave key; on Linux
//! the gesture is a fingerprint or security-key touch that also establishes the TPM policy the
//! signer consumes. The interface is runtime-polymorphic (an Allocator-style vtable) so the
//! agent core is generic over the backend or a test fake.

const std = @import("std");
const session = @import("session.zig");

/// Performs the presence gesture (and any per-key unlock) for `key_id`, returning normally on
/// success. Called by the agent only when a key's presence window is cold; an error means
/// refuse the signature. `cred` is the connecting peer's credential (null where unavailable); a
/// platform orchestrator uses it to pick the prompt channel (e.g. the peer's terminal). Backends
/// that draw their own prompt regardless (macOS Touch ID, fprintd) ignore it.
pub const Authorizer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        authorize: *const fn (ptr: *anyopaque, cred: ?session.Cred, key_id: []const u8, reason: []const u8) anyerror!void,
    };

    pub fn authorize(self: Authorizer, cred: ?session.Cred, key_id: []const u8, reason: []const u8) !void {
        return self.vtable.authorize(self.ptr, cred, key_id, reason);
    }
};

/// A fake authorizer for unit tests and the early agent (before any TPM/SE backend exists).
/// Counts the gestures performed; can be told to decline to exercise the refusal path.
pub const Fake = struct {
    granted: usize = 0,
    declines: bool = false,
    /// The error returned when `declines` is set; defaults to a user decline, but a test can choose
    /// PresenceUnavailable to exercise the "no reader / unevaluable" path.
    decline_error: anyerror = error.PresenceDeclined,

    pub fn authorizer(self: *Fake) Authorizer {
        return .{ .ptr = self, .vtable = &vt };
    }
    const vt = Authorizer.VTable{ .authorize = authorize };
    fn authorize(ptr: *anyopaque, cred: ?session.Cred, key_id: []const u8, reason: []const u8) !void {
        _ = cred;
        _ = key_id;
        _ = reason;
        const self: *Fake = @ptrCast(@alignCast(ptr));
        if (self.declines) return self.decline_error;
        self.granted += 1;
    }
};

test "fake authorizer grants presence through the vtable seam" {
    var fake = Fake{};
    const az = fake.authorizer();
    try az.authorize(null, "key-1", "sign");
    try az.authorize(null, "key-1", "sign");
    try std.testing.expectEqual(@as(usize, 2), fake.granted);
}

test "fake authorizer can decline (refusal path)" {
    var fake = Fake{ .declines = true };
    const az = fake.authorizer();
    try std.testing.expectError(error.PresenceDeclined, az.authorize(null, "k", "r"));
    try std.testing.expectEqual(@as(usize, 0), fake.granted);
}
