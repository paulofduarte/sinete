// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! Pure presence-policy helpers shared by the platform Authorizers: which gesture to use given the
//! discovered capabilities (a fingerprint reader with an enrolled finger, else a typed confirm).
//! Kept OS-free so the decision is unit-tested without a live fprintd.

const std = @import("std");
const presenter = @import("presenter.zig");

/// The presence capabilities the platform discovered (e.g. by querying fprintd).
pub const Caps = struct {
    /// fprintd (or an equivalent reader) is reachable.
    reader: bool = false,
    /// at least one finger is enrolled for this user.
    enrolled: bool = false,
};

/// The gesture to prompt for. FIDO2 will slot between fingerprint and confirm at Z6.
pub const Gesture = enum { fingerprint, confirm };

/// Select the presence gesture: a fingerprint only when a reader is present AND a finger is enrolled
/// (a present-but-unenrolled reader is useless, so it falls through), otherwise a typed confirm --
/// the universal floor that needs no hardware.
pub fn selectGesture(caps: Caps) Gesture {
    if (caps.reader and caps.enrolled) return .fingerprint;
    return .confirm;
}

/// The promptGesture cue reason for a selected gesture.
pub fn gestureReason(g: Gesture) presenter.Reason {
    return switch (g) {
        .fingerprint => .touch_fingerprint,
        .confirm => .confirm_sign,
    };
}

test "selectGesture: fingerprint only with reader + an enrolled finger" {
    try std.testing.expectEqual(Gesture.fingerprint, selectGesture(.{ .reader = true, .enrolled = true }));
    try std.testing.expectEqual(Gesture.confirm, selectGesture(.{ .reader = true, .enrolled = false })); // present, no fingers
    try std.testing.expectEqual(Gesture.confirm, selectGesture(.{ .reader = false, .enrolled = true })); // enrolled record, no reader
    try std.testing.expectEqual(Gesture.confirm, selectGesture(.{})); // nothing
}

test "gestureReason maps to the prompt cue" {
    try std.testing.expectEqual(presenter.Reason.touch_fingerprint, gestureReason(.fingerprint));
    try std.testing.expectEqual(presenter.Reason.confirm_sign, gestureReason(.confirm));
}
