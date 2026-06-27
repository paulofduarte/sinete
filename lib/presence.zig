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

/// Where to draw a prompt/message for a session: a graphical modal, or a terminal. Decided from the
/// logind session Type and TTY -- pure so the policy is unit-tested without a live bus.
pub const Channel = enum { graphical, terminal };

/// A graphical session draws a modal; a session with a controlling terminal (a local console or an
/// ssh pts) draws on that terminal; an unknown/typeless session with no tty prefers graphical (a
/// modal, which degrades to the log until the modal backends exist).
pub fn pickChannel(session_type: []const u8, tty: []const u8) Channel {
    if (isGraphical(session_type)) return .graphical;
    if (tty.len > 0) return .terminal;
    return .graphical;
}

fn isGraphical(session_type: []const u8) bool {
    return std.mem.eql(u8, session_type, "x11") or
        std.mem.eql(u8, session_type, "wayland") or
        std.mem.eql(u8, session_type, "mir");
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

test "pickChannel: graphical type wins; otherwise a tty is a terminal; else graphical" {
    try std.testing.expectEqual(Channel.graphical, pickChannel("wayland", "")); // graphical, no tty
    try std.testing.expectEqual(Channel.graphical, pickChannel("x11", "/dev/tty2")); // graphical even with a tty
    try std.testing.expectEqual(Channel.terminal, pickChannel("tty", "/dev/pts/3")); // ssh pts
    try std.testing.expectEqual(Channel.terminal, pickChannel("tty", "/dev/tty3")); // local console
    try std.testing.expectEqual(Channel.graphical, pickChannel("tty", "")); // typeless, no tty -> modal/log
    try std.testing.expectEqual(Channel.graphical, pickChannel("", "")); // unknown -> graphical
}
