// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! Pure helpers for the terminal presenter: the bytes to draw for a confirm prompt or a one-shot
//! message, and the mapping from a keypress to an Outcome. Kept OS-free (no termios, no fd) so the
//! prompt content and key handling are unit-tested without a tty; the impure src/backend/tty_prompt
//! does the open/raw-mode/read/write.

const std = @import("std");
const presenter = @import("../presenter.zig");

pub const Outcome = presenter.Outcome;

/// The confirm line shown for a gesture: the reason text plus the key legend. Written to the tty as
/// a prompt the user answers with a single key.
pub fn confirmLine(reason: presenter.Reason) []const u8 {
    return switch (reason) {
        // The fingerprint cue is normally drawn elsewhere; if it lands on a tty, still offer confirm.
        .touch_fingerprint => "sinete: touch the reader, or press [y] to approve / [n] to deny: ",
        else => "sinete: approve signing with your SSH key? [y/n]: ",
    };
}

/// Map a single input byte to an Outcome, or null to keep waiting for a decisive key. Only an
/// explicit y/Y approves -- Enter is deliberately NOT an approval, so a stray newline cannot sign;
/// n/N/Esc deny; Ctrl-C/Ctrl-D cancel. Everything else (including Enter) is ignored (null).
pub fn keyOutcome(b: u8) ?Outcome {
    return switch (b) {
        'y', 'Y' => .confirmed,
        'n', 'N', 0x1b => .declined, // Esc
        0x03, 0x04 => .cancelled, // Ctrl-C, Ctrl-D
        else => null, // includes Enter: never approve on a stray newline
    };
}

/// The closing line after a decision, so the prompt does not leave a dangling cursor.
pub fn outcomeLine(o: Outcome) []const u8 {
    return switch (o) {
        .confirmed => "approved\n",
        .declined => "denied\n",
        .cancelled => "cancelled\n",
        .unavailable => "unavailable\n",
    };
}

const testing = std.testing;

test "keyOutcome maps approve/deny/cancel and never approves on Enter" {
    try testing.expectEqual(Outcome.confirmed, keyOutcome('y').?);
    try testing.expectEqual(Outcome.confirmed, keyOutcome('Y').?);
    try testing.expectEqual(Outcome.declined, keyOutcome('n').?);
    try testing.expectEqual(Outcome.declined, keyOutcome(0x1b).?);
    try testing.expectEqual(Outcome.cancelled, keyOutcome(0x03).?);
    try testing.expectEqual(Outcome.cancelled, keyOutcome(0x04).?);
    try testing.expect(keyOutcome('\r') == null); // Enter must not approve a signature
    try testing.expect(keyOutcome('\n') == null);
    try testing.expect(keyOutcome('x') == null);
    try testing.expect(keyOutcome(' ') == null);
}

test "confirmLine and outcomeLine are single-line/terminated and ASCII" {
    inline for (.{ presenter.Reason.confirm_sign, presenter.Reason.touch_fingerprint }) |r| {
        const m = confirmLine(r);
        try testing.expect(m.len > 0);
        for (m) |c| try testing.expect(c < 0x80);
    }
    try testing.expect(std.mem.endsWith(u8, outcomeLine(.confirmed), "\n"));
    try testing.expect(std.mem.endsWith(u8, outcomeLine(.declined), "\n"));
}
