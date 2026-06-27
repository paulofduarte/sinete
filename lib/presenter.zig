// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The Presenter seam: where sinete renders a presence PROMPT ("act now") and a refusal/failure
//! MESSAGE, decoupled from the agent core. Implemented per channel (pinentry, a built-in X11/Wayland
//! modal, a tty, or a platform-native sheet) behind this vtable; a fake records calls for tests.
//! `showError` is called by the agent core on a refused/declined/failed signature; promptGesture /
//! promptInput are driven by the platform Authorizer when it needs a human gesture or PIN. The cred
//! lets an implementation pick the channel from the peer's session; a fake or a log-only impl
//! ignores it.

const std = @import("std");
const session = @import("session.zig");

/// What is being prompted, or why a signature was refused -- the user-facing reason taxonomy.
pub const Reason = enum {
    // promptGesture cues
    touch_fingerprint,
    confirm_sign,
    // showError taxonomy
    declined,
    unavailable,
    remote_refused,
    hardware,
    unknown_key,
    timeout,
};

/// The result of a gesture prompt.
pub const Outcome = enum { confirmed, declined, cancelled, unavailable };

/// A short, user-facing line for `reason`. Single-line ASCII, so it is safe to write straight to a
/// tty or into a modal without re-escaping.
pub fn message(reason: Reason) []const u8 {
    return switch (reason) {
        .touch_fingerprint => "sinete: touch the fingerprint reader to authorize signing",
        .confirm_sign => "sinete: approve signing with your SSH key?",
        .declined => "sinete: signing refused -- presence was declined",
        .unavailable => "sinete: signing refused -- no presence method is available",
        .remote_refused => "sinete: signing refused -- could not confirm a local session (remote or unverifiable); sign at the machine",
        .hardware => "sinete: signing failed -- the secure hardware returned an error",
        .unknown_key => "sinete: signing refused -- this key is not managed by sinete",
        .timeout => "sinete: signing refused -- presence timed out",
    };
}

pub const Presenter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Render a "do the gesture now" cue and block until it resolves. `done`, when non-null, is
        /// flipped true by another thread (e.g. an fprintd match) to dismiss the cue early.
        promptGesture: *const fn (ptr: *anyopaque, cred: ?session.Cred, reason: Reason, done: ?*std.atomic.Value(bool)) anyerror!Outcome,
        /// Collect a secret (PIN/passphrase) into `out`, returning its length. PR B implementations
        /// return error.Unsupported -- PIN input is deferred to the master-key / FIDO2 work.
        promptInput: *const fn (ptr: *anyopaque, cred: ?session.Cred, reason: Reason, out: []u8) anyerror!usize,
        /// Show a one-shot message (no input). Best-effort: it never fails the caller.
        showError: *const fn (ptr: *anyopaque, cred: ?session.Cred, reason: Reason, detail: []const u8) void,
    };

    pub fn promptGesture(self: Presenter, cred: ?session.Cred, reason: Reason, done: ?*std.atomic.Value(bool)) !Outcome {
        return self.vtable.promptGesture(self.ptr, cred, reason, done);
    }
    pub fn promptInput(self: Presenter, cred: ?session.Cred, reason: Reason, out: []u8) !usize {
        return self.vtable.promptInput(self.ptr, cred, reason, out);
    }
    pub fn showError(self: Presenter, cred: ?session.Cred, reason: Reason, detail: []const u8) void {
        self.vtable.showError(self.ptr, cred, reason, detail);
    }
};

/// A fake presenter for unit tests: records the last error reason and counts calls.
pub const Fake = struct {
    last_error: ?Reason = null,
    errors: usize = 0,
    gestures: usize = 0,

    pub fn presenter(self: *Fake) Presenter {
        return .{ .ptr = self, .vtable = &vt };
    }
    const vt = Presenter.VTable{ .promptGesture = promptGesture, .promptInput = promptInput, .showError = showError };
    fn promptGesture(ptr: *anyopaque, cred: ?session.Cred, reason: Reason, done: ?*std.atomic.Value(bool)) !Outcome {
        _ = cred;
        _ = reason;
        _ = done;
        const self: *Fake = @ptrCast(@alignCast(ptr));
        self.gestures += 1;
        return .confirmed;
    }
    fn promptInput(ptr: *anyopaque, cred: ?session.Cred, reason: Reason, out: []u8) !usize {
        _ = ptr;
        _ = cred;
        _ = reason;
        _ = out;
        return error.Unsupported;
    }
    fn showError(ptr: *anyopaque, cred: ?session.Cred, reason: Reason, detail: []const u8) void {
        _ = cred;
        _ = detail;
        const self: *Fake = @ptrCast(@alignCast(ptr));
        self.last_error = reason;
        self.errors += 1;
    }
};

test "message covers every reason and stays single-line ASCII" {
    inline for (std.meta.fields(Reason)) |f| {
        const m = message(@enumFromInt(f.value));
        try std.testing.expect(m.len > 0);
        try std.testing.expect(std.mem.indexOfAny(u8, m, "\n\r") == null);
        for (m) |b| try std.testing.expect(b < 0x80); // single-line AND ASCII-only
    }
}

test "fake presenter records the last error reason" {
    var f = Fake{};
    const p = f.presenter();
    p.showError(null, .remote_refused, "");
    p.showError(null, .declined, "");
    try std.testing.expectEqual(@as(usize, 2), f.errors);
    try std.testing.expectEqual(Reason.declined, f.last_error.?);
}
