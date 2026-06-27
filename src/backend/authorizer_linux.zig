// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The Linux presence orchestrator: it is the agent's Authorizer AND its Presenter. On a cold
//! window the core calls authorize(); the orchestrator picks the gesture (a fingerprint when a
//! reader is present, else a typed confirm) and drives it through the right channel. On a refusal
//! the core calls showError(); the orchestrator shows the reason on the same channel. The channel
//! is resolved from the peer credential via logind (logind.peerTty): a session with a controlling
//! terminal (a local console or an ssh pts) prompts on that terminal; a graphical session is a modal
//! channel, whose backends land in later milestones (until then a gesture there is unavailable and a
//! message falls back to the log). Everything fails closed: an unusable channel refuses (authorize)
//! or falls back to the log (showError).

const std = @import("std");
const sinete = @import("sinete");
const authz = sinete.authz;
const pres = sinete.presenter;
const presence = sinete.presence;
const session = sinete.session;
const fprintd = @import("fprintd.zig");
const logind = @import("logind.zig");
const tty = @import("tty_prompt.zig");
const pinentry = @import("pinentry.zig");
const presenter_log = @import("presenter_log.zig");

pub const Authorizer = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    fp: *fprintd.Fprintd,
    /// Resolves the peer's prompt channel (graphical vs which terminal) from its logind session.
    lg: *logind.Logind,
    /// The X11 DISPLAY forwarded to pinentry for a graphical prompt; "" if unset.
    display: []const u8,
    /// Log fallback for showError, and the always-on floor so a refusal is never lost.
    log: presenter_log.LogPresenter,

    pub fn init(io: std.Io, gpa: std.mem.Allocator, fp: *fprintd.Fprintd, lg: *logind.Logind, display: []const u8) Authorizer {
        return .{ .io = io, .gpa = gpa, .fp = fp, .lg = lg, .display = display, .log = .{ .io = io } };
    }

    pub fn authorizer(self: *Authorizer) authz.Authorizer {
        return .{ .ptr = self, .vtable = &az_vt };
    }
    pub fn presenter(self: *Authorizer) pres.Presenter {
        return .{ .ptr = self, .vtable = &pr_vt };
    }

    const az_vt = authz.Authorizer.VTable{ .authorize = authorize };
    const pr_vt = pres.Presenter.VTable{ .promptGesture = promptGesture, .promptInput = promptInput, .showError = showError };

    // --- Authorizer ---

    fn authorize(ptr: *anyopaque, cred: ?session.Cred, key_id: []const u8, reason: []const u8) anyerror!void {
        const self: *Authorizer = @ptrCast(@alignCast(ptr));
        _ = key_id; // presence-only; per-key binding is the TPM policy
        _ = reason;

        // Choose from the one capability we can measure today: a reachable default device routes to
        // the fingerprint verify, otherwise a typed confirm. Enrolled-finger detection (the full
        // presence.selectGesture Caps) is a later refinement; until then an enrolled-less reader
        // still routes to the verify, which refuses.
        const gesture: presence.Gesture = if (self.fp.hasDevice()) .fingerprint else .confirm;
        switch (gesture) {
            .fingerprint => try self.fp.authorize(), // fprintd renders its own reader prompt for now
            .confirm => {
                const outcome = self.confirm(cred, .confirm_sign) catch return error.PresenceUnavailable;
                switch (outcome) {
                    .confirmed => return,
                    .declined, .cancelled => return error.PresenceDeclined,
                    .unavailable => return error.PresenceUnavailable,
                }
            },
        }
    }

    /// Drive a confirm for `cred`, using `reason` for the prompt text: on a terminal session via the
    /// pure-Zig termios prompt, otherwise (a graphical session) via a pinentry dialog. Errors only
    /// when no channel is usable, which the caller maps to PresenceUnavailable.
    fn confirm(self: *Authorizer, cred: ?session.Cred, reason: pres.Reason) !pres.Outcome {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (self.targetTty(cred, &buf)) |path| return tty.promptConfirm(path, reason);
        var pe = pinentry.Pinentry{ .io = self.io, .gpa = self.gpa, .display = self.display };
        return pe.confirm(reason) catch return error.TtyUnavailable;
    }

    // --- Presenter ---

    fn promptGesture(ptr: *anyopaque, cred: ?session.Cred, reason: pres.Reason, done: ?*std.atomic.Value(bool)) anyerror!pres.Outcome {
        const self: *Authorizer = @ptrCast(@alignCast(ptr));
        _ = done; // async dismiss is used by the fingerprint cue (a later milestone)
        return self.confirm(cred, reason);
    }
    fn promptInput(ptr: *anyopaque, cred: ?session.Cred, reason: pres.Reason, out: []u8) anyerror!usize {
        _ = ptr;
        _ = cred;
        _ = reason;
        _ = out;
        return error.Unsupported; // PIN entry is deferred (master-key / FIDO2)
    }
    fn showError(ptr: *anyopaque, cred: ?session.Cred, reason: pres.Reason, detail: []const u8) void {
        const self: *Authorizer = @ptrCast(@alignCast(ptr));
        // Floor first: always record the reason (with detail) in the log, so a refusal is never lost
        // even if the terminal write below silently fails (tty vanished / wrong path / permissions).
        self.log.presenter().showError(cred, reason, detail);
        // Additionally surface the curated message (no detail) on the peer's own channel: its
        // terminal when there is one, otherwise a graphical pinentry dialog (best-effort).
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (self.targetTty(cred, &buf)) |path| {
            tty.showMessage(path, pres.message(reason));
        } else {
            var pe = pinentry.Pinentry{ .io = self.io, .gpa = self.gpa, .display = self.display };
            pe.message(reason);
        }
    }

    /// The terminal to prompt on for `cred`, or null for a graphical (or unresolvable) session -- in
    /// which case a gesture is currently unavailable and a message falls back to the log (the
    /// graphical modal channels land in later milestones). With a peer credential the terminal is the
    /// peer's own logind session TTY (a local console or an ssh pts); without one (no SO_PEERCRED) the
    /// agent's controlling terminal `/dev/tty` is tried, which reaches a foreground-run agent.
    fn targetTty(self: *Authorizer, cred: ?session.Cred, buf: []u8) ?[]const u8 {
        if (cred) |c| {
            if (c.pid <= 0) return null;
            return self.lg.peerTty(@intCast(c.pid), buf);
        }
        const path = "/dev/tty";
        if (path.len > buf.len) return null;
        @memcpy(buf[0..path.len], path);
        return buf[0..path.len];
    }
};
