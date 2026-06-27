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
const presenter_log = @import("presenter_log.zig");

pub const Authorizer = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    fp: *fprintd.Fprintd,
    /// Resolves the peer's prompt channel (graphical vs which terminal) from its logind session.
    lg: *logind.Logind,
    /// Log fallback for showError when no interactive channel is reachable.
    log: presenter_log.LogPresenter,

    pub fn init(io: std.Io, gpa: std.mem.Allocator, fp: *fprintd.Fprintd, lg: *logind.Logind) Authorizer {
        return .{ .io = io, .gpa = gpa, .fp = fp, .lg = lg, .log = .{ .io = io } };
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
                const outcome = self.confirm(cred) catch return error.PresenceUnavailable;
                switch (outcome) {
                    .confirmed => return,
                    .declined, .cancelled => return error.PresenceDeclined,
                    .unavailable => return error.PresenceUnavailable,
                }
            },
        }
    }

    /// Drive a typed confirm on the peer's terminal.
    fn confirm(self: *Authorizer, cred: ?session.Cred) !pres.Outcome {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = self.targetTty(cred, &buf) orelse return error.TtyUnavailable;
        return tty.promptConfirm(path, .confirm_sign);
    }

    // --- Presenter ---

    fn promptGesture(ptr: *anyopaque, cred: ?session.Cred, reason: pres.Reason, done: ?*std.atomic.Value(bool)) anyerror!pres.Outcome {
        const self: *Authorizer = @ptrCast(@alignCast(ptr));
        _ = reason;
        _ = done;
        return self.confirm(cred);
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
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (self.targetTty(cred, &buf)) |path| {
            tty.showMessage(path, pres.message(reason)); // curated text only; detail never hits the user's tty
        } else {
            self.log.presenter().showError(cred, reason, detail); // no terminal: log with detail
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
