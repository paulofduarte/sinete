// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The Linux presence orchestrator: it is the agent's Authorizer AND its Presenter. On a cold
//! window the core calls authorize(); the orchestrator picks the gesture (a fingerprint when a
//! reader is present, else a typed confirm) and drives it through the right channel. On a refusal
//! the core calls showError(); the orchestrator shows the reason on the same channel. The channel
//! is resolved from the peer credential via logind (logind.peerTty): a session with a controlling
//! terminal (a local console or an ssh pts) prompts on that terminal via the pure-Zig termios prompt;
//! a graphical session uses a pinentry dialog, falling back to the built-in X11 modal when pinentry
//! is absent, then to the built-in Wayland (wlr-layer-shell) modal for a stripped Wayland session
//! without XWayland. Everything fails closed: an unusable channel refuses (authorize), and showError
//! always records to the log before any terminal/pinentry/modal attempt.

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
const x11 = @import("x11_conn.zig");
const wayland = @import("wayland_conn.zig");
const presenter_log = @import("presenter_log.zig");

pub const Authorizer = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    fp: *fprintd.Fprintd,
    /// Resolves the peer's prompt channel (graphical vs which terminal) from its logind session.
    lg: *logind.Logind,
    /// The X11 DISPLAY for a graphical prompt (pinentry, then the built-in X11 modal); "" if unset.
    display: []const u8,
    /// The Xauthority file path for the built-in X11 modal ($XAUTHORITY or $HOME/.Xauthority).
    xauth_path: []const u8,
    /// $XDG_RUNTIME_DIR + $WAYLAND_DISPLAY for the built-in Wayland modal (no-XWayland fallback).
    runtime_dir: []const u8,
    wl_display: []const u8,
    /// Log fallback for showError, and the always-on floor so a refusal is never lost.
    log: presenter_log.LogPresenter,

    pub fn init(io: std.Io, gpa: std.mem.Allocator, fp: *fprintd.Fprintd, lg: *logind.Logind, display: []const u8, xauth_path: []const u8, runtime_dir: []const u8, wl_display: []const u8) Authorizer {
        return .{ .io = io, .gpa = gpa, .fp = fp, .lg = lg, .display = display, .xauth_path = xauth_path, .runtime_dir = runtime_dir, .wl_display = wl_display, .log = .{ .io = io } };
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
        // Graphical session: pinentry (native), then the built-in X11 modal, then the built-in
        // Wayland modal (a no-XWayland session). Each is tried only when its environment is present.
        var pe = pinentry.Pinentry{ .io = self.io, .gpa = self.gpa, .display = self.display };
        const pe_err = if (pe.confirm(reason)) |o| return o else |e| e;
        if (self.display.len > 0) {
            var xm = x11.X11{ .io = self.io, .gpa = self.gpa, .display = self.display, .xauth_path = self.xauth_path };
            if (xm.confirm(reason)) |o| return o else |_| {}
        }
        if (self.wl_display.len > 0) {
            var wm = wayland.Wayland{ .io = self.io, .gpa = self.gpa, .runtime_dir = self.runtime_dir, .wl_display = self.wl_display };
            return wm.confirm(reason); // error -> caller maps to PresenceUnavailable
        }
        return pe_err; // no graphical modal available: surface the pinentry failure
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
        // showError runs inline on the sign path, before the agent returns SSH_AGENT_FAILURE, so it
        // must not let a CLIENT-reachable channel stall it: the tty write (to the peer's pts) is
        // non-blocking, and a graphical session's error goes to the log only -- a blocking GUI error
        // modal would hang the request until the user dismissed it. (The gesture *prompt* may block;
        // presence legitimately waits for the user. An error message may not.) The log floor writes
        // to the agent's OWN stderr (journald/file), which the client cannot back-pressure, so it is
        // not a client-controllable DoS vector and is kept synchronous to guarantee the record.
        self.log.presenter().showError(cred, reason, detail); // floor: always recorded, with detail
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (self.targetTty(cred, &buf)) |path| {
            tty.showMessage(path, pres.message(reason)); // curated text only; detail never hits the user's tty
        }
    }

    /// The terminal to prompt on for `cred`, or null for a graphical (or unresolvable) session. For a
    /// null result the confirm path falls back to a graphical channel (pinentry, then the X11 modal),
    /// while showError deliberately logs only (it must not block the sign path on a GUI dialog). With
    /// a peer credential the terminal is the peer's own logind session TTY (a local console or an ssh
    /// pts); without one (no SO_PEERCRED) the agent's controlling terminal `/dev/tty` is tried, which
    /// reaches a foreground-run agent.
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
