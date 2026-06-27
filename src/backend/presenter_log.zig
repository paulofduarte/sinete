// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! A log-only Presenter: writes the refusal/failure reason to stderr (the agent log). It is the
//! default until the real channel presenters (pinentry / built-in modal / tty) land, and it remains
//! the floor everywhere -- every refusal is at least recorded. promptGesture/promptInput are not
//! used yet (the platform Authorizer still renders the gesture); they report Unsupported.

const std = @import("std");
const sinete = @import("sinete");
const pres = sinete.presenter;
const session = sinete.session;

pub const LogPresenter = struct {
    io: std.Io,

    pub fn presenter(self: *LogPresenter) pres.Presenter {
        return .{ .ptr = self, .vtable = &vt };
    }

    const vt = pres.Presenter.VTable{ .promptGesture = promptGesture, .promptInput = promptInput, .showError = showError };

    fn promptGesture(ptr: *anyopaque, cred: ?session.Cred, reason: pres.Reason, done: ?*std.atomic.Value(bool)) !pres.Outcome {
        _ = ptr;
        _ = cred;
        _ = reason;
        _ = done;
        return error.Unsupported;
    }
    fn promptInput(ptr: *anyopaque, cred: ?session.Cred, reason: pres.Reason, out: []u8) !usize {
        _ = ptr;
        _ = cred;
        _ = reason;
        _ = out;
        return error.Unsupported;
    }
    fn showError(ptr: *anyopaque, cred: ?session.Cred, reason: pres.Reason, detail: []const u8) void {
        _ = cred;
        _ = detail;
        const self: *LogPresenter = @ptrCast(@alignCast(ptr));
        var f = std.Io.File.stderr();
        f.writeStreamingAll(self.io, pres.message(reason)) catch return;
        f.writeStreamingAll(self.io, "\n") catch return;
    }
};
