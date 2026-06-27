// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The pinentry presenter: a graphical confirm / message dialog for a desktop session, drawn by the
//! system `pinentry` (the distro/desktop alternatives symlink picks the native gtk/qt/gnome3
//! frontend). sinete spawns pinentry, speaks the pure Assuan line protocol (lib/assuan.zig) over its
//! stdio pipes, and uses CONFIRM (the gpg message/touch pattern) -- never PIN entry yet. Everything
//! fails closed: pinentry missing, a protocol error, or any spawn/IO failure reports unavailable so
//! the orchestrator falls through to the next graphical channel. Used only for the graphical channel
//! (the terminal channel is the pure-Zig termios prompt).

const std = @import("std");
const sinete = @import("sinete");
const assuan = sinete.assuan;
const presenter = sinete.presenter;

pub const Error = error{PinentryUnavailable};

const greeting_max = 512;
const reply_max = 1024;

pub const Pinentry = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    /// The pinentry program to spawn; the bare name resolves the desktop-native frontend via the
    /// system alternatives symlink, exactly as gpg-agent's default does.
    program: []const u8 = "pinentry",
    /// The X11 DISPLAY to forward (OPTION display=), or "" to let pinentry use its own environment.
    display: []const u8 = "",

    /// Show a confirm dialog and return the user's choice: .confirmed when approved, .declined on a
    /// cancel/deny. Any failure to even show the dialog (no pinentry, protocol/IO error) is
    /// PinentryUnavailable.
    pub fn confirm(self: *Pinentry, reason: presenter.Reason) Error!presenter.Outcome {
        return self.run(reason, false);
    }

    /// Show a one-shot message (a refusal/failure) via a one-button dialog. Best-effort.
    pub fn message(self: *Pinentry, reason: presenter.Reason) void {
        _ = self.run(reason, true) catch {};
    }

    fn run(self: *Pinentry, reason: presenter.Reason, one_button: bool) Error!presenter.Outcome {
        var child = std.process.spawn(self.io, .{
            .argv = &.{self.program},
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .ignore,
        }) catch return error.PinentryUnavailable;
        var stdin = child.stdin orelse return self.abort(&child);
        var stdout = child.stdout orelse return self.abort(&child);

        var rbuf: [reply_max]u8 = undefined;
        // The greeting is the first line and must be OK.
        if (!isOk(self.readLine(&stdout, &rbuf) catch return self.abort(&child))) return self.abort(&child);

        self.setup(&stdin, &stdout, &rbuf, reason, one_button) catch return self.abort(&child);

        var line: std.ArrayList(u8) = .empty;
        defer line.deinit(self.gpa);
        assuan.appendConfirm(self.gpa, &line, one_button) catch return self.abort(&child);
        self.write(&stdin, line.items) catch return self.abort(&child);

        // Read until a terminal OK/ERR; status/comment lines precede it.
        const outcome = self.awaitConfirm(&stdout, &rbuf) catch return self.abort(&child);
        self.bye(&stdin);
        _ = child.wait(self.io) catch {};
        return outcome;
    }

    /// Send the OPTION display + SETDESC/SETOK[/SETCANCEL] setup lines, checking each reply is OK. A
    /// confirm uses Approve/Deny buttons; a one-button message uses a neutral OK and no cancel.
    fn setup(self: *Pinentry, stdin: *std.Io.File, stdout: *std.Io.File, rbuf: []u8, reason: presenter.Reason, one_button: bool) !void {
        var line: std.ArrayList(u8) = .empty;
        defer line.deinit(self.gpa);

        if (self.display.len > 0) {
            try assuan.appendOption(self.gpa, &line, "display", self.display);
        }
        try assuan.appendText(self.gpa, &line, "SETTITLE", "sinete");
        try assuan.appendText(self.gpa, &line, "SETDESC", presenter.message(reason));
        if (one_button) {
            try assuan.appendText(self.gpa, &line, "SETOK", "OK"); // a message: neutral, no cancel
        } else {
            try assuan.appendText(self.gpa, &line, "SETOK", "Approve");
            try assuan.appendText(self.gpa, &line, "SETCANCEL", "Deny");
        }

        // Send each line and consume its OK; an ERR on setup aborts (fail closed).
        var it = std.mem.splitScalar(u8, line.items, '\n');
        while (it.next()) |l| {
            if (l.len == 0) continue;
            try self.write(stdin, l);
            try self.write(stdin, "\n");
            if (!isOk(try self.readLine(stdout, rbuf))) return error.PinentryUnavailable;
        }
    }

    fn awaitConfirm(self: *Pinentry, stdout: *std.Io.File, rbuf: []u8) !presenter.Outcome {
        while (true) {
            const l = try self.readLine(stdout, rbuf);
            if (assuan.confirmOutcome(assuan.parseReply(l))) |o| return o;
        }
    }

    fn bye(self: *Pinentry, stdin: *std.Io.File) void {
        var line: std.ArrayList(u8) = .empty;
        defer line.deinit(self.gpa);
        assuan.appendBye(self.gpa, &line) catch return;
        self.write(stdin, line.items) catch {};
    }

    /// Kill the child, reap it (so a failed dialog leaves no zombie), and report unavailable -- the
    /// single fail-closed exit used on any error.
    fn abort(self: *Pinentry, child: *std.process.Child) Error {
        child.kill(self.io);
        _ = child.wait(self.io) catch {};
        return error.PinentryUnavailable;
    }

    fn write(self: *Pinentry, f: *std.Io.File, bytes: []const u8) !void {
        try f.writeStreamingAll(self.io, bytes);
    }

    /// Read one '\n'-terminated line into `buf`, returning it without the newline. Errors on EOF or
    /// an overlong line (so a wedged pinentry can't grow memory unbounded).
    fn readLine(self: *Pinentry, f: *std.Io.File, buf: []u8) ![]const u8 {
        var n: usize = 0;
        while (n < buf.len) {
            var one: [1]u8 = undefined;
            const got = f.readStreaming(self.io, &.{&one}) catch return error.PinentryUnavailable;
            if (got == 0) return error.PinentryUnavailable; // EOF before a line
            if (one[0] == '\n') return buf[0..n];
            buf[n] = one[0];
            n += 1;
        }
        return error.PinentryUnavailable; // line too long
    }

    fn isOk(line: []const u8) bool {
        return assuan.parseReply(line) == .ok;
    }

    /// Spawn `program`, read the greeting, send BYE -- a connectivity check for the
    /// `_pinentry-selftest` diagnostic, so the subprocess + Assuan plumbing can be verified without a
    /// real dialog. `program` lets the diagnostic point at a specific binary (SINETE_PINENTRY).
    pub fn selftest(io: std.Io, gpa: std.mem.Allocator, program: []const u8) Error!void {
        var p = Pinentry{ .io = io, .gpa = gpa, .program = program };
        var child = std.process.spawn(io, .{
            .argv = &.{p.program},
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .ignore,
        }) catch return error.PinentryUnavailable;
        var stdin = child.stdin orelse return p.abort(&child);
        var stdout = child.stdout orelse return p.abort(&child);
        var rbuf: [greeting_max]u8 = undefined;
        if (!isOk(p.readLine(&stdout, &rbuf) catch return p.abort(&child))) return p.abort(&child);
        p.bye(&stdin);
        _ = child.wait(io) catch {};
    }
};
