// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! Impure terminal I/O for the presenter: open a target tty, switch it to raw/no-echo, draw a
//! confirm prompt or a one-shot message, and read a single decisive keypress. The pure content and
//! key handling live in lib/tty/prompt.zig (golden-tested); this file only does the open / termios /
//! read / write / restore. Used by the Linux authorizer orchestrator for console + ssh sessions.

const std = @import("std");
const linux = std.os.linux;
const sinete = @import("sinete");
const ttyp = sinete.tty_prompt;
const presenter = sinete.presenter;

pub const Error = error{TtyUnavailable};

/// True if a raw linux syscall return indicates failure (a small negative errno).
fn failed(rc: usize) bool {
    return @as(isize, @bitCast(rc)) < 0;
}

/// Draw a confirm prompt on `tty_path` and block for a single decisive key. Restores the terminal
/// before returning. Any open/termios/IO failure is TtyUnavailable so the caller fails closed.
pub fn promptConfirm(tty_path: []const u8, reason: presenter.Reason) Error!presenter.Outcome {
    var t = try Term.open(tty_path);
    defer t.close();
    t.raw() catch return error.TtyUnavailable;
    defer t.restore();

    t.write(ttyp.confirmLine(reason));
    const outcome = t.readKey() catch return error.TtyUnavailable;
    t.write(ttyp.outcomeLine(outcome));
    return outcome;
}

/// Write a one-shot message line (a refusal/failure) to `tty_path`. The text is the curated
/// presenter.message() only -- diagnostic detail (error names) goes to the log, never the user's
/// terminal. Best-effort: a missing/unwritable tty is silently skipped (the caller logs instead).
pub fn showMessage(tty_path: []const u8, text: []const u8) void {
    var t = Term.open(tty_path) catch return;
    defer t.close();
    t.write(text);
    t.write("\n");
}

/// A tty fd with saved termios so raw mode can be reverted exactly. Writes are best-effort (a write
/// to a vanished terminal must not crash the agent); the read is the one operation that can fail the
/// confirm, so readKey surfaces its error.
const Term = struct {
    fd: i32,
    saved: ?std.posix.termios = null,

    fn open(path: []const u8) Error!Term {
        var zbuf: [std.fs.max_path_bytes]u8 = undefined;
        if (path.len + 1 > zbuf.len) return error.TtyUnavailable;
        @memcpy(zbuf[0..path.len], path);
        zbuf[path.len] = 0;
        const rc = linux.open(@ptrCast(&zbuf), .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true }, 0);
        if (failed(rc)) return error.TtyUnavailable;
        return .{ .fd = @intCast(rc) };
    }
    fn close(self: *Term) void {
        _ = linux.close(self.fd);
    }
    fn raw(self: *Term) !void {
        const cur = try std.posix.tcgetattr(self.fd);
        self.saved = cur;
        var rawt = cur;
        rawt.lflag.ECHO = false; // do not echo the keystroke
        rawt.lflag.ICANON = false; // deliver each key without waiting for a newline
        rawt.lflag.ISIG = false; // deliver Ctrl-C/Ctrl-D as bytes (-> .cancelled), not as signals
        // In non-canonical mode read() blocks until VMIN bytes arrive; set MIN=1, TIME=0 so it waits
        // for exactly one key rather than honoring an inherited VMIN==0 (which returns immediately).
        rawt.cc[@intFromEnum(std.posix.V.MIN)] = 1;
        rawt.cc[@intFromEnum(std.posix.V.TIME)] = 0;
        try std.posix.tcsetattr(self.fd, .FLUSH, rawt);
    }
    fn restore(self: *Term) void {
        if (self.saved) |s| std.posix.tcsetattr(self.fd, .FLUSH, s) catch {};
    }
    fn write(self: *Term, bytes: []const u8) void {
        var off: usize = 0;
        while (off < bytes.len) {
            const rc = linux.write(self.fd, bytes[off..].ptr, bytes.len - off);
            if (failed(rc) or rc == 0) return;
            off += rc;
        }
    }
    /// Block until a decisive key (per the pure keyOutcome table) is read; ignore other keys. EOF
    /// ends the wait as cancelled; a read error fails the confirm.
    fn readKey(self: *Term) !presenter.Outcome {
        var b: [1]u8 = undefined;
        while (true) {
            const rc = linux.read(self.fd, &b, 1);
            if (failed(rc)) return error.TtyUnavailable;
            if (rc == 0) return .cancelled; // EOF: the terminal closed
            if (ttyp.keyOutcome(b[0])) |o| return o;
        }
    }
};
