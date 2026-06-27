// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The Linux LocalSession check: refuse presence-gated signatures driven from a remote (SSH)
//! session, so a forwarded agent cannot tap the fingerprint reader at the machine. It maps the
//! peer's pid to a logind session (org.freedesktop.login1) and reads that session's Remote flag.
//! Fail-closed: a different uid, no session, or any D-Bus error is treated as not-local (refused).
//! A local text console session reports Remote=false and is allowed.

const std = @import("std");
const sinete = @import("sinete");
const session = sinete.session;
const wire = sinete.dbus_wire;
const calls = sinete.dbus_calls;
const dbus = @import("dbus_conn.zig");

pub const Logind = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    self_uid: u32,

    pub fn localSession(self: *Logind) session.LocalSession {
        return .{ .ptr = self, .vtable = &ls_vt };
    }

    const ls_vt = session.LocalSession.VTable{ .isLocal = isLocal };

    fn isLocal(ptr: *anyopaque, cred: session.Cred) anyerror!bool {
        const self: *Logind = @ptrCast(@alignCast(ptr));
        if (cred.pid <= 0) return false;
        if (cred.uid != self.self_uid) return false; // another user's connection is never our local session

        var conn = dbus.Conn.connectSystem(self.io, self.gpa) catch return false;
        defer conn.close();

        var sess_buf: [256]u8 = undefined;
        const sess = self.sessionByPid(&conn, @intCast(cred.pid)) catch return false;
        if (sess.len == 0 or sess.len > sess_buf.len) return false;
        @memcpy(sess_buf[0..sess.len], sess);

        const remote = self.remoteFlag(&conn, sess_buf[0..sess.len]) catch return false;
        return !remote;
    }

    fn sessionByPid(self: *Logind, conn: *dbus.Conn, pid: u32) ![]const u8 {
        const s = conn.nextSerial();
        var enc = wire.Encoder.init(self.gpa);
        defer enc.deinit();
        try calls.getSessionByPID(&enc, s, pid);
        try conn.send(enc.bytes());
        const r = try conn.awaitReply(s);
        return calls.parsePathOrString(r.body, r.endian);
    }

    fn remoteFlag(self: *Logind, conn: *dbus.Conn, sess_path: []const u8) !bool {
        const s = conn.nextSerial();
        var enc = wire.Encoder.init(self.gpa);
        defer enc.deinit();
        try calls.propertiesGet(&enc, s, calls.login1_dest, sess_path, calls.login1_session_iface, "Remote");
        try conn.send(enc.bytes());
        const r = try conn.awaitReply(s);
        return calls.parseVariantBool(r.body, r.endian);
    }
};
