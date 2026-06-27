// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The Linux LocalSession check: refuse presence-gated signatures driven from a remote (SSH)
//! session, so a forwarded agent cannot tap the fingerprint reader at the machine. It maps the
//! peer's pid to a logind session (org.freedesktop.login1) and reads that session's Remote flag.
//! A pid with NO session scope (a graphical terminal, or a systemd --user service under
//! user@<uid>.service) is not a refusal on its own: it falls back to the user's sessions and is
//! local only if the user owns a session and NONE of them is remote -- an open inbound SSH session
//! makes a sessionless process ambiguous, so it is refused (fail-safe; an attacker in an SSH
//! session can spawn a process under user@.service that is not attached to the SSH scope).
//! Fail-closed throughout: a different uid or any D-Bus error is treated as not-local (refused).
//! A local console session reports Remote=false and is allowed. Mirrors the validated Go
//! internal/localsession (IsLocal -> localOnlyForUID).

const std = @import("std");
const sinete = @import("sinete");
const session = sinete.session;
const wire = sinete.dbus_wire;
const calls = sinete.dbus_calls;
const message = sinete.dbus_message;
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

        // Primary signal: the peer's own logind session. An SSH process lives inside its sshd
        // session scope, so it is caught here (Remote=true => refuse).
        var sess_buf: [256]u8 = undefined;
        switch (self.sessionByPid(&conn, @intCast(cred.pid), &sess_buf)) {
            .session => |path| {
                const remote = self.remoteFlag(&conn, path) catch return false;
                return !remote;
            },
            // The peer escaped its login session cgroup (graphical terminal, systemd --user
            // service): decide from the user's sessions instead. Fail-closed on any error.
            .no_session => return self.userLocalSession(&conn, cred.uid) catch return false,
            .err => return false,
        }
    }

    const SessByPid = union(enum) {
        session: []const u8, // a session path copied into the caller's buffer
        no_session, // logind has no session for this pid -> fall back to the user's sessions
        err, // any other failure -> refuse
    };

    /// Resolve the peer pid's logind session path (copied into `buf`). A NoSessionForPID error is
    /// reported as `.no_session` (the signal to fall back to the user's sessions); any other failure
    /// is `.err`.
    fn sessionByPid(self: *Logind, conn: *dbus.Conn, pid: u32, buf: []u8) SessByPid {
        const s = conn.nextSerial();
        var enc = wire.Encoder.init(self.gpa);
        defer enc.deinit();
        calls.getSessionByPID(&enc, s, pid) catch return .err;
        conn.send(enc.bytes()) catch return .err;
        const r = conn.awaitReplyAllowError(s) catch return .err;
        if (r.type == message.msg_error) {
            const name = r.error_name orelse return .err;
            return if (std.mem.eql(u8, name, calls.login1_no_session_for_pid)) .no_session else .err;
        }
        const path = calls.parsePathOrString(r.body, r.endian) catch return .err;
        if (path.len == 0 or path.len > buf.len) return .err;
        @memcpy(buf[0..path.len], path);
        return .{ .session = buf[0..path.len] };
    }

    /// Fail-closed fallback for a sessionless peer: local iff the user owns at least one session and
    /// NONE is remote. The user's session paths are copied out first because reading each Remote flag
    /// reuses the connection and overwrites the ListSessions reply body. The decision itself is the
    /// pure, unit-tested calls.localOnlyForUser.
    fn userLocalSession(self: *Logind, conn: *dbus.Conn, uid: u32) !bool {
        var paths: std.ArrayList([]u8) = .empty;
        defer {
            for (paths.items) |p| self.gpa.free(p);
            paths.deinit(self.gpa);
        }

        {
            const s = conn.nextSerial();
            var enc = wire.Encoder.init(self.gpa);
            defer enc.deinit();
            try calls.listSessions(&enc, s);
            try conn.send(enc.bytes());
            const r = try conn.awaitReply(s);
            var it = try calls.SessionIter.init(r.body, r.endian);
            while (try it.next()) |sess| {
                if (sess.uid != uid) continue; // another user's sessions are irrelevant
                const copy = try self.gpa.dupe(u8, sess.path);
                paths.append(self.gpa, copy) catch |e| {
                    self.gpa.free(copy);
                    return e;
                };
            }
        }

        var infos: std.ArrayList(calls.SessionRemote) = .empty;
        defer infos.deinit(self.gpa);
        for (paths.items) |path| {
            // A Remote read failure for any of the user's sessions is "cannot confirm" -> propagate
            // -> the caller fails closed, never silently skipped.
            const remote = try self.remoteFlag(conn, path);
            try infos.append(self.gpa, .{ .uid = uid, .remote = remote });
        }
        return calls.localOnlyForUser(infos.items, uid);
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
