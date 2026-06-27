// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The Linux presence gesture: a fingerprint via fprintd (net.reactivated.Fprint) over D-Bus, the
//! counterpart to the macOS Touch ID authorizer. It implements the cross-platform Authorizer seam,
//! so the agent core's cold-window TTL cache is unchanged. The verify is blocking on the agent's
//! single thread (like the macOS prompt and the TPM sign), bounded by the connection read timeout.
//! Fail-closed: any missing reader, unenrolled finger, or D-Bus error refuses the signature.

const std = @import("std");
const sinete = @import("sinete");
const authz = sinete.authz;
const wire = sinete.dbus_wire;
const calls = sinete.dbus_calls;
const dbus = @import("dbus_conn.zig");

pub const Fprintd = struct {
    io: std.Io,
    gpa: std.mem.Allocator,

    pub const Error = error{ PresenceDeclined, PresenceUnavailable };

    pub fn authorizer(self: *Fprintd) authz.Authorizer {
        return .{ .ptr = self, .vtable = &az_vt };
    }

    const az_vt = authz.Authorizer.VTable{ .authorize = authorize };

    fn authorize(ptr: *anyopaque, key_id: []const u8, reason: []const u8) anyerror!void {
        const self: *Fprintd = @ptrCast(@alignCast(ptr));
        _ = key_id; // presence-only: the gesture proves a human; per-key binding is the TPM policy (5b)
        _ = reason; // fprintd renders its own prompt; there is no caller-message channel
        self.verify() catch |e| return switch (e) {
            error.PresenceDeclined => Error.PresenceDeclined,
            else => Error.PresenceUnavailable, // any D-Bus/daemon failure fails closed
        };
    }

    fn verify(self: *Fprintd) !void {
        var conn = try dbus.Conn.connectSystem(self.io, self.gpa);
        defer conn.close();

        // Resolve the default device; copy its path out before later calls clobber conn's buffer.
        const dev = try self.getDefaultDevice(&conn);
        var path_buf: [256]u8 = undefined;
        if (dev.len == 0 or dev.len > path_buf.len) return error.PresenceUnavailable;
        @memcpy(path_buf[0..dev.len], dev);
        const dev_path = path_buf[0..dev.len];

        try self.deviceCall(&conn, "Claim", dev_path, ""); // empty username = the caller's user
        defer self.deviceCallQuiet(&conn, "Release", dev_path);

        try self.addMatch(&conn);
        try self.startVerify(&conn, dev_path);
        defer self.deviceCallQuiet(&conn, "VerifyStop", dev_path);

        // VerifyStatus(result, done): "verify-match" succeeds; "verify-no-match"+done or any other
        // terminal result is a decline/unavailable; non-terminal scan feedback just keeps waiting.
        while (true) {
            const sig = try conn.recvSignal("VerifyStatus");
            const st = calls.parseVerifyStatus(sig.body, sig.endian) catch return error.PresenceUnavailable;
            if (std.mem.eql(u8, st.result, "verify-match")) return;
            if (std.mem.eql(u8, st.result, "verify-disconnected")) return error.PresenceUnavailable;
            if (st.done) {
                return if (std.mem.eql(u8, st.result, "verify-no-match")) error.PresenceDeclined else error.PresenceUnavailable;
            }
        }
    }

    fn getDefaultDevice(self: *Fprintd, conn: *dbus.Conn) ![]const u8 {
        const s = conn.nextSerial();
        var enc = wire.Encoder.init(self.gpa);
        defer enc.deinit();
        try calls.getDefaultDevice(&enc, s);
        try conn.send(enc.bytes());
        const r = try conn.awaitReply(s);
        return calls.parsePathOrString(r.body, r.endian) catch error.PresenceUnavailable;
    }

    fn addMatch(self: *Fprintd, conn: *dbus.Conn) !void {
        const rule = "type='signal',interface='" ++ calls.fprint_device_iface ++ "',member='VerifyStatus'";
        const s = conn.nextSerial();
        var enc = wire.Encoder.init(self.gpa);
        defer enc.deinit();
        try calls.addMatch(&enc, s, rule);
        try conn.send(enc.bytes());
        _ = try conn.awaitReply(s);
    }

    /// VerifyStart, then return without awaiting its method reply -- the verify loop demuxes that
    /// reply out while it waits for the VerifyStatus signals (and aborts on any error reply).
    fn startVerify(self: *Fprintd, conn: *dbus.Conn, dev_path: []const u8) !void {
        const s = conn.nextSerial();
        var enc = wire.Encoder.init(self.gpa);
        defer enc.deinit();
        try calls.verifyStart(&enc, s, dev_path, "any");
        try conn.send(enc.bytes());
    }

    /// A Device method that takes a single string and whose reply we await (Claim / VerifyStop /
    /// Release accept an empty `arg`; only Claim uses it).
    fn deviceCall(self: *Fprintd, conn: *dbus.Conn, comptime member: []const u8, dev_path: []const u8, arg: []const u8) !void {
        const s = conn.nextSerial();
        var enc = wire.Encoder.init(self.gpa);
        defer enc.deinit();
        if (std.mem.eql(u8, member, "Claim")) {
            try calls.claim(&enc, s, dev_path, arg);
        } else if (std.mem.eql(u8, member, "VerifyStop")) {
            try calls.verifyStop(&enc, s, dev_path);
        } else {
            try calls.release(&enc, s, dev_path);
        }
        try conn.send(enc.bytes());
        _ = try conn.awaitReply(s);
    }

    fn deviceCallQuiet(self: *Fprintd, conn: *dbus.Conn, comptime member: []const u8, dev_path: []const u8) void {
        self.deviceCall(conn, member, dev_path, "") catch {};
    }
};
