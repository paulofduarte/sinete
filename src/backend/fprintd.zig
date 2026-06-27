// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The Linux fingerprint gesture: a verify via fprintd (net.reactivated.Fprint) over D-Bus, the
//! counterpart to the macOS Touch ID gesture. It is a COMPONENT of the Linux authorizer orchestrator
//! (authorizer_linux.zig), which selects it via caps() only when a reader is present AND a finger is
//! enrolled, falling back to a typed confirm otherwise (no reader, or a reader with no enrolled
//! finger). fprintd renders its own reader prompt today; routing a "touch now" cue through the
//! Presenter (so it can auto-dismiss on the match) is a later milestone. The verify is blocking on
//! the agent's single thread (like the macOS prompt and the TPM sign), bounded by the connection read
//! timeout. Fail-closed: once selected, a no-match or any D-Bus error refuses the signature.

const std = @import("std");
const sinete = @import("sinete");
const presence = sinete.presence;
const wire = sinete.dbus_wire;
const calls = sinete.dbus_calls;
const dbus = @import("dbus_conn.zig");

pub const Fprintd = struct {
    io: std.Io,
    gpa: std.mem.Allocator,

    pub const Error = error{ PresenceDeclined, PresenceUnavailable };

    /// The presence capabilities the orchestrator selects on: a reachable default device, and whether
    /// any finger is enrolled for the caller. A box without a reader, or a reader with no enrolled
    /// finger, reports enrolled=false so the orchestrator falls back to a typed confirm rather than
    /// starting a verify that could only fail. Any D-Bus/daemon failure reports {false,false}.
    pub fn caps(self: *Fprintd) presence.Caps {
        var conn = dbus.Conn.connectSystem(self.io, self.gpa) catch return .{};
        defer conn.close();
        const dev = self.getDefaultDevice(&conn) catch return .{};
        if (dev.len == 0 or dev.len > 256) return .{};
        var path_buf: [256]u8 = undefined;
        @memcpy(path_buf[0..dev.len], dev);
        const enrolled = self.listEnrolled(&conn, path_buf[0..dev.len]) catch false;
        return .{ .reader = true, .enrolled = enrolled };
    }

    /// Whether the caller has any enrolled finger on `dev_path` (ListEnrolledFingers is a read-only
    /// query, no Claim needed). A D-Bus error is treated as "not enrolled" (-> confirm fallback).
    fn listEnrolled(self: *Fprintd, conn: *dbus.Conn, dev_path: []const u8) !bool {
        const s = conn.nextSerial();
        var enc = wire.Encoder.init(self.gpa);
        defer enc.deinit();
        try calls.listEnrolledFingers(&enc, s, dev_path, ""); // empty username = the caller's user
        try conn.send(enc.bytes());
        const r = try conn.awaitReply(s);
        return calls.parseStringArrayNonEmpty(r.body, r.endian);
    }

    /// Run a fingerprint verify, normalizing every failure to the two-value Error so the orchestrator
    /// maps them onto the presence outcome. A user no-match is PresenceDeclined; everything else
    /// (no reader, D-Bus/daemon failure) is PresenceUnavailable.
    pub fn authorize(self: *Fprintd) Error!void {
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
