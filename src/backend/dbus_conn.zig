// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The impure half of the D-Bus client: the AF_UNIX socket to the system bus, the text SASL
//! EXTERNAL handshake, and a blocking request/reply + signal demultiplexer over the pure framing
//! in lib/dbus. Linux-only (used by the fprintd authorizer and the logind session check); reuses
//! the socket-as-std.Io.File pattern from tpm_device.zig. A read timeout is set as a safety net so
//! a hung daemon cannot wedge the agent forever -- any read failure is surfaced fail-closed.

const std = @import("std");
const sinete = @import("sinete");
const wire = sinete.dbus_wire;
const message = sinete.dbus_message;
const sasl = sinete.dbus_sasl;
const net = std.Io.net;
const File = std.Io.File;
const linux = std.os.linux;

const default_system_bus = "/var/run/dbus/system_bus_socket";
const recv_timeout_s: i64 = 30; // generous: method replies are instant; verify signals arrive within it

pub const Error = error{ DbusConnect, DbusAuth, DbusClosed, DbusError, DbusProtocol };

pub const Conn = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    file: File,
    serial: u32 = 0,
    rx: std.ArrayList(u8) = .empty, // bytes read but not yet consumed
    cur: std.ArrayList(u8) = .empty, // the most recently extracted frame (Parsed aliases this)

    /// Connect to the system bus, run the SASL EXTERNAL handshake, and send Hello. The bus path is
    /// $DBUS_SYSTEM_BUS_ADDRESS (a `unix:path=` address) or the well-known default.
    pub fn connectSystem(io: std.Io, gpa: std.mem.Allocator) Error!Conn {
        // The system bus has a well-known path; $DBUS_SYSTEM_BUS_ADDRESS is almost never set for it
        // (unlike the session bus), and env access is not available on this Linux-only path in 0.16.
        const ua = net.UnixAddress.init(default_system_bus) catch return error.DbusConnect;
        const stream = ua.connect(io) catch return error.DbusConnect;
        var self = Conn{
            .io = io,
            .gpa = gpa,
            .file = .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = false } },
        };
        setRecvTimeout(stream.socket.handle, recv_timeout_s);
        errdefer self.close();
        self.handshake() catch return error.DbusAuth;
        return self;
    }

    pub fn close(self: *Conn) void {
        self.file.close(self.io);
        self.rx.deinit(self.gpa);
        self.cur.deinit(self.gpa);
    }

    pub fn nextSerial(self: *Conn) u32 {
        self.serial += 1;
        return self.serial;
    }

    pub fn send(self: *Conn, bytes: []const u8) Error!void {
        self.file.writeStreamingAll(self.io, bytes) catch return error.DbusClosed;
    }

    /// Block until the method reply (or error) for `serial` arrives, skipping signals and unrelated
    /// replies. The returned Parsed aliases internal storage and is valid only until the next read.
    pub fn awaitReply(self: *Conn, serial: u32) Error!message.Parsed {
        while (true) {
            const p = try self.readMessage();
            const rs = p.reply_serial orelse continue;
            if (rs != serial) continue;
            if (p.type == message.msg_error) return error.DbusError;
            return p;
        }
    }

    /// Block until a signal whose member is `member` arrives. An error reply (e.g. a failed
    /// VerifyStart) aborts. The returned Parsed aliases internal storage until the next read.
    pub fn recvSignal(self: *Conn, member: []const u8) Error!message.Parsed {
        while (true) {
            const p = try self.readMessage();
            if (p.type == message.msg_error) return error.DbusError;
            if (p.type == message.msg_signal) {
                if (p.member) |m| {
                    if (std.mem.eql(u8, m, member)) return p;
                }
            }
        }
    }

    fn handshake(self: *Conn) !void {
        try self.writeAll(&[_]u8{0}); // the leading NUL byte before SASL
        var line: [64]u8 = undefined;
        const auth = try sasl.authExternalLine(&line, linux.getuid());
        try self.writeAll(auth);

        var rbuf: [256]u8 = undefined;
        const reply = try self.readLine(&rbuf);
        switch (sasl.parseReply(reply)) {
            .ok => {},
            else => return error.DbusAuth,
        }
        try self.writeAll("BEGIN\r\n");

        // Hello establishes our unique name; validating that the reply decodes as a unique name
        // (":1.x") confirms the whole stack -- SASL, marshaling, framing, and string-body parsing.
        const s = self.nextSerial();
        var enc = wire.Encoder.init(self.gpa);
        defer enc.deinit();
        try sinete.dbus_calls.hello(&enc, s);
        try self.send(enc.bytes());
        const hello_reply = try self.awaitReply(s);
        const name = sinete.dbus_calls.parsePathOrString(hello_reply.body, hello_reply.endian) catch return error.DbusProtocol;
        if (name.len == 0 or name[0] != ':') return error.DbusProtocol;
    }

    /// Connect, handshake, and Hello, then close. Used by the `_dbus-selftest` diagnostic to confirm
    /// the pure-Zig D-Bus stack works against a real bus before the fprintd/logind paths need it.
    pub fn selftest(io: std.Io, gpa: std.mem.Allocator) Error!void {
        var conn = try connectSystem(io, gpa);
        conn.close();
    }

    fn writeAll(self: *Conn, bytes: []const u8) Error!void {
        self.file.writeStreamingAll(self.io, bytes) catch return error.DbusClosed;
    }

    /// Read one CRLF-terminated text line (SASL phase only) into `buf`, returning it without the
    /// CRLF handling left to the parser.
    fn readLine(self: *Conn, buf: []u8) Error![]const u8 {
        var n: usize = 0;
        while (n < buf.len) {
            var one: [1]u8 = undefined;
            const got = self.file.readStreaming(self.io, &.{&one}) catch return error.DbusClosed;
            if (got == 0) return error.DbusClosed;
            buf[n] = one[0];
            n += 1;
            if (n >= 2 and buf[n - 2] == '\r' and buf[n - 1] == '\n') return buf[0..n];
        }
        return error.DbusProtocol;
    }

    fn readMessage(self: *Conn) Error!message.Parsed {
        while (true) {
            if (try self.tryFrame()) |p| return p;
            try self.fillOnce();
        }
    }

    fn tryFrame(self: *Conn) Error!?message.Parsed {
        const fr = message.frameView(self.rx.items) catch return error.DbusProtocol;
        switch (fr) {
            .need_more => return null,
            .msg => |m| {
                self.cur.clearRetainingCapacity();
                self.cur.appendSlice(self.gpa, m) catch return error.DbusProtocol;
                self.consume(m.len);
                return message.parse(self.cur.items) catch return error.DbusProtocol;
            },
        }
    }

    fn fillOnce(self: *Conn) Error!void {
        var tmp: [4096]u8 = undefined;
        const n = self.file.readStreaming(self.io, &.{&tmp}) catch return error.DbusClosed;
        if (n == 0) return error.DbusClosed;
        self.rx.appendSlice(self.gpa, tmp[0..n]) catch return error.DbusProtocol;
    }

    fn consume(self: *Conn, total: usize) void {
        const rem = self.rx.items.len - total;
        std.mem.copyForwards(u8, self.rx.items[0..rem], self.rx.items[total..]);
        self.rx.items.len = rem;
    }
};

/// Best-effort SO_RCVTIMEO so a stuck daemon cannot block the agent forever. Uses the platform
/// timeval (its `sec` is isize, so the layout is correct on both 32- and 64-bit Linux ABIs).
fn setRecvTimeout(fd: i32, seconds: i64) void {
    const tv = linux.timeval{ .sec = @intCast(seconds), .usec = 0 };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(@TypeOf(tv)));
}
