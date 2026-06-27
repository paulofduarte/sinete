// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The built-in X11 modal: when pinentry is absent on a graphical session, sinete draws its own
//! confirm/message window by speaking the X11 wire protocol directly (pure builders in lib/x11), so
//! it depends on neither a toolkit nor server fonts. It connects to $DISPLAY's unix socket,
//! authenticates with the MIT-MAGIC-COOKIE-1 from ~/.Xauthority, creates an override-redirect window,
//! grabs the keyboard+pointer for true modality, uploads the rendered ARGB canvas via PutImage, and
//! runs an event loop until a button click or key resolves the modal. Fail-closed: any connect /
//! auth / IO failure reports X11Unavailable so the orchestrator falls through to the log. Works under
//! Xorg and, on Wayland, through XWayland.

const std = @import("std");
const linux = std.os.linux;
const sinete = @import("sinete");
const proto = sinete.x11_proto;
const ui = sinete.modal_ui;
const presenter = sinete.presenter;
const net = std.Io.net;
const File = std.Io.File;

pub const Error = error{X11Unavailable};

const recv_timeout_s: i64 = 120; // a modal waits for the human; bounded so a dead server can't wedge
const max_setup: usize = 64 * 1024; // a real setup reply is a few KB; cap before allocating, fail closed

pub const X11 = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    /// $DISPLAY (e.g. ":0"); only the local unix-socket form is supported.
    display: []const u8,
    /// The resolved Xauthority file path ($XAUTHORITY or $HOME/.Xauthority).
    xauth_path: []const u8,

    /// Show a confirm dialog; .confirmed = approved, .declined = denied/escaped. Any failure to even
    /// present the window is X11Unavailable (the caller falls through to the next channel / log).
    pub fn confirm(self: *X11, reason: presenter.Reason) Error!presenter.Outcome {
        return self.run(.{ .message = presenter.message(reason), .confirm = true });
    }

    /// Show a one-shot message (refusal/failure) with a single OK; best-effort.
    pub fn message(self: *X11, reason: presenter.Reason) void {
        _ = self.run(.{ .message = presenter.message(reason), .confirm = false }) catch {};
    }

    fn run(self: *X11, modal: ui.Modal) Error!presenter.Outcome {
        const dnum = displayNumber(self.display) orelse return error.X11Unavailable;

        var conn = self.connect(dnum) catch return error.X11Unavailable;
        defer conn.close(self.io);

        const setup = self.handshake(&conn, dnum) catch return error.X11Unavailable;
        const wid = setup.newId(0);
        const gc = setup.newId(1);

        // Render the modal once into an ARGB buffer; X (depth-24 TrueColor, LSBFirst) consumes the
        // little-endian u32s as B,G,R,X, which is exactly our 0xFFRRGGBB layout.
        const px = self.gpa.alloc(u32, ui.width * ui.height) catch return error.X11Unavailable;
        defer self.gpa.free(px);
        modal.paint(px);
        const img = std.mem.sliceAsBytes(px);

        self.openWindow(&conn, setup, wid, gc) catch return error.X11Unavailable;
        self.putImage(&conn, setup, wid, gc, img) catch return error.X11Unavailable;
        // Confirm the keyboard+pointer grabs actually took, else the window is not modal -> fail closed.
        self.awaitGrabs(&conn, setup, wid, gc, img) catch return error.X11Unavailable;

        return self.eventLoop(&conn, modal, setup, wid, gc, img) catch error.X11Unavailable;
    }

    // --- connection ---

    fn connect(self: *X11, dnum: u32) !File {
        var path_buf: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "/tmp/.X11-unix/X{d}", .{dnum});
        const ua = try net.UnixAddress.init(path);
        const stream = try ua.connect(self.io);
        setRecvTimeout(stream.socket.handle, recv_timeout_s);
        return .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = false } };
    }

    fn handshake(self: *X11, conn: *File, dnum: u32) !proto.Setup {
        // Require the MIT-MAGIC-COOKIE-1: if it can't be read/resolved, fail closed (the caller falls
        // back to the log) rather than attempting an unauthenticated connection. readCookie returns
        // error.X11Unavailable on a missing/unparseable Xauthority.
        var cookie_buf: [64]u8 = undefined;
        const cookie = try readCookie(self.io, self.xauth_path, dnum, &cookie_buf);

        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(self.gpa);
        try proto.setupRequest(self.gpa, &req, "MIT-MAGIC-COOKIE-1", cookie);
        try writeAll(self.io, conn, req.items);

        // The reply: an 8-byte header whose bytes 6..8 give the additional length in 4-byte units.
        var hdr: [8]u8 = undefined;
        try readAll(self.io, conn, &hdr);
        if (hdr[0] != 1) return error.X11Unavailable; // not success
        const add_units = std.mem.readInt(u16, hdr[6..8], .little);
        const total = 8 + @as(usize, add_units) * 4;
        if (total > max_setup) return error.X11Unavailable; // implausibly large reply -> fail closed
        const buf = try self.gpa.alloc(u8, total);
        defer self.gpa.free(buf);
        @memcpy(buf[0..8], &hdr);
        try readAll(self.io, conn, buf[8..]);
        return proto.parseSetup(buf) catch error.X11Unavailable;
    }

    fn openWindow(self: *X11, conn: *File, setup: proto.Setup, wid: u32, gc: u32) !void {
        const back: u32 = 0xFF1E1E28;
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(self.gpa);
        // Center on screen 0 is not known without the screen size; place near the top-left third,
        // which the override-redirect WM-bypass keeps fixed. A future refinement can query geometry.
        try proto.createWindow(self.gpa, &req, setup, wid, 200, 200, @intCast(ui.width), @intCast(ui.height), back);
        try proto.createGc(self.gpa, &req, gc, wid);
        try proto.mapWindow(self.gpa, &req, wid);
        try proto.grabPointer(self.gpa, &req, wid);
        try proto.grabKeyboard(self.gpa, &req, wid);
        try writeAll(self.io, conn, req.items);
    }

    fn putImage(self: *X11, conn: *File, setup: proto.Setup, wid: u32, gc: u32, img: []const u8) !void {
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(self.gpa);
        try proto.putImage(self.gpa, &req, wid, gc, @intCast(ui.width), @intCast(ui.height), setup.root_depth, img);
        try writeAll(self.io, conn, req.items);
    }

    /// Read until both grab replies (GrabPointer, then GrabKeyboard) arrive, failing closed if either
    /// status is not Success (the window would not be modal) or the server reports an error. Only the
    /// grab requests reply in the open-window batch, so any reply here is a grab reply; an Expose that
    /// races in is handled by repainting.
    fn awaitGrabs(self: *X11, conn: *File, setup: proto.Setup, wid: u32, gc: u32, img: []const u8) !void {
        var ev: [32]u8 = undefined;
        var seen: u8 = 0;
        while (seen < 2) {
            try readAll(self.io, conn, &ev);
            switch (ev[0]) {
                0 => return error.X11Unavailable, // X error
                1 => { // a reply: byte 1 is the grab status (0 = Success)
                    if (ev[1] != 0) return error.X11Unavailable;
                    seen += 1;
                },
                proto.ev_expose => try self.putImage(conn, setup, wid, gc, img),
                else => {}, // an input event before the grabs confirmed: ignore it
            }
        }
    }

    fn eventLoop(self: *X11, conn: *File, modal: ui.Modal, setup: proto.Setup, wid: u32, gc: u32, img: []const u8) !presenter.Outcome {
        var ev: [32]u8 = undefined;
        while (true) {
            try readAll(self.io, conn, &ev);
            switch (try proto.parseEvent(&ev)) {
                .expose => try self.putImage(conn, setup, wid, gc, img), // repaint on damage
                .key => |kc| if (modal.keyOutcome(keyByte(kc) orelse continue)) |o| return o,
                .button => |b| if (modal.clickOutcome(b.x, b.y)) |o| return o,
                .err => return error.X11Unavailable, // a server error must fail closed, not wedge
                .other => {}, // replies/unrelated events
            }
        }
    }
};

/// Map the stable, layout-independent evdev keycodes the modal uses to a representative byte. Letter
/// keys (y/n) vary by layout and are intentionally not mapped here (the modal is driven by clicks for
/// approval); only Escape/Return/Space are translated.
fn keyByte(keycode: u8) ?u8 {
    return switch (keycode) {
        9 => 0x1b, // Escape
        36 => '\n', // Return
        65 => ' ', // Space
        else => null,
    };
}

/// The display number N from a LOCAL ":N" / ":N.S" / "unix:N" DISPLAY, or null. A DISPLAY with a
/// non-local host (e.g. an SSH-forwarded "localhost:10.0") is rejected: connect() only uses the local
/// unix socket /tmp/.X11-unix/XN, so honoring N from a remote DISPLAY would draw the prompt on an
/// unintended local display. Such a session is refused (X11Unavailable), which is the safe outcome
/// for a presence prompt -- presence is local by design.
fn displayNumber(display: []const u8) ?u32 {
    const colon = std.mem.lastIndexOfScalar(u8, display, ':') orelse return null;
    const host = display[0..colon];
    if (host.len != 0 and !std.mem.eql(u8, host, "unix")) return null; // non-local DISPLAY -> refuse
    var s = display[colon + 1 ..];
    if (std.mem.indexOfScalar(u8, s, '.')) |dot| s = s[0..dot];
    if (s.len == 0) return null;
    return std.fmt.parseInt(u32, s, 10) catch null;
}

/// Read an MIT-MAGIC-COOKIE-1 from the Xauthority file whose display number matches, else the first
/// MIT-MAGIC-COOKIE-1 found. Entries are big-endian length-prefixed:
/// family(2) addr(2+n) number(2+n) name(2+n) data(2+n). Returns the cookie copied into `buf`.
fn readCookie(io: std.Io, path: []const u8, dnum: u32, buf: []u8) ![]const u8 {
    var dir = std.Io.Dir.cwd();
    const data = dir.readFileAlloc(io, path, std.heap.page_allocator, .limited(64 * 1024)) catch return error.X11Unavailable;
    defer std.heap.page_allocator.free(data);

    var num_str: [16]u8 = undefined;
    const want = std.fmt.bufPrint(&num_str, "{d}", .{dnum}) catch "";

    var fallback: ?[]const u8 = null;
    var p: usize = 0;
    while (p + 2 <= data.len) {
        p += 2; // family (the loop condition already guarantees these 2 bytes)
        const addr = readField(data, &p) orelse break;
        const number = readField(data, &p) orelse break;
        const name = readField(data, &p) orelse break;
        const cookie = readField(data, &p) orelse break;
        _ = addr;
        if (std.mem.eql(u8, name, "MIT-MAGIC-COOKIE-1")) {
            if (cookie.len <= buf.len) {
                if (std.mem.eql(u8, number, want)) {
                    @memcpy(buf[0..cookie.len], cookie);
                    return buf[0..cookie.len];
                }
                if (fallback == null) fallback = cookie;
            }
        }
    }
    if (fallback) |c| {
        @memcpy(buf[0..c.len], c);
        return buf[0..c.len];
    }
    return error.X11Unavailable;
}

/// A big-endian u16-length-prefixed field; advances `p` past it. Null on truncation.
fn readField(data: []const u8, p: *usize) ?[]const u8 {
    if (p.* + 2 > data.len) return null;
    const n = std.mem.readInt(u16, data[p.*..][0..2], .big);
    p.* += 2;
    if (p.* + n > data.len) return null;
    defer p.* += n;
    return data[p.* .. p.* + n];
}

fn setRecvTimeout(fd: i32, seconds: i64) void {
    const tv = linux.timeval{ .sec = @intCast(seconds), .usec = 0 };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(@TypeOf(tv)));
}

fn writeAll(io: std.Io, f: *File, bytes: []const u8) !void {
    try f.writeStreamingAll(io, bytes);
}

/// Read exactly buf.len bytes, looping over short reads; EOF before the end is an error.
fn readAll(io: std.Io, f: *File, buf: []u8) !void {
    var n: usize = 0;
    while (n < buf.len) {
        const got = try f.readStreaming(io, &.{buf[n..]});
        if (got == 0) return error.X11Unavailable;
        n += got;
    }
}
