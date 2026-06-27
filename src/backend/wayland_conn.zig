// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The built-in Wayland modal: the fallback when neither pinentry nor XWayland is available on a
//! stripped Wayland session (sway/Hyprland/niri without XWayland). sinete draws its own confirm/
//! message window by speaking the Wayland wire protocol directly (pure builders in lib/wayland) over
//! the wlr-layer-shell extension, which gives a non-compositor client a real input-grabbing overlay
//! (overlay layer + exclusive keyboard) -- the same mechanism swaylock/wofi use. It connects to
//! $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY, binds the globals, renders the shared modal canvas into a
//! wl_shm pool backed by a memfd (passed to the compositor via SCM_RIGHTS), and runs an event loop
//! until a click or key resolves the modal. Fail-closed: any connect/protocol/IO failure or a
//! missing required global reports WaylandUnavailable so the orchestrator falls back to the log.

const std = @import("std");
const linux = std.os.linux;
const sinete = @import("sinete");
const wl = sinete.wayland_proto;
const ui = sinete.modal_ui;
const presenter = sinete.presenter;
const net = std.Io.net;

pub const Error = error{WaylandUnavailable};

const recv_timeout_s: i64 = 300; // a modal waits for a human; a dead server is caught faster by EOF
const max_rx = 1 << 20; // the modal's traffic is tiny; cap the receive buffer and fail closed

// evdev keycodes (Wayland reports raw kernel codes): Escape=1, Enter=28, Space=57. Letter keys vary
// by layout (need a keymap), so the modal is driven by clicks for approval; only these are mapped.
const key_escape: u32 = 1;
const key_enter: u32 = 28;
const key_space: u32 = 57;
const btn_left: u32 = 0x110;

const Globals = struct {
    compositor: u32 = 0,
    shm: u32 = 0,
    seat: u32 = 0,
    layer_shell: u32 = 0,
    compositor_ver: u32 = 0,
    shm_ver: u32 = 0,
    seat_ver: u32 = 0,
    layer_shell_ver: u32 = 0,
};

pub const Wayland = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    runtime_dir: []const u8, // $XDG_RUNTIME_DIR
    wl_display: []const u8, // $WAYLAND_DISPLAY (e.g. "wayland-0")

    pub fn confirm(self: *Wayland, reason: presenter.Reason) Error!presenter.Outcome {
        return self.run(.{ .message = presenter.message(reason), .confirm = true });
    }
    pub fn message(self: *Wayland, reason: presenter.Reason) void {
        _ = self.run(.{ .message = presenter.message(reason), .confirm = false }) catch {};
    }

    fn run(self: *Wayland, modal: ui.Modal) Error!presenter.Outcome {
        if (self.runtime_dir.len == 0 or self.wl_display.len == 0) return error.WaylandUnavailable;
        var c = Conn.connect(self) catch return error.WaylandUnavailable;
        defer c.deinit();
        return c.drive(modal) catch error.WaylandUnavailable;
    }
};

/// The live connection: the socket, the object-id allocator, the receive buffer, and the per-object
/// ids discovered/created during the session. All the protocol orchestration is here.
const Conn = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    fd: i32,
    next_id: u32 = 2, // 1 is wl_display; client ids start at 2
    rx: std.ArrayList(u8) = .empty,
    cur: std.ArrayList(u8) = .empty,

    // session object ids (0 = not yet created)
    surface: u32 = 0,
    layer_surface: u32 = 0,
    seat: u32 = 0,
    keyboard: u32 = 0,
    pointer: u32 = 0,
    // last pointer position (surface-local), updated by enter/motion, used on a button press
    px: i32 = 0,
    py: i32 = 0,

    fn connect(w: *Wayland) !Conn {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = if (w.wl_display.len > 0 and w.wl_display[0] == '/')
            w.wl_display
        else
            try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ w.runtime_dir, w.wl_display });
        const ua = try net.UnixAddress.init(path);
        const stream = try ua.connect(w.io);
        setRecvTimeout(stream.socket.handle, recv_timeout_s);
        return .{ .io = w.io, .gpa = w.gpa, .fd = stream.socket.handle };
    }
    fn deinit(self: *Conn) void {
        _ = linux.close(self.fd);
        self.rx.deinit(self.gpa);
        self.cur.deinit(self.gpa);
    }

    fn alloc(self: *Conn) u32 {
        const id = self.next_id;
        self.next_id += 1;
        return id;
    }

    /// The whole session: registry -> bind -> layer surface -> buffer -> input loop.
    fn drive(self: *Conn, modal: ui.Modal) !presenter.Outcome {
        const g = try self.discoverGlobals();
        if (g.compositor == 0 or g.shm == 0 or g.seat == 0 or g.layer_shell == 0) return error.WaylandUnavailable;

        const compositor = try self.bind(g.compositor, "wl_compositor", @min(g.compositor_ver, 4));
        const shm = try self.bind(g.shm, "wl_shm", @min(g.shm_ver, 1));
        self.seat = try self.bind(g.seat, "wl_seat", @min(g.seat_ver, 5));
        const layer_shell = try self.bind(g.layer_shell, "zwlr_layer_shell_v1", @min(g.layer_shell_ver, 4));

        self.surface = self.alloc();
        try self.req(wl.createSurface, .{ compositor, self.surface });
        self.layer_surface = self.alloc();
        try self.req(wl.getLayerSurface, .{ layer_shell, self.layer_surface, self.surface, @as(u32, 0), wl.layer_overlay, "sinete" });
        try self.req(wl.layerSurfaceSetSize, .{ self.layer_surface, @as(u32, @intCast(ui.width)), @as(u32, @intCast(ui.height)) });
        try self.req(wl.layerSurfaceSetKeyboardInteractivity, .{ self.layer_surface, wl.keyboard_exclusive });
        try self.req(wl.surfaceCommit, .{self.surface});
        try self.awaitConfigure();

        try self.attachBuffer(shm, modal);

        return self.eventLoop(modal);
    }

    /// get_registry + sync; collect the names/versions of the globals the modal needs, returning once
    /// the sync callback fires (all globals delivered).
    fn discoverGlobals(self: *Conn) !Globals {
        const registry = self.alloc(); // 2
        const cb = self.alloc(); // 3
        try self.req(wl.getRegistry, .{registry});
        try self.req(wl.sync, .{cb});

        var g = Globals{};
        while (true) {
            const m = try self.readMsg();
            if (m.obj == cb and m.opcode == wl.wl_callback_done) return g;
            if (m.obj == registry and m.opcode == wl.wl_registry_global) {
                const gl = wl.parseGlobal(m.body) catch continue;
                if (std.mem.eql(u8, gl.interface, "wl_compositor")) {
                    g.compositor = gl.name;
                    g.compositor_ver = gl.version;
                } else if (std.mem.eql(u8, gl.interface, "wl_shm")) {
                    g.shm = gl.name;
                    g.shm_ver = gl.version;
                } else if (std.mem.eql(u8, gl.interface, "wl_seat")) {
                    g.seat = gl.name;
                    g.seat_ver = gl.version;
                } else if (std.mem.eql(u8, gl.interface, "zwlr_layer_shell_v1")) {
                    g.layer_shell = gl.name;
                    g.layer_shell_ver = gl.version;
                }
            } else if (m.obj == wl.display_id and m.opcode == wl.wl_display_error) {
                return error.WaylandUnavailable;
            }
        }
    }

    fn bind(self: *Conn, name: u32, iface: []const u8, version: u32) !u32 {
        const id = self.alloc();
        try self.reqBind(name, iface, version, id);
        return id;
    }

    /// Wait for the layer surface's first configure and ack it (so the compositor will show a buffer).
    fn awaitConfigure(self: *Conn) !void {
        while (true) {
            const m = try self.readMsg();
            if (m.obj == self.layer_surface and m.opcode == wl.layer_surface_configure) {
                const cfg = try wl.parseConfigure(m.body);
                try self.req(wl.layerSurfaceAckConfigure, .{ self.layer_surface, cfg.serial });
                return;
            }
            if (m.obj == wl.display_id and m.opcode == wl.wl_display_error) return error.WaylandUnavailable;
        }
    }

    /// memfd-backed shm pool: render the modal into mapped memory, hand the fd to the compositor via
    /// SCM_RIGHTS, make a buffer, and attach+damage+commit it to the surface.
    fn attachBuffer(self: *Conn, shm: u32, modal: ui.Modal) !void {
        const w: u32 = @intCast(ui.width);
        const h: u32 = @intCast(ui.height);
        const stride = w * 4;
        const size: usize = stride * h;

        const mfd = linux.memfd_create("sinete-modal", linux.MFD.CLOEXEC);
        if (sysErr(mfd)) return error.WaylandUnavailable;
        const memfd: i32 = @intCast(mfd);
        defer _ = linux.close(memfd);
        if (sysErr(linux.ftruncate(memfd, @intCast(size)))) return error.WaylandUnavailable;

        const m = linux.mmap(null, size, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, memfd, 0);
        if (sysErr(m)) return error.WaylandUnavailable;
        const ptr: [*]u8 = @ptrFromInt(m);
        defer _ = linux.munmap(ptr, size);
        const pixels: []u32 = @as([*]u32, @ptrCast(@alignCast(ptr)))[0 .. w * h];
        modal.paint(pixels);

        const pool = self.alloc();
        try self.reqWithFd(memfd, wl.shmCreatePool, .{ shm, pool, @as(u32, @intCast(size)) });
        const buffer = self.alloc();
        try self.req(wl.poolCreateBuffer, .{ pool, buffer, @as(u32, 0), w, h, stride, wl.format_argb8888 });
        try self.req(wl.surfaceAttach, .{ self.surface, buffer, @as(i32, 0), @as(i32, 0) });
        try self.req(wl.surfaceDamage, .{ self.surface, @as(i32, 0), @as(i32, 0), @as(i32, @intCast(w)), @as(i32, @intCast(h)) });
        try self.req(wl.surfaceCommit, .{self.surface});
    }

    fn eventLoop(self: *Conn, modal: ui.Modal) !presenter.Outcome {
        while (true) {
            const m = try self.readMsg();
            if (m.obj == wl.display_id and m.opcode == wl.wl_display_error) return error.WaylandUnavailable;
            if (m.obj == self.layer_surface and m.opcode == wl.layer_surface_configure) {
                const cfg = try wl.parseConfigure(m.body);
                try self.req(wl.layerSurfaceAckConfigure, .{ self.layer_surface, cfg.serial });
            } else if (m.obj == self.seat and m.opcode == wl.wl_seat_capabilities) {
                try self.bindSeatCaps(try wl.parseCapabilities(m.body));
            } else if (self.keyboard != 0 and m.obj == self.keyboard and m.opcode == wl.wl_keyboard_key) {
                const k = try wl.parseKey(m.body);
                if (k.pressed) {
                    if (keyByte(k.key)) |b| {
                        if (modal.keyOutcome(b)) |o| return o;
                    }
                }
            } else if (self.pointer != 0 and m.obj == self.pointer) {
                if (m.opcode == wl.wl_pointer_enter) {
                    const p = try wl.parseEnter(m.body);
                    self.px = p.x;
                    self.py = p.y;
                } else if (m.opcode == wl.wl_pointer_motion) {
                    const p = try wl.parseMotion(m.body);
                    self.px = p.x;
                    self.py = p.y;
                } else if (m.opcode == wl.wl_pointer_button) {
                    const btn = try wl.parseButton(m.body);
                    if (btn.pressed and btn.button == btn_left) {
                        if (modal.clickOutcome(self.px, self.py)) |o| return o;
                    }
                }
            }
        }
    }

    /// Bind the pointer/keyboard when the seat announces them (capabilities bit 0 = pointer, 1 = kbd).
    fn bindSeatCaps(self: *Conn, caps: u32) !void {
        if ((caps & 1) != 0 and self.pointer == 0) {
            self.pointer = self.alloc();
            try self.req(wl.seatGetPointer, .{ self.seat, self.pointer });
        }
        if ((caps & 2) != 0 and self.keyboard == 0) {
            self.keyboard = self.alloc();
            try self.req(wl.seatGetKeyboard, .{ self.seat, self.keyboard });
        }
    }

    // --- request helpers ---

    /// Build a request via `builder` (a lib/wayland fn taking (*ArrayList, gpa, args...)) and send it.
    fn req(self: *Conn, comptime builder: anytype, args: anytype) !void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.gpa);
        try @call(.auto, builder, .{ &out, self.gpa } ++ args);
        try self.writeAll(out.items);
    }

    /// Same as req but the message carries a single fd via SCM_RIGHTS (wl_shm.create_pool).
    fn reqWithFd(self: *Conn, fd: i32, comptime builder: anytype, args: anytype) !void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.gpa);
        try @call(.auto, builder, .{ &out, self.gpa } ++ args);
        try self.sendWithFd(out.items, fd);
    }

    /// wl_registry.bind has an extra interface string, so it does not fit the (builder, args) shape.
    fn reqBind(self: *Conn, name: u32, iface: []const u8, version: u32, new_id: u32) !void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.gpa);
        try wl.registryBind(&out, self.gpa, 2, name, iface, version, new_id); // registry is object id 2
        try self.writeAll(out.items);
    }

    fn writeAll(self: *Conn, bytes: []const u8) !void {
        var off: usize = 0;
        while (off < bytes.len) {
            const n = linux.write(self.fd, bytes[off..].ptr, bytes.len - off);
            if (sysErr(n) or n == 0) return error.WaylandUnavailable;
            off += n;
        }
    }

    /// sendmsg the bytes with `fd` attached as SCM_RIGHTS ancillary data (one fd). The control buffer
    /// holds a cmsghdr followed by the fd: cmsg_len = CMSG_LEN(sizeof fd), and msg_controllen =
    /// CMSG_SPACE(sizeof fd) -- the alignment-padded size the kernel expects (a bare CMSG_LEN can be
    /// rejected with EINVAL on 64-bit). The buffer is zeroed so the padding bytes are defined.
    fn sendWithFd(self: *Conn, bytes: []const u8, fd: i32) !void {
        var iov = [_]std.posix.iovec_const{.{ .base = bytes.ptr, .len = bytes.len }};
        const hdr = @sizeOf(linux.cmsghdr);
        const data_off = cmsgAlign(hdr); // CMSG_DATA offset
        const space = cmsgAlign(hdr) + cmsgAlign(@sizeOf(i32)); // CMSG_SPACE(sizeof fd)
        // The buffer must be cmsghdr-aligned for the @alignCast below to be sound.
        var ctrl: [64]u8 align(@alignOf(linux.cmsghdr)) = [_]u8{0} ** 64;
        const ch: *linux.cmsghdr = @ptrCast(@alignCast(&ctrl));
        ch.level = linux.SOL.SOCKET;
        ch.type = linux.SCM.RIGHTS;
        ch.len = @intCast(hdr + @sizeOf(i32)); // CMSG_LEN(sizeof fd)
        @memcpy(ctrl[data_off .. data_off + 4], std.mem.asBytes(&fd));
        var msg = linux.msghdr_const{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &ctrl,
            .controllen = @intCast(space),
            .flags = 0,
        };
        const n = linux.sendmsg(self.fd, &msg, 0);
        if (sysErr(n)) return error.WaylandUnavailable;
    }

    // --- receive: frame the message stream, reaping any fds events carry ---

    fn readMsg(self: *Conn) !wl.Msg {
        while (true) {
            if (try self.takeFrame()) |m| return m;
            try self.recvMore();
        }
    }

    fn takeFrame(self: *Conn) !?wl.Msg {
        const len = (wl.frameLen(self.rx.items) catch return error.WaylandUnavailable) orelse return null;
        self.cur.clearRetainingCapacity();
        self.cur.appendSlice(self.gpa, self.rx.items[0..len]) catch return error.WaylandUnavailable;
        const rem = self.rx.items.len - len;
        std.mem.copyForwards(u8, self.rx.items[0..rem], self.rx.items[len..]);
        self.rx.items.len = rem;
        return wl.parse(self.cur.items) catch return error.WaylandUnavailable;
    }

    /// recvmsg one chunk into rx; close any fds the server attached (e.g. wl_keyboard.keymap) so a
    /// long-lived agent does not leak descriptors across modals.
    fn recvMore(self: *Conn) !void {
        if (self.rx.items.len >= max_rx) return error.WaylandUnavailable;
        var tmp: [4096]u8 = undefined;
        var iov = [_]std.posix.iovec{.{ .base = &tmp, .len = tmp.len }};
        var ctrl: [256]u8 align(@alignOf(linux.cmsghdr)) = undefined;
        var msg = linux.msghdr{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &ctrl,
            .controllen = ctrl.len,
            .flags = 0,
        };
        const n = linux.recvmsg(self.fd, &msg, 0);
        if (sysErr(n) or n == 0) return error.WaylandUnavailable;
        reapFds(&msg);
        self.rx.appendSlice(self.gpa, tmp[0..n]) catch return error.WaylandUnavailable;
    }
};

/// CMSG_ALIGN: round up to the control-message alignment (the size of usize on Linux).
fn cmsgAlign(n: usize) usize {
    const a: usize = @alignOf(usize);
    return (n + a - 1) & ~(a - 1);
}

/// Close every fd delivered in the recvmsg ancillary data (SCM_RIGHTS), so received keymap/etc. fds
/// don't accumulate in the agent. Guards the cmsg length against truncation/corruption so it never
/// reads past the control buffer.
fn reapFds(msg: *linux.msghdr) void {
    const clen: usize = @intCast(msg.controllen);
    const hdr = @sizeOf(linux.cmsghdr);
    if (clen < hdr) return;
    const base: [*]u8 = @ptrCast(msg.control.?);
    const ch: *const linux.cmsghdr = @ptrCast(@alignCast(base));
    if (ch.level != linux.SOL.SOCKET or ch.type != linux.SCM.RIGHTS) return;
    const len: usize = @intCast(ch.len);
    if (len < hdr or len > clen) return; // malformed/truncated: do not read past the buffer
    const data_off = cmsgAlign(hdr); // CMSG_DATA offset (== hdr on common ABIs, but be explicit)
    if (data_off > len) return;
    const fd_bytes = len - data_off;
    var i: usize = 0;
    while (i + 4 <= fd_bytes) : (i += 4) {
        var fd: i32 = undefined;
        @memcpy(std.mem.asBytes(&fd), base[data_off + i .. data_off + i + 4]);
        _ = linux.close(fd);
    }
}

/// Map the stable evdev keycodes the modal uses to a representative byte; letter keys vary by layout
/// and are driven by clicks instead.
fn keyByte(keycode: u32) ?u8 {
    return switch (keycode) {
        key_escape => 0x1b,
        key_enter => '\n',
        key_space => ' ',
        else => null,
    };
}

/// True if a raw linux syscall return is a small negative errno.
fn sysErr(rc: usize) bool {
    return @as(isize, @bitCast(rc)) < 0;
}

fn setRecvTimeout(fd: i32, seconds: i64) void {
    const tv = linux.timeval{ .sec = @intCast(seconds), .usec = 0 };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(@TypeOf(tv)));
}
