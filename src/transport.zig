// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The agent's IPC transport: serve the ssh-agent protocol on an AF_UNIX socket, driven by a
//! single-threaded libxev event loop (kqueue on macOS, epoll/io_uring on Linux). This is the
//! one piece that owns the OS — sockets and the event loop — so it lives in the executable, not in
//! the OS-free `sinete` core. The message framing and protocol dispatch are pure and live in the
//! core (`sinete.framing`); here we only feed it bytes from the socket and write its reply back.
//! Single-threaded by design: it is the seam where Z3's main-thread Touch ID prompt will dispatch.

const std = @import("std");
const builtin = @import("builtin");
const xev = @import("xev");
const sinete = @import("sinete");
const framing = sinete.framing;

comptime {
    // sinete currently supports macOS and Linux (a BSD port is the Z9 follow-up). The transport is
    // built on a POSIX unix-domain socket (AF_UNIX); other targets — notably Windows, which would
    // need a named pipe — are rejected here with a clear message rather than a deep std error.
    switch (builtin.os.tag) {
        .linux, .macos => {},
        else => @compileError("sinete's agent transport currently supports only macOS and Linux"),
    }
}

/// One whole framed request fits in a 4-byte length + body. The per-connection read buffer grows on
/// demand from `in_init` up to this cap, so an idle connection doesn't reserve the full max_body.
const in_cap = 4 + framing.max_body;
const in_init = 512; // initial per-connection read buffer; typical agent requests fit in one read

pub const Options = struct {
    backlog: u31 = 64,
};

/// Serve the ssh-agent protocol on an AF_UNIX socket at `sock_path` until the loop ends. A stale
/// socket left at the path is removed first (but a non-socket file there is refused, not deleted);
/// the socket is unlinked on return. Blocks the caller.
pub fn serve(gpa: std.mem.Allocator, io: std.Io, agent: *sinete.Agent, sock_path: []const u8, opts: Options) !void {
    try clearStaleSocket(io, sock_path);
    const ua = try std.Io.net.UnixAddress.init(sock_path);

    // Create the socket owner-only from birth: a restrictive umask during bind means it is never
    // momentarily world-connectable, even for a --sock path in a world-traversable dir like /tmp
    // (where a private parent dir can't help). Restored immediately; startup is single-threaded.
    const old_umask = osUmask(0o177);
    const server = ua.listen(io, .{ .kernel_backlog = opts.backlog }) catch |e| {
        _ = osUmask(old_umask);
        return e;
    };
    _ = osUmask(old_umask);
    defer server.socket.close(io);
    defer removeOwnSocket(io, sock_path); // unlink our socket, but never a non-socket left in its place

    // Enforce owner-only (0600) explicitly too: the umask above already achieves this on POSIX, but
    // an ssh-agent socket must never be connectable by other users (who could inject signing
    // requests), so guarantee it. Chmod by path (fchmodat): fchmod on a socket fd is EINVAL on BSD.
    try std.Io.Dir.cwd().setFilePermissions(io, sock_path, @enumFromInt(0o600), .{ .follow_symlinks = false });

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    // Hand the listening fd to libxev: std.Io.net created the socket; libxev drives accept/read/write.
    var srv = Server{ .gpa = gpa, .io = io, .loop = &loop, .agent = agent, .listener = xev.TCP.initFd(server.socket.handle) };
    srv.listener.accept(&loop, &srv.accept_c, Server, &srv, onAccept);
    try loop.run(.until_done);
}

/// Set the process umask, returning the previous value. Linux issues the raw syscall (no libc);
/// macOS uses libSystem (std.c.umask), which every Darwin binary always links, so it adds no new
/// dependency. The BSD follow-up (Z9) will add its own branch and may need linkLibC for this call.
fn osUmask(mode: std.posix.mode_t) std.posix.mode_t {
    return switch (builtin.os.tag) {
        .linux => @intCast(std.os.linux.syscall1(.umask, mode)),
        .macos => @intCast(std.c.umask(@intCast(mode))),
        else => @compileError("osUmask: no umask path for this target"),
    };
}

/// Remove a stale socket left by a previous run. Refuses to touch a path that exists but is not a
/// socket, so a mistyped `--sock` pointing at a regular file (or a symlink) is reported, not deleted.
fn clearStaleSocket(io: std.Io, sock_path: []const u8) !void {
    const st = std.Io.Dir.cwd().statFile(io, sock_path, .{ .follow_symlinks = false }) catch |e| switch (e) {
        error.FileNotFound => return, // nothing in the way
        else => return e,
    };
    if (st.kind != .unix_domain_socket) return error.SocketPathNotASocket;
    try std.Io.Dir.cwd().deleteFile(io, sock_path);
}

/// Best-effort unlink of our socket on shutdown. Skips silently if the path is gone or is no longer
/// a socket (something replaced it with a regular file), so we never delete a non-socket. (A racing
/// process that rebound the path with its own socket could still be unlinked; that race is benign.)
fn removeOwnSocket(io: std.Io, sock_path: []const u8) void {
    const st = std.Io.Dir.cwd().statFile(io, sock_path, .{ .follow_symlinks = false }) catch return;
    if (st.kind != .unix_domain_socket) return;
    std.Io.Dir.cwd().deleteFile(io, sock_path) catch {};
}

const Server = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    loop: *xev.Loop,
    agent: *sinete.Agent,
    listener: xev.TCP,
    accept_c: xev.Completion = undefined,
    discard_c: xev.Completion = undefined, // closes a socket accepted when we couldn't allocate its Conn
};

/// Per-connection state. Heap-allocated on accept, freed on close; it outlives every callback. One
/// completion is reused across this connection's read/write/close, which never overlap.
const Conn = struct {
    srv: *Server,
    tcp: xev.TCP,
    c: xev.Completion = undefined,
    arena: std.heap.ArenaAllocator,
    body: sinete.wire.Encoder, // the response body from respond
    frame: sinete.wire.Encoder, // the framed response (u32 length + body) being written
    in: std.ArrayList(u8) = .empty, // request bytes; grows on demand up to in_cap, freed on close
    out_off: usize = 0, // bytes of `frame` already written (partial-write progress)
};

fn onAccept(srv_opt: ?*Server, loop: *xev.Loop, _: *xev.Completion, r: xev.AcceptError!xev.TCP) xev.CallbackAction {
    const srv = srv_opt.?;
    const tcp = r catch return .rearm; // accept error: keep listening
    const conn = srv.gpa.create(Conn) catch {
        // Out of memory: close the just-accepted socket so its fd isn't leaked, then resume
        // accepting once the close completes (onDiscardClose re-arms). Disarming accept here keeps
        // discard_c single-use: no second OOM-close can reuse the still-in-flight completion.
        tcp.close(loop, &srv.discard_c, Server, srv, onDiscardClose);
        return .disarm;
    };
    conn.* = .{
        .srv = srv,
        .tcp = tcp,
        .arena = std.heap.ArenaAllocator.init(srv.gpa),
        .body = sinete.wire.Encoder.init(srv.gpa),
        .frame = sinete.wire.Encoder.init(srv.gpa),
    };
    _ = pump(conn);
    return .rearm; // keep accepting further connections
}

/// Advance one connection: respond to a buffered complete frame, otherwise read more. Always issues
/// exactly one libxev op (write, read, or close) and returns .disarm; the matching callback
/// re-enters pump. The framing decision is pure (`framing.processOne`); pump only executes it.
fn pump(conn: *Conn) xev.CallbackAction {
    const loop = conn.srv.loop;
    const now: i64 = @intCast(@divFloor(std.Io.Clock.boot.now(conn.srv.io).nanoseconds, 1_000_000));
    _ = conn.arena.reset(.retain_capacity);

    switch (framing.processOne(conn.srv.agent, conn.arena.allocator(), now, conn.in.items, &conn.body, &conn.frame)) {
        .close => return closeConn(conn),
        .replied => |total| {
            // Carry any pipelined bytes after this request to the front of the buffer.
            const leftover = conn.in.items.len - total;
            if (leftover != 0) std.mem.copyForwards(u8, conn.in.items[0..leftover], conn.in.items[total..]);
            conn.in.items.len = leftover;

            conn.out_off = 0;
            conn.tcp.write(loop, &conn.c, .{ .slice = conn.frame.bytes() }, Conn, conn, onWrite);
            return .disarm;
        },
        .need_more => {
            if (conn.in.items.len >= in_cap) return closeConn(conn); // request overran the cap
            if (conn.in.items.len == conn.in.capacity) { // buffer full: grow toward the cap
                const next = @min(in_cap, @max(in_init, conn.in.capacity * 2));
                conn.in.ensureTotalCapacityPrecise(conn.srv.gpa, next) catch return closeConn(conn);
            }
            const tail = conn.in.allocatedSlice()[conn.in.items.len..];
            conn.tcp.read(loop, &conn.c, .{ .slice = tail }, Conn, conn, onRead);
            return .disarm;
        },
    }
}

fn onRead(conn_opt: ?*Conn, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.ReadBuffer, r: xev.ReadError!usize) xev.CallbackAction {
    const conn = conn_opt.?;
    const n = r catch return closeConn(conn); // peer reset / error
    if (n == 0) return closeConn(conn); // EOF: peer closed
    conn.in.items.len += n;
    return pump(conn);
}

fn onWrite(conn_opt: ?*Conn, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.WriteBuffer, r: xev.WriteError!usize) xev.CallbackAction {
    const conn = conn_opt.?;
    const n = r catch return closeConn(conn);
    conn.out_off += n;
    if (conn.out_off < conn.frame.bytes().len) {
        // Short write: queue the remainder.
        conn.tcp.write(conn.srv.loop, &conn.c, .{ .slice = conn.frame.bytes()[conn.out_off..] }, Conn, conn, onWrite);
        return .disarm;
    }
    return pump(conn); // reply sent: serve the next request or read more
}

fn closeConn(conn: *Conn) xev.CallbackAction {
    conn.tcp.close(conn.srv.loop, &conn.c, Conn, conn, onClose);
    return .disarm;
}

fn onClose(conn_opt: ?*Conn, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.CloseError!void) xev.CallbackAction {
    const conn = conn_opt.?;
    const gpa = conn.srv.gpa;
    conn.in.deinit(gpa);
    conn.frame.deinit();
    conn.body.deinit();
    conn.arena.deinit();
    gpa.destroy(conn);
    return .disarm;
}

/// Close completion for a socket we accepted but couldn't allocate a Conn for: reclaim the fd, then
/// resume accepting (onAccept disarmed itself, so discard_c stays single-use until this fires).
fn onDiscardClose(srv_opt: ?*Server, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.CloseError!void) xev.CallbackAction {
    const srv = srv_opt.?;
    srv.listener.accept(srv.loop, &srv.accept_c, Server, srv, onAccept);
    return .disarm;
}
