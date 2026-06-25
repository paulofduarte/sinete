// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The agent's IPC transport: serve the ssh-agent protocol on an AF_UNIX socket, driven by a
//! single-threaded libxev event loop (kqueue on macOS/BSD, epoll/io_uring on Linux). This is the
//! one piece that owns the OS — sockets and the event loop — so it lives in the executable, not
//! in the OS-free `sinete` core. It frames messages (a big-endian u32 length then that many body
//! bytes), hands each body to `sinete.server.respond`, and frames the reply back. Single-threaded
//! by design: it is the seam where Z3's main-thread Touch ID prompt will dispatch.

const std = @import("std");
const xev = @import("xev");
const sinete = @import("sinete");

/// Largest accepted request body. Agent messages are small; bound it so a malformed or hostile
/// length fails closed instead of growing a buffer without limit.
const max_body = 256 * 1024;
const in_cap = 4 + max_body;

pub const Options = struct {
    backlog: u31 = 64,
};

/// Serve the ssh-agent protocol on an AF_UNIX socket at `sock_path` until the loop ends. Any stale
/// socket file at the path is removed first; the socket is unlinked on return. Blocks the caller.
pub fn serve(gpa: std.mem.Allocator, io: std.Io, agent: *sinete.Agent, sock_path: []const u8, opts: Options) !void {
    std.Io.Dir.cwd().deleteFile(io, sock_path) catch {}; // clear a stale socket file from a previous run
    const ua = try std.Io.net.UnixAddress.init(sock_path);
    const server = try ua.listen(io, .{ .kernel_backlog = opts.backlog });
    defer server.socket.close(io);
    defer std.Io.Dir.cwd().deleteFile(io, sock_path) catch {};

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    // Hand the listening fd to libxev: std.Io.net created the socket; libxev drives accept/read/write.
    var srv = Server{ .gpa = gpa, .io = io, .loop = &loop, .agent = agent, .listener = xev.TCP.initFd(server.socket.handle) };
    srv.listener.accept(&loop, &srv.accept_c, Server, &srv, onAccept);
    try loop.run(.until_done);
}

const Server = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    loop: *xev.Loop,
    agent: *sinete.Agent,
    listener: xev.TCP,
    accept_c: xev.Completion = undefined,
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
    in: [in_cap]u8 = undefined, // accumulates request bytes across partial reads
    in_len: usize = 0,
    out_off: usize = 0, // bytes of `frame` already written (partial-write progress)
};

fn onAccept(srv_opt: ?*Server, _: *xev.Loop, _: *xev.Completion, r: xev.AcceptError!xev.TCP) xev.CallbackAction {
    const srv = srv_opt.?;
    const tcp = r catch return .rearm; // accept error: keep listening
    const conn = srv.gpa.create(Conn) catch return .rearm; // backpressure: drop, keep listening
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

/// Advance one connection: write a buffered complete frame if there is one, otherwise read more.
/// Always issues exactly one libxev op (read, write, or close) and returns .disarm; the matching
/// callback re-enters pump. Returns .disarm so callers can `return pump(conn)`.
fn pump(conn: *Conn) xev.CallbackAction {
    const loop = conn.srv.loop;

    if (conn.in_len >= 4) {
        const want = std.mem.readInt(u32, conn.in[0..4], .big);
        if (want > max_body) return closeConn(conn); // fail closed on an absurd length
        const total = 4 + @as(usize, want);
        if (conn.in_len >= total) {
            // A full request is buffered: respond, frame the reply, queue the write.
            const now: i64 = @intCast(@divFloor(std.Io.Clock.boot.now(conn.srv.io).nanoseconds, 1_000_000));
            _ = conn.arena.reset(.retain_capacity);
            conn.body.reset();
            sinete.server.respond(conn.srv.agent, conn.in[4..total], conn.arena.allocator(), now, &conn.body) catch
                return closeConn(conn); // only reachable if even FAILURE cannot be written (OOM)

            conn.frame.reset();
            conn.frame.u32be(@intCast(conn.body.bytes().len)) catch return closeConn(conn);
            conn.frame.raw(conn.body.bytes()) catch return closeConn(conn);

            // Carry any pipelined bytes after this request to the front of the buffer.
            const leftover = conn.in_len - total;
            if (leftover != 0) std.mem.copyForwards(u8, conn.in[0..leftover], conn.in[total..conn.in_len]);
            conn.in_len = leftover;

            conn.out_off = 0;
            conn.tcp.write(loop, &conn.c, .{ .slice = conn.frame.bytes() }, Conn, conn, onWrite);
            return .disarm;
        }
    }

    // Not enough buffered yet: read more into the free tail of the buffer.
    if (conn.in_len >= conn.in.len) return closeConn(conn); // request overran the cap
    conn.tcp.read(loop, &conn.c, .{ .slice = conn.in[conn.in_len..] }, Conn, conn, onRead);
    return .disarm;
}

fn onRead(conn_opt: ?*Conn, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.ReadBuffer, r: xev.ReadError!usize) xev.CallbackAction {
    const conn = conn_opt.?;
    const n = r catch return closeConn(conn); // peer reset / error
    if (n == 0) return closeConn(conn); // EOF: peer closed
    conn.in_len += n;
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
    conn.frame.deinit();
    conn.body.deinit();
    conn.arena.deinit();
    gpa.destroy(conn);
    return .disarm;
}
