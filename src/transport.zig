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

/// What `processOne` decided about the head of a connection's input buffer.
const Outcome = union(enum) {
    need_more, // no complete frame buffered yet; read more input
    close, // an oversize length, or a reply that cannot be represented: drop the connection
    replied: usize, // a request was handled into `frame_out`; this many input bytes were consumed
};

/// Pure frame processing, shared by the libxev `pump` and exercised directly by the tests below.
/// If `in` begins with a complete `[u32 length][body]` frame, run the protocol (`server.respond`,
/// itself fail-closed) and write the framed reply into `frame_out`. Transport-free and bounded, so
/// the whole request/response path is testable without sockets or an event loop.
fn processOne(
    agent: *sinete.Agent,
    arena: std.mem.Allocator,
    now_ms: i64,
    in: []const u8,
    body: *sinete.wire.Encoder,
    frame_out: *sinete.wire.Encoder,
) Outcome {
    if (in.len < 4) return .need_more;
    const want = std.mem.readInt(u32, in[0..4], .big);
    if (want > max_body) return .close; // fail closed on an absurd length
    const total = 4 + @as(usize, want);
    if (in.len < total) return .need_more;

    body.reset();
    // respond turns malformed/unsupported bodies into a FAILURE message; it errors only if even
    // that single byte cannot be written (OOM), in which case we drop the connection.
    sinete.server.respond(agent, in[4..total], arena, now_ms, body) catch return .close;

    frame_out.reset();
    frame_out.u32be(@intCast(body.bytes().len)) catch return .close;
    frame_out.raw(body.bytes()) catch return .close;
    return .{ .replied = total };
}

/// Advance one connection: respond to a buffered complete frame, otherwise read more. Always issues
/// exactly one libxev op (write, read, or close) and returns .disarm; the matching callback
/// re-enters pump. Returns .disarm so callers can `return pump(conn)`.
fn pump(conn: *Conn) xev.CallbackAction {
    const loop = conn.srv.loop;
    const now: i64 = @intCast(@divFloor(std.Io.Clock.boot.now(conn.srv.io).nanoseconds, 1_000_000));
    _ = conn.arena.reset(.retain_capacity);

    switch (processOne(conn.srv.agent, conn.arena.allocator(), now, conn.in[0..conn.in_len], &conn.body, &conn.frame)) {
        .close => return closeConn(conn),
        .replied => |total| {
            // Carry any pipelined bytes after this request to the front of the buffer.
            const leftover = conn.in_len - total;
            if (leftover != 0) std.mem.copyForwards(u8, conn.in[0..leftover], conn.in[total..conn.in_len]);
            conn.in_len = leftover;

            conn.out_off = 0;
            conn.tcp.write(loop, &conn.c, .{ .slice = conn.frame.bytes() }, Conn, conn, onWrite);
            return .disarm;
        },
        .need_more => {
            if (conn.in_len >= conn.in.len) return closeConn(conn); // request overran the cap
            conn.tcp.read(loop, &conn.c, .{ .slice = conn.in[conn.in_len..] }, Conn, conn, onRead);
            return .disarm;
        },
    }
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

// Integration tests of the framing layer with the protocol core (server.respond) over the in-tree
// fakes, without sockets or the event loop. The live socket round-trip is covered by `ssh-add -l`.

const testing = std.testing;

const Harness = struct {
    arena: std.heap.ArenaAllocator,
    body: sinete.wire.Encoder,
    frame: sinete.wire.Encoder,
    agent: sinete.Agent,

    // cp and az are owned by the caller (stable addresses), so the agent's interface pointers
    // stay valid even though this struct is returned by value.
    fn init(cp: *sinete.crypto.Fake, az: *sinete.authz.Fake) Harness {
        return .{
            .arena = std.heap.ArenaAllocator.init(testing.allocator),
            .body = sinete.wire.Encoder.init(testing.allocator),
            .frame = sinete.wire.Encoder.init(testing.allocator),
            .agent = sinete.Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 }),
        };
    }
    fn deinit(h: *Harness) void {
        h.agent.deinit();
        h.frame.deinit();
        h.body.deinit();
        h.arena.deinit();
    }
    fn run(h: *Harness, in: []const u8) Outcome {
        return processOne(&h.agent, h.arena.allocator(), 1000, in, &h.body, &h.frame);
    }
};

test "processOne: a complete REQUEST_IDENTITIES frame yields a framed IDENTITIES_ANSWER" {
    var cp = sinete.crypto.Fake{ .keys = &.{.{ .blob = "k1", .comment = "one" }} };
    var az = sinete.authz.Fake{};
    var h = Harness.init(&cp, &az);
    defer h.deinit();

    const req = [_]u8{ 0, 0, 0, 1, 11 }; // [u32 1][SSH_AGENTC_REQUEST_IDENTITIES]
    const r = h.run(&req);
    try testing.expect(std.meta.activeTag(r) == .replied);
    try testing.expectEqual(@as(usize, req.len), r.replied);

    var d = sinete.wire.Decoder{ .data = h.frame.bytes() };
    try testing.expectEqual(@as(usize, h.frame.bytes().len - 4), try d.u32be()); // length prefix
    try testing.expectEqual(@as(u8, 12), try d.byte()); // SSH_AGENT_IDENTITIES_ANSWER
    try testing.expectEqual(@as(u32, 1), try d.u32be()); // one identity
    try testing.expectEqualStrings("k1", try d.string());
    try testing.expectEqualStrings("one", try d.string());
}

test "processOne: incomplete input asks for more (short header, then short body)" {
    var cp = sinete.crypto.Fake{ .keys = &.{} };
    var az = sinete.authz.Fake{};
    var h = Harness.init(&cp, &az);
    defer h.deinit();

    try testing.expect(std.meta.activeTag(h.run(&[_]u8{ 0, 0 })) == .need_more); // < 4 length bytes
    try testing.expect(std.meta.activeTag(h.run(&[_]u8{ 0, 0, 0, 5, 11 })) == .need_more); // 5 claimed, 1 present
}

test "processOne: an oversize length fails closed" {
    var cp = sinete.crypto.Fake{ .keys = &.{} };
    var az = sinete.authz.Fake{};
    var h = Harness.init(&cp, &az);
    defer h.deinit();
    try testing.expect(std.meta.activeTag(h.run(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF })) == .close);
}

test "processOne: an unsupported request is framed as FAILURE, not closed" {
    var cp = sinete.crypto.Fake{ .keys = &.{} };
    var az = sinete.authz.Fake{};
    var h = Harness.init(&cp, &az);
    defer h.deinit();

    const r = h.run(&[_]u8{ 0, 0, 0, 1, 99 }); // [u32 1][unknown type]
    try testing.expect(std.meta.activeTag(r) == .replied);
    var d = sinete.wire.Decoder{ .data = h.frame.bytes() };
    _ = try d.u32be(); // length prefix
    try testing.expectEqual(@as(u8, 5), try d.byte()); // SSH_AGENT_FAILURE
}

test "processOne: pipelined frames are consumed one at a time" {
    var cp = sinete.crypto.Fake{ .keys = &.{.{ .blob = "k1", .comment = "one" }} };
    var az = sinete.authz.Fake{};
    var h = Harness.init(&cp, &az);
    defer h.deinit();

    const two = [_]u8{ 0, 0, 0, 1, 11, 0, 0, 0, 1, 11 }; // two REQUEST_IDENTITIES back to back
    const r1 = h.run(&two);
    try testing.expect(std.meta.activeTag(r1) == .replied);
    try testing.expectEqual(@as(usize, 5), r1.replied);

    const r2 = h.run(two[r1.replied..]); // the caller advances past the consumed frame
    try testing.expect(std.meta.activeTag(r2) == .replied);
    try testing.expectEqual(@as(usize, 5), r2.replied);
}
