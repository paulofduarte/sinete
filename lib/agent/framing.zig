// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! ssh-agent message framing: parse a big-endian u32 length prefix and its body, dispatch the body
//! through the protocol core (server.respond), and frame the reply the same way. This is pure and
//! transport-free — the libxev unix-socket loop (src/transport.zig) drives it — so the whole
//! request/response path is unit-tested here with no sockets, event loop, or OS dependency, and is
//! exercised by the same coverage run as the rest of the core.

const std = @import("std");
const core = @import("core.zig");
const server = @import("server.zig");
const wire = @import("../ssh/wire.zig");

/// Largest accepted request body. Agent messages are small; bound it so a malformed or hostile
/// length fails closed instead of growing a buffer without limit.
pub const max_body = 256 * 1024;

/// What `processOne` decided about the head of an input buffer.
pub const Outcome = union(enum) {
    need_more, // no complete frame buffered yet; read more input
    close, // an oversize length, or a reply that cannot be represented: drop the connection
    replied: usize, // a request was handled into `frame_out`; this many input bytes were consumed
};

/// If `in` begins with a complete `[u32 length][body]` frame, run the protocol (`server.respond`,
/// itself fail-closed) and write the framed reply into `frame_out`, returning the bytes consumed.
/// `body` is scratch for the response body; `arena` backs respond's per-request allocation.
pub fn processOne(
    agent: *core.Agent,
    arena: std.mem.Allocator,
    now_ms: i64,
    in: []const u8,
    body: *wire.Encoder,
    frame_out: *wire.Encoder,
) Outcome {
    if (in.len < 4) return .need_more;
    const want = std.mem.readInt(u32, in[0..4], .big);
    if (want > max_body) return .close; // fail closed on an absurd length
    const total = 4 + @as(usize, want);
    if (in.len < total) return .need_more;

    body.reset();
    // respond turns malformed/unsupported bodies into a FAILURE message; it errors only if even
    // that single byte cannot be written (OOM), in which case we drop the connection.
    server.respond(agent, in[4..total], arena, now_ms, body) catch return .close;

    frame_out.reset();
    frame_out.u32be(@intCast(body.bytes().len)) catch return .close;
    frame_out.raw(body.bytes()) catch return .close;
    return .{ .replied = total };
}

const testing = std.testing;
const crypto = @import("../crypto.zig");
const authz = @import("../authz.zig");

const Harness = struct {
    arena: std.heap.ArenaAllocator,
    body: wire.Encoder,
    frame: wire.Encoder,
    agent: core.Agent,

    // cp and az are owned by the caller (stable addresses), so the agent's interface pointers
    // stay valid even though this struct is returned by value.
    fn init(cp: *crypto.Fake, az: *authz.Fake) Harness {
        return .{
            .arena = std.heap.ArenaAllocator.init(testing.allocator),
            .body = wire.Encoder.init(testing.allocator),
            .frame = wire.Encoder.init(testing.allocator),
            .agent = core.Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 }),
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
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "k1", .comment = "one" }} };
    var az = authz.Fake{};
    var h = Harness.init(&cp, &az);
    defer h.deinit();

    const req = [_]u8{ 0, 0, 0, 1, 11 }; // [u32 1][SSH_AGENTC_REQUEST_IDENTITIES]
    const r = h.run(&req);
    try testing.expect(std.meta.activeTag(r) == .replied);
    try testing.expectEqual(@as(usize, req.len), r.replied);

    var d = wire.Decoder{ .data = h.frame.bytes() };
    try testing.expectEqual(@as(usize, h.frame.bytes().len - 4), try d.u32be()); // length prefix
    try testing.expectEqual(@as(u8, 12), try d.byte()); // SSH_AGENT_IDENTITIES_ANSWER
    try testing.expectEqual(@as(u32, 1), try d.u32be()); // one identity
    try testing.expectEqualStrings("k1", try d.string());
    try testing.expectEqualStrings("one", try d.string());
}

test "processOne: incomplete input asks for more (short header, then short body)" {
    var cp = crypto.Fake{ .keys = &.{} };
    var az = authz.Fake{};
    var h = Harness.init(&cp, &az);
    defer h.deinit();

    try testing.expect(std.meta.activeTag(h.run(&[_]u8{ 0, 0 })) == .need_more); // < 4 length bytes
    try testing.expect(std.meta.activeTag(h.run(&[_]u8{ 0, 0, 0, 5, 11 })) == .need_more); // 5 claimed, 1 present
}

test "processOne: an oversize length fails closed" {
    var cp = crypto.Fake{ .keys = &.{} };
    var az = authz.Fake{};
    var h = Harness.init(&cp, &az);
    defer h.deinit();
    try testing.expect(std.meta.activeTag(h.run(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF })) == .close);
}

test "processOne: an unsupported request is framed as FAILURE, not closed" {
    var cp = crypto.Fake{ .keys = &.{} };
    var az = authz.Fake{};
    var h = Harness.init(&cp, &az);
    defer h.deinit();

    const r = h.run(&[_]u8{ 0, 0, 0, 1, 99 }); // [u32 1][unknown type]
    try testing.expect(std.meta.activeTag(r) == .replied);
    var d = wire.Decoder{ .data = h.frame.bytes() };
    _ = try d.u32be(); // length prefix
    try testing.expectEqual(@as(u8, 5), try d.byte()); // SSH_AGENT_FAILURE
}

test "processOne: pipelined frames are consumed one at a time" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "k1", .comment = "one" }} };
    var az = authz.Fake{};
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
