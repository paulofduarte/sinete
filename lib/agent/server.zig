// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! Protocol dispatch: turn one parsed ssh-agent request into a response body by driving the
//! Agent sign-path (core.zig). This is the seam between the wire protocol (agent_proto.zig)
//! and the orchestration core; Z2's libxev socket layer reads a framed message, calls
//! `respond`, then frames the body back. Kept transport-free so it stays unit-testable.

const std = @import("std");
const proto = @import("../ssh/agent_proto.zig");
const wire = @import("../ssh/wire.zig");
const core = @import("core.zig");

/// The largest signature blob we emit: `ecdsa-sha2-nistp256` is ~101 bytes; 512 is ample.
const max_sig = 512;

/// Handle one request `body` (a parsed message body, sans length frame), writing the
/// response body into `enc`. `arena` backs any per-request allocation; `now_ms` is injected
/// for the TTL logic. Any malformed input or backend/presence error becomes SSH_AGENT_FAILURE
/// — the agent never leaks an error to the client beyond "refused".
pub fn respond(agent: *core.Agent, body: []const u8, arena: std.mem.Allocator, now_ms: i64, enc: *wire.Encoder) !void {
    const req = proto.parseRequest(body) catch return proto.writeFailure(enc);
    switch (req) {
        .request_identities => {
            const keys = agent.identities(arena) catch return proto.writeFailure(enc);
            const ids = try arena.alloc(proto.Identity, keys.len);
            for (keys, 0..) |k, i| ids[i] = .{ .blob = k.blob, .comment = k.comment };
            try proto.writeIdentitiesAnswer(enc, ids);
        },
        .sign_request => |sr| {
            var sig: [max_sig]u8 = undefined;
            const n = agent.sign(sr.key_blob, sr.data, now_ms, &sig) catch return proto.writeFailure(enc);
            try proto.writeSignResponse(enc, sig[0..n]);
        },
        .unsupported => try proto.writeFailure(enc),
    }
}

const testing = std.testing;
const authz = @import("../authz.zig");
const crypto = @import("../crypto.zig");

fn buildSignRequestBody(enc: *wire.Encoder, key_blob: []const u8, data: []const u8, flags: u32) !void {
    try enc.byte(13); // SSH_AGENTC_SIGN_REQUEST
    try enc.string(key_blob);
    try enc.string(data);
    try enc.u32be(flags);
}

test "REQUEST_IDENTITIES is answered with the advertised keys" {
    var cp = crypto.Fake{ .keys = &.{
        .{ .blob = "k1", .comment = "one" },
        .{ .blob = "k2", .comment = "two" },
    } };
    var az = authz.Fake{};
    var agent = core.Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit(); // respond allocates into the arena; freed wholesale here

    var enc = wire.Encoder.init(testing.allocator);
    defer enc.deinit();
    try respond(&agent, &.{11}, arena.allocator(), 1000, &enc);

    var d = wire.Decoder{ .data = enc.bytes() };
    try testing.expectEqual(@as(u8, 12), try d.byte()); // IDENTITIES_ANSWER
    try testing.expectEqual(@as(u32, 2), try d.u32be());
    try testing.expectEqualStrings("k1", try d.string());
    try testing.expectEqualStrings("one", try d.string());
}

test "SIGN_REQUEST for a known key yields SIGN_RESPONSE and runs presence once" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "k1", .comment = "one" }} };
    var az = authz.Fake{};
    var agent = core.Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var body = wire.Encoder.init(testing.allocator);
    defer body.deinit();
    try buildSignRequestBody(&body, "k1", "payload", 0);

    var enc = wire.Encoder.init(testing.allocator);
    defer enc.deinit();
    try respond(&agent, body.bytes(), testing.allocator, 1000, &enc);

    var d = wire.Decoder{ .data = enc.bytes() };
    try testing.expectEqual(@as(u8, 14), try d.byte()); // SIGN_RESPONSE
    const sig = try d.string();
    try testing.expectEqual(@as(usize, 1), sig.len); // the fake's 1-byte blob
    try testing.expectEqual(@as(usize, 1), az.granted);
}

test "a declined presence gesture yields FAILURE" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "k1", .comment = "one" }} };
    var az = authz.Fake{ .declines = true };
    var agent = core.Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var body = wire.Encoder.init(testing.allocator);
    defer body.deinit();
    try buildSignRequestBody(&body, "k1", "payload", 0);

    var enc = wire.Encoder.init(testing.allocator);
    defer enc.deinit();
    try respond(&agent, body.bytes(), testing.allocator, 1000, &enc);
    try testing.expectEqual(@as(u8, 5), enc.bytes()[0]); // SSH_AGENT_FAILURE
}

test "an unknown key yields FAILURE, never a partial response" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "k1", .comment = "one" }} };
    var az = authz.Fake{};
    var agent = core.Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var body = wire.Encoder.init(testing.allocator);
    defer body.deinit();
    try buildSignRequestBody(&body, "no-such-key", "payload", 0);

    var enc = wire.Encoder.init(testing.allocator);
    defer enc.deinit();
    try respond(&agent, body.bytes(), testing.allocator, 1000, &enc);
    try testing.expectEqual(@as(u8, 5), enc.bytes()[0]); // FAILURE
}

test "unsupported and malformed requests both yield FAILURE" {
    var cp = crypto.Fake{ .keys = &.{} };
    var az = authz.Fake{};
    var agent = core.Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1, .max_ms = 1 });
    defer agent.deinit();

    var enc = wire.Encoder.init(testing.allocator);
    defer enc.deinit();
    try respond(&agent, &.{99}, testing.allocator, 1, &enc); // unsupported type
    try testing.expectEqual(@as(u8, 5), enc.bytes()[0]);

    var enc2 = wire.Encoder.init(testing.allocator);
    defer enc2.deinit();
    try respond(&agent, &.{}, testing.allocator, 1, &enc2); // empty/malformed body
    try testing.expectEqual(@as(u8, 5), enc2.bytes()[0]);
}
