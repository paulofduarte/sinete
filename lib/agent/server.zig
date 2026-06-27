// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! Protocol dispatch: turn one parsed ssh-agent request into a response body by driving the
//! agent sign-path (core.zig). This is the seam between the wire protocol (agent_proto.zig)
//! and the orchestration core. The transport layer reads a framed message, calls respond, and
//! frames the body back. It is transport-free so it stays unit-testable.

const std = @import("std");
const proto = @import("../ssh/agent_proto.zig");
const wire = @import("../ssh/wire.zig");
const core = @import("core.zig");
const session = @import("../session.zig");

/// The largest signature blob emitted. An ecdsa-sha2-nistp256 signature is about 101 bytes,
/// so 512 is ample.
const max_sig = 512;

/// Handle one request body (a parsed message body without the length frame), writing the
/// response body into enc. arena backs per-request allocation, and now_ms is injected for the
/// TTL logic. Fail-closed: malformed input, a backend or presence error, and a response that
/// cannot be represented all collapse to a single SSH_AGENT_FAILURE. An error is returned only
/// if even that one byte cannot be written, for example under memory exhaustion.
pub fn respond(agent: *core.Agent, cred: ?session.Cred, body: []const u8, arena: std.mem.Allocator, now_ms: i64, enc: *wire.Encoder) !void {
    buildResponse(agent, cred, body, arena, now_ms, enc) catch {
        // Discard any partial response, then answer FAILURE.
        enc.reset();
        try proto.writeFailure(enc);
    };
}

fn buildResponse(agent: *core.Agent, cred: ?session.Cred, body: []const u8, arena: std.mem.Allocator, now_ms: i64, enc: *wire.Encoder) !void {
    switch (try proto.parseRequest(body)) {
        .request_identities => {
            const keys = try agent.identities(arena);
            const ids = try arena.alloc(proto.Identity, keys.len);
            for (keys, 0..) |k, i| ids[i] = .{ .blob = k.blob, .comment = k.comment };
            try proto.writeIdentitiesAnswer(enc, ids);
        },
        .sign_request => |sr| {
            var sig: [max_sig]u8 = undefined;
            const n = try agent.sign(cred, sr.key_blob, sr.data, now_ms, &sig);
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
    try respond(&agent, null, &.{11}, arena.allocator(), 1000, &enc);

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
    try respond(&agent, null, body.bytes(), testing.allocator, 1000, &enc);

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
    try respond(&agent, null, body.bytes(), testing.allocator, 1000, &enc);
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
    try respond(&agent, null, body.bytes(), testing.allocator, 1000, &enc);
    try testing.expectEqual(@as(u8, 5), enc.bytes()[0]); // FAILURE
}

test "unsupported and malformed requests both yield FAILURE" {
    var cp = crypto.Fake{ .keys = &.{} };
    var az = authz.Fake{};
    var agent = core.Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1, .max_ms = 1 });
    defer agent.deinit();

    var enc = wire.Encoder.init(testing.allocator);
    defer enc.deinit();
    try respond(&agent, null, &.{99}, testing.allocator, 1, &enc); // unsupported type
    try testing.expectEqual(@as(u8, 5), enc.bytes()[0]);

    var enc2 = wire.Encoder.init(testing.allocator);
    defer enc2.deinit();
    try respond(&agent, null, &.{}, testing.allocator, 1, &enc2); // empty/malformed body
    try testing.expectEqual(@as(u8, 5), enc2.bytes()[0]);
}
