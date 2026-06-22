// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The ssh-agent protocol (draft-miller-ssh-agent): parse client requests and build agent
//! responses, on top of the SSH wire codec (wire.zig). Framing convention here: a wire
//! message is `u32 length` + `length` body bytes, where the body is `byte type` + payload.
//! `parseRequest` takes a body (the IPC layer reads the length first, then that many bytes);
//! the response builders write a body too — call `frame` to prepend the length for the wire.

const std = @import("std");
const wire = @import("wire.zig");

/// Message type bytes. Non-exhaustive: unknown/unsupported types round-trip as their integer.
pub const MessageType = enum(u8) {
    failure = 5,
    success = 6,
    request_identities = 11,
    identities_answer = 12,
    sign_request = 13,
    sign_response = 14,
    _,
};

pub const SignRequest = struct {
    key_blob: []const u8,
    data: []const u8,
    flags: u32,
};

/// A parsed client→agent request. `unsupported` carries the raw type byte so the agent can
/// answer SSH_AGENT_FAILURE without the protocol layer knowing every message.
pub const Request = union(enum) {
    request_identities,
    sign_request: SignRequest,
    unsupported: u8,
};

pub const ParseError = wire.Decoder.Error || error{TrailingData};

/// Parse a request body (`byte type` + payload). Slices in the result alias `body`. Known
/// message types are parsed strictly: trailing bytes past the documented fields are rejected
/// as `error.TrailingData` (→ the agent answers FAILURE) so untrusted input can't smuggle
/// extra data. Unknown types are returned as `unsupported` without inspecting their payload.
pub fn parseRequest(body: []const u8) ParseError!Request {
    var d = wire.Decoder{ .data = body };
    const t = try d.byte();
    switch (@as(MessageType, @enumFromInt(t))) {
        .request_identities => {
            if (!d.done()) return error.TrailingData;
            return .request_identities;
        },
        .sign_request => {
            const req = SignRequest{
                .key_blob = try d.string(),
                .data = try d.string(),
                .flags = try d.u32be(),
            };
            if (!d.done()) return error.TrailingData;
            return .{ .sign_request = req };
        },
        else => return .{ .unsupported = t },
    }
}

/// One advertised identity in an IDENTITIES_ANSWER.
pub const Identity = struct {
    blob: []const u8,
    comment: []const u8,
};

/// Write an SSH_AGENT_IDENTITIES_ANSWER body into `enc`.
pub fn writeIdentitiesAnswer(enc: *wire.Encoder, ids: []const Identity) !void {
    try enc.byte(@intFromEnum(MessageType.identities_answer));
    try enc.u32be(@intCast(ids.len));
    for (ids) |id| {
        try enc.string(id.blob);
        try enc.string(id.comment);
    }
}

/// Write an SSH_AGENT_SIGN_RESPONSE body (the signature is itself an SSH blob).
pub fn writeSignResponse(enc: *wire.Encoder, signature: []const u8) !void {
    try enc.byte(@intFromEnum(MessageType.sign_response));
    try enc.string(signature);
}

pub fn writeFailure(enc: *wire.Encoder) !void {
    try enc.byte(@intFromEnum(MessageType.failure));
}

pub fn writeSuccess(enc: *wire.Encoder) !void {
    try enc.byte(@intFromEnum(MessageType.success));
}

/// Prepend the u32 length frame to a finished `body`, producing the bytes to write on the
/// wire, into `out`.
pub fn frame(out: *wire.Encoder, body: []const u8) !void {
    try out.u32be(@intCast(body.len));
    try out.raw(body);
}

test "parse a REQUEST_IDENTITIES body" {
    try std.testing.expectEqual(Request.request_identities, try parseRequest(&.{11}));
}

test "parse a SIGN_REQUEST body" {
    var enc = wire.Encoder.init(std.testing.allocator);
    defer enc.deinit();
    try enc.byte(13);
    try enc.string("the-key-blob");
    try enc.string("data-to-sign");
    try enc.u32be(0x04); // SSH_AGENT_RSA_SHA2_512-style flag value, opaque here

    const req = try parseRequest(enc.bytes());
    try std.testing.expectEqualStrings("the-key-blob", req.sign_request.key_blob);
    try std.testing.expectEqualStrings("data-to-sign", req.sign_request.data);
    try std.testing.expectEqual(@as(u32, 4), req.sign_request.flags);
}

test "an unknown type parses as unsupported (→ FAILURE)" {
    const req = try parseRequest(&.{99});
    try std.testing.expectEqual(@as(u8, 99), req.unsupported);
}

test "trailing bytes on a known message are rejected" {
    // REQUEST_IDENTITIES with a stray trailing byte
    try std.testing.expectError(error.TrailingData, parseRequest(&.{ 11, 0 }));

    // SIGN_REQUEST with extra bytes after flags
    var enc = wire.Encoder.init(std.testing.allocator);
    defer enc.deinit();
    try enc.byte(13);
    try enc.string("blob");
    try enc.string("data");
    try enc.u32be(0);
    try enc.byte(0xFF); // trailing junk
    try std.testing.expectError(error.TrailingData, parseRequest(enc.bytes()));
}

test "build + frame an IDENTITIES_ANSWER, then read it back" {
    var body = wire.Encoder.init(std.testing.allocator);
    defer body.deinit();
    try writeIdentitiesAnswer(&body, &.{
        .{ .blob = "blobA", .comment = "a@h" },
        .{ .blob = "blobB", .comment = "b@h" },
    });

    var framed = wire.Encoder.init(std.testing.allocator);
    defer framed.deinit();
    try frame(&framed, body.bytes());

    var d = wire.Decoder{ .data = framed.bytes() };
    const len = try d.u32be();
    try std.testing.expectEqual(body.bytes().len, len);
    try std.testing.expectEqual(@as(u8, @intFromEnum(MessageType.identities_answer)), try d.byte());
    try std.testing.expectEqual(@as(u32, 2), try d.u32be());
    try std.testing.expectEqualStrings("blobA", try d.string());
    try std.testing.expectEqualStrings("a@h", try d.string());
    try std.testing.expectEqualStrings("blobB", try d.string());
    try std.testing.expectEqualStrings("b@h", try d.string());
    try std.testing.expect(d.done());
}

test "SIGN_RESPONSE carries the signature blob" {
    var enc = wire.Encoder.init(std.testing.allocator);
    defer enc.deinit();
    try writeSignResponse(&enc, "sig-bytes");
    var d = wire.Decoder{ .data = enc.bytes() };
    try std.testing.expectEqual(@as(u8, @intFromEnum(MessageType.sign_response)), try d.byte());
    try std.testing.expectEqualStrings("sig-bytes", try d.string());
}
