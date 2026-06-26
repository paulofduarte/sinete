// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! ECDSA P-256 SSH public-key blob construction and parsing. The blob is the standard
//! ecdsa-sha2-nistp256 form: string("ecdsa-sha2-nistp256") || string("nistp256") ||
//! string(0x04 || X || Y). Pure wire shuffling shared by the backends (which assemble a blob from
//! a secure-element public point) and by signing (which recovers the point from a key_id).

const std = @import("std");
const wire = @import("wire.zig");

pub const key_type = "ecdsa-sha2-nistp256";
pub const curve_name = "nistp256";
/// An uncompressed P-256 point: 0x04 || X(32) || Y(32).
pub const point_len = 65;

pub const Error = error{ NotEcdsaP256, BadPoint };

/// Append the ecdsa-sha2-nistp256 public-key blob for `point` (an uncompressed 0x04||X||Y point).
pub fn writePubBlob(enc: *wire.Encoder, point: []const u8) !void {
    if (point.len != point_len or point[0] != 0x04) return Error.BadPoint;
    try enc.string(key_type);
    try enc.string(curve_name);
    try enc.string(point);
}

/// Return the 65-byte uncompressed point from an ecdsa-sha2-nistp256 public-key blob; the result
/// is a pointer-to-array (so the length is guaranteed in the type) aliasing `blob`. Rejects a blob
/// whose type or curve string is wrong, or whose point is not a 65-byte 0x04-prefixed point.
/// Trailing bytes after the point are ignored, so a key_id need only begin with a well-formed blob.
pub fn pointFromPubBlob(blob: []const u8) !*const [point_len]u8 {
    var dec = wire.Decoder{ .data = blob };
    const t = dec.string() catch return Error.NotEcdsaP256;
    if (!std.mem.eql(u8, t, key_type)) return Error.NotEcdsaP256;
    const c = dec.string() catch return Error.NotEcdsaP256;
    if (!std.mem.eql(u8, c, curve_name)) return Error.NotEcdsaP256;
    const point = dec.string() catch return Error.BadPoint;
    if (point.len != point_len or point[0] != 0x04) return Error.BadPoint;
    return point[0..point_len];
}

const testing = std.testing;

fn samplePoint() [point_len]u8 {
    var p: [point_len]u8 = undefined;
    p[0] = 0x04;
    for (1..point_len) |i| p[i] = @intCast(i);
    return p;
}

test "writePubBlob/pointFromPubBlob round-trip" {
    const point = samplePoint();
    var enc = wire.Encoder.init(testing.allocator);
    defer enc.deinit();
    try writePubBlob(&enc, &point);

    const got = try pointFromPubBlob(enc.bytes());
    try testing.expectEqualSlices(u8, &point, got);
}

test "writePubBlob rejects a malformed point" {
    var enc = wire.Encoder.init(testing.allocator);
    defer enc.deinit();
    try testing.expectError(Error.BadPoint, writePubBlob(&enc, &[_]u8{ 0x04, 0x01 })); // too short
    var uncompressed = samplePoint();
    uncompressed[0] = 0x02; // compressed-point prefix, not 0x04
    try testing.expectError(Error.BadPoint, writePubBlob(&enc, &uncompressed));
}

test "pointFromPubBlob rejects the wrong key type and curve" {
    var enc = wire.Encoder.init(testing.allocator);
    defer enc.deinit();
    const point = samplePoint();

    enc.reset();
    try enc.string("ssh-ed25519");
    try enc.string(curve_name);
    try enc.string(&point);
    try testing.expectError(Error.NotEcdsaP256, pointFromPubBlob(enc.bytes()));

    enc.reset();
    try enc.string(key_type);
    try enc.string("nistp384");
    try enc.string(&point);
    try testing.expectError(Error.NotEcdsaP256, pointFromPubBlob(enc.bytes()));
}

test "pointFromPubBlob rejects a bad point and a truncated blob" {
    var enc = wire.Encoder.init(testing.allocator);
    defer enc.deinit();

    enc.reset();
    try enc.string(key_type);
    try enc.string(curve_name);
    try enc.string(&[_]u8{ 0x04, 0x00 }); // wrong length
    try testing.expectError(Error.BadPoint, pointFromPubBlob(enc.bytes()));

    try testing.expectError(Error.NotEcdsaP256, pointFromPubBlob(&[_]u8{ 0, 0, 0 })); // truncated header
}
