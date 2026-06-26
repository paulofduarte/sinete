// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! Convert a DER-encoded ECDSA P-256 signature (as a secure element's sign returns) into the SSH
//! ecdsa-sha2-nistp256 signature blob. DER is SEQUENCE { INTEGER r, INTEGER s }; the SSH blob is
//! string("ecdsa-sha2-nistp256") || string( mpint(r) || mpint(s) ). No allocator: the result is
//! written into a caller buffer, fitting the allocator-free Cryptoprocessor.sign contract. DER
//! INTEGER and SSH mpint share the same minimal big-endian magnitude with a single 0x00 prepended
//! when the top bit is set, so r and s convert by canonicalizing the integer octets.

const std = @import("std");
const ecdsa_key = @import("ecdsa_key.zig");
const wire = @import("wire.zig");

pub const Error = error{ BadDer, TrailingData, NoSpace };

const Parsed = struct { content: []const u8, end: usize };

/// Parse one short-form DER element with the given tag at der[pos..]. A P-256 signature's SEQUENCE
/// (~70 bytes) and its INTEGERs (<= 33 bytes) always fit short-form lengths; a long-form length is
/// rejected, since a conforming P-256 signature never needs one.
fn parse(der: []const u8, pos: usize, tag: u8) Error!Parsed {
    if (pos + 2 > der.len or der[pos] != tag) return Error.BadDer;
    const len: usize = der[pos + 1];
    if (len >= 0x80) return Error.BadDer; // long-form length: not a conforming P-256 signature
    const start = pos + 2;
    const end = std.math.add(usize, start, len) catch return Error.BadDer;
    if (end > der.len) return Error.BadDer;
    return .{ .content = der[start..end], .end = end };
}

/// Reduce a DER INTEGER's content octets to an SSH-mpint magnitude: strip the leading 0x00 sign
/// bytes DER adds, leaving the minimal big-endian magnitude. Rejects an empty integer.
fn magnitude(int: []const u8) Error![]const u8 {
    if (int.len == 0) return Error.BadDer;
    var m = int;
    while (m.len > 1 and m[0] == 0x00) m = m[1..];
    return m;
}

/// Byte length of the SSH mpint for a stripped magnitude: 4 length bytes + an optional 0x00 sign
/// byte (when the high bit is set) + the magnitude.
fn mpintLen(mag: []const u8) u32 {
    const pad: u32 = if (mag[0] >= 0x80) 1 else 0;
    return 4 + pad + @as(u32, @intCast(mag.len));
}

/// Convert a DER ECDSA-Sig-Value into the SSH ecdsa-sha2-nistp256 signature blob, written into
/// `out`. Returns the blob length (~101 bytes for P-256). out too small -> error.NoSpace.
pub fn derP256ToSshBlob(der: []const u8, out: []u8) Error!usize {
    const seq = try parse(der, 0, 0x30);
    if (seq.end != der.len) return Error.TrailingData;
    const r_el = try parse(seq.content, 0, 0x02);
    const s_el = try parse(seq.content, r_el.end, 0x02);
    if (s_el.end != seq.content.len) return Error.TrailingData;
    const r = try magnitude(r_el.content);
    const s = try magnitude(s_el.content);

    var w = Writer{ .buf = out };
    try w.string(ecdsa_key.key_type);
    try w.u32be(mpintLen(r) + mpintLen(s)); // the inner blob is two mpints, of known total length
    try w.mpint(r);
    try w.mpint(s);
    return w.pos;
}

/// A bounded cursor that writes SSH-wire values into a fixed caller buffer, failing with NoSpace
/// rather than growing (mirrors wire.Encoder but without an allocator).
const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn byte(self: *Writer, v: u8) Error!void {
        if (self.pos >= self.buf.len) return Error.NoSpace;
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn raw(self: *Writer, s: []const u8) Error!void {
        const end = std.math.add(usize, self.pos, s.len) catch return Error.NoSpace;
        if (end > self.buf.len) return Error.NoSpace;
        @memcpy(self.buf[self.pos..end], s);
        self.pos = end;
    }
    fn u32be(self: *Writer, v: u32) Error!void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .big);
        try self.raw(&b);
    }
    fn string(self: *Writer, s: []const u8) Error!void {
        try self.u32be(@intCast(s.len));
        try self.raw(s);
    }
    fn mpint(self: *Writer, mag: []const u8) Error!void {
        const pad: u32 = if (mag[0] >= 0x80) 1 else 0;
        try self.u32be(pad + @as(u32, @intCast(mag.len)));
        if (pad == 1) try self.byte(0x00);
        try self.raw(mag);
    }
};

const testing = std.testing;

/// Build a DER SEQUENCE{INTEGER r, INTEGER s} from raw INTEGER content octets, into `buf`.
fn buildDer(r: []const u8, s: []const u8, buf: []u8) []u8 {
    var pos: usize = 0;
    const body_len = 2 + r.len + 2 + s.len;
    buf[pos] = 0x30;
    buf[pos + 1] = @intCast(body_len);
    pos += 2;
    for ([_][]const u8{ r, s }) |int| {
        buf[pos] = 0x02;
        buf[pos + 1] = @intCast(int.len);
        pos += 2;
        @memcpy(buf[pos..][0..int.len], int);
        pos += int.len;
    }
    return buf[0..pos];
}

test "derP256ToSshBlob: 32-byte r,s with high bit clear -> two 32-byte mpints" {
    var rbytes: [32]u8 = undefined;
    var sbytes: [32]u8 = undefined;
    for (0..32) |i| {
        rbytes[i] = @intCast(i + 1); // first byte 0x01, high bit clear
        sbytes[i] = @intCast(0x7f - i);
    }
    var der_buf: [80]u8 = undefined;
    const der = buildDer(&rbytes, &sbytes, &der_buf);

    var out: [256]u8 = undefined;
    const n = try derP256ToSshBlob(der, &out);

    var dec = wire.Decoder{ .data = out[0..n] };
    try testing.expectEqualStrings(ecdsa_key.key_type, try dec.string());
    const inner = try dec.string();
    try testing.expect(dec.done());
    var idec = wire.Decoder{ .data = inner };
    try testing.expectEqualSlices(u8, &rbytes, try idec.string()); // no 0x00 pad
    try testing.expectEqualSlices(u8, &sbytes, try idec.string());
    try testing.expect(idec.done());
}

test "derP256ToSshBlob: high-bit-set magnitude gets a 0x00 mpint pad" {
    const r = [_]u8{0x80} ++ [_]u8{0xAB} ** 31; // top bit set
    const s = [_]u8{0x01} ** 32;
    var der_buf: [80]u8 = undefined;
    const der = buildDer(&r, &s, &der_buf);

    var out: [256]u8 = undefined;
    const n = try derP256ToSshBlob(der, &out);
    var dec = wire.Decoder{ .data = out[0..n] };
    _ = try dec.string(); // type
    var idec = wire.Decoder{ .data = try dec.string() };
    const mr = try idec.string();
    try testing.expectEqual(@as(usize, 33), mr.len); // 0x00 + 32 magnitude bytes
    try testing.expectEqual(@as(u8, 0x00), mr[0]);
    try testing.expectEqualSlices(u8, &r, mr[1..]);
}

test "derP256ToSshBlob: an existing DER 0x00 sign byte is not doubled" {
    // DER encodes a high-bit-set integer with a leading 0x00; the mpint must carry exactly one.
    const r = [_]u8{ 0x00, 0x80 } ++ [_]u8{0x11} ** 31; // 33-byte DER INTEGER content
    const s = [_]u8{0x02} ** 32;
    var der_buf: [80]u8 = undefined;
    const der = buildDer(&r, &s, &der_buf);

    var out: [256]u8 = undefined;
    const n = try derP256ToSshBlob(der, &out);
    var dec = wire.Decoder{ .data = out[0..n] };
    _ = try dec.string();
    var idec = wire.Decoder{ .data = try dec.string() };
    const mr = try idec.string();
    try testing.expectEqual(@as(usize, 33), mr.len);
    try testing.expectEqual(@as(u8, 0x00), mr[0]);
    try testing.expectEqual(@as(u8, 0x80), mr[1]); // single pad, not 0x00 0x00 0x80
}

test "derP256ToSshBlob: a short (31-byte) integer keeps its length" {
    const r = [_]u8{0x33} ** 31;
    const s = [_]u8{0x44} ** 32;
    var der_buf: [80]u8 = undefined;
    const der = buildDer(&r, &s, &der_buf);

    var out: [256]u8 = undefined;
    const n = try derP256ToSshBlob(der, &out);
    var dec = wire.Decoder{ .data = out[0..n] };
    _ = try dec.string();
    var idec = wire.Decoder{ .data = try dec.string() };
    try testing.expectEqual(@as(usize, 31), (try idec.string()).len);
}

test "derP256ToSshBlob: malformed DER is rejected" {
    var out: [256]u8 = undefined;
    // wrong SEQUENCE tag
    try testing.expectError(Error.BadDer, derP256ToSshBlob(&[_]u8{ 0x31, 0x02, 0x02, 0x00 }, &out));
    // truncated: SEQUENCE length claims more than is present
    try testing.expectError(Error.BadDer, derP256ToSshBlob(&[_]u8{ 0x30, 0x10, 0x02, 0x01, 0x01 }, &out));
    // long-form length byte
    try testing.expectError(Error.BadDer, derP256ToSshBlob(&[_]u8{ 0x30, 0x81, 0x01, 0x00 }, &out));
    // empty INTEGER
    var der_buf: [80]u8 = undefined;
    const der = buildDer(&[_]u8{}, &[_]u8{0x01}, &der_buf);
    try testing.expectError(Error.BadDer, derP256ToSshBlob(der, &out));
}

test "derP256ToSshBlob: trailing bytes after the SEQUENCE and after s are rejected" {
    var out: [256]u8 = undefined;
    var der_buf: [80]u8 = undefined;
    const der = buildDer(&[_]u8{0x01} ** 32, &[_]u8{0x02} ** 32, &der_buf);
    var with_trailer: [96]u8 = undefined;
    @memcpy(with_trailer[0..der.len], der);
    with_trailer[der.len] = 0xFF;
    try testing.expectError(Error.TrailingData, derP256ToSshBlob(with_trailer[0 .. der.len + 1], &out));
}

test "derP256ToSshBlob: a too-small output buffer fails closed" {
    var der_buf: [80]u8 = undefined;
    const der = buildDer(&[_]u8{0x01} ** 32, &[_]u8{0x02} ** 32, &der_buf);
    var tiny: [10]u8 = undefined;
    try testing.expectError(Error.NoSpace, derP256ToSshBlob(der, &tiny));
}
