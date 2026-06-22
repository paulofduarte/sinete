// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! SSH wire-format primitives (RFC 4251 section 5): strings prefixed by a big-endian u32
//! length, fixed-width ints, and raw bytes. These are the shared substrate for the ssh-agent
//! protocol framing and the ecdsa-sha2-nistp256 key and signature blobs. The Encoder grows a
//! single buffer; the Decoder returns sub-slices of its input and never allocates.

const std = @import("std");

/// Appends SSH-wire values into a growable buffer. The caller owns the allocator and must
/// call deinit. bytes() returns the encoded slice, valid until the next append or deinit.
pub const Encoder = struct {
    gpa: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) Encoder {
        return .{ .gpa = gpa };
    }
    pub fn deinit(self: *Encoder) void {
        self.buf.deinit(self.gpa);
    }

    pub fn byte(self: *Encoder, v: u8) !void {
        try self.buf.append(self.gpa, v);
    }
    pub fn u32be(self: *Encoder, v: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .big);
        try self.buf.appendSlice(self.gpa, &b);
    }
    /// An SSH string: a u32 length followed by that many bytes (also used for blobs). A slice
    /// too long to express in the u32 length prefix returns error.StringTooLong.
    pub fn string(self: *Encoder, s: []const u8) !void {
        if (s.len > std.math.maxInt(u32)) return error.StringTooLong;
        try self.u32be(@intCast(s.len));
        try self.buf.appendSlice(self.gpa, s);
    }
    /// Raw bytes with no length prefix, for splicing a pre-encoded blob.
    pub fn raw(self: *Encoder, s: []const u8) !void {
        try self.buf.appendSlice(self.gpa, s);
    }
    pub fn bytes(self: *const Encoder) []const u8 {
        return self.buf.items;
    }
    /// Discard the encoded bytes, keeping the allocated capacity for reuse.
    pub fn reset(self: *Encoder) void {
        self.buf.clearRetainingCapacity();
    }
};

/// Reads SSH-wire values from a fixed input slice. Returned slices alias the input, so copy
/// them if they must outlive it. Never allocates. Lengths come from untrusted input, so every
/// read is bounds-checked and offset arithmetic is overflow-checked.
pub const Decoder = struct {
    data: []const u8,
    pos: usize = 0,

    pub const Error = error{Truncated};

    pub fn byte(self: *Decoder) Error!u8 {
        if (self.pos >= self.data.len) return error.Truncated;
        defer self.pos += 1;
        return self.data[self.pos];
    }
    pub fn u32be(self: *Decoder) Error!u32 {
        const end = std.math.add(usize, self.pos, 4) catch return error.Truncated;
        if (end > self.data.len) return error.Truncated;
        defer self.pos = end;
        return std.mem.readInt(u32, self.data[self.pos..][0..4], .big);
    }
    pub fn string(self: *Decoder) Error![]const u8 {
        const n: usize = try self.u32be();
        const end = std.math.add(usize, self.pos, n) catch return error.Truncated;
        if (end > self.data.len) return error.Truncated;
        defer self.pos = end;
        return self.data[self.pos..end];
    }
    /// True once the entire input has been consumed.
    pub fn done(self: *const Decoder) bool {
        return self.pos == self.data.len;
    }
};

test "encode/decode round-trip" {
    var enc = Encoder.init(std.testing.allocator);
    defer enc.deinit();
    try enc.string("ssh-agent");
    try enc.u32be(0xCAFEBABE);
    try enc.byte(11);
    try enc.string(""); // an empty string is a valid 4-byte zero length

    var dec = Decoder{ .data = enc.bytes() };
    try std.testing.expectEqualStrings("ssh-agent", try dec.string());
    try std.testing.expectEqual(@as(u32, 0xCAFEBABE), try dec.u32be());
    try std.testing.expectEqual(@as(u8, 11), try dec.byte());
    try std.testing.expectEqualStrings("", try dec.string());
    try std.testing.expect(dec.done());
}

test "decoder rejects a string that overruns the buffer" {
    // length prefix claims 5 bytes but only 2 follow
    var dec = Decoder{ .data = &[_]u8{ 0, 0, 0, 5, 'a', 'b' } };
    try std.testing.expectError(error.Truncated, dec.string());
}

test "decoder rejects a string whose length would overflow the offset" {
    // a near-max length must fail cleanly as Truncated, not wrap the position
    var dec = Decoder{ .data = &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 'a' } };
    try std.testing.expectError(error.Truncated, dec.string());
}

test "decoder rejects a truncated u32" {
    var dec = Decoder{ .data = &[_]u8{ 0, 0 } };
    try std.testing.expectError(error.Truncated, dec.u32be());
}
