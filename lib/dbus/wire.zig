// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! D-Bus marshaling primitives (the freedesktop D-Bus spec, "Message Protocol"). Unlike the SSH
//! wire format, D-Bus is type-aligned: every fixed-width value sits at an offset that is a multiple
//! of its size, measured from the start of the message, with NUL padding in between. The Encoder
//! grows a single buffer and pads as it writes; the Decoder reads from a fixed slice and never
//! allocates. Only the subset sinete needs is implemented (basic types + the (yv) header-field
//! struct + arrays); there is no general container marshaler.
//!
//! Byte order: the Encoder always emits little-endian (the 'l' a message header declares). The
//! Decoder honors the order byte a message carries, so replies in either order parse.

const std = @import("std");

/// Appends D-Bus values into a growable buffer, inserting alignment padding before each aligned
/// type. The caller owns the allocator and must call deinit. bytes() is valid until the next
/// append or deinit. Offsets are measured from index 0, which the message layer keeps 8-aligned at
/// the body boundary so a body marshaled on its own Encoder aligns identically once spliced.
pub const Encoder = struct {
    gpa: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) Encoder {
        return .{ .gpa = gpa };
    }
    pub fn deinit(self: *Encoder) void {
        self.buf.deinit(self.gpa);
    }
    pub fn bytes(self: *const Encoder) []const u8 {
        return self.buf.items;
    }
    pub fn reset(self: *Encoder) void {
        self.buf.clearRetainingCapacity();
    }
    pub fn mark(self: *const Encoder) usize {
        return self.buf.items.len;
    }

    /// Pad with NUL bytes until the length is a multiple of `a` (1, 2, 4, or 8).
    pub fn pad(self: *Encoder, a: usize) !void {
        while (self.buf.items.len % a != 0) try self.buf.append(self.gpa, 0);
    }
    pub fn byte(self: *Encoder, v: u8) !void {
        try self.buf.append(self.gpa, v);
    }
    pub fn raw(self: *Encoder, s: []const u8) !void {
        try self.buf.appendSlice(self.gpa, s);
    }
    pub fn put16(self: *Encoder, v: u16) !void {
        try self.pad(2);
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, v, .little);
        try self.buf.appendSlice(self.gpa, &b);
    }
    pub fn put32(self: *Encoder, v: u32) !void {
        try self.pad(4);
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try self.buf.appendSlice(self.gpa, &b);
    }
    pub fn boolean(self: *Encoder, v: bool) !void {
        try self.put32(if (v) 1 else 0);
    }
    /// A STRING (s) or OBJECT_PATH (o): a 4-aligned u32 length (excluding the NUL) then the bytes
    /// then a trailing NUL.
    pub fn string(self: *Encoder, s: []const u8) !void {
        try self.put32(@intCast(s.len));
        try self.buf.appendSlice(self.gpa, s);
        try self.buf.append(self.gpa, 0);
    }
    /// A SIGNATURE (g): a 1-byte length (no alignment) then the bytes then a trailing NUL.
    pub fn signature(self: *Encoder, s: []const u8) !void {
        try self.buf.append(self.gpa, @intCast(s.len));
        try self.buf.appendSlice(self.gpa, s);
        try self.buf.append(self.gpa, 0);
    }
    /// Overwrite a previously reserved 4-aligned u32 (an array length backpatched once its data is
    /// written). `pos` must be a mark() taken right after a pad(4).
    pub fn patchU32(self: *Encoder, pos: usize, v: u32) void {
        std.mem.writeInt(u32, self.buf.items[pos..][0..4], v, .little);
    }
};

/// Reads D-Bus values from a fixed input slice. Returned slices alias the input. Never allocates;
/// every read is bounds- and overflow-checked. `endian` is taken from the message's order byte.
pub const Decoder = struct {
    data: []const u8,
    pos: usize = 0,
    endian: std.builtin.Endian = .little,

    pub const Error = error{ Truncated, BadMessage };

    /// Skip padding so the next read starts on an `a`-byte boundary (relative to index 0).
    pub fn alignTo(self: *Decoder, a: usize) Error!void {
        while (self.pos % a != 0) {
            if (self.pos >= self.data.len) return error.Truncated;
            self.pos += 1;
        }
    }
    pub fn byte(self: *Decoder) Error!u8 {
        if (self.pos >= self.data.len) return error.Truncated;
        defer self.pos += 1;
        return self.data[self.pos];
    }
    pub fn get16(self: *Decoder) Error!u16 {
        try self.alignTo(2);
        const end = std.math.add(usize, self.pos, 2) catch return error.Truncated;
        if (end > self.data.len) return error.Truncated;
        defer self.pos = end;
        return std.mem.readInt(u16, self.data[self.pos..][0..2], self.endian);
    }
    pub fn get32(self: *Decoder) Error!u32 {
        try self.alignTo(4);
        const end = std.math.add(usize, self.pos, 4) catch return error.Truncated;
        if (end > self.data.len) return error.Truncated;
        defer self.pos = end;
        return std.mem.readInt(u32, self.data[self.pos..][0..4], self.endian);
    }
    pub fn boolean(self: *Decoder) Error!bool {
        return (try self.get32()) != 0;
    }
    /// A STRING (s) or OBJECT_PATH (o); returns the bytes without the NUL.
    pub fn string(self: *Decoder) Error![]const u8 {
        const n: usize = @intCast(try self.get32());
        // n bytes of content + 1 NUL terminator
        const end = std.math.add(usize, self.pos, n + 1) catch return error.Truncated;
        if (end > self.data.len) return error.Truncated;
        defer self.pos = end;
        return self.data[self.pos .. self.pos + n];
    }
    /// A SIGNATURE (g); returns the bytes without the NUL.
    pub fn signature(self: *Decoder) Error![]const u8 {
        const n: usize = try self.byte();
        const end = std.math.add(usize, self.pos, n + 1) catch return error.Truncated;
        if (end > self.data.len) return error.Truncated;
        defer self.pos = end;
        return self.data[self.pos .. self.pos + n];
    }
    /// Skip a single basic value of the given type code, used to step over header-field variants we
    /// do not consume. Containers are not handled (header fields are always basic).
    pub fn skipBasic(self: *Decoder, type_char: u8) Error!void {
        switch (type_char) {
            'y' => _ = try self.byte(),
            'n', 'q' => _ = try self.get16(),
            'b', 'i', 'u' => _ = try self.get32(),
            'x', 't', 'd' => {
                try self.alignTo(8);
                const end = std.math.add(usize, self.pos, 8) catch return error.Truncated;
                if (end > self.data.len) return error.Truncated;
                self.pos = end;
            },
            's', 'o' => _ = try self.string(),
            'g' => _ = try self.signature(),
            else => return error.BadMessage,
        }
    }
    pub fn done(self: *const Decoder) bool {
        return self.pos == self.data.len;
    }
};

const testing = std.testing;

test "encoder pads each type to its alignment" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try enc.byte(0xAB); // offset 0
    try enc.put32(0x11223344); // offset 1 -> pad to 4 (3 NULs) -> bytes at 4
    try enc.put16(0x5566); // offset 8 -> already aligned
    try testing.expectEqualSlices(u8, &[_]u8{
        0xAB, 0x00, 0x00, 0x00, // byte + 3 pad
        0x44, 0x33, 0x22, 0x11, // u32 little-endian
        0x66, 0x55, // u16 little-endian
    }, enc.bytes());
}

test "string carries a length prefix and a NUL; signature uses a byte length" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try enc.string("ab");
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x00, 0x00, 0x00, 'a', 'b', 0x00 }, enc.bytes());
    enc.reset();
    try enc.signature("sb");
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 's', 'b', 0x00 }, enc.bytes());
}

test "encode/decode round-trip across the basic types" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try enc.byte(7);
    try enc.boolean(true);
    try enc.put32(0xDEADBEEF);
    try enc.string("/org/example");
    try enc.put16(0x0102);
    try enc.signature("v");

    var dec = Decoder{ .data = enc.bytes() };
    try testing.expectEqual(@as(u8, 7), try dec.byte());
    try testing.expectEqual(true, try dec.boolean());
    try testing.expectEqual(@as(u32, 0xDEADBEEF), try dec.get32());
    try testing.expectEqualStrings("/org/example", try dec.string());
    try testing.expectEqual(@as(u16, 0x0102), try dec.get16());
    try testing.expectEqualStrings("v", try dec.signature());
    try testing.expect(dec.done());
}

test "decoder honors a big-endian order byte" {
    var dec = Decoder{ .data = &[_]u8{ 0x11, 0x22, 0x33, 0x44 }, .endian = .big };
    try testing.expectEqual(@as(u32, 0x11223344), try dec.get32());
}

test "decoder rejects a string that overruns its buffer" {
    var dec = Decoder{ .data = &[_]u8{ 5, 0, 0, 0, 'a', 'b' } }; // says 5, only 2 follow
    try testing.expectError(error.Truncated, dec.string());
}

test "skipBasic steps over an unconsumed variant value" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try enc.put32(99); // a 'u' value to skip
    try enc.string("after");
    var dec = Decoder{ .data = enc.bytes() };
    try dec.skipBasic('u');
    try testing.expectEqualStrings("after", try dec.string());
}

test "skipBasic handles every basic type and rejects a container" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try enc.byte(1); // y
    try enc.put16(2); // q (also covers n)
    try enc.put32(3); // u (also covers b, i)
    try enc.pad(8);
    try enc.raw(&([_]u8{0} ** 8)); // x (also covers t, d): an 8-byte value
    try enc.signature("g"); // g
    try enc.string("s"); // s (also covers o)
    var d = Decoder{ .data = enc.bytes() };
    for ("yquxgs") |t| try d.skipBasic(t);
    try testing.expect(d.done());

    var d2 = Decoder{ .data = &[_]u8{0} };
    try testing.expectError(error.BadMessage, d2.skipBasic('a')); // a container code is rejected
}
