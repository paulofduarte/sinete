// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 wire marshaling: the command/response header framing and the big-endian primitives
//! (u8/u16/u32/u64, TPM2B size-prefixed buffers) used to build TPM2 commands and parse responses
//! directly over the device -- no tpm2-tss, the same approach go-tpm takes in pure Go. Pure and
//! allocator-free: a command marshals into a fixed caller buffer (TPM commands are bounded), so the
//! whole layer is golden-vector unit-tested with no hardware.

const std = @import("std");

pub const Error = error{ NoSpace, Truncated };

/// Command/response tags.
pub const st_no_sessions: u16 = 0x8001;
pub const st_sessions: u16 = 0x8002;

/// A bounded big-endian writer into a fixed buffer; fails with NoSpace rather than growing.
pub const Marshal = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn put8(self: *Marshal, v: u8) Error!void {
        if (self.pos >= self.buf.len) return Error.NoSpace;
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    pub fn putBytes(self: *Marshal, s: []const u8) Error!void {
        const end = std.math.add(usize, self.pos, s.len) catch return Error.NoSpace;
        if (end > self.buf.len) return Error.NoSpace;
        @memcpy(self.buf[self.pos..end], s);
        self.pos = end;
    }
    pub fn putInt(self: *Marshal, comptime T: type, v: T) Error!void {
        var b: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
        std.mem.writeInt(T, &b, v, .big);
        try self.putBytes(&b);
    }
    pub fn put16(self: *Marshal, v: u16) Error!void {
        return self.putInt(u16, v);
    }
    pub fn put32(self: *Marshal, v: u32) Error!void {
        return self.putInt(u32, v);
    }
    pub fn put64(self: *Marshal, v: u64) Error!void {
        return self.putInt(u64, v);
    }
    /// A TPM2B: a u16 byte count followed by that many bytes.
    pub fn put2b(self: *Marshal, s: []const u8) Error!void {
        if (s.len > 0xffff) return Error.NoSpace; // a TPM2B length must fit in its u16 prefix
        try self.put16(@intCast(s.len));
        try self.putBytes(s);
    }
    /// Reserve a u16 size field to be backfilled by `endSized` once the wrapped bytes are written
    /// (for a TPM2B wrapping a marshaled structure, e.g. TPM2B_PUBLIC around a TPMT_PUBLIC).
    pub fn beginSized(self: *Marshal) Error!usize {
        const at = self.pos;
        try self.put16(0);
        return at;
    }
    pub fn endSized(self: *Marshal, at: usize) Error!void {
        const n = self.pos - (at + 2);
        if (n > 0xffff) return Error.NoSpace; // the wrapped region must fit in the u16 size field
        std.mem.writeInt(u16, self.buf[at..][0..2], @intCast(n), .big);
    }
    pub fn bytes(self: *const Marshal) []const u8 {
        return self.buf[0..self.pos];
    }
};

/// Start a command in `buf`: writes the tag, a placeholder commandSize, and the commandCode, and
/// returns a Marshal positioned to write the parameters. Call `finishCommand` to backfill the size.
pub fn startCommand(buf: []u8, tag: u16, code: u32) Error!Marshal {
    var m = Marshal{ .buf = buf };
    try m.put16(tag);
    try m.put32(0); // commandSize placeholder at [2..6]
    try m.put32(code);
    return m;
}

/// Backfill the commandSize header from the bytes written so far.
pub fn finishCommand(m: *Marshal) void {
    std.mem.writeInt(u32, m.buf[2..6], @intCast(m.pos), .big);
}

/// A parsed response: the responseCode (0 = success) and the parameter bytes after the header.
pub const Response = struct { code: u32, params: []const u8 };

/// Parse the 10-byte response header (tag, responseSize, responseCode) and return the code + the
/// parameter slice. Rejects a header that overruns the buffer.
pub fn parseResponse(resp: []const u8) Error!Response {
    if (resp.len < 10) return Error.Truncated;
    const size = std.mem.readInt(u32, resp[2..6], .big);
    if (size < 10 or size > resp.len) return Error.Truncated;
    return .{
        .code = std.mem.readInt(u32, resp[6..10], .big),
        .params = resp[10..size],
    };
}

/// A big-endian reader over response parameter bytes; bounds-checked, never allocates.
pub const Unmarshal = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn getInt(self: *Unmarshal, comptime T: type) Error!T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        const end = std.math.add(usize, self.pos, n) catch return Error.Truncated;
        if (end > self.data.len) return Error.Truncated;
        defer self.pos = end;
        return std.mem.readInt(T, self.data[self.pos..][0..n], .big);
    }
    pub fn get8(self: *Unmarshal) Error!u8 {
        return self.getInt(u8);
    }
    pub fn get16(self: *Unmarshal) Error!u16 {
        return self.getInt(u16);
    }
    pub fn get32(self: *Unmarshal) Error!u32 {
        return self.getInt(u32);
    }
    pub fn get64(self: *Unmarshal) Error!u64 {
        return self.getInt(u64);
    }
    pub fn getBytes(self: *Unmarshal, n: usize) Error![]const u8 {
        const end = std.math.add(usize, self.pos, n) catch return Error.Truncated;
        if (end > self.data.len) return Error.Truncated;
        defer self.pos = end;
        return self.data[self.pos..end];
    }
    /// Read a TPM2B: a u16 count then that many bytes (the slice aliases the input).
    pub fn get2b(self: *Unmarshal) Error![]const u8 {
        const n = try self.get16();
        return self.getBytes(n);
    }
    pub fn done(self: *const Unmarshal) bool {
        return self.pos == self.data.len;
    }
};

const testing = std.testing;

test "marshal a command and backfill its size" {
    var buf: [64]u8 = undefined;
    var m = try startCommand(&buf, st_no_sessions, 0x0000017C); // GetRandom
    try m.put16(8); // bytesRequested
    finishCommand(&m);

    const got = m.bytes();
    const want = [_]u8{ 0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7C, 0, 8 };
    try testing.expectEqualSlices(u8, &want, got);
}

test "marshal primitives: ints, bytes, tpm2b, sized" {
    var buf: [64]u8 = undefined;
    var m = Marshal{ .buf = &buf };
    try m.put8(0xAB);
    try m.put32(0xDEADBEEF);
    try m.put2b("hi"); // 00 02 'h' 'i'
    const at = try m.beginSized();
    try m.put16(0x0102);
    try m.endSized(at); // size = 2
    try testing.expectEqualSlices(u8, &[_]u8{
        0xAB,
        0xDE,
        0xAD,
        0xBE,
        0xEF,
        0x00,
        0x02,
        'h',
        'i',
        0x00,
        0x02,
        0x01,
        0x02,
    }, m.bytes());
}

test "put64/get8/get64 round-trip" {
    var buf: [9]u8 = undefined;
    var m = Marshal{ .buf = &buf };
    try m.put8(0x42);
    try m.put64(0x0102030405060708);
    var u = Unmarshal{ .data = m.bytes() };
    try testing.expectEqual(@as(u8, 0x42), try u.get8());
    try testing.expectEqual(@as(u64, 0x0102030405060708), try u.get64());
    try testing.expect(u.done());
}

test "marshal fails closed when the buffer overflows" {
    var buf: [3]u8 = undefined;
    var m = Marshal{ .buf = &buf };
    try testing.expectError(Error.NoSpace, m.put32(1));
}

test "put2b fails closed for a value too large for its u16 length prefix" {
    var buf: [4]u8 = undefined;
    var m = Marshal{ .buf = &buf };
    var big: [0x10000]u8 = undefined; // 65536 > 0xffff
    try testing.expectError(Error.NoSpace, m.put2b(&big));
}

test "endSized fails closed when the wrapped region exceeds u16" {
    var buf: [0x10003]u8 = undefined;
    var m = Marshal{ .buf = &buf };
    const at = try m.beginSized();
    var body: [0x10000]u8 = undefined; // 65536 wrapped bytes > 0xffff
    try m.putBytes(&body);
    try testing.expectError(Error.NoSpace, m.endSized(at));
}

test "parse a response header and unmarshal params" {
    // header(10) + u32 0x01020304 + tpm2b "ab" = 18 bytes, so responseSize = 0x12
    const resp = [_]u8{ 0x80, 0x01, 0, 0, 0, 0x12, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x00, 0x02 } ++ [_]u8{ 'a', 'b' };
    const r = try parseResponse(&resp);
    try testing.expectEqual(@as(u32, 0), r.code);
    var u = Unmarshal{ .data = r.params };
    try testing.expectEqual(@as(u32, 0x01020304), try u.get32());
    try testing.expectEqualStrings("ab", try u.get2b());
    try testing.expect(u.done());
}

test "parse rejects a truncated header and an oversize declared size" {
    try testing.expectError(Error.Truncated, parseResponse(&[_]u8{ 0x80, 0x01, 0, 0 }));
    // declared size 0xFF but only 10 bytes present
    try testing.expectError(Error.Truncated, parseResponse(&[_]u8{ 0x80, 0x01, 0, 0, 0, 0xFF, 0, 0, 0, 0 }));
}

test "unmarshal bounds-checks reads" {
    var u = Unmarshal{ .data = &[_]u8{ 0, 1 } };
    try testing.expectError(Error.Truncated, u.get32());
    var ub = Unmarshal{ .data = &[_]u8{ 0, 5, 'a' } }; // tpm2b claims 5 bytes, 1 present
    try testing.expectError(Error.Truncated, ub.get2b());
}
