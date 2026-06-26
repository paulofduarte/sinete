// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The TSS2 private-key file format (the "BEGIN TSS2 PRIVATE KEY" PEM from the Bottomley draft /
//! go-tpm-keyfiles), so a TPM key persists on disk and interoperates with tpm2-tools, the OpenSSL
//! tpm2 provider, etc. A sinete key is a loadable key under the owner-hierarchy primary with no
//! auth and no policy, so the structure is fixed:
//!
//!   TPMKey ::= SEQUENCE {
//!       type      OBJECT IDENTIFIER,      -- 2.23.133.10.1.3 (loadable key)
//!       emptyAuth [0] EXPLICIT BOOLEAN,   -- TRUE
//!       parent    INTEGER,                -- 0x40000001 (TPM_RH_OWNER)
//!       pubkey    OCTET STRING,           -- a marshaled TPM2B_PUBLIC
//!       privkey   OCTET STRING }          -- a marshaled TPM2B_PRIVATE
//!
//! Pure and allocator-free (the file is small): encode writes the PEM into a caller buffer; decode
//! parses a PEM back into the public/private blobs. Golden-vector and round-trip unit-tested.

const std = @import("std");

pub const Error = error{ BadKeyFile, NoSpace };

const loadable_key_oid = [_]u8{ 0x67, 0x81, 0x05, 0x0A, 0x01, 0x03 }; // 2.23.133.10.1.3
const owner_parent = [_]u8{ 0x40, 0x00, 0x00, 0x01 }; // TPM_RH_OWNER as a DER INTEGER (high bit clear)
const pem_label = "TSS2 PRIVATE KEY";

const Der = struct {
    buf: []u8,
    pos: usize = 0,

    fn byte(self: *Der, v: u8) Error!void {
        if (self.pos >= self.buf.len) return Error.NoSpace;
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn bytes(self: *Der, s: []const u8) Error!void {
        const end = std.math.add(usize, self.pos, s.len) catch return Error.NoSpace;
        if (end > self.buf.len) return Error.NoSpace;
        @memcpy(self.buf[self.pos..end], s);
        self.pos = end;
    }
    /// A DER definite length: short form (< 128) or 1-/2-byte long form (covers the few-hundred-byte
    /// TPM blobs).
    fn len(self: *Der, n: usize) Error!void {
        if (n < 0x80) {
            try self.byte(@intCast(n));
        } else if (n < 0x100) {
            try self.byte(0x81);
            try self.byte(@intCast(n));
        } else if (n < 0x10000) {
            try self.byte(0x82);
            try self.byte(@intCast(n >> 8));
            try self.byte(@intCast(n & 0xFF));
        } else return Error.NoSpace;
    }
    fn tlv(self: *Der, tag: u8, value: []const u8) Error!void {
        try self.byte(tag);
        try self.len(value.len);
        try self.bytes(value);
    }
    fn out(self: *const Der) []const u8 {
        return self.buf[0..self.pos];
    }
};

/// Build the DER TPMKey for a loadable key (owner parent, empty auth) into `out`.
fn encodeDer(out: []u8, public: []const u8, private: []const u8) Error![]const u8 {
    var body_buf: [1024]u8 = undefined;
    var body = Der{ .buf = &body_buf };
    try body.tlv(0x06, &loadable_key_oid); // type
    try body.tlv(0xA0, &[_]u8{ 0x01, 0x01, 0xFF }); // [0] EXPLICIT BOOLEAN TRUE (emptyAuth)
    try body.tlv(0x02, &owner_parent); // parent INTEGER
    try body.tlv(0x04, public); // pubkey OCTET STRING
    try body.tlv(0x04, private); // privkey OCTET STRING

    var der = Der{ .buf = out };
    try der.byte(0x30); // SEQUENCE
    try der.len(body.pos);
    try der.bytes(body.out());
    return der.out();
}

/// Write the TSS2 PEM key file for (public, private) into `out`, returning the text slice.
pub fn encode(out: []u8, public: []const u8, private: []const u8) Error![]const u8 {
    var der_buf: [1280]u8 = undefined;
    const der = try encodeDer(&der_buf, public, private);

    var w = Der{ .buf = out };
    try w.bytes("-----BEGIN " ++ pem_label ++ "-----\n");
    const Enc = std.base64.standard.Encoder;
    var b64_buf: [2048]u8 = undefined;
    const b64 = Enc.encode(&b64_buf, der);
    var i: usize = 0;
    while (i < b64.len) : (i += 64) {
        try w.bytes(b64[i..@min(i + 64, b64.len)]);
        try w.byte('\n');
    }
    try w.bytes("-----END " ++ pem_label ++ "-----\n");
    return w.out();
}

const Parsed = struct { public: []const u8, private: []const u8 };

const DerReader = struct {
    data: []const u8,
    pos: usize = 0,

    fn elem(self: *DerReader) Error!struct { tag: u8, value: []const u8 } {
        if (self.pos + 2 > self.data.len) return Error.BadKeyFile;
        const tag = self.data[self.pos];
        var p = self.pos + 1;
        var n: usize = self.data[p];
        p += 1;
        if (n == 0x81) {
            if (p >= self.data.len) return Error.BadKeyFile;
            n = self.data[p];
            p += 1;
        } else if (n == 0x82) {
            if (p + 2 > self.data.len) return Error.BadKeyFile;
            n = (@as(usize, self.data[p]) << 8) | self.data[p + 1];
            p += 2;
        } else if (n >= 0x80) return Error.BadKeyFile;
        const end = std.math.add(usize, p, n) catch return Error.BadKeyFile;
        if (end > self.data.len) return Error.BadKeyFile;
        self.pos = end;
        return .{ .tag = tag, .value = self.data[p..end] };
    }
};

/// Parse a TSS2 PEM key file (in `pem`) into its public/private blobs, decoding the base64 into
/// `scratch` (the returned slices alias `scratch`). Tolerates other tools' files of the same shape.
pub fn decode(pem: []const u8, scratch: []u8) Error!Parsed {
    // Extract the base64 body between the PEM guards, dropping whitespace.
    const begin = std.mem.indexOf(u8, pem, "-----BEGIN " ++ pem_label ++ "-----") orelse return Error.BadKeyFile;
    const body_start = begin + ("-----BEGIN " ++ pem_label ++ "-----").len;
    const end = std.mem.indexOfPos(u8, pem, body_start, "-----END " ++ pem_label ++ "-----") orelse return Error.BadKeyFile;

    var b64_buf: [2048]u8 = undefined;
    var bl: usize = 0;
    for (pem[body_start..end]) |c| {
        if (c == '\n' or c == '\r' or c == ' ' or c == '\t') continue;
        if (bl >= b64_buf.len) return Error.BadKeyFile;
        b64_buf[bl] = c;
        bl += 1;
    }
    const Dec = std.base64.standard.Decoder;
    const der_len = Dec.calcSizeForSlice(b64_buf[0..bl]) catch return Error.BadKeyFile;
    if (der_len > scratch.len) return Error.NoSpace;
    Dec.decode(scratch[0..der_len], b64_buf[0..bl]) catch return Error.BadKeyFile;

    var top = DerReader{ .data = scratch[0..der_len] };
    const seq = try top.elem();
    if (seq.tag != 0x30) return Error.BadKeyFile;
    var r = DerReader{ .data = seq.value };
    _ = try r.elem(); // OID
    _ = try r.elem(); // [0] emptyAuth
    _ = try r.elem(); // parent INTEGER
    const public = try r.elem();
    const private = try r.elem();
    if (public.tag != 0x04 or private.tag != 0x04) return Error.BadKeyFile;
    return .{ .public = public.value, .private = private.value };
}

const testing = std.testing;

test "encode/decode round-trips the blobs" {
    const public = [_]u8{0xAB} ** 88; // a stand-in TPM2B_PUBLIC
    const private = [_]u8{0xCD} ** 126; // a stand-in TPM2B_PRIVATE
    var pem_buf: [2048]u8 = undefined;
    const pem = try encode(&pem_buf, &public, &private);

    try testing.expect(std.mem.startsWith(u8, pem, "-----BEGIN TSS2 PRIVATE KEY-----\n"));
    try testing.expect(std.mem.endsWith(u8, pem, "-----END TSS2 PRIVATE KEY-----\n"));

    var scratch: [1280]u8 = undefined;
    const got = try decode(pem, &scratch);
    try testing.expectEqualSlices(u8, &public, got.public);
    try testing.expectEqualSlices(u8, &private, got.private);
}

test "encoded DER has the expected TPMKey prefix (type + emptyAuth + parent)" {
    var der_buf: [256]u8 = undefined;
    const der = try encodeDer(&der_buf, "pub", "priv");
    // 0x30 <len> | 06 06 <oid> | A0 03 01 01 FF | 02 04 40 00 00 01 | 04 03 'pub' | 04 04 'priv'
    const want_prefix = [_]u8{
        0x30, 0x1e,
        0x06, 0x06,
        0x67, 0x81,
        0x05, 0x0a,
        0x01, 0x03,
        0xa0, 0x03,
        0x01, 0x01,
        0xff, 0x02,
        0x04, 0x40,
        0x00, 0x00,
        0x01, 0x04,
        0x03, 'p',
        'u',  'b',
        0x04, 0x04,
        'p',  'r',
        'i',  'v',
    };
    try testing.expectEqualSlices(u8, &want_prefix, der);
}

test "long-form length encodes a >127-byte octet string" {
    var der_buf: [512]u8 = undefined;
    const der = try encodeDer(&der_buf, &([_]u8{0x11} ** 200), "x");
    var r = DerReader{ .data = der };
    const seq = try r.elem();
    var b = DerReader{ .data = seq.value };
    _ = try b.elem(); // oid
    _ = try b.elem(); // emptyAuth
    _ = try b.elem(); // parent
    const pub_el = try b.elem();
    try testing.expectEqual(@as(usize, 200), pub_el.value.len);
}

test "decode rejects garbage and missing guards" {
    var scratch: [256]u8 = undefined;
    try testing.expectError(Error.BadKeyFile, decode("not a pem", &scratch));
    try testing.expectError(Error.BadKeyFile, decode("-----BEGIN TSS2 PRIVATE KEY-----\n!!!\n-----END TSS2 PRIVATE KEY-----\n", &scratch));
}
