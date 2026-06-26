// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The text SASL handshake D-Bus runs before binary messages begin. sinete uses only the EXTERNAL
//! mechanism (the kernel-attested uid over the AF_UNIX socket): the client sends a leading NUL,
//! then `AUTH EXTERNAL <hex(ascii(decimal uid))>`, expects `OK <guid>`, then sends `BEGIN`. All
//! lines are CRLF-terminated. This module is the pure text formatting/parsing; the socket I/O and
//! the constant NUL/BEGIN bytes live in the connection layer.

const std = @import("std");

/// Format the `AUTH EXTERNAL <hex>\r\n` line into `out`. The authorization id is the uid rendered
/// as a decimal string, then hex-encoded byte-by-byte (uid 1000 -> "1000" -> "31303030").
pub fn authExternalLine(out: []u8, uid: u32) error{NoSpace}![]const u8 {
    const prefix = "AUTH EXTERNAL ";
    var dec_buf: [10]u8 = undefined; // u32 max is 10 digits
    const dec = std.fmt.bufPrint(&dec_buf, "{d}", .{uid}) catch return error.NoSpace;
    const need = prefix.len + dec.len * 2 + 2;
    if (out.len < need) return error.NoSpace;
    const hex = "0123456789abcdef";
    @memcpy(out[0..prefix.len], prefix);
    var i: usize = prefix.len;
    for (dec) |c| {
        out[i] = hex[c >> 4];
        out[i + 1] = hex[c & 0x0f];
        i += 2;
    }
    out[i] = '\r';
    out[i + 1] = '\n';
    return out[0 .. i + 2];
}

pub const Reply = union(enum) {
    ok: []const u8, // the server GUID (may be empty)
    rejected,
    data: []const u8,
    other,
};

/// Classify a server reply line (with or without a trailing CRLF).
pub fn parseReply(line: []const u8) Reply {
    var l = line;
    while (l.len > 0 and (l[l.len - 1] == '\r' or l[l.len - 1] == '\n')) l = l[0 .. l.len - 1];
    if (std.mem.eql(u8, l, "OK")) return .{ .ok = "" };
    if (std.mem.startsWith(u8, l, "OK ")) return .{ .ok = l["OK ".len..] };
    if (std.mem.startsWith(u8, l, "REJECTED")) return .rejected;
    if (std.mem.startsWith(u8, l, "DATA ")) return .{ .data = l["DATA ".len..] };
    return .other;
}

const testing = std.testing;

test "authExternalLine hex-encodes the decimal uid" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("AUTH EXTERNAL 31303030\r\n", try authExternalLine(&buf, 1000));
    try testing.expectEqualStrings("AUTH EXTERNAL 30\r\n", try authExternalLine(&buf, 0)); // "0" -> 0x30
}

test "authExternalLine fails closed without space" {
    var small: [4]u8 = undefined;
    try testing.expectError(error.NoSpace, authExternalLine(&small, 1000));
}

test "parseReply classifies the server lines" {
    try testing.expectEqualStrings("a1b2", (parseReply("OK a1b2\r\n")).ok);
    try testing.expectEqualStrings("", (parseReply("OK")).ok);
    try testing.expectEqual(Reply.rejected, parseReply("REJECTED EXTERNAL\r\n"));
    try testing.expect(parseReply("ERROR something") == .other);
}
