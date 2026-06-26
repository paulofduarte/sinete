// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! D-Bus message framing: the fixed header, the a(yv) header-field array, body splicing, and the
//! inverse parse. A D-Bus message is `endian byte | type | flags | version | u32 body_len |
//! u32 serial | a(yv) header fields | pad to 8 | body`. The body is marshaled separately (on its
//! own Encoder, which starts 8-aligned exactly as the spliced body does) and passed in as bytes.

const std = @import("std");
const wire = @import("wire.zig");

pub const Encoder = wire.Encoder;
pub const Decoder = wire.Decoder;
pub const Error = error{ Truncated, BadMessage };

pub const msg_method_call: u8 = 1;
pub const msg_method_return: u8 = 2;
pub const msg_error: u8 = 3;
pub const msg_signal: u8 = 4;

// Header field codes (a(yv) entries).
const f_path: u8 = 1;
const f_interface: u8 = 2;
const f_member: u8 = 3;
const f_error_name: u8 = 4;
const f_reply_serial: u8 = 5;
const f_destination: u8 = 6;
const f_signature: u8 = 8;

/// Marshal a METHOD_CALL into `enc`. `body` is the already-marshaled argument bytes (empty for a
/// no-arg call) and `body_sig` its signature (empty when there is no body).
pub fn encodeMethodCall(
    enc: *Encoder,
    serial: u32,
    dest: []const u8,
    path: []const u8,
    iface: []const u8,
    member: []const u8,
    body_sig: []const u8,
    body: []const u8,
) !void {
    try enc.byte('l'); // little-endian
    try enc.byte(msg_method_call);
    try enc.byte(0); // flags
    try enc.byte(1); // protocol version
    try enc.put32(@intCast(body.len)); // body length (offset 4)
    try enc.put32(serial); // serial (offset 8, must be nonzero)

    // a(yv) header fields: a 4-aligned u32 byte-length, then 8-aligned struct entries. The length
    // counts only the entry bytes, not the padding between it and the first entry.
    try enc.pad(4);
    const len_pos = enc.mark();
    try enc.raw(&[_]u8{ 0, 0, 0, 0 }); // placeholder, backpatched below
    try enc.pad(8);
    const data_start = enc.mark();
    try fieldStr(enc, f_path, "o", path);
    try fieldStr(enc, f_interface, "s", iface);
    try fieldStr(enc, f_member, "s", member);
    try fieldStr(enc, f_destination, "s", dest);
    if (body_sig.len > 0) try fieldSig(enc, body_sig);
    enc.patchU32(len_pos, @intCast(enc.mark() - data_start));

    try enc.pad(8); // the body begins 8-aligned
    try enc.raw(body);
}

/// One a(yv) entry whose variant value is a string/object-path (`vsig` is "s" or "o").
fn fieldStr(enc: *Encoder, code: u8, vsig: []const u8, value: []const u8) !void {
    try enc.pad(8);
    try enc.byte(code);
    try enc.signature(vsig);
    try enc.string(value);
}

/// One a(yv) entry whose variant value is itself a signature (the SIGNATURE header field).
fn fieldSig(enc: *Encoder, sig: []const u8) !void {
    try enc.pad(8);
    try enc.byte(f_signature);
    try enc.signature("g");
    try enc.signature(sig);
}

fn alignUp(n: usize, a: usize) Error!usize {
    const r = std.math.add(usize, n, a - 1) catch return error.BadMessage;
    return r & ~(a - 1);
}

pub const Frame = union(enum) {
    need_more,
    msg: []const u8, // a complete message, aliasing the input
};

/// Whether `data` holds a complete message, computing its total length from the header without
/// allocating. Mirrors lib/agent/framing.zig's need_more/complete decision so the connection layer
/// can demux a stream of replies and signals.
pub fn frameView(data: []const u8) Error!Frame {
    if (data.len < 16) return .need_more;
    const endian: std.builtin.Endian = switch (data[0]) {
        'l' => .little,
        'B' => .big,
        else => return error.BadMessage,
    };
    const body_len: usize = std.mem.readInt(u32, data[4..8], endian);
    const array_len: usize = std.mem.readInt(u32, data[12..16], endian);
    const header_end = std.math.add(usize, 16, array_len) catch return error.BadMessage;
    const body_start = try alignUp(header_end, 8);
    const total = std.math.add(usize, body_start, body_len) catch return error.BadMessage;
    if (data.len < total) return .need_more;
    return .{ .msg = data[0..total] };
}

pub const Parsed = struct {
    type: u8,
    serial: u32,
    endian: std.builtin.Endian,
    reply_serial: ?u32 = null,
    member: ?[]const u8 = null,
    iface: ?[]const u8 = null,
    error_name: ?[]const u8 = null,
    body_sig: ?[]const u8 = null,
    body: []const u8,
};

/// Parse one complete message (as returned by frameView) into the header fields sinete consults
/// plus the body slice. Unknown header fields are skipped by their variant signature.
pub fn parse(msg: []const u8) Error!Parsed {
    if (msg.len < 16) return error.Truncated;
    const endian: std.builtin.Endian = switch (msg[0]) {
        'l' => .little,
        'B' => .big,
        else => return error.BadMessage,
    };
    var d = Decoder{ .data = msg, .endian = endian };
    _ = try d.byte(); // order
    const mtype = try d.byte();
    _ = try d.byte(); // flags
    _ = try d.byte(); // version
    const body_len: usize = try d.get32();
    const serial = try d.get32();

    const array_len: usize = try d.get32(); // offset 12
    const arr_end = std.math.add(usize, d.pos, array_len) catch return error.BadMessage;
    if (arr_end > msg.len) return error.Truncated;

    var out = Parsed{ .type = mtype, .serial = serial, .endian = endian, .body = &.{} };
    while (d.pos < arr_end) {
        try d.alignTo(8);
        if (d.pos >= arr_end) break;
        const code = try d.byte();
        const sig = try d.signature();
        if (sig.len == 0) return error.BadMessage;
        switch (code) {
            f_reply_serial => out.reply_serial = try d.get32(),
            f_member => out.member = try d.string(),
            f_interface => out.iface = try d.string(),
            f_error_name => out.error_name = try d.string(),
            f_signature => out.body_sig = try d.signature(),
            else => try d.skipBasic(sig[0]),
        }
    }
    const body_start = try alignUp(arr_end, 8);
    const body_end = std.math.add(usize, body_start, body_len) catch return error.BadMessage;
    if (body_end > msg.len) return error.Truncated;
    out.body = msg[body_start..body_end];
    return out;
}

const testing = std.testing;

test "method call round-trips through parse with the expected header fields" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    // Properties.Get(interface, property): body = two strings.
    var body = Encoder.init(testing.allocator);
    defer body.deinit();
    try body.string("org.freedesktop.login1.Session");
    try body.string("Remote");
    try encodeMethodCall(&enc, 3, "org.freedesktop.login1", "/org/freedesktop/login1/session/_31", "org.freedesktop.DBus.Properties", "Get", "ss", body.bytes());

    // The whole buffer is exactly one frame.
    const fr = try frameView(enc.bytes());
    try testing.expectEqualSlices(u8, enc.bytes(), fr.msg);

    const p = try parse(enc.bytes());
    try testing.expectEqual(msg_method_call, p.type);
    try testing.expectEqual(@as(u32, 3), p.serial);
    try testing.expectEqualStrings("Get", p.member.?);
    try testing.expectEqualStrings("org.freedesktop.DBus.Properties", p.iface.?);
    try testing.expectEqualStrings("ss", p.body_sig.?);
    try testing.expectEqualSlices(u8, body.bytes(), p.body);
}

test "header offsets and alignment are byte-exact for a no-arg call" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try encodeMethodCall(&enc, 1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello", "", "");
    const b = enc.bytes();
    try testing.expectEqual(@as(u8, 'l'), b[0]);
    try testing.expectEqual(@as(u8, msg_method_call), b[1]);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, b[4..8], .little)); // empty body
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, b[8..12], .little)); // serial
    // no SIGNATURE field (empty body), and the message is a whole number of 8-byte blocks once the
    // header array (which is padded to 8 for a would-be body) is accounted for.
    const p = try parse(b);
    try testing.expectEqualStrings("Hello", p.member.?);
    try testing.expectEqual(@as(usize, 0), p.body.len);
    try testing.expectEqual(@as(?[]const u8, null), p.body_sig);
}

test "frameView reports need_more until the full message is present" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try encodeMethodCall(&enc, 7, "d", "/p", "i", "m", "", "");
    const full = enc.bytes();
    try testing.expectEqual(Frame.need_more, try frameView(full[0..8])); // < 16
    try testing.expectEqual(Frame.need_more, try frameView(full[0 .. full.len - 1]));
    const fr = try frameView(full);
    try testing.expectEqualSlices(u8, full, fr.msg);
}

test "frameView rejects an unknown order byte" {
    var b = [_]u8{0} ** 16;
    b[0] = 'x';
    try testing.expectError(error.BadMessage, frameView(&b));
}

test "parse reads reply_serial and error_name and skips unknown header fields" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    // Hand-build an ERROR reply with REPLY_SERIAL (5, u), ERROR_NAME (4, s), and SENDER (7, s, skipped).
    try enc.byte('l');
    try enc.byte(msg_error);
    try enc.byte(0);
    try enc.byte(1);
    try enc.put32(0); // empty body
    try enc.put32(7); // serial
    try enc.pad(4);
    const lp = enc.mark();
    try enc.raw(&[_]u8{ 0, 0, 0, 0 });
    try enc.pad(8);
    const ds = enc.mark();
    try enc.pad(8); // REPLY_SERIAL
    try enc.byte(5);
    try enc.signature("u");
    try enc.put32(99);
    try enc.pad(8); // ERROR_NAME
    try enc.byte(4);
    try enc.signature("s");
    try enc.string("org.example.Boom");
    try enc.pad(8); // SENDER (code 7) -- not consumed; exercises the skipBasic path
    try enc.byte(7);
    try enc.signature("s");
    try enc.string(":1.5");
    enc.patchU32(lp, @intCast(enc.mark() - ds));
    try enc.pad(8);

    const p = try parse(enc.bytes());
    try testing.expectEqual(msg_error, p.type);
    try testing.expectEqual(@as(u32, 99), p.reply_serial.?);
    try testing.expectEqualStrings("org.example.Boom", p.error_name.?);
}
