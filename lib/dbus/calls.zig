// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The exact D-Bus calls sinete makes: the bus daemon (Hello, AddMatch), fprintd
//! (net.reactivated.Fprint Manager/Device), and login1 (GetSessionByPID + the Properties.Get used
//! to read a session's Remote flag). Each builder marshals a method call into the caller's Encoder;
//! each parser reads a reply/signal body. Kept deliberately narrow -- this is not a general D-Bus
//! binding.

const std = @import("std");
const wire = @import("wire.zig");
const message = @import("message.zig");

pub const Encoder = wire.Encoder;

// Well-known names, object paths, and interfaces.
const bus_dest = "org.freedesktop.DBus";
const bus_path = "/org/freedesktop/DBus";
const bus_iface = "org.freedesktop.DBus";
const props_iface = "org.freedesktop.DBus.Properties";

const fprint_dest = "net.reactivated.Fprint";
const fprint_mgr_path = "/net/reactivated/Fprint/Manager";
const fprint_mgr_iface = "net.reactivated.Fprint.Manager";
pub const fprint_device_iface = "net.reactivated.Fprint.Device";

const login1_dest = "org.freedesktop.login1";
const login1_path = "/org/freedesktop/login1";
const login1_mgr_iface = "org.freedesktop.login1.Manager";
pub const login1_session_iface = "org.freedesktop.login1.Session";

// --- bus daemon ---

/// org.freedesktop.DBus.Hello() -> s (our unique bus name). The first message after BEGIN.
pub fn hello(enc: *Encoder, serial: u32) !void {
    try message.encodeMethodCall(enc, serial, bus_dest, bus_path, bus_iface, "Hello", "", "");
}

/// org.freedesktop.DBus.AddMatch(s rule).
pub fn addMatch(enc: *Encoder, serial: u32, rule: []const u8) !void {
    var body = Encoder.init(enc.gpa);
    defer body.deinit();
    try body.string(rule);
    try message.encodeMethodCall(enc, serial, bus_dest, bus_path, bus_iface, "AddMatch", "s", body.bytes());
}

// --- fprintd ---

/// net.reactivated.Fprint.Manager.GetDefaultDevice() -> o (the device object path).
pub fn getDefaultDevice(enc: *Encoder, serial: u32) !void {
    try message.encodeMethodCall(enc, serial, fprint_dest, fprint_mgr_path, fprint_mgr_iface, "GetDefaultDevice", "", "");
}

/// net.reactivated.Fprint.Device.Claim(s username). Empty username = the caller's own user.
pub fn claim(enc: *Encoder, serial: u32, dev_path: []const u8, username: []const u8) !void {
    try deviceCallS(enc, serial, dev_path, "Claim", username);
}

/// net.reactivated.Fprint.Device.VerifyStart(s finger). "any" matches any enrolled finger.
pub fn verifyStart(enc: *Encoder, serial: u32, dev_path: []const u8, finger: []const u8) !void {
    try deviceCallS(enc, serial, dev_path, "VerifyStart", finger);
}

pub fn verifyStop(enc: *Encoder, serial: u32, dev_path: []const u8) !void {
    try message.encodeMethodCall(enc, serial, fprint_dest, dev_path, fprint_device_iface, "VerifyStop", "", "");
}

pub fn release(enc: *Encoder, serial: u32, dev_path: []const u8) !void {
    try message.encodeMethodCall(enc, serial, fprint_dest, dev_path, fprint_device_iface, "Release", "", "");
}

fn deviceCallS(enc: *Encoder, serial: u32, dev_path: []const u8, member: []const u8, arg: []const u8) !void {
    var body = Encoder.init(enc.gpa);
    defer body.deinit();
    try body.string(arg);
    try message.encodeMethodCall(enc, serial, fprint_dest, dev_path, fprint_device_iface, member, "s", body.bytes());
}

// --- login1 ---

/// org.freedesktop.login1.Manager.GetSessionByPID(u pid) -> o (the session object path).
pub fn getSessionByPID(enc: *Encoder, serial: u32, pid: u32) !void {
    var body = Encoder.init(enc.gpa);
    defer body.deinit();
    try body.put32(pid);
    try message.encodeMethodCall(enc, serial, login1_dest, login1_path, login1_mgr_iface, "GetSessionByPID", "u", body.bytes());
}

/// org.freedesktop.DBus.Properties.Get(s interface, s property) -> v, on `dest`/`obj_path`.
pub fn propertiesGet(enc: *Encoder, serial: u32, dest: []const u8, obj_path: []const u8, iface: []const u8, prop: []const u8) !void {
    var body = Encoder.init(enc.gpa);
    defer body.deinit();
    try body.string(iface);
    try body.string(prop);
    try message.encodeMethodCall(enc, serial, dest, obj_path, props_iface, "Get", "ss", body.bytes());
}

// --- body parsers ---

pub const ParseError = wire.Decoder.Error || error{UnexpectedType};

/// A reply whose body is a single object path (o) or string (s).
pub fn parsePathOrString(body: []const u8, endian: std.builtin.Endian) ParseError![]const u8 {
    var d = wire.Decoder{ .data = body, .endian = endian };
    return d.string();
}

/// org.freedesktop.DBus.Properties.Get reply: a variant (v) wrapping a boolean (b).
pub fn parseVariantBool(body: []const u8, endian: std.builtin.Endian) ParseError!bool {
    var d = wire.Decoder{ .data = body, .endian = endian };
    const sig = try d.signature();
    if (!std.mem.eql(u8, sig, "b")) return error.UnexpectedType;
    return d.boolean();
}

/// net.reactivated.Fprint.Device.VerifyStatus signal body: (s result, b done).
pub fn parseVerifyStatus(body: []const u8, endian: std.builtin.Endian) ParseError!struct { result: []const u8, done: bool } {
    var d = wire.Decoder{ .data = body, .endian = endian };
    const result = try d.string();
    const done = try d.boolean();
    return .{ .result = result, .done = done };
}

const testing = std.testing;

fn parseBody(enc: *const Encoder) !message.Parsed {
    return message.parse(enc.bytes());
}

test "getSessionByPID carries the pid and the right member" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try getSessionByPID(&enc, 5, 4242);
    const p = try parseBody(&enc);
    try testing.expectEqualStrings("GetSessionByPID", p.member.?);
    try testing.expectEqualStrings("org.freedesktop.login1.Manager", p.iface.?);
    try testing.expectEqualStrings("u", p.body_sig.?);
    var d = wire.Decoder{ .data = p.body, .endian = p.endian };
    try testing.expectEqual(@as(u32, 4242), try d.get32());
}

test "claim targets the device path with a string arg" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try claim(&enc, 9, "/net/reactivated/Fprint/Device/0", "");
    const p = try parseBody(&enc);
    try testing.expectEqualStrings("Claim", p.member.?);
    try testing.expectEqualStrings("net.reactivated.Fprint.Device", p.iface.?);
    try testing.expectEqualStrings("", try parsePathOrString(p.body, p.endian));
}

test "propertiesGet asks for the named interface property" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try propertiesGet(&enc, 2, login1_dest, "/org/freedesktop/login1/session/_31", login1_session_iface, "Remote");
    const p = try parseBody(&enc);
    try testing.expectEqualStrings("Get", p.member.?);
    try testing.expectEqualStrings("ss", p.body_sig.?);
}

test "parseVariantBool reads a Properties.Get(Remote) reply" {
    // body = variant("b", true): signature 'b' then a 4-aligned boolean.
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try enc.signature("b");
    try enc.boolean(true);
    try testing.expectEqual(true, try parseVariantBool(enc.bytes(), .little));

    enc.reset();
    try enc.signature("s"); // wrong inner type
    try enc.string("x");
    try testing.expectError(error.UnexpectedType, parseVariantBool(enc.bytes(), .little));
}

test "parseVerifyStatus reads (result, done)" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try enc.string("verify-match");
    try enc.boolean(true);
    const s = try parseVerifyStatus(enc.bytes(), .little);
    try testing.expectEqualStrings("verify-match", s.result);
    try testing.expectEqual(true, s.done);
}
