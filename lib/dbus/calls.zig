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

pub const login1_dest = "org.freedesktop.login1";
const login1_path = "/org/freedesktop/login1";
const login1_mgr_iface = "org.freedesktop.login1.Manager";
pub const login1_session_iface = "org.freedesktop.login1.Session";

/// The error GetSessionByPID returns when the pid is not in any logind session scope (a graphical
/// terminal, a systemd --user service): the signal to fall back to the user's sessions.
pub const login1_no_session_for_pid = "org.freedesktop.login1.NoSessionForPID";

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

/// org.freedesktop.login1.Manager.ListSessions() -> a(susso): one struct per session,
/// (s session_id, u uid, s user_name, s seat_id, o session_path). Used by the remote gate to
/// answer "does this user have a session, and is any of them remote?" for a sessionless peer.
pub fn listSessions(enc: *Encoder, serial: u32) !void {
    try message.encodeMethodCall(enc, serial, login1_dest, login1_path, login1_mgr_iface, "ListSessions", "", "");
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

/// One element of a ListSessions reply. The slices alias the reply body.
pub const Session = struct {
    id: []const u8,
    uid: u32,
    user: []const u8,
    seat: []const u8,
    path: []const u8,
};

/// A streaming decoder over a ListSessions reply body (a(susso)) -- yields one Session per struct
/// element without allocating. The D-Bus array is a 4-aligned u32 byte-count followed by the
/// element data padded to the struct's 8-byte boundary; each struct is 8-aligned in turn.
pub const SessionIter = struct {
    d: wire.Decoder,
    end: usize,

    pub fn init(body: []const u8, endian: std.builtin.Endian) ParseError!SessionIter {
        var d = wire.Decoder{ .data = body, .endian = endian };
        const len: usize = @intCast(try d.get32());
        if (len == 0) return .{ .d = d, .end = d.pos }; // empty array: no element-alignment padding
        try d.alignTo(8); // padding to the struct element boundary precedes the first element
        const end = std.math.add(usize, d.pos, len) catch return error.UnexpectedType;
        if (end > body.len) return error.UnexpectedType;
        return .{ .d = d, .end = end };
    }

    pub fn next(self: *SessionIter) ParseError!?Session {
        if (self.d.pos >= self.end) return null;
        try self.d.alignTo(8); // each (susso) struct starts on an 8-byte boundary
        if (self.d.pos >= self.end) return null;
        const id = try self.d.string();
        const uid = try self.d.get32();
        const user = try self.d.string();
        const seat = try self.d.string();
        const path = try self.d.string(); // an object path decodes like a string
        return .{ .id = id, .uid = uid, .user = user, .seat = seat, .path = path };
    }
};

/// One session reduced to the fields the local-only decision needs.
pub const SessionRemote = struct { uid: u32, remote: bool };

/// The security decision for a sessionless peer, factored pure for testing: true iff `uid` owns at
/// least one session and NONE of uid's sessions is remote. A sessionless process cannot be pinned
/// to a specific session, so a uid that is ALSO logged in remotely is ambiguous and refused;
/// another user's remote session is irrelevant. Mirrors the validated Go localsession.localOnlyForUID.
pub fn localOnlyForUser(sessions: []const SessionRemote, uid: u32) bool {
    var has_local = false;
    for (sessions) |s| {
        if (s.uid != uid) continue;
        if (s.remote) return false; // a remote session for this user => ambiguous => refuse
        has_local = true;
    }
    return has_local;
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

/// Marshal one (susso) struct element, 8-aligned as D-Bus requires for a struct.
fn appendSession(enc: *Encoder, id: []const u8, uid: u32, user: []const u8, seat: []const u8, path: []const u8) !void {
    try enc.pad(8);
    try enc.string(id);
    try enc.put32(uid);
    try enc.string(user);
    try enc.string(seat);
    try enc.string(path); // an object path marshals like a string
}

test "SessionIter walks a(susso) and yields uid + path per session" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    // Hand-build the array body: a 4-aligned u32 byte-length, padding to the 8-byte struct
    // boundary, then the struct elements; the length counts only the element bytes.
    const lp = enc.mark();
    try enc.raw(&[_]u8{ 0, 0, 0, 0 }); // length placeholder, backpatched below
    try enc.pad(8);
    const ds = enc.mark();
    try appendSession(&enc, "1", 1000, "alice", "seat0", "/org/freedesktop/login1/session/_31");
    try appendSession(&enc, "2", 1000, "alice", "", "/org/freedesktop/login1/session/_32");
    try appendSession(&enc, "c1", 0, "root", "", "/org/freedesktop/login1/session/c1");
    enc.patchU32(lp, @intCast(enc.mark() - ds));

    var it = try SessionIter.init(enc.bytes(), .little);
    const a = (try it.next()).?;
    try testing.expectEqual(@as(u32, 1000), a.uid);
    try testing.expectEqualStrings("/org/freedesktop/login1/session/_31", a.path);
    const b = (try it.next()).?;
    try testing.expectEqual(@as(u32, 1000), b.uid);
    try testing.expectEqualStrings("/org/freedesktop/login1/session/_32", b.path);
    const c = (try it.next()).?;
    try testing.expectEqual(@as(u32, 0), c.uid);
    try testing.expectEqualStrings("root", c.user);
    try testing.expect((try it.next()) == null);
}

test "SessionIter on an empty array yields nothing" {
    var enc = Encoder.init(testing.allocator);
    defer enc.deinit();
    try enc.put32(0); // zero-length array: no element-alignment padding follows
    var it = try SessionIter.init(enc.bytes(), .little);
    try testing.expect((try it.next()) == null);
}

test "localOnlyForUser: local iff the user has a session and none is remote" {
    const u: u32 = 1000;
    try testing.expect(!localOnlyForUser(&.{}, u)); // no sessions at all -> cannot confirm
    try testing.expect(!localOnlyForUser(&.{.{ .uid = 0, .remote = false }}, u)); // only another user's
    try testing.expect(localOnlyForUser(&.{.{ .uid = u, .remote = false }}, u)); // one local session
    try testing.expect(localOnlyForUser(&.{ .{ .uid = u, .remote = false }, .{ .uid = u, .remote = false } }, u));
    // a remote session for this user makes a sessionless peer ambiguous -> refuse
    try testing.expect(!localOnlyForUser(&.{ .{ .uid = u, .remote = false }, .{ .uid = u, .remote = true } }, u));
    // another user's remote session is irrelevant and ignored
    try testing.expect(localOnlyForUser(&.{ .{ .uid = u, .remote = false }, .{ .uid = 0, .remote = true } }, u));
}
