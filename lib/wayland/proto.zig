// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The slice of the Wayland wire protocol the built-in modal needs: request builders and event
//! parsing for wl_display/registry/compositor/shm/shm_pool/surface/seat/keyboard/pointer and the
//! wlr-layer-shell extension (zwlr_layer_shell_v1 / zwlr_layer_surface_v1). Pure host-endian
//! marshalling (little-endian on the targets we build); the impure socket, the shm memfd, the
//! SCM_RIGHTS fd-passing and the event loop live in src/backend/wayland_conn.zig. A Wayland message
//! is `object_id:u32 | (size<<16 | opcode):u32 | args`, size counting the 8-byte header; strings are
//! a u32 length (incl. the NUL) then the bytes padded to 4; an fd argument travels out of band.

const std = @import("std");

pub const Error = error{ Truncated, BadMessage };

// Wayland is a local IPC and uses the HOST byte order on the wire (both peers share endianness).
const native_end = @import("builtin").cpu.arch.endian();

// The fixed display object id, and the format/enum values the modal uses.
pub const display_id: u32 = 1;
pub const format_argb8888: u32 = 0;
pub const layer_overlay: u32 = 3;
pub const keyboard_exclusive: u32 = 1;

// Request opcodes (request = client -> server).
pub const wl_display_sync: u16 = 0;
pub const wl_callback_done: u16 = 0;
pub const wl_display_get_registry: u16 = 1;
pub const wl_registry_bind: u16 = 0;
pub const wl_compositor_create_surface: u16 = 0;
pub const wl_shm_create_pool: u16 = 0;
pub const wl_shm_pool_create_buffer: u16 = 0;
pub const wl_surface_attach: u16 = 1;
pub const wl_surface_damage: u16 = 2;
pub const wl_surface_commit: u16 = 6;
pub const wl_seat_get_pointer: u16 = 0;
pub const wl_seat_get_keyboard: u16 = 1;
pub const layer_shell_get_layer_surface: u16 = 0;
pub const layer_surface_set_size: u16 = 0;
pub const layer_surface_set_keyboard_interactivity: u16 = 4;
pub const layer_surface_ack_configure: u16 = 6;

// Event opcodes (event = server -> client).
pub const wl_display_error: u16 = 0;
pub const wl_registry_global: u16 = 0;
pub const wl_seat_capabilities: u16 = 0;
pub const wl_keyboard_key: u16 = 3;
pub const wl_pointer_enter: u16 = 0;
pub const wl_pointer_motion: u16 = 2;
pub const wl_pointer_button: u16 = 3;
pub const layer_surface_configure: u16 = 0;

const Encoder = std.ArrayList(u8);

fn putU32(out: *Encoder, gpa: std.mem.Allocator, v: u32) !void {
    try out.appendSlice(gpa, &std.mem.toBytes(v)); // native byte order (Wayland is host-endian)
}

/// A length-prefixed Wayland string: u32 length INCLUDING the NUL terminator, the bytes, the NUL,
/// then zero-padding to a 4-byte boundary.
fn putString(out: *Encoder, gpa: std.mem.Allocator, s: []const u8) !void {
    const n: u32 = @intCast(s.len + 1);
    try putU32(out, gpa, n);
    try out.appendSlice(gpa, s);
    try out.append(gpa, 0);
    while ((out.items.len % 4) != 0) try out.append(gpa, 0);
}

/// Emit a message: header (object id, then size<<16 | opcode) followed by `body`. `size` counts the
/// 8-byte header plus the body and is always a multiple of 4 (the builders pad their args).
fn message(out: *Encoder, gpa: std.mem.Allocator, obj: u32, opcode: u16, body: []const u8) !void {
    const size: u32 = @intCast(8 + body.len);
    try putU32(out, gpa, obj);
    try putU32(out, gpa, (size << 16) | @as(u32, opcode));
    try out.appendSlice(gpa, body);
}

// --- request builders ---

/// wl_display.get_registry(new_id registry).
pub fn getRegistry(out: *Encoder, gpa: std.mem.Allocator, new_registry: u32) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, new_registry);
    try message(out, gpa, display_id, wl_display_get_registry, b.items);
}

/// wl_display.sync(new_id callback) -- the server replies with callback.done once it has processed
/// everything sent so far, which the client uses to know all registry globals have been delivered.
pub fn sync(out: *Encoder, gpa: std.mem.Allocator, new_callback: u32) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, new_callback);
    try message(out, gpa, display_id, wl_display_sync, b.items);
}

/// wl_registry.bind(name, interface, version, new_id) -- the bind new_id is untyped, so the wire
/// carries the interface string and version explicitly.
pub fn registryBind(out: *Encoder, gpa: std.mem.Allocator, registry: u32, name: u32, iface: []const u8, version: u32, new_id: u32) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, name);
    try putString(&b, gpa, iface);
    try putU32(&b, gpa, version);
    try putU32(&b, gpa, new_id);
    try message(out, gpa, registry, wl_registry_bind, b.items);
}

pub fn createSurface(out: *Encoder, gpa: std.mem.Allocator, compositor: u32, new_surface: u32) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, new_surface);
    try message(out, gpa, compositor, wl_compositor_create_surface, b.items);
}

/// wl_shm.create_pool(new_id pool, fd, size) -- the fd is passed out of band via SCM_RIGHTS, so it is
/// NOT in the message body; only the new id and size are marshalled here.
pub fn shmCreatePool(out: *Encoder, gpa: std.mem.Allocator, shm: u32, new_pool: u32, size: u32) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, new_pool);
    try putU32(&b, gpa, size);
    try message(out, gpa, shm, wl_shm_create_pool, b.items);
}

pub fn poolCreateBuffer(out: *Encoder, gpa: std.mem.Allocator, pool: u32, new_buffer: u32, offset: u32, w: u32, h: u32, stride: u32, format: u32) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, new_buffer);
    try putU32(&b, gpa, offset);
    try putU32(&b, gpa, w);
    try putU32(&b, gpa, h);
    try putU32(&b, gpa, stride);
    try putU32(&b, gpa, format);
    try message(out, gpa, pool, wl_shm_pool_create_buffer, b.items);
}

pub fn surfaceAttach(out: *Encoder, gpa: std.mem.Allocator, surface: u32, buffer: u32, x: i32, y: i32) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, buffer);
    try putU32(&b, gpa, @bitCast(x));
    try putU32(&b, gpa, @bitCast(y));
    try message(out, gpa, surface, wl_surface_attach, b.items);
}

pub fn surfaceDamage(out: *Encoder, gpa: std.mem.Allocator, surface: u32, x: i32, y: i32, w: i32, h: i32) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, @bitCast(x));
    try putU32(&b, gpa, @bitCast(y));
    try putU32(&b, gpa, @bitCast(w));
    try putU32(&b, gpa, @bitCast(h));
    try message(out, gpa, surface, wl_surface_damage, b.items);
}

pub fn surfaceCommit(out: *Encoder, gpa: std.mem.Allocator, surface: u32) !void {
    try message(out, gpa, surface, wl_surface_commit, "");
}

pub fn seatGetKeyboard(out: *Encoder, gpa: std.mem.Allocator, seat: u32, new_kbd: u32) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, new_kbd);
    try message(out, gpa, seat, wl_seat_get_keyboard, b.items);
}

pub fn seatGetPointer(out: *Encoder, gpa: std.mem.Allocator, seat: u32, new_ptr: u32) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, new_ptr);
    try message(out, gpa, seat, wl_seat_get_pointer, b.items);
}

/// zwlr_layer_shell_v1.get_layer_surface(new_id, surface, output, layer, namespace).
pub fn getLayerSurface(out: *Encoder, gpa: std.mem.Allocator, layer_shell: u32, new_ls: u32, surface: u32, output: u32, layer: u32, namespace: []const u8) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, new_ls);
    try putU32(&b, gpa, surface);
    try putU32(&b, gpa, output);
    try putU32(&b, gpa, layer);
    try putString(&b, gpa, namespace);
    try message(out, gpa, layer_shell, layer_shell_get_layer_surface, b.items);
}

pub fn layerSurfaceSetSize(out: *Encoder, gpa: std.mem.Allocator, ls: u32, w: u32, h: u32) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, w);
    try putU32(&b, gpa, h);
    try message(out, gpa, ls, layer_surface_set_size, b.items);
}

pub fn layerSurfaceSetKeyboardInteractivity(out: *Encoder, gpa: std.mem.Allocator, ls: u32, mode: u32) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, mode);
    try message(out, gpa, ls, layer_surface_set_keyboard_interactivity, b.items);
}

pub fn layerSurfaceAckConfigure(out: *Encoder, gpa: std.mem.Allocator, ls: u32, serial: u32) !void {
    var b: Encoder = .empty;
    defer b.deinit(gpa);
    try putU32(&b, gpa, serial);
    try message(out, gpa, ls, layer_surface_ack_configure, b.items);
}

// --- event parsing ---

/// One message peeled off the wire: its target object, opcode, and body slice (aliasing the input).
pub const Msg = struct { obj: u32, opcode: u16, body: []const u8 };

/// The total byte length of the message at the front of `data`, or null if it is not yet complete.
pub fn frameLen(data: []const u8) Error!?usize {
    if (data.len < 8) return null;
    const word2 = std.mem.readInt(u32, data[4..8], native_end);
    const size: usize = @intCast(word2 >> 16);
    if (size < 8) return error.BadMessage;
    if (data.len < size) return null;
    return size;
}

/// Parse the message at the front of `data` (which must hold a full frame per frameLen).
pub fn parse(data: []const u8) Error!Msg {
    const size = (try frameLen(data)) orelse return error.Truncated;
    const obj = std.mem.readInt(u32, data[0..4], native_end);
    const word2 = std.mem.readInt(u32, data[4..8], native_end);
    return .{ .obj = obj, .opcode = @intCast(word2 & 0xffff), .body = data[8..size] };
}

/// wl_registry.global(name, interface, version): the name id, the interface string, its version.
pub fn parseGlobal(body: []const u8) Error!struct { name: u32, interface: []const u8, version: u32 } {
    var d = Reader{ .b = body };
    const name = try d.rU32();
    const iface = try d.string();
    const version = try d.rU32();
    return .{ .name = name, .interface = iface, .version = version };
}

/// zwlr_layer_surface_v1.configure(serial, width, height).
pub fn parseConfigure(body: []const u8) Error!struct { serial: u32, width: u32, height: u32 } {
    var d = Reader{ .b = body };
    return .{ .serial = try d.rU32(), .width = try d.rU32(), .height = try d.rU32() };
}

/// wl_seat.capabilities(capabilities) -- bit 0 = pointer, bit 1 = keyboard.
pub fn parseCapabilities(body: []const u8) Error!u32 {
    var d = Reader{ .b = body };
    return d.rU32();
}

/// wl_keyboard.key(serial, time, key, state): the evdev keycode and whether it is a press (1).
pub fn parseKey(body: []const u8) Error!struct { key: u32, pressed: bool } {
    var d = Reader{ .b = body };
    _ = try d.rU32(); // serial
    _ = try d.rU32(); // time
    const key = try d.rU32();
    const state = try d.rU32();
    return .{ .key = key, .pressed = state == 1 };
}

/// wl_pointer.button(serial, time, button, state): the button code and whether it is a press (1).
pub fn parseButton(body: []const u8) Error!struct { button: u32, pressed: bool } {
    var d = Reader{ .b = body };
    _ = try d.rU32(); // serial
    _ = try d.rU32(); // time
    const button = try d.rU32();
    const state = try d.rU32();
    return .{ .button = button, .pressed = state == 1 };
}

/// wl_pointer.enter(serial, surface, x, y): the surface-local position in 24.8 fixed point.
pub fn parseEnter(body: []const u8) Error!struct { x: i32, y: i32 } {
    var d = Reader{ .b = body };
    _ = try d.rU32(); // serial
    _ = try d.rU32(); // surface
    const x = try d.fixedToInt();
    const y = try d.fixedToInt();
    return .{ .x = x, .y = y };
}

/// wl_pointer.motion(time, x, y): the surface-local position in 24.8 fixed point.
pub fn parseMotion(body: []const u8) Error!struct { x: i32, y: i32 } {
    var d = Reader{ .b = body };
    _ = try d.rU32(); // time
    const x = try d.fixedToInt();
    const y = try d.fixedToInt();
    return .{ .x = x, .y = y };
}

const Reader = struct {
    b: []const u8,
    pos: usize = 0,
    fn rU32(self: *Reader) Error!u32 {
        if (self.pos + 4 > self.b.len) return error.Truncated;
        defer self.pos += 4;
        return std.mem.readInt(u32, self.b[self.pos..][0..4], native_end);
    }
    /// A wl_fixed (24.8 signed) truncated to its integer part.
    fn fixedToInt(self: *Reader) Error!i32 {
        const raw: i32 = @bitCast(try self.rU32());
        return raw >> 8;
    }
    fn string(self: *Reader) Error![]const u8 {
        const n: usize = @intCast(try self.rU32());
        if (n == 0) return "";
        if (self.pos + n > self.b.len) return error.Truncated;
        if (self.b[self.pos + n - 1] != 0) return error.BadMessage; // the trailing NUL must be present
        const s = self.b[self.pos .. self.pos + n - 1]; // content without the NUL
        const padded = (n + 3) & ~@as(usize, 3);
        if (self.pos + padded > self.b.len) return error.Truncated;
        self.pos += padded;
        return s;
    }
};

const testing = std.testing;

fn lastMsg(items: []const u8) !Msg {
    return parse(items);
}

test "message header carries object, opcode and a 4-aligned size" {
    var out: Encoder = .empty;
    defer out.deinit(testing.allocator);
    try getRegistry(&out, testing.allocator, 2);
    try testing.expectEqual(@as(usize, 0), out.items.len % 4);
    const m = try lastMsg(out.items);
    try testing.expectEqual(display_id, m.obj);
    try testing.expectEqual(wl_display_get_registry, m.opcode);
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, m.body[0..4], native_end)); // new registry id
    try testing.expectEqual(@as(usize, out.items.len), (try frameLen(out.items)).?);
}

test "registryBind marshals name, interface string (padded), version and id" {
    var out: Encoder = .empty;
    defer out.deinit(testing.allocator);
    try registryBind(&out, testing.allocator, 2, 7, "wl_shm", 1, 3);
    const m = try lastMsg(out.items);
    try testing.expectEqual(wl_registry_bind, m.opcode);
    var d = Reader{ .b = m.body };
    try testing.expectEqual(@as(u32, 7), try d.rU32());
    try testing.expectEqualStrings("wl_shm", try d.string());
    try testing.expectEqual(@as(u32, 1), try d.rU32());
    try testing.expectEqual(@as(u32, 3), try d.rU32());
    try testing.expectEqual(@as(usize, 0), out.items.len % 4);
}

test "getLayerSurface carries the overlay layer and namespace" {
    var out: Encoder = .empty;
    defer out.deinit(testing.allocator);
    try getLayerSurface(&out, testing.allocator, 5, 6, 4, 0, layer_overlay, "sinete");
    const m = try lastMsg(out.items);
    try testing.expectEqual(layer_shell_get_layer_surface, m.opcode);
    var d = Reader{ .b = m.body };
    try testing.expectEqual(@as(u32, 6), try d.rU32()); // new layer surface id
    try testing.expectEqual(@as(u32, 4), try d.rU32()); // surface
    try testing.expectEqual(@as(u32, 0), try d.rU32()); // output = none
    try testing.expectEqual(layer_overlay, try d.rU32());
    try testing.expectEqualStrings("sinete", try d.string());
}

test "poolCreateBuffer marshals all six args in order" {
    var out: Encoder = .empty;
    defer out.deinit(testing.allocator);
    try poolCreateBuffer(&out, testing.allocator, 8, 9, 0, 420, 140, 420 * 4, format_argb8888);
    const m = try lastMsg(out.items);
    var d = Reader{ .b = m.body };
    try testing.expectEqual(@as(u32, 9), try d.rU32());
    try testing.expectEqual(@as(u32, 0), try d.rU32());
    try testing.expectEqual(@as(u32, 420), try d.rU32());
    try testing.expectEqual(@as(u32, 140), try d.rU32());
    try testing.expectEqual(@as(u32, 1680), try d.rU32());
    try testing.expectEqual(format_argb8888, try d.rU32());
}

test "parse + frameLen split a two-message buffer" {
    var out: Encoder = .empty;
    defer out.deinit(testing.allocator);
    try surfaceCommit(&out, testing.allocator, 4);
    const first_len = (try frameLen(out.items)).?;
    try surfaceCommit(&out, testing.allocator, 5);
    try testing.expectEqual(first_len, (try frameLen(out.items)).?); // first frame length unchanged
    const m1 = try parse(out.items[0..first_len]);
    const m2 = try parse(out.items[first_len..]);
    try testing.expectEqual(@as(u32, 4), m1.obj);
    try testing.expectEqual(@as(u32, 5), m2.obj);
    try testing.expect((try frameLen(out.items[0..6])) == null); // a short buffer is incomplete
}

test "parseGlobal / parseConfigure / parseKey / parseEnter decode event bodies" {
    var out: Encoder = .empty;
    defer out.deinit(testing.allocator);
    // global(name=1, "zwlr_layer_shell_v1", version=4)
    try putU32(&out, testing.allocator, 1);
    try putString(&out, testing.allocator, "zwlr_layer_shell_v1");
    try putU32(&out, testing.allocator, 4);
    const g = try parseGlobal(out.items);
    try testing.expectEqual(@as(u32, 1), g.name);
    try testing.expectEqualStrings("zwlr_layer_shell_v1", g.interface);
    try testing.expectEqual(@as(u32, 4), g.version);

    var k: Encoder = .empty;
    defer k.deinit(testing.allocator);
    try putU32(&k, testing.allocator, 0); // serial
    try putU32(&k, testing.allocator, 0); // time
    try putU32(&k, testing.allocator, 1); // key = evdev Escape
    try putU32(&k, testing.allocator, 1); // state = pressed
    const key = try parseKey(k.items);
    try testing.expectEqual(@as(u32, 1), key.key);
    try testing.expect(key.pressed);

    var e: Encoder = .empty;
    defer e.deinit(testing.allocator);
    try putU32(&e, testing.allocator, 0); // serial
    try putU32(&e, testing.allocator, 0); // surface
    try putU32(&e, testing.allocator, @bitCast(@as(i32, 130 << 8))); // x = 130.0 fixed
    try putU32(&e, testing.allocator, @bitCast(@as(i32, 110 << 8))); // y = 110.0 fixed
    const pos = try parseEnter(e.items);
    try testing.expectEqual(@as(i32, 130), pos.x);
    try testing.expectEqual(@as(i32, 110), pos.y);
}
