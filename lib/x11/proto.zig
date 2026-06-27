// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The slice of the X11 wire protocol the built-in modal needs: the connection setup request and
//! reply, and builders for CreateWindow / MapWindow / CreateGC / GrabKeyboard / GrabPointer /
//! PutImage, plus 32-byte event classification (Expose / KeyPress / ButtonPress / Error). Pure
//! little-endian marshalling (we always announce order 'l'); the impure socket + .Xauthority + event
//! loop live in src/backend/x11_conn.zig. Only what a single transient modal window requires -- not
//! a general X binding.

const std = @import("std");

pub const Error = error{ Truncated, SetupFailed, BadReply };

// Request opcodes used by the modal.
pub const op_create_window: u8 = 1;
pub const op_map_window: u8 = 8;
pub const op_grab_pointer: u8 = 26;
pub const op_grab_keyboard: u8 = 31;
pub const op_create_gc: u8 = 55;
pub const op_put_image: u8 = 72;

// CreateWindow value-mask bits.
const cw_back_pixel: u32 = 0x0002;
const cw_override_redirect: u32 = 0x0200;
const cw_event_mask: u32 = 0x0800;
// Event-mask bits we select.
const em_key_press: u32 = 0x0001;
const em_button_press: u32 = 0x0004;
const em_exposure: u32 = 0x8000;

// Event type codes (low 7 bits of byte 0).
pub const ev_error: u8 = 0;
pub const ev_key_press: u8 = 2;
pub const ev_button_press: u8 = 4;
pub const ev_expose: u8 = 12;

fn put16(out: *std.ArrayList(u8), gpa: std.mem.Allocator, v: u16) !void {
    try out.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(u16, v)));
}
fn put32(out: *std.ArrayList(u8), gpa: std.mem.Allocator, v: u32) !void {
    try out.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(u32, v)));
}

/// The connection setup request: little-endian order, protocol 11.0, with an optional auth scheme
/// (MIT-MAGIC-COOKIE-1) name + data. Both auth fields are padded to 4 bytes.
pub fn setupRequest(gpa: std.mem.Allocator, out: *std.ArrayList(u8), auth_name: []const u8, auth_data: []const u8) !void {
    try out.append(gpa, 'l'); // byte order: little-endian
    try out.append(gpa, 0); // unused
    try put16(out, gpa, 11); // protocol-major-version
    try put16(out, gpa, 0); // protocol-minor-version
    try put16(out, gpa, @intCast(auth_name.len));
    try put16(out, gpa, @intCast(auth_data.len));
    try put16(out, gpa, 0); // unused
    try out.appendSlice(gpa, auth_name);
    try padTo4(gpa, out);
    try out.appendSlice(gpa, auth_data);
    try padTo4(gpa, out);
}

/// The fields the modal needs from a successful setup reply.
pub const Setup = struct {
    resource_id_base: u32,
    resource_id_mask: u32,
    root: u32,
    root_visual: u32,
    root_depth: u8,
    image_byte_order: u8, // 0 = LSBFirst, 1 = MSBFirst

    /// The n-th allocatable resource id (window, gc, ...).
    pub fn newId(self: Setup, n: u32) u32 {
        return self.resource_id_base | (n & self.resource_id_mask);
    }
};

/// Parse a complete setup reply (the 8-byte header + `len`*4 additional bytes). Extracts the id
/// base/mask and screen 0's root window, visual and depth, skipping the vendor string and pixmap
/// formats. Fails closed on a non-success status or a short buffer.
pub fn parseSetup(buf: []const u8) Error!Setup {
    if (buf.len < 8) return error.Truncated;
    if (buf[0] != 1) return error.SetupFailed; // 0 = failed, 2 = authenticate
    var d = Reader{ .b = buf, .pos = 8 }; // skip status(1) pad(1) major(2) minor(2) addlen(2)
    _ = try d.r32(); // release-number
    const base = try d.r32();
    const mask = try d.r32();
    _ = try d.r32(); // motion-buffer-size
    const vendor_len = try d.r16();
    _ = try d.r16(); // max-request-length
    const num_screens = try d.r8();
    const num_formats = try d.r8();
    const image_byte_order = try d.r8();
    try d.skip(1 + 1 + 1 + 1 + 1 + 4); // bitmap-bit-order, scanline-unit/pad, min/max-keycode, pad(4)
    try d.skip(align4(vendor_len)); // vendor string, padded
    try d.skip(@as(usize, num_formats) * 8); // FORMATs
    if (num_screens < 1) return error.BadReply;

    // SCREEN 0: root, then the fields up to root-visual/depth.
    const root = try d.r32();
    try d.skip(4 * 4 + 2 * 6); // colormap, white, black, input-masks, then 6 u16 dimension fields
    const root_visual = try d.r32();
    try d.skip(2); // backing-stores(1), save-unders(1)
    const root_depth = try d.r8();
    return .{
        .resource_id_base = base,
        .resource_id_mask = mask,
        .root = root,
        .root_visual = root_visual,
        .root_depth = root_depth,
        .image_byte_order = image_byte_order,
    };
}

/// CreateWindow for a transient modal: override-redirect, InputOutput, copying the root's depth and
/// visual, selecting Expose/KeyPress/ButtonPress, on a dark background pixel.
pub fn createWindow(gpa: std.mem.Allocator, out: *std.ArrayList(u8), s: Setup, wid: u32, x: i16, y: i16, w: u16, h: u16, back_pixel: u32) !void {
    const value_mask = cw_back_pixel | cw_override_redirect | cw_event_mask;
    try out.append(gpa, op_create_window);
    try out.append(gpa, s.root_depth);
    try put16(out, gpa, 8 + 3); // request length in 4-byte units (8 fixed + 3 values)
    try put32(out, gpa, wid);
    try put32(out, gpa, s.root);
    try put16(out, gpa, @bitCast(x));
    try put16(out, gpa, @bitCast(y));
    try put16(out, gpa, w);
    try put16(out, gpa, h);
    try put16(out, gpa, 0); // border-width
    try put16(out, gpa, 1); // class = InputOutput
    try put32(out, gpa, s.root_visual);
    try put32(out, gpa, value_mask);
    try put32(out, gpa, back_pixel); // CWBackPixel
    try put32(out, gpa, 1); // CWOverrideRedirect = true
    try put32(out, gpa, em_exposure | em_key_press | em_button_press); // CWEventMask
}

pub fn mapWindow(gpa: std.mem.Allocator, out: *std.ArrayList(u8), wid: u32) !void {
    try out.append(gpa, op_map_window);
    try out.append(gpa, 0);
    try put16(out, gpa, 2);
    try put32(out, gpa, wid);
}

pub fn createGc(gpa: std.mem.Allocator, out: *std.ArrayList(u8), cid: u32, drawable: u32) !void {
    try out.append(gpa, op_create_gc);
    try out.append(gpa, 0);
    try put16(out, gpa, 4); // no values
    try put32(out, gpa, cid);
    try put32(out, gpa, drawable);
    try put32(out, gpa, 0); // value-mask = 0
}

pub fn grabKeyboard(gpa: std.mem.Allocator, out: *std.ArrayList(u8), wid: u32) !void {
    try out.append(gpa, op_grab_keyboard);
    try out.append(gpa, 1); // owner-events = true
    try put16(out, gpa, 4);
    try put32(out, gpa, wid);
    try put32(out, gpa, 0); // time = CurrentTime
    try out.append(gpa, 1); // pointer-mode = Asynchronous
    try out.append(gpa, 1); // keyboard-mode = Asynchronous
    try put16(out, gpa, 0); // pad
}

pub fn grabPointer(gpa: std.mem.Allocator, out: *std.ArrayList(u8), wid: u32) !void {
    try out.append(gpa, op_grab_pointer);
    try out.append(gpa, 1); // owner-events = true
    try put16(out, gpa, 6);
    try put32(out, gpa, wid);
    try put16(out, gpa, @intCast(em_button_press)); // event-mask (16-bit here): ButtonPress
    try out.append(gpa, 1); // pointer-mode = Asynchronous
    try out.append(gpa, 1); // keyboard-mode = Asynchronous
    try put32(out, gpa, 0); // confine-to = None
    try put32(out, gpa, 0); // cursor = None
    try put32(out, gpa, 0); // time = CurrentTime
}

/// PutImage of a ZPixmap (the whole image in one request; the modal is < 256 KB so it fits the
/// classic request-length limit). `data` is width*height 32-bit pixels already in the server's
/// expected byte order; its length is padded to 4.
pub fn putImage(gpa: std.mem.Allocator, out: *std.ArrayList(u8), drawable: u32, gc: u32, w: u16, h: u16, depth: u8, data: []const u8) !void {
    const pad = align4(data.len) - data.len;
    const req_units = 6 + (align4(data.len) / 4); // 6 fixed 4-byte units + image
    try out.append(gpa, op_put_image);
    try out.append(gpa, 2); // format = ZPixmap
    try put16(out, gpa, @intCast(req_units));
    try put32(out, gpa, drawable);
    try put32(out, gpa, gc);
    try put16(out, gpa, w);
    try put16(out, gpa, h);
    try put16(out, gpa, 0); // dst-x
    try put16(out, gpa, 0); // dst-y
    try out.append(gpa, 0); // left-pad
    try out.append(gpa, depth);
    try put16(out, gpa, 0); // pad
    try out.appendSlice(gpa, data);
    try out.appendNTimes(gpa, 0, pad);
}

/// A decoded input event the modal acts on.
pub const Event = union(enum) {
    expose,
    key: u8, // keycode
    button: struct { x: i16, y: i16 }, // press location in the window
    other,
    err,
};

/// Classify one 32-byte event. KeyPress yields its keycode; ButtonPress yields the event-relative
/// position. Synthetic events (high bit of the type) are treated like their real counterpart.
pub fn parseEvent(ev: []const u8) Error!Event {
    if (ev.len < 32) return error.Truncated;
    switch (ev[0] & 0x7f) {
        ev_error => return .err,
        ev_expose => return .expose,
        ev_key_press => return .{ .key = ev[1] },
        ev_button_press => return .{ .button = .{
            .x = std.mem.readInt(i16, ev[24..26], .little),
            .y = std.mem.readInt(i16, ev[26..28], .little),
        } },
        else => return .other,
    }
}

// --- helpers ---

fn padTo4(gpa: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
    try out.appendNTimes(gpa, 0, align4(out.items.len) - out.items.len);
}
fn align4(n: usize) usize {
    return (n + 3) & ~@as(usize, 3);
}

const Reader = struct {
    b: []const u8,
    pos: usize,
    fn r8(self: *Reader) Error!u8 {
        if (self.pos + 1 > self.b.len) return error.Truncated;
        defer self.pos += 1;
        return self.b[self.pos];
    }
    fn r16(self: *Reader) Error!u16 {
        if (self.pos + 2 > self.b.len) return error.Truncated;
        defer self.pos += 2;
        return std.mem.readInt(u16, self.b[self.pos..][0..2], .little);
    }
    fn r32(self: *Reader) Error!u32 {
        if (self.pos + 4 > self.b.len) return error.Truncated;
        defer self.pos += 4;
        return std.mem.readInt(u32, self.b[self.pos..][0..4], .little);
    }
    fn skip(self: *Reader, n: usize) Error!void {
        if (self.pos + n > self.b.len) return error.Truncated;
        self.pos += n;
    }
};

const testing = std.testing;

test "setupRequest pads auth name and data to 4 bytes" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try setupRequest(testing.allocator, &out, "MIT-MAGIC-COOKIE-1", &[_]u8{0xAB} ** 16);
    try testing.expectEqual(@as(u8, 'l'), out.items[0]);
    try testing.expectEqual(@as(u16, 18), std.mem.readInt(u16, out.items[6..8], .little)); // name len
    try testing.expectEqual(@as(u16, 16), std.mem.readInt(u16, out.items[8..10], .little)); // data len
    try testing.expectEqual(@as(usize, 0), out.items.len % 4); // whole request is 4-aligned
}

test "parseSetup extracts ids, root, visual, depth past vendor + formats" {
    // Hand-build a minimal success reply: header + fixed block + 5-byte vendor + 1 format + 1 screen.
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(testing.allocator);
    const a = testing.allocator;
    try b.appendSlice(a, &.{ 1, 0, 11, 0, 0, 0, 0, 0 }); // status=success + header padding
    try put32(&b, a, 0); // release
    try put32(&b, a, 0x0440_0000); // resource-id-base
    try put32(&b, a, 0x001f_ffff); // resource-id-mask
    try put32(&b, a, 0); // motion buffer
    try put16(&b, a, 5); // vendor length
    try put16(&b, a, 65535); // max request
    try b.append(a, 1); // num screens
    try b.append(a, 1); // num formats
    try b.append(a, 0); // image-byte-order = LSBFirst
    try b.appendSlice(a, &.{ 0, 0, 0, 0, 0 }); // bitmap-bit-order, units, keycodes
    try b.appendNTimes(a, 0, 4); // pad
    try b.appendSlice(a, "ABCDE"); // vendor (5)
    try b.appendNTimes(a, 0, 3); // pad to 8
    try b.appendNTimes(a, 0, 8); // one FORMAT
    // SCREEN
    try put32(&b, a, 0x0000_01ab); // root
    try b.appendNTimes(a, 0, 4 * 4 + 2 * 6); // colormap..dimensions
    try put32(&b, a, 0x0000_0021); // root-visual
    try b.appendSlice(a, &.{ 0, 0 }); // backing-stores, save-unders
    try b.append(a, 24); // root-depth

    const s = try parseSetup(b.items);
    try testing.expectEqual(@as(u32, 0x0440_0000), s.resource_id_base);
    try testing.expectEqual(@as(u32, 0x0000_01ab), s.root);
    try testing.expectEqual(@as(u32, 0x0000_0021), s.root_visual);
    try testing.expectEqual(@as(u8, 24), s.root_depth);
    try testing.expectEqual(@as(u32, 0x0440_0000), s.newId(0));
    try testing.expectEqual(@as(u32, 0x0440_0001), s.newId(1));
}

test "parseSetup rejects a failed status" {
    try testing.expectError(error.SetupFailed, parseSetup(&[_]u8{ 0, 1, 0, 0, 0, 0, 0, 0 }));
}

test "createWindow encodes opcode, depth, length and the three values" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    const s = Setup{ .resource_id_base = 0x200, .resource_id_mask = 0xff, .root = 0x1ab, .root_visual = 0x21, .root_depth = 24, .image_byte_order = 0 };
    try createWindow(testing.allocator, &out, s, s.newId(0), 10, 20, 420, 140, 0xFF1E1E28);
    try testing.expectEqual(op_create_window, out.items[0]);
    try testing.expectEqual(@as(u8, 24), out.items[1]); // depth
    try testing.expectEqual(@as(u16, 11), std.mem.readInt(u16, out.items[2..4], .little)); // length units
    try testing.expectEqual(@as(usize, 11 * 4), out.items.len);
}

test "putImage length counts the fixed units plus the padded image" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    const data = [_]u8{0xAB} ** (2 * 2 * 4); // 2x2 ARGB = 16 bytes, already 4-aligned
    try putImage(testing.allocator, &out, 0x1, 0x2, 2, 2, 24, &data);
    try testing.expectEqual(op_put_image, out.items[0]);
    try testing.expectEqual(@as(u8, 2), out.items[1]); // ZPixmap
    try testing.expectEqual(@as(u16, 6 + 4), std.mem.readInt(u16, out.items[2..4], .little)); // 6 + 16/4
    try testing.expectEqual(@as(usize, (6 + 4) * 4), out.items.len);
}

test "parseEvent classifies expose, key and button" {
    var ev = [_]u8{0} ** 32;
    ev[0] = ev_expose;
    try testing.expect((try parseEvent(&ev)) == .expose);
    ev[0] = ev_key_press;
    ev[1] = 9; // Escape keycode
    try testing.expectEqual(@as(u8, 9), (try parseEvent(&ev)).key);
    ev[0] = ev_button_press;
    std.mem.writeInt(i16, ev[24..26], 130, .little);
    std.mem.writeInt(i16, ev[26..28], 110, .little);
    const b = (try parseEvent(&ev)).button;
    try testing.expectEqual(@as(i16, 130), b.x);
    try testing.expectEqual(@as(i16, 110), b.y);
    ev[0] = ev_error;
    try testing.expect((try parseEvent(&ev)) == .err);
}
