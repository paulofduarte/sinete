// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! A tiny software canvas: a caller-owned ARGB8888 pixel buffer with fill/rect/text primitives that
//! blit the embedded bitmap font. Pure (no windowing) so the same rendering drives both the X11 and
//! Wayland modals -- each backend only hands the finished buffer to its server (X PutImage / wl_shm).
//! Colors are 0xAARRGGBB; the modal is opaque so alpha is 0xFF throughout.

const std = @import("std");
const font = @import("font.zig");

pub const Canvas = struct {
    px: []u32,
    w: usize, // dimensions kept as usize so all indexing/slicing is native (no per-site casts)
    h: usize,

    pub fn init(px: []u32, w: usize, h: usize) Canvas {
        std.debug.assert(px.len >= w * h);
        return .{ .px = px, .w = w, .h = h };
    }

    pub fn fill(self: Canvas, color: u32) void {
        @memset(self.px[0 .. self.w * self.h], color);
    }

    /// Fill the rectangle (x,y,w,h), clipped to the canvas. Negative origins and overflowing extents
    /// are clipped from the true edges, so an off-canvas rect draws nothing (not a wrapped column).
    pub fn rect(self: Canvas, x: i32, y: i32, w: u32, h: u32, color: u32) void {
        const cw: i32 = @intCast(self.w);
        const ch: i32 = @intCast(self.h);
        const x0: usize = @intCast(std.math.clamp(x, 0, cw));
        const y0: usize = @intCast(std.math.clamp(y, 0, ch));
        const x1: usize = @intCast(std.math.clamp(x +| @as(i32, @intCast(w)), 0, cw));
        const y1: usize = @intCast(std.math.clamp(y +| @as(i32, @intCast(h)), 0, ch));
        var yy = y0;
        while (yy < y1) : (yy += 1) {
            var xx = x0;
            const base = yy * self.w;
            while (xx < x1) : (xx += 1) self.px[base + xx] = color;
        }
    }

    /// A 1px-wide border around (x,y,w,h).
    pub fn border(self: Canvas, x: i32, y: i32, w: u32, h: u32, color: u32) void {
        self.rect(x, y, w, 1, color);
        self.rect(x, y + @as(i32, @intCast(h)) - 1, w, 1, color);
        self.rect(x, y, 1, h, color);
        self.rect(x + @as(i32, @intCast(w)) - 1, y, 1, h, color);
    }

    /// Draw one glyph with its top-left at (x,y); set pixels get `color`, clear pixels are untouched.
    pub fn glyph(self: Canvas, c: u8, x: i32, y: i32, color: u32) void {
        var gy: u4 = 0;
        while (true) : (gy += 1) {
            var gx: u3 = 0;
            while (true) : (gx += 1) {
                if (font.pixel(c, gx, gy)) self.plot(x + @as(i32, gx), y + @as(i32, gy), color);
                if (gx == @as(u3, font.width - 1)) break;
            }
            if (gy == @as(u4, font.height - 1)) break;
        }
    }

    /// Draw a string left to right from (x,y); advances one glyph width per character.
    pub fn text(self: Canvas, s: []const u8, x: i32, y: i32, color: u32) void {
        var cx = x;
        for (s) |c| {
            self.glyph(c, cx, y, color);
            cx += @as(i32, font.width);
        }
    }

    /// The pixel width a string occupies (for centering).
    pub fn textWidth(s: []const u8) u32 {
        return @as(u32, @intCast(s.len)) * @as(u32, font.width);
    }

    fn plot(self: Canvas, x: i32, y: i32, color: u32) void {
        if (x < 0 or y < 0) return;
        const ux: usize = @intCast(x);
        const uy: usize = @intCast(y);
        if (ux >= self.w or uy >= self.h) return;
        self.px[uy * self.w + ux] = color;
    }
};

const testing = std.testing;

test "fill sets every pixel" {
    var buf: [4 * 3]u32 = undefined;
    const c = Canvas.init(&buf, 4, 3);
    c.fill(0xFF112233);
    for (buf) |p| try testing.expectEqual(@as(u32, 0xFF112233), p);
}

test "rect clips to the canvas and respects bounds" {
    var buf = [_]u32{0} ** (4 * 4);
    const c = Canvas.init(&buf, 4, 4);
    c.rect(2, 2, 10, 10, 0xFFFFFFFF); // overflows: only the bottom-right 2x2 is set
    try testing.expectEqual(@as(u32, 0), buf[0]);
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), buf[2 * 4 + 2]);
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), buf[3 * 4 + 3]);
    c.rect(-5, 0, 1, 4, 0xFFAAAAAA); // fully off the left: no-op
    try testing.expectEqual(@as(u32, 0), buf[0]);
}

test "glyph blits set pixels at the expected offset and leaves clear ones" {
    var buf = [_]u32{0} ** (16 * 20);
    const c = Canvas.init(&buf, 16, 20);
    c.glyph('!', 4, 1, 0xFFFFFFFF); // '!' row 2 = 0x18 -> columns 3,4 set
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), buf[(1 + 2) * 16 + (4 + 3)]);
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), buf[(1 + 2) * 16 + (4 + 4)]);
    try testing.expectEqual(@as(u32, 0), buf[(1 + 2) * 16 + (4 + 0)]); // left edge clear
}

test "text advances per glyph and reports its width" {
    try testing.expectEqual(@as(u32, 3 * font.width), Canvas.textWidth("abc"));
    var buf = [_]u32{0} ** (64 * 16);
    const c = Canvas.init(&buf, 64, 16);
    c.text("AB", 0, 0, 0xFFFFFFFF); // just exercise the path: some pixel of 'B' is in the 2nd cell
    var any = false;
    var i: usize = font.width;
    while (i < 2 * font.width) : (i += 1) {
        if (buf[2 * 64 + i] != 0) any = true;
    }
    try testing.expect(any);
}
