// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The built-in modal's bitmap font: Spleen 8x16 (BSD-2-Clause, Frederic Cambus), printable ASCII
//! only (0x20..0x7E), extracted from its BDF into assets/spleen-8x16-ascii.bin and embedded here so
//! the modal depends on neither server-side core fonts nor a client font library. Each glyph is 16
//! rows of one byte; bit 7 (0x80) is the leftmost pixel. Pure: the canvas blits these pixels.

const std = @import("std");

/// 95 printable-ASCII glyphs, 16 bytes each (one row per byte), in codepoint order from 0x20.
const blob = @embedFile("spleen-8x16-ascii.bin");

pub const width: u8 = 8;
pub const height: u8 = 16;
const first: u8 = 0x20;
const last: u8 = 0x7e;

/// The 16 row-bytes for `c`. A codepoint outside the printable range falls back to space (0x20),
/// so an unexpected byte renders blank rather than reading out of bounds.
pub fn glyph(c: u8) *const [height]u8 {
    const idx: usize = if (c >= first and c <= last) c - first else 0;
    return blob[idx * height ..][0..height];
}

/// Whether pixel column `gx` (0..7, left to right) of row `gy` (0..15) is set for `c`.
pub fn pixel(c: u8, gx: u3, gy: u4) bool {
    const row = glyph(c)[gy];
    return (row >> (7 - @as(u3, gx))) & 1 == 1;
}

const testing = std.testing;

test "the blob holds exactly the printable-ASCII glyphs" {
    const glyphs: usize = last - first + 1;
    try testing.expectEqual(glyphs * height, blob.len); // 95 * 16 = 1520
}

test "space is blank and '!' has the expected stem" {
    for (glyph(' ')) |row| try testing.expectEqual(@as(u8, 0), row);
    // '!' (Spleen 8x16): a centered 0x18 stem on most rows, a gap, then the dot.
    const bang = glyph('!');
    try testing.expectEqual(@as(u8, 0x18), bang[2]);
    try testing.expectEqual(@as(u8, 0x00), bang[9]); // the gap above the dot
    try testing.expect(pixel('!', 3, 2)); // a stem pixel is set
    try testing.expect(!pixel('!', 0, 2)); // the left edge is clear
}

test "an out-of-range codepoint falls back to blank space" {
    for (glyph(0x01)) |row| try testing.expectEqual(@as(u8, 0), row);
    for (glyph(0xff)) |row| try testing.expectEqual(@as(u8, 0), row);
}
