// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The modal's content model, independent of X11/Wayland: the fixed window size, where the message
//! and buttons sit, how to paint them onto a Canvas, and how a keypress or a click resolves to an
//! Outcome. Pure so the layout + decision logic are golden-tested; each backend creates a window of
//! `width`x`height`, calls paint() with a pixel buffer, and feeds key/click events to the matchers.

const std = @import("std");
const presenter = @import("../presenter.zig");
const font = @import("font.zig");
const Canvas = @import("canvas.zig").Canvas;

pub const Outcome = presenter.Outcome;

pub const width: usize = 420; // usize so the pixel buffer alloc/index math is native; cast at the
pub const height: usize = 140; // X11/Wayland edges (u16/i16) where the protocols need narrower ints

// Opaque ARGB palette (0xAARRGGBB): a dark panel, light text, a subtle border, two buttons.
const col_bg: u32 = 0xFF1E1E28;
const col_fg: u32 = 0xFFE6E6F0;
const col_border: u32 = 0xFF5A5A78;
const col_ok: u32 = 0xFF2E7D32; // approve = green
const col_cancel: u32 = 0xFF8E2A2A; // deny = red
const col_btn_fg: u32 = 0xFFFFFFFF;

const margin: i32 = 16;
const btn_w: u32 = 110;
const btn_h: u32 = 30;
const btn_y: i32 = @as(i32, @intCast(height)) - margin - @as(i32, @intCast(btn_h));

/// A button's rectangle and the outcome a click on it yields.
const Button = struct { x: i32, y: i32, w: u32, h: u32, outcome: Outcome };

/// The Approve button (right) -- present for both confirm and message modes.
fn okButton() Button {
    return .{ .x = @as(i32, @intCast(width)) - margin - @as(i32, @intCast(btn_w)), .y = btn_y, .w = btn_w, .h = btn_h, .outcome = .confirmed };
}

/// The Deny button (left of Approve), present only for a confirm (a one-button message has none).
fn cancelButton() Button {
    return .{ .x = okButton().x - @as(i32, @intCast(btn_w)) - margin, .y = btn_y, .w = btn_w, .h = btn_h, .outcome = .declined };
}

/// The modal content: the message line and whether it offers a deny button (a confirm) or only an
/// acknowledge (a one-shot message).
pub const Modal = struct {
    message: []const u8,
    confirm: bool, // true = Approve/Deny; false = a single OK (message)

    /// Paint the modal onto `px` (an ARGB buffer of width*height). Caller then uploads it.
    pub fn paint(self: Modal, px: []u32) void {
        const c = Canvas.init(px, width, height);
        c.fill(col_bg);
        c.border(0, 0, width, height, col_border);

        // The message, left-aligned at the top margin, truncated to the panel width. Compute the
        // available width in u32, then a usize cap for slicing (avoid a signed/unsigned mix).
        const avail: usize = width - 2 * @as(usize, @intCast(margin));
        const max_chars: usize = avail / @as(usize, font.width);
        const msg = if (self.message.len > max_chars) self.message[0..max_chars] else self.message;
        c.text(msg, margin, margin + 6, col_fg);

        const ok = okButton();
        button(c, ok, if (self.confirm) "Approve" else "OK", col_ok);
        if (self.confirm) button(c, cancelButton(), "Deny", col_cancel);
    }

    /// The outcome of a click at (px,py), or null if it missed every button.
    pub fn clickOutcome(self: Modal, px: i32, py: i32) ?Outcome {
        if (inside(okButton(), px, py)) return .confirmed;
        if (self.confirm and inside(cancelButton(), px, py)) return .declined;
        return null;
    }

    /// The outcome of a keypress, or null to keep waiting. Mirrors the tty rules: only an explicit
    /// y/Y approves (never Enter, so a stray keystroke cannot sign); n/N/Esc deny/dismiss. For a
    /// one-button message any of Enter/Space/Esc/y/n simply closes it (returns .confirmed = ack).
    pub fn keyOutcome(self: Modal, ch: u8) ?Outcome {
        if (!self.confirm) {
            return switch (ch) {
                '\r', '\n', ' ', 0x1b, 'y', 'Y', 'n', 'N' => .confirmed, // ack/close
                else => null,
            };
        }
        return switch (ch) {
            'y', 'Y' => .confirmed,
            'n', 'N', 0x1b => .declined,
            else => null, // Enter/Space/other: keep waiting (no accidental approval)
        };
    }
};

fn button(c: Canvas, b: Button, label: []const u8, bg: u32) void {
    c.rect(b.x, b.y, b.w, b.h, bg);
    c.border(b.x, b.y, b.w, b.h, col_border);
    const tx = b.x + @as(i32, @intCast((b.w -| Canvas.textWidth(label)) / 2));
    const ty = b.y + @as(i32, @intCast((b.h -| @as(u32, font.height)) / 2));
    c.text(label, tx, ty, col_btn_fg);
}

fn inside(b: Button, px: i32, py: i32) bool {
    return px >= b.x and px < b.x + @as(i32, @intCast(b.w)) and py >= b.y and py < b.y + @as(i32, @intCast(b.h));
}

const testing = std.testing;

test "confirm keys: only y/Y approves, n/N/Esc deny, Enter waits" {
    const m = Modal{ .message = "Approve signing?", .confirm = true };
    try testing.expectEqual(Outcome.confirmed, m.keyOutcome('y').?);
    try testing.expectEqual(Outcome.confirmed, m.keyOutcome('Y').?);
    try testing.expectEqual(Outcome.declined, m.keyOutcome('n').?);
    try testing.expectEqual(Outcome.declined, m.keyOutcome(0x1b).?);
    try testing.expect(m.keyOutcome('\r') == null); // no accidental approval
    try testing.expect(m.keyOutcome(' ') == null);
}

test "message keys: any of Enter/Space/Esc/y/n acknowledges" {
    const m = Modal{ .message = "Refused: remote session", .confirm = false };
    try testing.expectEqual(Outcome.confirmed, m.keyOutcome('\n').?);
    try testing.expectEqual(Outcome.confirmed, m.keyOutcome(' ').?);
    try testing.expectEqual(Outcome.confirmed, m.keyOutcome(0x1b).?);
    try testing.expect(m.keyOutcome('q') == null);
}

test "clicks hit the right button; a message has no deny" {
    const cm = Modal{ .message = "Approve signing?", .confirm = true };
    const ok = okButton();
    try testing.expectEqual(Outcome.confirmed, cm.clickOutcome(ok.x + 5, ok.y + 5).?);
    const dn = cancelButton();
    try testing.expectEqual(Outcome.declined, cm.clickOutcome(dn.x + 5, dn.y + 5).?);
    try testing.expect(cm.clickOutcome(0, 0) == null); // missed

    const mm = Modal{ .message = "msg", .confirm = false };
    try testing.expectEqual(Outcome.confirmed, mm.clickOutcome(ok.x + 5, ok.y + 5).?);
    try testing.expect(mm.clickOutcome(cancelButton().x + 5, cancelButton().y + 5) == null); // no deny button
}

test "paint fills the buffer without going out of bounds" {
    const buf = testing.allocator.alloc(u32, width * height) catch unreachable;
    defer testing.allocator.free(buf);
    const m = Modal{ .message = "Approve signing with your SSH key?", .confirm = true };
    m.paint(buf);
    // The border pixel and some button pixels are painted (not the background fill color).
    try testing.expectEqual(col_border, buf[0]);
    const ok = okButton();
    try testing.expectEqual(col_ok, buf[@as(usize, @intCast(ok.y + 5)) * width + @as(usize, @intCast(ok.x + 5))]);
}
