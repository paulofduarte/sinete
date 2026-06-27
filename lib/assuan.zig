// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The Assuan line protocol that pinentry speaks: build the request lines sinete sends (OPTION,
//! SETDESC/SETPROMPT/SETOK/SETCANCEL/SETTITLE, CONFIRM, MESSAGE, BYE) and classify the reply lines
//! it reads (OK / ERR / D / S / # / INQUIRE). Pure and golden-tested; the impure spawn + pipe I/O
//! lives in src/backend/pinentry.zig. sinete uses pinentry only as a message/confirm dialog (the
//! gpg "touch your token" pattern), never for PIN entry yet, so GETPIN is intentionally absent.

const std = @import("std");
const presenter = @import("presenter.zig");

pub const Outcome = presenter.Outcome;

/// Percent-encode an Assuan value: '%', CR, LF and any control byte become %XX, so a value cannot
/// inject a newline (a new command) or break the line. Spaces are legal in a trailing argument and
/// are left literal. Appends to `out`.
pub fn percentEncode(gpa: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    const hex = "0123456789ABCDEF";
    for (value) |b| {
        if (b == '%' or b < 0x20 or b == 0x7f) { // %, C0 control bytes, and DEL
            try out.append(gpa, '%');
            try out.append(gpa, hex[b >> 4]);
            try out.append(gpa, hex[b & 0x0f]);
        } else {
            try out.append(gpa, b);
        }
    }
}

/// OPTION <name>=<value>\n -- e.g. OPTION display=:0 / OPTION ttyname=/dev/pts/3. The value is
/// percent-encoded; the name is a fixed keyword and is written verbatim.
pub fn appendOption(gpa: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
    try out.appendSlice(gpa, "OPTION ");
    try out.appendSlice(gpa, name);
    try out.append(gpa, '=');
    try percentEncode(gpa, out, value);
    try out.append(gpa, '\n');
}

/// A command with a single trailing text argument (SETDESC/SETPROMPT/SETOK/SETCANCEL/SETTITLE): the
/// text is percent-encoded. An empty text yields just "<cmd>\n".
pub fn appendText(gpa: std.mem.Allocator, out: *std.ArrayList(u8), cmd: []const u8, text: []const u8) !void {
    try out.appendSlice(gpa, cmd);
    if (text.len > 0) {
        try out.append(gpa, ' ');
        try percentEncode(gpa, out, text);
    }
    try out.append(gpa, '\n');
}

/// CONFIRM, optionally with --one-button (a message-only acknowledgement, the gpg "touch" pattern).
pub fn appendConfirm(gpa: std.mem.Allocator, out: *std.ArrayList(u8), one_button: bool) !void {
    try out.appendSlice(gpa, if (one_button) "CONFIRM --one-button\n" else "CONFIRM\n");
}

pub fn appendBye(gpa: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
    try out.appendSlice(gpa, "BYE\n");
}

/// A classified Assuan reply line (the trailing newline already stripped). Slices alias the input.
pub const Reply = union(enum) {
    ok: []const u8, // OK [text]
    err: struct { code: u32, desc: []const u8 }, // ERR <code> <desc>
    data: []const u8, // D <data>
    status: []const u8, // S <keyword args>
    comment, // # ...
    inquire: []const u8, // INQUIRE <keyword>
    unknown,
};

/// Classify one reply line (without its newline) by its leading token.
pub fn parseReply(line: []const u8) Reply {
    if (eqOrPrefix(line, "OK")) return .{ .ok = rest(line, 2) };
    if (std.mem.startsWith(u8, line, "D ")) return .{ .data = line[2..] };
    if (std.mem.startsWith(u8, line, "S ")) return .{ .status = line[2..] };
    if (eqOrPrefix(line, "ERR")) {
        const tail = rest(line, 3); // "<code> <desc>"
        const sp = std.mem.indexOfScalar(u8, tail, ' ') orelse tail.len;
        const code = std.fmt.parseInt(u32, tail[0..sp], 10) catch 0;
        const desc = if (sp < tail.len) tail[sp + 1 ..] else "";
        return .{ .err = .{ .code = code, .desc = desc } };
    }
    if (std.mem.startsWith(u8, line, "INQUIRE ")) return .{ .inquire = line[8..] };
    if (line.len > 0 and line[0] == '#') return .comment;
    return .unknown;
}

/// The outcome of a CONFIRM dialog from a terminal reply, or null to keep reading (status/comment
/// lines precede the final OK/ERR). OK => the user approved; ERR => not approved (a cancel or the
/// no/second button) which is a decline.
pub fn confirmOutcome(reply: Reply) ?Outcome {
    return switch (reply) {
        .ok => .confirmed,
        .err => .declined,
        else => null, // S/D/#/INQUIRE: not terminal, keep reading
    };
}

/// True if `line` is exactly `tok` or `tok` followed by a space (so "OK" and "OK text" both match
/// but "OKAY" does not).
fn eqOrPrefix(line: []const u8, tok: []const u8) bool {
    if (std.mem.eql(u8, line, tok)) return true;
    return line.len > tok.len and std.mem.startsWith(u8, line, tok) and line[tok.len] == ' ';
}

/// The text after a leading token of length n (skipping the single separating space at index n), or
/// "" when the line is just the token.
fn rest(line: []const u8, n: usize) []const u8 {
    if (line.len <= n) return "";
    return line[n + 1 ..]; // index n is the separating space; n+1 starts the text
}

const testing = std.testing;

fn build(comptime f: anytype, args: anytype) !std.ArrayList(u8) {
    var out: std.ArrayList(u8) = .empty;
    try @call(.auto, f, .{ testing.allocator, &out } ++ args);
    return out;
}

test "percentEncode escapes %, control bytes, and newlines; leaves text/space" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try percentEncode(testing.allocator, &out, "a b%c\n\r\t\x7f");
    try testing.expectEqualStrings("a b%25c%0A%0D%09%7F", out.items); // DEL escaped too
}

test "appendOption / appendText / appendConfirm produce exact lines" {
    var o1 = try build(appendOption, .{ "ttyname", "/dev/pts/3" });
    defer o1.deinit(testing.allocator);
    try testing.expectEqualStrings("OPTION ttyname=/dev/pts/3\n", o1.items);

    var o2 = try build(appendText, .{ "SETDESC", "Approve signing?" });
    defer o2.deinit(testing.allocator);
    try testing.expectEqualStrings("SETDESC Approve signing?\n", o2.items);

    var o3 = try build(appendText, .{ "MESSAGE", "" });
    defer o3.deinit(testing.allocator);
    try testing.expectEqualStrings("MESSAGE\n", o3.items);

    var o4 = try build(appendConfirm, .{true});
    defer o4.deinit(testing.allocator);
    try testing.expectEqualStrings("CONFIRM --one-button\n", o4.items);
}

test "a SETDESC value cannot inject a second command" {
    var out = try build(appendText, .{ "SETDESC", "x\nGETPIN" });
    defer out.deinit(testing.allocator);
    try testing.expectEqualStrings("SETDESC x%0AGETPIN\n", out.items); // newline escaped, one line
}

test "parseReply classifies each reply kind" {
    try testing.expectEqualStrings("Pleased to meet you", parseReply("OK Pleased to meet you").ok);
    try testing.expectEqualStrings("", parseReply("OK").ok);
    try testing.expectEqualStrings("1.3.2", parseReply("D 1.3.2").data);
    try testing.expectEqualStrings("ERROR curses", parseReply("S ERROR curses").status);
    try testing.expect(parseReply("# a comment") == .comment);
    try testing.expectEqualStrings("PINENTRY_LAUNCHED", parseReply("INQUIRE PINENTRY_LAUNCHED").inquire);
    const e = parseReply("ERR 83886142 Timeout <Pinentry>");
    try testing.expectEqual(@as(u32, 83886142), e.err.code);
    try testing.expectEqualStrings("Timeout <Pinentry>", e.err.desc);
}

test "confirmOutcome: OK approves, ERR declines, status keeps reading" {
    try testing.expectEqual(Outcome.confirmed, confirmOutcome(parseReply("OK")).?);
    try testing.expectEqual(Outcome.declined, confirmOutcome(parseReply("ERR 114 canceled")).?);
    try testing.expect(confirmOutcome(parseReply("S PINENTRY_LAUNCHED 1234")) == null);
}
