// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The presence-window cache (after gpg-agent): the first signature with a key runs the
//! Authorizer (a Touch ID / TPM-ticket gesture); within the per-key idle TTL — and an
//! absolute cap — further signatures are silent. Windows are keyed by the **public-key
//! blob**, not the name, so a deleted-and-recreated key must re-authenticate
//! (KEY-AUTHZ-DESIGN.md). Pure/time-injected: `now_ms` is passed in, never read here.

const std = @import("std");

/// One key's open window: when presence was first granted, and when last used.
pub const Window = struct {
    created_ms: i64,
    accessed_ms: i64,

    /// Whether this window is still valid at `now_ms`, bounded by the idle TTL (since last
    /// use) and the absolute cap (since creation). A non-positive idle or max is "always
    /// cold" — every signature re-authenticates.
    pub fn fresh(self: Window, now_ms: i64, idle_ms: i64, max_ms: i64) bool {
        if (idle_ms <= 0 or max_ms <= 0) return false;
        return now_ms < self.accessed_ms + idle_ms and now_ms < self.created_ms + max_ms;
    }
};

/// Per-public-key window cache. Owns copies of the key blobs it tracks.
pub const Cache = struct {
    gpa: std.mem.Allocator,
    map: std.StringHashMapUnmanaged(Window) = .empty,

    pub fn init(gpa: std.mem.Allocator) Cache {
        return .{ .gpa = gpa };
    }
    pub fn deinit(self: *Cache) void {
        var it = self.map.keyIterator();
        while (it.next()) |k| self.gpa.free(k.*);
        self.map.deinit(self.gpa);
    }

    /// Whether `key` has a fresh window at `now_ms`; on a hit, slides the idle clock forward
    /// (a silent signature counts as "used"). A miss/stale entry returns false — the caller
    /// must then run the Authorizer and `open` the window.
    pub fn fresh(self: *Cache, key: []const u8, now_ms: i64, idle_ms: i64, max_ms: i64) bool {
        if (self.map.getPtr(key)) |w| {
            if (w.fresh(now_ms, idle_ms, max_ms)) {
                w.accessed_ms = now_ms;
                return true;
            }
        }
        return false;
    }

    /// Open (or restart) the window for `key` at `now_ms`, after a successful gesture.
    pub fn open(self: *Cache, key: []const u8, now_ms: i64) !void {
        const gop = try self.map.getOrPut(self.gpa, key);
        if (!gop.found_existing) gop.key_ptr.* = try self.gpa.dupe(u8, key);
        gop.value_ptr.* = .{ .created_ms = now_ms, .accessed_ms = now_ms };
    }

    /// Drop a single key's window (a deleted/recreated key must re-authenticate).
    pub fn invalidate(self: *Cache, key: []const u8) void {
        if (self.map.fetchRemove(key)) |kv| self.gpa.free(kv.key);
    }
};

test "window freshness honours both idle and absolute caps" {
    const w = Window{ .created_ms = 1000, .accessed_ms = 1000 };
    try std.testing.expect(w.fresh(1500, 1000, 5000)); // within idle and max
    try std.testing.expect(!w.fresh(2500, 1000, 5000)); // idle lapsed (accessed+1000 = 2000)
    try std.testing.expect(!w.fresh(1500, 1000, 200)); // absolute lapsed (created+200 = 1200)
    try std.testing.expect(!w.fresh(1500, 0, 5000)); // zero idle ⇒ always cold
}

test "cache open/fresh/invalidate is keyed by the blob" {
    var c = Cache.init(std.testing.allocator);
    defer c.deinit();
    const key = "ecdsa-pubkey-blob";

    try std.testing.expect(!c.fresh(key, 1000, 1000, 5000)); // cold: never opened
    try c.open(key, 1000);
    try std.testing.expect(c.fresh(key, 1500, 1000, 5000)); // warm within idle
    try std.testing.expect(c.fresh(key, 2400, 1000, 5000)); // idle slid forward by the prior hit
    c.invalidate(key);
    try std.testing.expect(!c.fresh(key, 2500, 1000, 5000)); // invalidated ⇒ cold again
}

test "a different key blob does not share a window" {
    var c = Cache.init(std.testing.allocator);
    defer c.deinit();
    try c.open("key-A", 1000);
    try std.testing.expect(!c.fresh("key-B", 1100, 5000, 50000));
}
