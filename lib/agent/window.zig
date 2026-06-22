// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The presence-window cache. The first signature with a key runs the Authorizer (a presence
//! gesture); within the per-key idle TTL, and an absolute cap, further signatures are silent.
//! Windows are keyed by the public-key blob rather than the name, so a key that is deleted and
//! recreated must re-authenticate. The cache is pure and time-injected: now_ms is passed in,
//! never read here.

const std = @import("std");

/// One key's open window: when presence was first granted, and when it was last used.
pub const Window = struct {
    created_ms: i64,
    accessed_ms: i64,

    /// Whether this window is still valid at now_ms, bounded by the idle TTL (since last use)
    /// and the absolute cap (since creation). A non-positive idle or max is always cold, so
    /// every signature re-authenticates.
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

    /// Whether key has a fresh window at now_ms. Non-mutating, so the caller can commit the
    /// window only after the signature succeeds (touch on a warm hit, open on a cold one) and
    /// a failed sign never primes a silent window.
    pub fn peek(self: *Cache, key: []const u8, now_ms: i64, idle_ms: i64, max_ms: i64) bool {
        if (self.map.get(key)) |w| return w.fresh(now_ms, idle_ms, max_ms);
        return false;
    }

    /// Slide the idle clock of an existing warm window forward; a silent signature counts as
    /// use. A no-op if the key has no window. Keeps the original creation time so the absolute
    /// cap still applies.
    pub fn touch(self: *Cache, key: []const u8, now_ms: i64) void {
        if (self.map.getPtr(key)) |w| w.accessed_ms = now_ms;
    }

    /// Open or restart the window for key at now_ms, after a successful cold-path sign. On a
    /// new key the blob is duplicated into the cache first, so an allocation failure leaves the
    /// map unchanged rather than holding a borrowed key pointer.
    pub fn open(self: *Cache, key: []const u8, now_ms: i64) !void {
        const win = Window{ .created_ms = now_ms, .accessed_ms = now_ms };
        if (self.map.getPtr(key)) |w| {
            w.* = win; // the key is already owned; just restart the window
            return;
        }
        const owned = try self.gpa.dupe(u8, key);
        errdefer self.gpa.free(owned);
        try self.map.put(self.gpa, owned, win);
    }

    /// Drop a single key's window so it must re-authenticate.
    pub fn invalidate(self: *Cache, key: []const u8) void {
        if (self.map.fetchRemove(key)) |kv| self.gpa.free(kv.key);
    }
};

test "window freshness honours both idle and absolute caps" {
    const w = Window{ .created_ms = 1000, .accessed_ms = 1000 };
    try std.testing.expect(w.fresh(1500, 1000, 5000)); // within idle and max
    try std.testing.expect(!w.fresh(2500, 1000, 5000)); // idle lapsed (accessed+1000 = 2000)
    try std.testing.expect(!w.fresh(1500, 1000, 200)); // absolute lapsed (created+200 = 1200)
    try std.testing.expect(!w.fresh(1500, 0, 5000)); // zero idle is always cold
}

test "cache peek/touch/open/invalidate is keyed by the blob" {
    var c = Cache.init(std.testing.allocator);
    defer c.deinit();
    const key = "ecdsa-pubkey-blob";

    try std.testing.expect(!c.peek(key, 1000, 1000, 5000)); // cold, never opened
    try c.open(key, 1000);
    try std.testing.expect(c.peek(key, 1500, 1000, 5000)); // warm within idle, peek is pure
    try std.testing.expect(c.peek(key, 1500, 1000, 5000)); // still warm, peek did not mutate
    c.touch(key, 1500); // a silent sign at t=1500 slides the idle clock
    try std.testing.expect(c.peek(key, 2400, 1000, 5000)); // valid until 2500 thanks to the touch
    c.invalidate(key);
    try std.testing.expect(!c.peek(key, 2450, 1000, 5000)); // invalidated, cold again
}

test "open keeps the creation time on a touch but resets it on re-open" {
    var c = Cache.init(std.testing.allocator);
    defer c.deinit();
    try c.open("k", 1000); // created at 1000, cap at 1000+max
    c.touch("k", 1800); // idle slides, creation stays 1000
    try std.testing.expect(!c.peek("k", 1900, 1000, 500)); // absolute cap 1000+500=1500 exceeded
    try c.open("k", 1900); // cold re-open resets creation, cap now 1900+500
    try std.testing.expect(c.peek("k", 2000, 1000, 500));
}

test "a different key blob does not share a window" {
    var c = Cache.init(std.testing.allocator);
    defer c.deinit();
    try c.open("key-A", 1000);
    try std.testing.expect(!c.peek("key-B", 1100, 5000, 50000));
}

test "open rolls back cleanly when an allocation fails" {
    // Fail the map insert after the key dup succeeds; the errdefer must free the dup and the
    // map must be left empty, with no leak and no borrowed key pointer.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    var c = Cache.init(failing.allocator());
    defer c.deinit();
    try std.testing.expectError(error.OutOfMemory, c.open("k", 1000));
    try std.testing.expect(!c.peek("k", 1100, 1000, 5000));
}
