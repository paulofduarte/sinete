// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The agent sign-path — the backend-agnostic core that ties presence (Authorizer), the
//! per-key TTL window, and the secure element (Cryptoprocessor) together. This is the
//! "Model B" gate (internal design notes): every registry key is advertised; the first signature with a
//! key runs presence, then within the idle/absolute TTL further signatures are silent.
//! Pure orchestration — `now_ms` is injected, so the whole flow is unit-tested with fakes.

const std = @import("std");
const authz = @import("../authz.zig");
const crypto = @import("../crypto.zig");
const window = @import("window.zig");

pub const Config = struct {
    /// Idle TTL: silent window since the last signature (ms).
    idle_ms: i64,
    /// Absolute cap: max lifetime of a window since it opened (ms).
    max_ms: i64,
    /// The prompt reason shown by the presence gesture.
    reason: []const u8 = "sinete: authorize SSH key use",
};

/// Why a signature was refused — surfaced so the protocol layer can answer FAILURE and the
/// CLI can explain. (`PresenceRefused` wraps any Authorizer error; `BackendError` any
/// Cryptoprocessor one.) Window bookkeeping can't fail the call — a lost window just means an
/// extra presence prompt next time.
pub const SignError = error{ PresenceRefused, BackendError };

pub const Agent = struct {
    gpa: std.mem.Allocator,
    cp: crypto.Cryptoprocessor,
    az: authz.Authorizer,
    cfg: Config,
    windows: window.Cache,

    pub fn init(gpa: std.mem.Allocator, cp: crypto.Cryptoprocessor, az: authz.Authorizer, cfg: Config) Agent {
        return .{ .gpa = gpa, .cp = cp, .az = az, .cfg = cfg, .windows = window.Cache.init(gpa) };
    }
    pub fn deinit(self: *Agent) void {
        self.windows.deinit();
    }

    /// The keys to advertise (REQUEST_IDENTITIES). Allocated into `arena` by the backend.
    pub fn identities(self: *Agent, arena: std.mem.Allocator) ![]const crypto.KeyInfo {
        return self.cp.enumerate(arena);
    }

    /// Sign `data` with the key whose public blob is `key_id`, writing the signature into
    /// `out` and returning its length. Runs the presence gesture only when the key's window
    /// is cold; refreshes the window on success.
    pub fn sign(self: *Agent, key_id: []const u8, data: []const u8, now_ms: i64, out: []u8) SignError!usize {
        // Peek is non-mutating: we require presence on a cold window, then commit the window
        // ONLY after the signature succeeds — so a failed sign never primes a silent window.
        const warm = self.windows.peek(key_id, now_ms, self.cfg.idle_ms, self.cfg.max_ms);
        if (!warm) self.az.authorize(key_id, self.cfg.reason) catch return error.PresenceRefused;

        const n = self.cp.sign(key_id, data, out) catch return error.BackendError;

        // Signature succeeded → open (cold) or slide (warm) the window. An allocation failure
        // here is swallowed: the worst case is one extra presence prompt next time.
        if (warm) self.windows.touch(key_id, now_ms) else self.windows.open(key_id, now_ms) catch {};
        return n;
    }

    /// Force re-authentication for a key (e.g. it was deleted/recreated, or config changed).
    pub fn invalidate(self: *Agent, key_id: []const u8) void {
        self.windows.invalidate(key_id);
    }
};

const testing = std.testing;

test "first sign authenticates; signs within the idle TTL are silent" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    _ = try agent.sign("key-1", "a", 1000, &out); // cold → authenticate
    _ = try agent.sign("key-1", "b", 1500, &out); // warm within idle → silent
    _ = try agent.sign("key-1", "c", 2200, &out); // idle slid forward by prior hit → silent
    try testing.expectEqual(@as(usize, 1), az.granted);
    try testing.expectEqual(@as(usize, 3), cp.signs);
}

test "a lapsed idle window re-authenticates" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    _ = try agent.sign("key-1", "a", 1000, &out); // authenticate
    _ = try agent.sign("key-1", "b", 5000, &out); // idle lapsed (>1000 since last) → re-auth
    try testing.expectEqual(@as(usize, 2), az.granted);
}

test "the absolute cap forces re-authentication even with steady use" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 10_000, .max_ms = 2000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    _ = try agent.sign("key-1", "a", 1000, &out); // open at t=1000 (cap → 3000)
    _ = try agent.sign("key-1", "b", 2500, &out); // within idle and cap → silent
    _ = try agent.sign("key-1", "c", 3500, &out); // past the absolute cap → re-auth
    try testing.expectEqual(@as(usize, 2), az.granted);
}

test "a failed signature does not prime a silent window (regression)" {
    var cp = crypto.Fake{ .keys = &.{} }; // no keys → cp.sign fails with UnknownKey
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    try testing.expectError(error.BackendError, agent.sign("ghost", "a", 1000, &out));
    // presence did run, but because the sign failed the window must stay cold
    try testing.expectEqual(@as(usize, 1), az.granted);
    try testing.expect(!agent.windows.peek("ghost", 1100, 1000, 10_000));
}

test "a declined presence gesture refuses the signature and does not sign" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
    var az = authz.Fake{ .declines = true };
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    try testing.expectError(error.PresenceRefused, agent.sign("key-1", "a", 1000, &out));
    try testing.expectEqual(@as(usize, 0), cp.signs);
}

test "invalidate forces the next signature to re-authenticate" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    _ = try agent.sign("key-1", "a", 1000, &out);
    agent.invalidate("key-1");
    _ = try agent.sign("key-1", "b", 1100, &out); // would be silent, but invalidated → re-auth
    try testing.expectEqual(@as(usize, 2), az.granted);
}

test "identities reflects the cryptoprocessor enumeration" {
    var cp = crypto.Fake{ .keys = &.{
        .{ .blob = "k1", .comment = "one" },
        .{ .blob = "k2", .comment = "two" },
    } };
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1, .max_ms = 1 });
    defer agent.deinit();

    const ids = try agent.identities(testing.allocator);
    try testing.expectEqual(@as(usize, 2), ids.len);
    try testing.expectEqualStrings("k2", ids[1].blob);
}
