// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The agent sign-path: the backend-agnostic core that ties the presence gate (Authorizer),
//! the per-key TTL window, and the secure element (Cryptoprocessor) together. Every known key
//! is advertised; the first signature with a key runs the presence gesture, and within the
//! idle and absolute TTL further signatures are silent. The orchestration is pure: now_ms is
//! injected, so the whole flow is exercised by unit tests with fakes.

const std = @import("std");
const authz = @import("../authz.zig");
const crypto = @import("../crypto.zig");
const window = @import("window.zig");

pub const Config = struct {
    /// Idle TTL: how long a window stays silent since the last signature, in ms.
    idle_ms: i64,
    /// Absolute cap: the maximum lifetime of a window since it opened, in ms.
    max_ms: i64,
    /// The prompt reason shown by the presence gesture.
    reason: []const u8 = "sinete: authorize SSH key use",
};

/// Why a signature was refused, so the protocol layer can answer FAILURE and the CLI can
/// explain. PresenceRefused wraps any Authorizer error; BackendError wraps any Cryptoprocessor
/// error. Window bookkeeping cannot fail the call: a lost window just means one extra presence
/// prompt next time.
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

    /// The keys to advertise in a REQUEST_IDENTITIES answer, allocated into arena.
    pub fn identities(self: *Agent, arena: std.mem.Allocator) ![]const crypto.KeyInfo {
        return self.cp.enumerate(arena);
    }

    /// Sign data with the key whose public blob is key_id, writing the signature into out and
    /// returning its length. Runs the presence gesture only when the key's window is cold, and
    /// refreshes the window on success.
    pub fn sign(self: *Agent, key_id: []const u8, data: []const u8, now_ms: i64, out: []u8) SignError!usize {
        // peek is non-mutating: require presence on a cold window, then commit the window only
        // after the signature succeeds, so a failed sign never primes a silent window.
        const warm = self.windows.peek(key_id, now_ms, self.cfg.idle_ms, self.cfg.max_ms);
        if (!warm) self.az.authorize(key_id, self.cfg.reason) catch return error.PresenceRefused;

        const n = self.cp.sign(key_id, data, out) catch return error.BackendError;

        // Signature succeeded: open a new window (cold) or slide the idle clock (warm). An
        // allocation failure here is swallowed; the worst case is one extra presence prompt.
        if (warm) self.windows.touch(key_id, now_ms) else self.windows.open(key_id, now_ms) catch {};
        return n;
    }

    /// Force re-authentication for a key, for instance after it is recreated or reconfigured.
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
    _ = try agent.sign("key-1", "a", 1000, &out); // cold, presence runs
    _ = try agent.sign("key-1", "b", 1500, &out); // warm within idle, silent
    _ = try agent.sign("key-1", "c", 2200, &out); // idle slid forward by the prior sign, silent
    try testing.expectEqual(@as(usize, 1), az.granted);
    try testing.expectEqual(@as(usize, 3), cp.signs);
}

test "a lapsed idle window re-authenticates" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    _ = try agent.sign("key-1", "a", 1000, &out); // presence runs
    _ = try agent.sign("key-1", "b", 5000, &out); // idle lapsed (>1000 since last use), presence runs again
    try testing.expectEqual(@as(usize, 2), az.granted);
}

test "the absolute cap forces re-authentication even with steady use" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 10_000, .max_ms = 2000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    _ = try agent.sign("key-1", "a", 1000, &out); // opens at t=1000, absolute cap at 3000
    _ = try agent.sign("key-1", "b", 2500, &out); // within idle and cap, silent
    _ = try agent.sign("key-1", "c", 3500, &out); // past the absolute cap, presence runs again
    try testing.expectEqual(@as(usize, 2), az.granted);
}

test "a failed signature does not prime a silent window" {
    var cp = crypto.Fake{ .keys = &.{} }; // no keys, so cp.sign fails with UnknownKey
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    try testing.expectError(error.BackendError, agent.sign("ghost", "a", 1000, &out));
    // presence ran, but because the sign failed the window must stay cold
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
    _ = try agent.sign("key-1", "b", 1100, &out); // would be silent, but invalidation forces presence again
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
