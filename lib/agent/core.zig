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
const session = @import("../session.zig");
const presenter = @import("../presenter.zig");
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
/// error; RemoteRefused means the LocalSession check rejected a remote/forwarded caller. Window
/// bookkeeping cannot fail the call: a lost window just means one extra presence prompt next time.
pub const SignError = error{ PresenceRefused, BackendError, RemoteRefused };

pub const Agent = struct {
    gpa: std.mem.Allocator,
    cp: crypto.Cryptoprocessor,
    az: authz.Authorizer,
    cfg: Config,
    windows: window.Cache,
    /// Optional remote-session gate. When set, every signature requires a peer credential that the
    /// LocalSession confirms is the agent's own local session. Left null on platforms/builds without
    /// a peer-cred path (then no remote refusal happens); main.zig sets it after init on Linux.
    session: ?session.LocalSession = null,
    /// Optional presenter for user-facing refusal/failure messages. Null => no message (the protocol
    /// still answers FAILURE). The presence *prompt* itself is rendered by the platform Authorizer;
    /// this is only the failure channel the core owns. main.zig sets it after init.
    presenter: ?presenter.Presenter = null,

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
    pub fn sign(self: *Agent, cred: ?session.Cred, key_id: []const u8, data: []const u8, now_ms: i64, out: []u8) SignError!usize {
        // Remote gate first: a forwarded/remote caller is refused before any presence prompt or
        // window check, and on every signature so a window warmed locally cannot be ridden remotely.
        if (self.session) |s| {
            const c = cred orelse {
                self.notify(null, .remote_refused, "no peer credential");
                return error.RemoteRefused;
            };
            const local = s.isLocal(c) catch |e| {
                self.notify(cred, .remote_refused, @errorName(e));
                return error.RemoteRefused;
            };
            if (!local) {
                self.notify(cred, .remote_refused, "");
                return error.RemoteRefused;
            }
        }

        // peek is non-mutating: require presence on a cold window, then commit the window only
        // after the signature succeeds, so a failed sign never primes a silent window.
        const warm = self.windows.peek(key_id, now_ms, self.cfg.idle_ms, self.cfg.max_ms);
        if (!warm) self.az.authorize(cred, key_id, self.cfg.reason) catch |e| {
            // Distinguish "no presence method available" from a user decline so the message is right.
            self.notify(cred, if (e == error.PresenceUnavailable) .unavailable else .declined, @errorName(e));
            return error.PresenceRefused;
        };

        const n = self.cp.sign(key_id, data, out) catch |e| {
            self.notify(cred, if (e == error.UnknownKey) .unknown_key else .hardware, @errorName(e));
            return error.BackendError;
        };

        // Signature succeeded: open a new window (cold) or slide the idle clock (warm). An
        // allocation failure here is swallowed; the worst case is one extra presence prompt.
        if (warm) self.windows.touch(key_id, now_ms) else self.windows.open(key_id, now_ms) catch {};
        return n;
    }

    /// Force re-authentication for a key, for instance after it is recreated or reconfigured.
    pub fn invalidate(self: *Agent, key_id: []const u8) void {
        self.windows.invalidate(key_id);
    }

    /// Best-effort user-facing message for a refused/failed signature, with optional diagnostic
    /// detail (an underlying error name) for the log. No-op without a presenter.
    fn notify(self: *Agent, cred: ?session.Cred, reason: presenter.Reason, detail: []const u8) void {
        if (self.presenter) |p| p.showError(cred, reason, detail);
    }
};

const testing = std.testing;

test "first sign authenticates; signs within the idle TTL are silent" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    _ = try agent.sign(null, "key-1", "a", 1000, &out); // cold, presence runs
    _ = try agent.sign(null, "key-1", "b", 1500, &out); // warm within idle, silent
    _ = try agent.sign(null, "key-1", "c", 2200, &out); // idle slid forward by the prior sign, silent
    try testing.expectEqual(@as(usize, 1), az.granted);
    try testing.expectEqual(@as(usize, 3), cp.signs);
}

test "a lapsed idle window re-authenticates" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    _ = try agent.sign(null, "key-1", "a", 1000, &out); // presence runs
    _ = try agent.sign(null, "key-1", "b", 5000, &out); // idle lapsed (>1000 since last use), presence runs again
    try testing.expectEqual(@as(usize, 2), az.granted);
}

test "the absolute cap forces re-authentication even with steady use" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 10_000, .max_ms = 2000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    _ = try agent.sign(null, "key-1", "a", 1000, &out); // opens at t=1000, absolute cap at 3000
    _ = try agent.sign(null, "key-1", "b", 2500, &out); // within idle and cap, silent
    _ = try agent.sign(null, "key-1", "c", 3500, &out); // past the absolute cap, presence runs again
    try testing.expectEqual(@as(usize, 2), az.granted);
}

test "a failed signature does not prime a silent window" {
    var cp = crypto.Fake{ .keys = &.{} }; // no keys, so cp.sign fails with UnknownKey
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    try testing.expectError(error.BackendError, agent.sign(null, "ghost", "a", 1000, &out));
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
    try testing.expectError(error.PresenceRefused, agent.sign(null, "key-1", "a", 1000, &out));
    try testing.expectEqual(@as(usize, 0), cp.signs);
}

test "the remote gate refuses a non-local caller and a missing credential" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
    var az = authz.Fake{};
    var sess = session.Fake{ .local = false };
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    agent.session = sess.session();
    defer agent.deinit();

    var out: [8]u8 = undefined;
    // remote session -> refused before presence or signing
    try testing.expectError(error.RemoteRefused, agent.sign(.{ .pid = 9, .uid = 501 }, "key-1", "a", 1000, &out));
    // session set but no credential available -> also refused
    try testing.expectError(error.RemoteRefused, agent.sign(null, "key-1", "a", 1000, &out));
    try testing.expectEqual(@as(usize, 0), cp.signs);
    try testing.expectEqual(@as(usize, 0), az.granted);
}

test "the remote gate admits a confirmed local caller" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
    var az = authz.Fake{};
    var sess = session.Fake{ .local = true };
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    agent.session = sess.session();
    defer agent.deinit();

    var out: [8]u8 = undefined;
    _ = try agent.sign(.{ .pid = 9, .uid = 501 }, "key-1", "a", 1000, &out);
    try testing.expectEqual(@as(usize, 1), cp.signs);
    try testing.expectEqual(@as(usize, 1), az.granted);
}

test "invalidate forces the next signature to re-authenticate" {
    var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
    defer agent.deinit();

    var out: [8]u8 = undefined;
    _ = try agent.sign(null, "key-1", "a", 1000, &out);
    agent.invalidate("key-1");
    _ = try agent.sign(null, "key-1", "b", 1100, &out); // would be silent, but invalidation forces presence again
    try testing.expectEqual(@as(usize, 2), az.granted);
}

test "the presenter is notified of the reason on each refusal path" {
    var pres = presenter.Fake{};
    var out: [8]u8 = undefined;

    // remote refusal -- both branches: a non-local caller, and a missing credential
    {
        var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
        var az = authz.Fake{};
        var sess = session.Fake{ .local = false };
        var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
        agent.session = sess.session();
        agent.presenter = pres.presenter();
        defer agent.deinit();
        // a non-local caller (isLocal == false)
        try testing.expectError(error.RemoteRefused, agent.sign(.{ .pid = 9, .uid = 501 }, "key-1", "a", 1000, &out));
        try testing.expectEqual(presenter.Reason.remote_refused, pres.last_error.?);
        pres.last_error = null;
        // a missing credential while the gate is set (the cred-orelse branch, notify(null, ...))
        try testing.expectError(error.RemoteRefused, agent.sign(null, "key-1", "a", 1000, &out));
        try testing.expectEqual(presenter.Reason.remote_refused, pres.last_error.?);
    }
    // a declined gesture
    {
        var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
        var az = authz.Fake{ .declines = true };
        var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
        agent.presenter = pres.presenter();
        defer agent.deinit();
        try testing.expectError(error.PresenceRefused, agent.sign(null, "key-1", "a", 1000, &out));
        try testing.expectEqual(presenter.Reason.declined, pres.last_error.?);
    }
    // an unavailable gesture (no reader / unevaluable) maps to .unavailable, not .declined
    {
        var cp = crypto.Fake{ .keys = &.{.{ .blob = "key-1", .comment = "me@host" }} };
        var az = authz.Fake{ .declines = true, .decline_error = error.PresenceUnavailable };
        var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
        agent.presenter = pres.presenter();
        defer agent.deinit();
        try testing.expectError(error.PresenceRefused, agent.sign(null, "key-1", "a", 1000, &out));
        try testing.expectEqual(presenter.Reason.unavailable, pres.last_error.?);
    }
    // a backend error for an unknown key maps to unknown_key, not hardware
    {
        var cp = crypto.Fake{ .keys = &.{} };
        var az = authz.Fake{};
        var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1000, .max_ms = 10_000 });
        agent.presenter = pres.presenter();
        defer agent.deinit();
        try testing.expectError(error.BackendError, agent.sign(null, "ghost", "a", 1000, &out));
        try testing.expectEqual(presenter.Reason.unknown_key, pres.last_error.?);
    }
    try testing.expectEqual(@as(usize, 5), pres.errors);
}

test "identities reflects the cryptoprocessor enumeration" {
    var cp = crypto.Fake{ .keys = &.{
        .{ .blob = "k1", .comment = "one" },
        .{ .blob = "k2", .comment = "two" },
    } };
    var az = authz.Fake{};
    var agent = Agent.init(testing.allocator, cp.processor(), az.authorizer(), .{ .idle_ms = 1, .max_ms = 1 });
    defer agent.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ids = try agent.identities(arena.allocator());
    try testing.expectEqual(@as(usize, 2), ids.len);
    try testing.expectEqualStrings("k2", ids[1].blob);
}
