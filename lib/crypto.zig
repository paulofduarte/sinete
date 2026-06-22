// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The Cryptoprocessor interface: the secure-element authority for key lifecycle and signing
//! (macOS Secure Enclave, Linux TPM 2.0, or a fake). It owns the key handles, and the agent
//! reaches it only through this vtable. Presence is gated separately by the Authorizer
//! (authz.zig), so a sign here is the post-presence, silent path.

const std = @import("std");

/// A public key as advertised to ssh clients: its ecdsa-sha2-nistp256 wire blob and a human
/// comment. The slices are owned by whatever allocator enumerate was given.
pub const KeyInfo = struct {
    blob: []const u8,
    comment: []const u8,
};

pub const Cryptoprocessor = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// List every key the secure element holds, allocating into arena. The caller frees
        /// it wholesale, typically a per-request arena.
        enumerate: *const fn (ptr: *anyopaque, arena: std.mem.Allocator) anyerror![]const KeyInfo,
        /// Sign data with the key identified by its public blob key_id, writing the SSH
        /// signature blob into out and returning its length. Computed in hardware.
        sign: *const fn (ptr: *anyopaque, key_id: []const u8, data: []const u8, out: []u8) anyerror!usize,
    };

    pub fn enumerate(self: Cryptoprocessor, arena: std.mem.Allocator) ![]const KeyInfo {
        return self.vtable.enumerate(self.ptr, arena);
    }
    pub fn sign(self: Cryptoprocessor, key_id: []const u8, data: []const u8, out: []u8) !usize {
        return self.vtable.sign(self.ptr, key_id, data, out);
    }
};

/// A fake cryptoprocessor over a fixed key set, for unit tests and the pre-backend agent.
/// `sign` writes a deterministic blob (the data length) and counts calls; an unknown key_id
/// is `error.UnknownKey`.
pub const Fake = struct {
    keys: []const KeyInfo,
    signs: usize = 0,

    pub fn processor(self: *Fake) Cryptoprocessor {
        return .{ .ptr = self, .vtable = &vt };
    }
    const vt = Cryptoprocessor.VTable{ .enumerate = enumerate, .sign = sign };

    fn enumerate(ptr: *anyopaque, arena: std.mem.Allocator) ![]const KeyInfo {
        const self: *Fake = @ptrCast(@alignCast(ptr));
        // Copy into arena so the fake matches the real contract: returned slices live in the
        // arena, not in the backend, and callers can rely on that lifetime.
        const out = try arena.alloc(KeyInfo, self.keys.len);
        for (self.keys, 0..) |k, i| out[i] = .{
            .blob = try arena.dupe(u8, k.blob),
            .comment = try arena.dupe(u8, k.comment),
        };
        return out;
    }
    fn sign(ptr: *anyopaque, key_id: []const u8, data: []const u8, out: []u8) !usize {
        const self: *Fake = @ptrCast(@alignCast(ptr));
        for (self.keys) |k| {
            if (std.mem.eql(u8, k.blob, key_id)) {
                if (out.len < 1) return error.NoSpace;
                out[0] = @truncate(data.len);
                self.signs += 1;
                return 1;
            }
        }
        return error.UnknownKey;
    }
};

test "fake cryptoprocessor enumerates and signs known keys" {
    var fake = Fake{ .keys = &.{
        .{ .blob = "blob-A", .comment = "a@host" },
        .{ .blob = "blob-B", .comment = "b@host" },
    } };
    const cp = fake.processor();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const keys = try cp.enumerate(arena.allocator());
    try std.testing.expectEqual(@as(usize, 2), keys.len);
    try std.testing.expectEqualStrings("b@host", keys[1].comment);

    var out: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try cp.sign("blob-A", "hello", &out));
    try std.testing.expectEqual(@as(u8, 5), out[0]);
    try std.testing.expectEqual(@as(usize, 1), fake.signs);
    try std.testing.expectError(error.UnknownKey, cp.sign("blob-Z", "x", &out));
}
