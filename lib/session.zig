// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The LocalSession seam: decides whether a client connection originates from the user's
//! own local login session, so the agent can refuse presence-gated signatures driven from a
//! remote/forwarded context (the scenario-4 refusal — issue #23). Implemented per-platform
//! (macOS audit session, Linux logind) behind this vtable; a fake drives the unit tests.

const std = @import("std");

pub const Cred = struct {
    /// The peer process id of the connecting client (from SO_PEERCRED / LOCAL_PEERPID).
    pid: i32,
    /// The peer's uid; the agent additionally refuses a uid mismatch.
    uid: u32,
};

pub const LocalSession = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Whether `cred` belongs to the same local login session as the agent. A false
        /// here means refuse presence-gated use (it may be a forwarded/remote caller).
        isLocal: *const fn (ptr: *anyopaque, cred: Cred) anyerror!bool,
    };

    pub fn isLocal(self: LocalSession, cred: Cred) !bool {
        return self.vtable.isLocal(self.ptr, cred);
    }
};

/// A fake session oracle returning a fixed verdict — the unit-test stand-in until the
/// platform backends (macOS audit session / Linux logind) land.
pub const Fake = struct {
    local: bool = true,

    pub fn session(self: *Fake) LocalSession {
        return .{ .ptr = self, .vtable = &vt };
    }
    const vt = LocalSession.VTable{ .isLocal = isLocal };
    fn isLocal(ptr: *anyopaque, cred: Cred) !bool {
        _ = cred;
        const self: *Fake = @ptrCast(@alignCast(ptr));
        return self.local;
    }
};

test "fake session reports its fixed verdict" {
    var f = Fake{ .local = true };
    const s = f.session();
    try std.testing.expect(try s.isLocal(.{ .pid = 123, .uid = 501 }));
    f.local = false;
    try std.testing.expect(!try s.isLocal(.{ .pid = 123, .uid = 501 }));
}
