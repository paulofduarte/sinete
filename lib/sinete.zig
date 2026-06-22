// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! libsinete — the cross-platform core of sinete (no OS dependencies, fully unit-testable).
//! Holds the ssh-agent protocol, SSH wire format, the presence-window/TTL logic, and the
//! key-authorization seam. OS specifics (Secure Enclave, TPM, presence, sockets) live in the
//! `backend` and are reached only through the interfaces defined here. See ZIG-ARCHITECTURE.md.

const std = @import("std");

pub const version = "0.0.0-dev";

pub const authz = @import("authz.zig");
pub const wire = @import("ssh/wire.zig");
pub const window = @import("agent/window.zig");

// Headline types, re-exported for ergonomic consumers.
pub const Authorizer = authz.Authorizer;
pub const Grant = authz.Grant;
pub const WindowCache = window.Cache;

test {
    // Pull every submodule into the test binary so `zig build test` runs all of libsinete.
    _ = authz;
    _ = wire;
    _ = window;
}
