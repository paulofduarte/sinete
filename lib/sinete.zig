// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! libsinete is the cross-platform core of sinete: the ssh-agent protocol, the SSH wire
//! format, the presence-window TTL logic, and the key-authorization interfaces. It has no
//! operating-system dependencies and is exercised entirely by unit tests. Platform specifics
//! such as the Secure Enclave, TPM, presence, and sockets live in a separate backend and are
//! reached only through the interfaces declared here.

pub const version = "0.0.0-dev";

pub const authz = @import("authz.zig");
pub const crypto = @import("crypto.zig");
pub const session = @import("session.zig");
pub const wire = @import("ssh/wire.zig");
pub const agent_proto = @import("ssh/agent_proto.zig");
pub const window = @import("agent/window.zig");
pub const agent = @import("agent/core.zig");
pub const server = @import("agent/server.zig");
pub const framing = @import("agent/framing.zig");

// Headline types, re-exported for convenience.
pub const Authorizer = authz.Authorizer;
pub const Cryptoprocessor = crypto.Cryptoprocessor;
pub const LocalSession = session.LocalSession;
pub const WindowCache = window.Cache;
pub const Agent = agent.Agent;

test {
    // Reference every submodule so its tests are included in the module test binary.
    _ = authz;
    _ = crypto;
    _ = session;
    _ = wire;
    _ = agent_proto;
    _ = window;
    _ = agent;
    _ = server;
    _ = framing;
}
