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
pub const presenter = @import("presenter.zig");
pub const presence = @import("presence.zig");
pub const wire = @import("ssh/wire.zig");
pub const ecdsa_key = @import("ssh/ecdsa_key.zig");
pub const ecdsa_sig = @import("ssh/ecdsa_sig.zig");
pub const tpm_wire = @import("tpm/wire.zig");
pub const tpm_commands = @import("tpm/commands.zig");
pub const tpm_keyfile = @import("tpm/keyfile.zig");
pub const dbus_wire = @import("dbus/wire.zig");
pub const dbus_message = @import("dbus/message.zig");
pub const dbus_sasl = @import("dbus/sasl.zig");
pub const dbus_calls = @import("dbus/calls.zig");
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
    _ = presenter;
    _ = presence;
    _ = wire;
    _ = ecdsa_key;
    _ = ecdsa_sig;
    _ = tpm_wire;
    _ = tpm_commands;
    _ = tpm_keyfile;
    _ = dbus_wire;
    _ = dbus_message;
    _ = dbus_sasl;
    _ = dbus_calls;
    _ = agent_proto;
    _ = window;
    _ = agent;
    _ = server;
    _ = framing;
}
