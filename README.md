<!--
SPDX-FileCopyrightText: 2026 Paulo Duarte
SPDX-License-Identifier: Apache-2.0
-->

![sinete](logo.webp)

# sinete

**sinete** (Portuguese: *signet / seal-stamp* -- the handheld device that imprints a personal seal) is a hardware-backed cryptographic identity provider. It keeps its private key inside the platform's secure hardware and exposes **only the public key**.

## Why it exists

- The private key is generated in, and never leaves, the secure hardware. Only the public key is exported, and every signature happens inside the secure hardware, gated by user presence.
- It is fully CLI / scriptable.

## Status

Proof-of-concept spike. See the planned work below.

## Planned

- `sinete generate <name>` -- create a key.
- `sinete export <name>` -- print the public key.
- `sinete daemon` -- run as an ssh-agent.

## License

Apache-2.0. Built on [`facebookincubator/sks`](https://github.com/facebookincubator/sks) (Apache-2.0).
