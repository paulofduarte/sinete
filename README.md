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

Working key manager and ssh-agent. Pre-release.

## Usage

`sinete` manages the keys; its agent serves them to `ssh` and `git`.

    sinete generate <name>      create a key, print its public key
    sinete list                 list keys
    sinete export <name>        print a key's public key
    sinete ssh-setup <name>     write the public key and print ssh/git config
    sinete delete <name>        delete a key
    sinete config <key> <val>   set presence-ttl / presence-max-ttl
    sinete agent                run the agent (usually started at login)

The agent advertises every key, so `ssh`/`git` use them automatically once
`SSH_AUTH_SOCK` points at it. The first signature with a key checks user
presence; further signatures within the configured window are silent. It also
forwards keys it does not own to your existing agent, so it can take over
`SSH_AUTH_SOCK` without losing anything.

## License

Apache-2.0. Built on [`facebookincubator/sks`](https://github.com/facebookincubator/sks) (Apache-2.0).
