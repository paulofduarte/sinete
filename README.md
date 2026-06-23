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

## Status — `develop-zig` (experimental Zig rewrite)

This branch is an **experimental rewrite in [Zig](https://ziglang.org) (0.16)**, run in parallel
to the Go implementation on `develop`. It targets the hardened end-state directly — per-key TPM
`authPolicy` + hardware presence + the multi-user broker — so it does not reproduce intermediate
Go stages. The two branches will be compared before a direction is chosen.

## Build & develop

The repo builds with **`zig build` alone** — no nix needed if you have Zig 0.16 installed:

```sh
zig build                 # → zig-out/bin/sinete
zig build run -- version
zig build test
zig build coverage        # build kcov from source via Zig + run tests under it → kcov-out/
zig fmt .                 # format (enforced by the pre-commit hook)
```

Optionally, a pinned toolchain via [devenv](https://devenv.sh) (nixpkgs 26.05 → Zig 0.16):

```sh
devenv shell              # provides zig + shellcheck; sets the hooks path
```

Pre-commit hooks are plain shell (`.githooks/pre-commit`: `zig fmt` + SPDX header + shellcheck).
Enable once with `git config core.hooksPath .githooks` (the devenv shell does this automatically).

## Continuous integration

GitHub Actions (`.github/workflows/ci.yml`) gates every push and pull request on a `lint` job
(`zig fmt`, [REUSE](https://reuse.software) compliance, shellcheck), then a `coverage` job that runs
the tests under kcov (`zig build coverage`, which builds kcov from source via Zig) across a Linux +
macOS matrix (x86_64 and arm64), uploading the report as an artifact. Coverage runs the tests, so
there is no separate test job. The build needs only Zig and no nix; CI additionally runs
shellcheck (lint) and jq (coverage summary), both preinstalled on the GitHub runners.

## License

Apache-2.0.
