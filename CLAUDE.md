# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sinete` is a hardware-backed SSH agent + key-management CLI. Private keys are generated inside, and never leave, the platform secure element (macOS Secure Enclave via Touch ID; Linux TPM 2.0 via PIN). Only public keys are ever exported; every signature happens in-hardware. Keys are presented as plain `ecdsa-sha2-nistp256` so they work with GitHub, OpenSSH servers, and SSH-based git commit signing — the whole reason the project exists (macOS's native SE path yields `sk-ecdsa-...@openssh.com`, which GitHub rejects).

The crypto/hardware core is [`facebookincubator/sks`](https://github.com/facebookincubator/sks) (Apache-2.0), which abstracts Secure Enclave + TPM behind one Go API. `sinete` adds the SSH/agent/CLI layer on top.

**Read `.claude/SPEC.md` first.** It is the authoritative design reference (rationale, CLI surface, key model, roadmap, open questions). The entire `.claude/` directory is gitignored, so SPEC.md is local-only and not on any branch.

## Current state

The repo is at the **PoC spike** stage: `./main.go` is a single-file round-trip (create SE key → export plain `ecdsa` public key → sign in-enclave → verify), **verified on Apple Silicon (M4 Pro) — but only when run from a code-signed `.app` bundle with a provisioning profile** (see *Build & test*). A bare `go run` / `nix build` binary is SIGKILLed by AMFI or rejected by the Secure Enclave (`-34018`). **Caveat:** no Touch ID prompt fired on signing, so user-presence gating is *not yet verified*. It is *not* the final structure. The first real implementation task is to restructure into the target layout (see SPEC §10):

```
cmd/sinete/        # CLI entrypoint (replaces ./main.go)
internal/enclave/  # thin sks wrapper: create/open/sign/remove, pubkey export, name ↔ (label,tag)
internal/agent/    # ssh-agent (golang.org/x/crypto/ssh/agent.Agent), read-only, unix socket
internal/registry/ # local key index at $XDG_CONFIG_HOME/sinete/keys.json (sks can't enumerate keys)
```

## Architecture notes that aren't obvious from the code

- **The agent is read-only.** It implements `ssh/agent.Agent` but `List`/`Sign` only — `Add`/`Remove`/`Lock`/`Unlock` must return "unsupported". Key lifecycle is the CLI's job, not the agent protocol's.
- **A local registry exists because `sks` cannot enumerate an app's keys.** `internal/registry` maps `name → {label, tag, publicKey, created, options}` and caches public keys so `list`/`export`/`fingerprint` never touch hardware (no Touch ID prompt). It holds no secret material.
- **`sks.Key` is a `crypto.Signer`.** Wrap it with `ssh.NewSignerFromSigner` to get the ECDSA→SSH wire-format conversion and signing for free; `Sign` is where the Touch ID / PIN prompt fires.
- **`sks.NewKey(label, tag, useBiometrics, accessibleWhenUnlockedOnly, hash)`**: `hash == nil` generates a new key; non-nil looks one up. If the key already exists the two bool flags are ignored. Algorithm is always ECDSA **P-256** — Secure Enclave does nothing else (no RSA, no other curves).
- Platform differences (biometrics vs PIN) stay behind `sks`; don't special-case them above the `internal/enclave` boundary. Note `sks` biometrics is macOS-only — Linux TPM presence/PIN handling is still TBD (SPEC §7, §13).

## Build & test

cgo is **required** — `sks` calls platform crypto APIs (Security/LocalAuthentication on macOS, TPM libs on Linux). Plain `go build` works only with `CGO_ENABLED=1` and the platform toolchain present (macOS: `xcode-select --install`).

Preferred (Nix, matches CI):

```sh
nix build                          # → ./result/bin/sinete
nix develop -c go test ./...       # tests inside the dev shell (go, gopls, golangci-lint)
nix develop -c go vet ./...
nix flake check
```

**Running the spike requires code-signing.** The Secure Enclave rejects an unsigned/unentitled binary (`-34018`), and macOS (AMFI) SIGKILLs a bare CLI that claims the required restricted `application-identifier` entitlement — so `go run .` and a plain `nix build` binary cannot do SE ops. It must run from a signed `.app` bundle with a provisioning profile:

```sh
nix build
bash scripts/bundle-and-sign.sh /path/to/<dev>.provisionprofile -keep
```

This builds `sinete.app` (binary + `Info.plist` + `embedded.provisionprofile`), signs it with `sinete.entitlements` (Apple Development identity, **no** hardened runtime so the ad-hoc-signed nix dylibs load), and runs it. `-keep` retains the key so you can register the printed public key with GitHub/a server. Prereqs: an Apple Development identity, the WWDR **G3** intermediate installed, and a dev provisioning profile for this device + App ID `me.paulofduarte.*`. Full chain: `.claude/ROADMAP.md` Phase 1.

Run a single test: `nix develop -c go test ./internal/registry -run TestName`.

## Build notes

`flake.nix` pins nixpkgs to `nixos-26.05` (locked in `flake.lock`), sets a real `vendorHash`, and no longer references the removed `darwin.apple_sdk.frameworks` (the SDK is implicit on 26.05). `sks` is pinned to the `paulofduarte/sks` fork via a `replace` in `go.mod`. If `go.mod`/`go.sum` change, regenerate the `vendorHash` — `nix build` fails and prints the new hash to paste into `flake.nix`.

## Branching

- **`develop`** — active development (all code, flake, CI). **Work here.**
- **`main`** (default) — clean landing page: only `README.md`, `LICENSE.md`, `.gitignore`. Releases merge/tag here.
- Module path: `github.com/paulofduarte/sinete`. CI (`nix flake check`/`build`/`go test`/`go vet`) runs on push to `develop` and PRs to `develop`/`main`, on a `macos-14` + `ubuntu-latest` matrix.
