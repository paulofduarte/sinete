# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sinete` is a hardware-backed SSH key manager + agent. Private keys are generated inside, and never leave, the platform secure element (macOS Secure Enclave; Linux TPM 2.0 is planned). Only public keys are ever exported; every signature is computed in-hardware. Keys are presented as plain `ecdsa-sha2-nistp256` so they work with GitHub, OpenSSH servers, and SSH-based git commit signing — the whole reason the project exists (macOS's native SE path yields `sk-ecdsa-...@openssh.com`, which GitHub rejects).

The crypto/hardware core is [`facebookincubator/sks`](https://github.com/facebookincubator/sks) (Apache-2.0), which abstracts Secure Enclave + TPM behind one Go API. `sinete` adds the SSH/agent/CLI layer on top.

**Read `.claude/SPEC.md` and `.claude/AGENT-V2-PLAN.md` first.** They are the authoritative design references (rationale, CLI surface, key model, the v2 agent design). The entire `.claude/` directory is gitignored, so they are local-only and not on any branch.

## Layout

```
cmd/sinete/         # CLI entrypoint
internal/enclave/   # thin sks wrapper: create/open/sign/remove, pubkey export, name <-> (label,tag)
internal/agent/     # the ssh-agent (served via x/crypto ServeAgent)
internal/registry/  # signed presence config at $XDG_CONFIG_HOME/sinete/registry.json (keys are enumerated from the SE)
internal/presence/  # user-presence check (macOS LocalAuthentication, cgo); stub elsewhere
internal/loginitem/ # register the launchd agent as a login item (macOS SMAppService, cgo); stub elsewhere
internal/install/   # app-driven setup/teardown: link + login item + install.json state; stub elsewhere
ui/                 # SwiftUI control panel (sinete-ui), compiled by `nix run .#bundle`
launchd/            # me.paulofduarte.sinete.agent.plist (bundled into the .app for SMAppService)
```

## The agent model (v2 — "Model B")

This is the core design; get it right:

- **Keys are presence-less in the SE.** `enclave.Create` calls `sks.NewKey(... useBiometrics=false ...)`, so the Secure Enclave does *not* prompt per signature. (Legacy keys created before this carry the SE's `UserPresence` ACL and will double-prompt; regenerate them.)
- **The agent advertises every registry key** (`List` from the registry), so a client talking to it uses them with no manual `ssh-add`. It holds only enclave-backed signer *handles*, never key material.
- **Presence is gated at sign time, in software, with a TTL cache** (after gpg-agent): the first signature with a key runs `presence.Authenticate` (Touch ID); within the per-key idle TTL — and an absolute cap — further signatures are silent. `presence-ttl` / `presence-max-ttl` are set with `sinete config`, stored in the registry, and re-read by the agent live.
- **Presence windows are keyed by the public key, not the name** — a deleted-and-recreated key must re-authenticate.
- **Superset / delegation.** The agent forwards everything it doesn't own (List ∪ upstream; Sign/Add/Remove/…) to the session's existing agent — the `SSH_AUTH_SOCK` it inherits (normally macOS's `com.openssh.ssh-agent`), skipped if that socket is itself — so a client pointed at sinete still sees its other keys.
- **launchd login item.** The agent is registered with `SMAppService` (`sinete service register`, in `internal/loginitem`) from the *signed* bundle, so its plist lives at `Contents/Library/LaunchAgents/` and macOS attributes the item to sinete.app (name + icon, not a stray script). On launch `prepareLaunchSession` only redirects the log (the bundled plist has no `Standard*Path`); it does **not** republish `SSH_AUTH_SOCK`.
- **Reaching the agent — no env takeover.** `launchctl setenv SSH_AUTH_SOCK` does *not* work on modern macOS: the system `com.openssh.ssh-agent` declares `Sockets → SecureSocketWithKey SSH_AUTH_SOCK`, so launchd bakes its socket into every GUI process's environment before the desktop loads, and that wins. Clients reach sinete by **config**, not env: `~/.ssh/config` `IdentityAgent <sock>` (which *overrides* `SSH_AUTH_SOCK`; use `Host *`). Git commit **signing** is the exception — `ssh-keygen -Y sign` reads `SSH_AUTH_SOCK`, not `ssh_config` — so for signing, export `SSH_AUTH_SOCK=<sock>` in the shell. The socket is `~/Library/Caches/sinete/agent.sock`.

## Architecture notes that aren't obvious from the code

- **The main thread matters.** macOS only draws the presence (LocalAuthentication) prompt from the main OS thread. `main` calls `runtime.LockOSThread`; the agent serves connections on goroutines but dispatches signing (and its prompt) to a main-thread `Run` loop.
- **Keys are enumerated from the secure element; config is a signed file.** sinete no longer keeps an on-disk key index — `list`/`export`/the agent enumerate the SE (the source of truth; the in-repo cgo in `internal/enclave` does what stock `sks` can't). `internal/registry` holds only the per-key presence config in a single signed `registry.json` (`$XDG_CONFIG_HOME/sinete/`), whose payload is signed by an internal enclave **master key** and bound to a replay **epoch** (a keychain item); tampering or replay is detected and falls back to built-in defaults. It holds no secret material.
- **`sks.Key` is a `crypto.Signer`** wrapped with `ssh.NewSignerFromSigner`. It's a handle — `Sign` computes in the SE; for presence-less keys it does *not* prompt (the agent gates presence separately).
- **`sks.NewKey(label, tag, useBiometrics, accessibleWhenUnlockedOnly, hash)`**: `hash == nil` generates, non-nil looks up. Algorithm is always ECDSA **P-256** (SE constraint). Upstream sks ignores `useBiometrics` on macOS — exactly what we want (presence-less keys), which is why the fork was dropped.
- **The entitlement wall.** SE keys are bound to sinete's keychain access group, so only the signed sinete bundle can use them. `ssh`/`ssh-add`/any in-process library cannot reach the key — the agent is the only channel (this is why a PKCS#11 / SecurityKeyProvider can't give agentless access).
- **Diagnostics & hooks.** `sinete sign` (direct sign) and `sinete present[-n]` (presence prompt) are unlisted diagnostics; `sinete service <register|unregister|status>` exposes the `SMAppService` registration directly (the `install`/`uninstall` flow registers via `internal/loginitem`).

## Build & test

cgo is **required** (`sks` + `internal/presence` call platform crypto APIs). Preferred (Nix, matches CI):

```sh
nix build                     # → ./result/bin/sinete
nix develop -c go test ./...
nix fmt                       # treefmt: gofumpt + nixfmt + shfmt
nix flake check               # formatting + golangci-lint(*) + reuse + shellcheck
```

(*) golangci-lint runs in the dev shell / CI, not the no-network flake-check sandbox (it needs the module graph) — see `flake.nix`.

**Secure-Enclave ops require a signed `.app` bundle.** An unsigned/unentitled binary is rejected by the SE (`-34018`) or SIGKILLed by AMFI, so the agent (and `generate`/`sign`/`delete`) must run from the bundle:

```sh
nix run .#bundle -- /path/to/<dev>.provisionprofile   # builds + signs sinete.app
./sinete.app/Contents/MacOS/sinete install            # link + SMAppService login item + state
```

(Or just double-click `sinete.app` and use the setup wizard — both call the same `sinete install`.)

`nix run .#bundle` (macOS only) folds in the former `bundle-and-sign.sh`: it takes the nix-built `sinete`, compiles `ui/SineteUI.swift` to `sinete-ui` with `xcrun swiftc` (nixpkgs swift is too old for the macOS-26 SwiftUI module), runs `actool`, assembles the `.app`, and signs — the unentitled `sinete-ui` first, then the bundle (which signs `sinete` with the SE entitlements). Or double-click `sinete.app`: the SwiftUI panel runs the setup wizard / shows the ready screen.

For quick **non-SE** checks (`list`, `config`, `present`), `nix run -- <args>` is the default app: it signs the bare nix-built binary (same dev identity + `sinete.entitlements` as the bundle) and execs it. SE ops still need the `.app` — a bare binary can't carry the provisioning profile.

Prereqs: an Apple Development identity, the WWDR **G3** intermediate, and a dev provisioning profile for this device + App ID `me.paulofduarte.*`. Note the presence prompt (LocalAuthentication) works even from a bare binary; only SE ops need the bundle.

**Commit signing:** the git-hooks need the dev shell active, so commit from within `nix develop` (or set up direnv). Sign with the enclave key via `SSH_AUTH_SOCK=<agent sock>`; never push unsigned commits.

## Build notes

`flake.nix` pins nixpkgs to `nixos-26.05`, sets a real `vendorHash`, and wires `treefmt-nix` + `git-hooks.nix`. `sks` is upstream `facebookincubator/sks` (the `paulofduarte/sks` fork was dropped in v2; the `replace` is gone). If `go.mod` / `go.sum` change, regenerate the `vendorHash` (set it to `pkgs.lib.fakeHash`, run `nix build`, paste the printed hash).

## Branching

- **`develop`** — active development (all code, flake, CI). **Work here.** (Agent v2 lands via a PR from `agent-v2`.)
- **`main`** (default) — clean landing page: `README.md`, `LICENSE.md`, `.gitignore`, logo. Releases merge/tag here.
- Module path: `github.com/paulofduarte/sinete`. CI gates everything on a `lint` job (build/test and the release workflow `needs:` it), on a `macos-14` + `ubuntu-latest` matrix.
