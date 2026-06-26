# Z3 manual checklist — macOS Secure Enclave + Touch ID

The Secure Enclave and Touch ID paths cannot run in CI (no enclave, no signed bundle), so the
Objective-C shims (`src/backend/darwin_se.m`, `src/backend/darwin_presence.m`) and the agent's real
sign path are verified by this checklist on an Apple-silicon Mac with Touch ID.

Prerequisites: an Apple Development signing identity and a provisioning profile for App ID
`me.paulofduarte.sinete` on this device. `scripts/bundle.sh` generates the entitlements from
`SINETE_TEAM` / `SINETE_BUNDLE_ID` (defaulting to this project's), so a fork signs with its own
team via those env vars, no tracked-file edits.

## Build + sign the bundle

```sh
scripts/bundle.sh /path/to/dev.provisionprofile
```

- [ ] Build + codesign succeed; the verify output shows `TeamIdentifier=LDT534J26W` and the
      `keychain-access-groups` entitlement.

## Key management (presence-less; use a throwaway name; do NOT remove production keys)

The keys are presence-less, so generate/list/export/remove run with **no Touch ID** — presence is
gated only on the agent's sign path (below).

```sh
BIN=./dist/sinete.app/Contents/MacOS/sinete
"$BIN" generate ztest        # no prompt; prints an ecdsa-sha2-nistp256 authorized_keys line
"$BIN" list                  # lists ztest AND the existing production keys (SHA256 fingerprints)
"$BIN" export ztest          # prints ztest's authorized_keys line again
```

- [ ] `generate ztest` prints a key with **no Touch ID** (no `-34018`; entitlement + profile OK).
- [ ] `list` shows `sinete-ztest` and the pre-existing keys; the reserved master key is absent.
- [ ] `export ztest` (and `export sinete-ztest`) match the generated line.

## Agent: real signing gated by Touch ID

```sh
SOCK=/tmp/z3.sock
"$BIN" agent --sock "$SOCK" &
SSH_AUTH_SOCK=$SOCK ssh-add -l           # lists the enclave identities
echo test | SSH_AUTH_SOCK=$SOCK ssh-keygen -Y sign -n file -f <(ssh-add -L | head -1) /dev/stdin
```

- [ ] `ssh-add -l` lists the enclave keys with `(ECDSA)` and correct fingerprints.
- [ ] The first signature prompts Touch ID; a second signature within the idle TTL is silent
      (presence window), confirming the software TTL gate.
- [ ] A produced signature verifies against the public key (`ssh-keygen -Y verify` with an
      allowed_signers line), confirming the DER -> SSH conversion is correct.

## End-to-end (production key, reused identity)

- [ ] `ssh -T git@github.com` authenticates through the agent (Touch ID on first use).
- [ ] `git commit -S` produces a signature GitHub shows as Verified.

## Cleanup

```sh
"$BIN" remove ztest          # deletes the throwaway key
```

- [ ] `remove ztest` succeeds and `list` no longer shows it.
