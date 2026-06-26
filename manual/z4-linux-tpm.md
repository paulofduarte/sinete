# Z4 manual checklist — Linux TPM 2.0

The TPM device path cannot run in CI (no TPM, and Docker blocks `io_uring`), so the impure backend
(`src/backend/linux.zig`, `tpm_device.zig`) is verified against **swtpm** and on a real Linux TPM.
The pure marshaling (`lib/tpm/*`) is unit-tested without a TPM.

## Against swtpm (local, no real TPM)

`scripts/tpm-it.sh` runs this in an OrbStack/Docker Linux container; the steps by hand:

```sh
swtpm socket --tpm2 --tpmstate dir=/tmp/tpm \
    --ctrl type=unixio,path=/tmp/tpm/ctrl --server type=unixio,path=/tmp/tpm/sock --flags startup-clear &
export SINETE_TPM=/tmp/tpm/sock          # selects the swtpm socket over /dev/tpmrm0
sinete _tpm-selftest                     # create -> sign -> std.crypto verify -> NV epoch +1
sinete generate ztest                    # TPM key, written as a TSS2 key file
sinete list                              # lists ztest (SHA256 fingerprint)
sinete agent --sock /tmp/a.sock &        # needs io_uring: in Docker run with --security-opt seccomp=unconfined
SSH_AUTH_SOCK=/tmp/a.sock ssh-add -l     # lists the TPM key
echo hi | SSH_AUTH_SOCK=/tmp/a.sock ssh-keygen -Y sign -f <(ssh-add -L) -n test /dev/stdin
sinete remove ztest
```

- [ ] `_tpm-selftest` prints `SELFTEST PASS` (sign verifies, epoch increments).
- [ ] `generate`/`list`/`export`/`remove` round-trip a key file.
- [ ] `ssh-add -l` through the agent lists the TPM key.
- [ ] `ssh-keygen -Y sign` through the agent produces a signature that `ssh-keygen -Y verify` accepts.

## On a real Linux box with a TPM (`/dev/tpmrm0`)

The default device; no `SINETE_TPM`. The user must be able to read/write `/dev/tpmrm0` (group `tss`).

```sh
sinete generate work                     # Touch the TPM; a TSS2 key file at ~/.local/share/sinete/keys/work
sinete agent &                           # default socket ~/Library/Caches/... no -- on Linux: $XDG_RUNTIME_DIR/sinete/agent.sock
ssh-add -L > ~/sinete-tpm.pub            # register with GitHub (auth + signing)
```

- [ ] `ssh -T git@github.com` authenticates through the agent with the TPM key.
- [ ] `git commit -S` produces a signature GitHub shows as Verified.
- [ ] The TSS2 key file is interoperable: `tpm2_load`/the OpenSSL tpm2 provider can read it.

## Notes
- Keys are **presence-less** in v1 (no per-signature gesture); presence (fprintd/FIDO2) is Z5.
- The TPM key is a child of a deterministic owner-hierarchy primary, re-derived per signature.
