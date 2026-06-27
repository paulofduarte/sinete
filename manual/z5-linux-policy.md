# Z5b manual checklist — Linux TPM authPolicy binding

Z5b binds each data key's TPM usage to the presence gesture via a `PolicySecret` authPolicy: signing
requires a policy session that proves a 32-byte master secret `S`. So a copied key file is inert
without `S`, and the on-machine bypass (signing the key file directly via `/dev/tpmrm0`) now also
needs `S`. The pure marshaling and the digest formula are unit-tested; the binding itself is verified
against swtpm by `scripts/tpm-it.sh` (`_tpm-policy-selftest`) and on a real TPM here.

## Automated (swtpm)

- [ ] `scripts/tpm-it.sh` prints `ok: policy binding (empty-auth sign rejected, policy-session sign
      verifies)` and `ALL OK`.
- [ ] `SINETE_TPM=<sock> sinete _tpm-policy-selftest` prints `POLICY SELFTEST PASS` (the negative
      empty-auth Sign is rejected; the positive policy-session Sign verifies).

## On a real Linux box with a TPM (`/dev/tpmrm0`)

```sh
sinete generate work          # auto-enrolls the master on first use: ~/.local/share/sinete/keys/master.secret
                              # (0600) + an NV index, and creates a policy-bound key
ls -l ~/.local/share/sinete/keys/   # work (0600), master.secret (0600), dir 0700
```

- [ ] `generate` creates `master.secret` (0600) and a key file; the key's public key registers with
      GitHub like any `ecdsa-sha2-nistp256` key (the authPolicy does not change the public point).
- [ ] With the agent running and a fingerprint enrolled, `git commit -S` / `ssh -T git@github.com`
      prompts for the fingerprint (Z5a) and then signs (Z5b authorizes the TPM via the policy).
- [ ] **The binding holds:** copy the key file to another machine (or rename `master.secret` away) and
      confirm the key can no longer sign — `tpm2_sign` with empty auth on the loaded key fails, and the
      agent reports a failure without `master.secret`.
- [ ] A key generated before Z5b (legacy empty-auth) still signs; new keys are policy-bound. They
      coexist in the same directory.

## Migration / re-enroll

A policy cannot be retrofitted onto an existing key (authPolicy is fixed at create time), so upgrading
a legacy key means generating a new one and re-registering its public key:

```sh
sinete remove work && sinete generate work   # new public key -> re-register with GitHub
```

## Notes / known limitations
- `S` at rest is protected by filesystem permissions only (0600). Sealing `S` under the deterministic
  primary (so a raw disk copy yields neither a loadable key nor a usable `S`) is a planned 5b-class
  hardening; full same-user protection (a process running as you cannot read `S`) arrives with the
  **Z7 broker**. The cryptographically-bound **FIDO2 `PolicySigned`** path (no secret in agent memory)
  is **Z6**.
- The master NV index is `0x018E7E7F` (sibling of the epoch `0x018E7E7E`).
- Milestone-1 re-proves `PolicySecret` on every signature; the hardware ticket-TTL optimization
  (`PolicyTicket`) is a follow-up that mainly pays off once `S` becomes an expensive FIDO2 assertion.
