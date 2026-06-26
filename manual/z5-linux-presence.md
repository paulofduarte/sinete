# Z5a manual checklist — Linux presence (fprintd) + remote-refuse (logind)

Z5a gates each cold-window signature behind a **fingerprint** (fprintd over D-Bus) and **refuses
remote/SSH-forwarded sessions** (logind). Both need real daemons, so unit tests cover only the pure
D-Bus marshaling and the remote-gate logic (with fakes); the D-Bus *wire* is validated against a
real `dbus-daemon` by `scripts/dbus-it.sh`. The fprintd and logind *behaviours* are checked here.

Keys in 5a are still presence-**less in the TPM** (Z4 empty-auth): the fingerprint gates clients
that go *through the agent*, but a same-user process can still sign a key file directly. The TPM
`authPolicy` binding that closes that hole is **5b**.

## Automated (no fingerprint hardware)

- [ ] `scripts/dbus-it.sh` prints `ALL OK` — SASL EXTERNAL + Hello round-trip against a real
      `dbus-daemon` (proves the pure-Zig D-Bus marshaling/alignment).
- [ ] `sinete _dbus-selftest` prints `DBUS SELFTEST PASS` on a box with a system bus.

## fprintd (needs an enrolled fingerprint, or the virtual device)

On a machine with a fingerprint reader and an enrolled finger (`fprintd-enroll`):

```sh
sinete agent &                      # $XDG_RUNTIME_DIR/sinete/agent.sock
SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/sinete/agent.sock ssh-add -l    # lists keys, no prompt
# first signature in a cold window prompts for a fingerprint:
echo hi | SSH_AUTH_SOCK=... ssh-keygen -Y sign -f <(ssh-add -L) -n test /dev/stdin
```

- [ ] The first signature triggers the fingerprint reader; a matching finger completes the signature.
- [ ] A non-matching finger (to exhaustion) refuses the signature (agent returns FAILURE).
- [ ] Within the idle TTL, subsequent signatures are silent (no prompt).
- [ ] With **no reader / no enrolled finger**, a signature is refused fail-closed (never silently
      allowed).

Without hardware, drive fprintd's **virtual device** (`umockdev` / `FP_DRIVER=virtual_device`) to
script `verify-match`, `verify-no-match`, and a missing device, and confirm the same outcomes.

## logind remote-refuse

- [ ] From a **local console / tty** session, a presence-gated signature is allowed (the session's
      `Remote` property is false).
- [ ] Over an **`ssh` login** to the same box, a signature through the same agent is **refused**
      (`Remote` true) — "user presence can't be confirmed over a remote session".
- [ ] `ssh-add -l` / `ssh-add -L` still work over a forwarded/remote connection (only *signatures*
      are refused remotely, not identity listing).
- [ ] A connection from a **different uid** is refused (uid mismatch).

## Notes
- The system bus is reached at the well-known `/var/run/dbus/system_bus_socket`
  (`$DBUS_SYSTEM_BUS_ADDRESS` is not consulted for the system bus).
- The fingerprint verify blocks the agent's single thread while waiting (like the macOS Touch ID
  prompt and the TPM sign); a stuck daemon is bounded by the socket read timeout, fail-closed.
- Sessionless callers (cron, some containers) have no logind session and are therefore refused —
  a documented v1 limitation.
