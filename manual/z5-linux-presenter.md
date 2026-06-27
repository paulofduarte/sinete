# Z5 manual checklist — Linux presence presenter (PR B)

The presenter channels can't run in CI (no logind session, no tty/display, no pinentry/X server), so
the prompt + failure paths are verified here on a real Linux box. Build the agent and point a client
at its socket:

```sh
zig build
SOCK=/tmp/sinete-pb.sock
zig-out/bin/sinete agent --sock "$SOCK" &
```

Drive signatures through the agent (any registry key) from each kind of session and observe the
prompt / refusal. The orchestrator picks the channel from the peer's logind session.

## Gesture selection

- [ ] With **no fingerprint device** (fprintd unreachable / no reader), a cold-window sign shows a
      **confirm** (not a hard refusal): `[y/n]` on a terminal session, or a dialog on a graphical one.
- [ ] With a **reachable device + an enrolled finger**, a cold-window sign runs the **fingerprint
      verify** (fprintd).
- [ ] A reachable device with **no enrolled finger** routes to a **confirm** (not the verify): the
      orchestrator checks `ListEnrolledFingers` up front, so an enrolled-less reader does not start a
      verify that could only fail.

## Terminal channel (pure-Zig termios) — the 3 tty scenarios

- [ ] **Local console / KMS tty** (Ctrl-Alt-F3): a cold sign prints the `[y/n]` prompt on that tty;
      `y` approves, `n`/Esc deny. Enter does **not** approve.
- [ ] **ssh into the box**: a presence-gated sign is refused (remote gate) and the reason message
      appears on the ssh pts; `ssh-add -l` over the forwarded agent still lists keys.
- [ ] The prompt restores the terminal (no stuck raw mode) after a decision or Ctrl-C.

## Graphical channel — pinentry (native)

- [ ] With **pinentry installed**, a cold sign on the desktop pops the **native** pinentry dialog
      (gtk/qt/gnome3 per the system `pinentry` symlink); Approve signs, Deny refuses.
- [ ] `SINETE_PINENTRY=$(command -v pinentry) zig-out/bin/sinete _pinentry-selftest` prints
      `PINENTRY SELFTEST PASS`.

## Graphical channel — built-in X11 modal (pinentry absent)

Temporarily make pinentry unavailable (e.g. `PATH` without it, or no pinentry package) so the modal
is exercised:

- [ ] On **Xorg**, a cold sign draws sinete's own dark modal ("Approve signing…?") with **Approve**
      (green) / **Deny** (red) buttons, readable Spleen text, and a keyboard/pointer grab.
- [ ] **Click Approve** signs; **click Deny** (or press **Esc**) refuses. The window is modal
      (other windows don't take input while it's up).
- [ ] On a **Wayland** session with **XWayland** present, the X11 modal appears (via XWayland).

## Graphical channel — built-in Wayland modal (no pinentry, no XWayland)

On a wlroots compositor (sway / Hyprland / niri) with **XWayland disabled** and **pinentry absent**,
the built-in Wayland layer-shell modal is exercised:

- [ ] A cold sign draws sinete's own modal as a `zwlr_layer_shell_v1` overlay (top-most), with an
      **exclusive keyboard grab** so it is truly modal.
- [ ] **Click Approve** signs; **click Deny** (or press **Esc**) refuses.
- [ ] Compositors **without** `zwlr_layer_shell_v1` (notably GNOME/Mutter) are not covered by this
      path — but they ship XWayland, so the X11 modal covers them. A session with neither
      layer-shell nor XWayland falls back to the log.
- [ ] Killing the X server while the modal is up fails closed (the sign is refused, agent survives).

## Refusal/failure messages (non-blocking)

`showError` runs inline on the sign path (before `SSH_AGENT_FAILURE`), so it must not block:

- [ ] **Terminal/ssh** refusal: the reason is written to the peer's tty (quick, non-blocking) and
      logged.
- [ ] **Graphical** refusal: the reason is **logged only** (no GUI message modal) so the client
      command returns promptly. (A non-blocking desktop notification could be added later; a blocking
      GUI error dialog is intentionally avoided here.)

## Notes / known intermediate state

- The X11 modal places the window at a fixed offset (no screen-geometry query yet); it is centered
  in a later refinement.
- Keyboard approval in the GUI is intentionally click-only (y/n keycodes are layout-dependent and
  need GetKeyboardMapping, deferred with PIN input); Escape/closing always deny.
- A graphical session with **neither pinentry nor XWayland** is covered by the built-in Wayland
  layer-shell modal (above), provided the compositor implements `zwlr_layer_shell_v1`; a session with
  none of pinentry, XWayland, or layer-shell falls back to the log.
