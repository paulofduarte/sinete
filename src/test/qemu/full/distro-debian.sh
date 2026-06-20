# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Debian (glibc, systemd-logind) shim for the e2e matrix. Sourced both by cloud-init
# (distro_provision) and by the shared driver.sh (distro_expose_pinentry). POSIX sh.
# shellcheck shell=sh

# shellcheck disable=SC2034  # consumed by driver.sh via the sourced shim
DISTRO=debian

# distro_provision installs the test deps, ensures sshd, and arranges a LOCAL autologin
# session on the serial console that launches the driver. The Debian cloud kernel
# already has the TPM driver, so no kernel swap is needed (unlike Alpine).
distro_provision() {
  export DEBIAN_FRONTEND=noninteractive
  ok=
  for _ in 1 2 3; do
    if apt-get update -qq && apt-get install -y -qq pinentry-curses pinentry-tty expect openssh-server openssh-client; then
      ok=1
      break
    fi
    sleep 5
  done
  # Fail hard (don't mark provisioned) so the driver's .provisioned wait fails fast
  # rather than running scenarios with missing dependencies.
  [ -n "$ok" ] || {
    echo "FATAL: apt provisioning failed after retries"
    return 1
  }
  ssh-keygen -A >/dev/null 2>&1
  systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null || true
  mkdir -p /etc/systemd/system/serial-getty@ttyS0.service.d
  cat >/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf <<-EOF
		[Service]
		ExecStart=
		ExecStart=-/sbin/agetty --autologin root --noclear --keep-baud 115200,57600,38400,9600 %I vt220
	EOF
  printf '[ -f /root/driver.sh ] && bash /root/driver.sh\n' >/root/.bash_profile
  cp /root/.bash_profile /root/.profile
  touch /root/.provisioned
  systemctl daemon-reload
  systemctl restart serial-getty@ttyS0 # → autologin root → .bash_profile → driver.sh
}

# distro_expose_pinentry leaves ONLY the requested pinentry discoverable on PATH, so the
# selection sinete makes is unambiguous. Debian ships pinentry-curses + pinentry-tty (and
# an alternatives `pinentry`). pin_hide / pin_restore come from driver.sh.
distro_expose_pinentry() { # curses|tty|none|all
  for p in pinentry-curses pinentry-tty pinentry; do pin_restore "$p"; done
  case "$1" in
  curses)
    pin_hide pinentry-tty
    pin_hide pinentry
    ;;
  tty)
    pin_hide pinentry-curses
    pin_hide pinentry
    ;;
  none)
    pin_hide pinentry-curses
    pin_hide pinentry-tty
    pin_hide pinentry
    ;;
  all) : ;;
  esac
}

distro_pinentry_curses() { echo pinentry-curses; }
