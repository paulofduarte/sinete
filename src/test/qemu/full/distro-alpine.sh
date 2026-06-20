# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Alpine (musl, elogind) shim for the e2e matrix. Sourced by cloud-init (distro_provision)
# and by the shared driver.sh (distro_expose_pinentry). POSIX sh.
# shellcheck shell=sh

# shellcheck disable=SC2034  # consumed by driver.sh via the sourced shim
DISTRO=alpine

# distro_provision installs the test deps + elogind/dbus/PAM, arranges a LOCAL autologin
# session, then swaps the TPM-less linux-virt kernel for linux-lts and reboots into it.
# The driver runs on that second boot (its TPM gate skips the first). cloud-init does not
# re-run after the reboot, but the inittab autologin and rc-update'd services persist.
distro_provision() {
  # Fail hard (don't reach the .provisioned marker) if package install fails, so the
  # driver's wait fails fast instead of running scenarios with missing dependencies.
  if ! { apk update && apk add bash elogind elogind-openrc dbus dbus-openrc linux-pam \
    shadow-login util-linux expect openssh pinentry pinentry-tty linux-lts; }; then
    echo "FATAL: apk provisioning failed"
    return 1
  fi
  # PAM: create elogind sessions on local login AND over ssh.
  for f in /etc/pam.d/base-session /etc/pam.d/login /etc/pam.d/sshd; do
    [ -f "$f" ] && { grep -q pam_elogind "$f" || echo "session optional pam_elogind.so" >>"$f"; }
  done
  # sshd: root PUBKEY login (no password) + PAM (so the ssh session is an elogind
  # session, Remote=yes).
  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
  grep -q '^PermitRootLogin ' /etc/ssh/sshd_config || echo 'PermitRootLogin prohibit-password' >>/etc/ssh/sshd_config
  grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >>/etc/ssh/sshd_config
  grep -q '^UsePAM yes' /etc/ssh/sshd_config || echo 'UsePAM yes' >>/etc/ssh/sshd_config
  ssh-keygen -A
  rc-update add dbus
  rc-update add elogind
  rc-update add sshd
  rc-service dbus start
  rc-service elogind start
  rc-service sshd start
  # autologin root on ttyS0 via util-linux agetty → PAM login → pam_elogind session.
  sed -i '/ttyS0/d' /etc/inittab
  echo 'ttyS0::respawn:/sbin/agetty --autologin root -L 115200 ttyS0 vt100' >>/etc/inittab
  printf '[ -f /root/driver.sh ] && bash /root/driver.sh\n' >/root/.profile
  cp /root/.profile /root/.bash_profile
  touch /root/.provisioned
  # Boot the TPM-capable lts kernel next time (linux-virt has no TPM driver).
  update-extlinux 2>/dev/null || true
  if [ -f /boot/extlinux.conf ]; then
    sed -i 's/^DEFAULT .*/DEFAULT lts/' /boot/extlinux.conf
    grep -q '^DEFAULT lts' /boot/extlinux.conf || sed -i '1iDEFAULT lts' /boot/extlinux.conf
  fi
  sync
  reboot
}

# Alpine ships `pinentry` (the ncurses one — there is no pinentry-curses binary) and
# `pinentry-tty`. pin_hide / pin_restore come from driver.sh.
distro_expose_pinentry() { # curses|tty|none|all
  for p in pinentry-curses pinentry-tty pinentry; do pin_restore "$p"; done
  case "$1" in
  curses) pin_hide pinentry-tty ;; # leaves `pinentry` (ncurses)
  tty) pin_hide pinentry ;;        # leaves pinentry-tty
  none)
    pin_hide pinentry
    pin_hide pinentry-tty
    ;; # x/term fallback
  all) : ;;
  esac
}

distro_pinentry_curses() { echo pinentry; }
