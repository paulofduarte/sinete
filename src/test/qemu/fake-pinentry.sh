#!/bin/sh
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Fake pinentry for the QEMU distro e2e matrix (src/test/qemu/full). It speaks the
# minimal Assuan protocol go-pinentry expects and always returns a fixed PIN, so the
# guest can exercise the Linux master-key crypto path (_enclave-check / master
# provisioning) non-interactively. NOT for production — wired in only via the guest's
# gpg-agent.conf (see full/driver.sh: fake_pinentry_on). The variant tests still drive
# the REAL pinentry programs.

printf 'OK sinete fake-pinentry\n'
while IFS= read -r line; do
  case "$line" in
  GETPIN)
    printf 'D 1234\n'
    printf 'OK\n'
    ;;
  BYE)
    printf 'OK\n'
    exit 0
    ;;
  *) printf 'OK\n' ;;
  esac
done
