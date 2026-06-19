#!/bin/busybox sh
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Fake pinentry for the QEMU integration test. It speaks the minimal Assuan protocol
# go-pinentry expects and always returns a fixed PIN, so the non-interactive guest can
# exercise the Linux master-key PIN path (config writes / _enclave-check) without a
# real pinentry or terminal. NOT for production — wired in only via the guest's
# gpg-agent.conf (see init.sh).

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
