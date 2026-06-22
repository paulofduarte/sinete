# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# OPTIONAL dev environment. The repo builds with `zig build` alone — devenv only
# provides a pinned zig (nixpkgs 26.05 → 0.16.0) plus shellcheck for the hooks.
# If you have zig installed another way, you do NOT need devenv or nix at all:
# just `zig build` and run `git config core.hooksPath .githooks` once.
{ pkgs, ... }:
{
  packages = [
    pkgs.zig # 0.16.0 on nixpkgs 26.05
    pkgs.shellcheck # only used by the pre-commit hook (optional)

    # `zig build coverage` builds kcov (roc-lang/zig-kcov) via Zig and links these system
    # libraries. nixpkgs pins a recent elfutils, whose libdw parses Zig's DWARF correctly --
    # the distro-packaged libdw on older systems does not, so nix is the reliable toolchain.
    pkgs.pkg-config
    pkgs.elfutils # libelf + libdw
    pkgs.curl
    pkgs.zlib
    pkgs.libcxx
  ];

  enterShell = ''
    git config core.hooksPath .githooks 2>/dev/null || true
    echo "sinete (zig) devenv — zig $(zig version); hooks → .githooks"
  '';
}
