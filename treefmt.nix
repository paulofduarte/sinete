# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0

# treefmt: one `nix fmt` for the whole tree. Formatters only — linting is
# golangci-lint (Go) and swiftlint (Swift), both local (dev shell) + CI hooks.
# Markdown and binary assets are left alone.
{ pkgs, ... }:
{
  projectRootFile = "flake.nix";

  programs = {
    gofumpt.enable = true; # Go
    nixfmt.enable = true; # Nix
    shfmt.enable = true; # shell scripts
  };

  # Swift (sinete-ui) via swiftformat from nixpkgs — self-contained (no Apple
  # toolchain), reads .swiftformat. Linting is swiftlint (see flake.nix hooks).
  settings.formatter.swiftformat = {
    command = "${pkgs.swiftformat}/bin/swiftformat";
    includes = [ "*.swift" ];
  };

  settings.global.excludes = [
    "*.lock"
    "*.md"
    "*.webp"
    "*.png"
    "*.ico"
    "*.icns"
    "*.entitlements"
    "*.plist"
    "*.provisionprofile"
    "result"
    "vendor/*"
    ".direnv/*"
  ];
}
