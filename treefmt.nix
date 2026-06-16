# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0

# treefmt: one `nix fmt` for the whole tree. Formatters only — linting is
# golangci-lint (see .golangci.yml). Markdown and binary assets are left alone.
{ ... }:
{
  projectRootFile = "flake.nix";

  programs = {
    gofumpt.enable = true; # Go
    nixfmt.enable = true; # Nix
    shfmt.enable = true; # shell scripts
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
