# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
{
  description = "sinete — hardware-backed SSH agent (Secure Enclave / TPM)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      treefmt-nix,
      git-hooks,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        # One `nix fmt` for every tree; also a `nix flake check` formatting gate.
        treefmtEval = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;

        # Network-free hooks, safe to run inside the `nix flake check` sandbox.
        sandboxHooks = {
          treefmt = {
            enable = true;
            package = treefmtEval.config.build.wrapper;
          };
          shellcheck.enable = true;
          # SPDX / license compliance for the whole tree (inline headers +
          # REUSE.toml for files that don't carry one). reuse.software.
          reuse = {
            enable = true;
            name = "reuse";
            entry = "${pkgs.reuse}/bin/reuse lint";
            pass_filenames = false;
          };
        };

        # The sandboxed flake-check gate omits golangci-lint: it would fetch the
        # Go module graph, and the build sandbox has no network. CI runs
        # golangci-lint in the dev shell instead (see .github/workflows).
        pre-commit-check = git-hooks.lib.${system}.run {
          src = ./.;
          hooks = sandboxHooks;
        };

        # Local hooks (installed into .git/hooks on entering the dev shell) add
        # golangci-lint — the dev machine has the Go module cache and a toolchain.
        pre-commit-local = git-hooks.lib.${system}.run {
          src = ./.;
          hooks = sandboxHooks // {
            golangci-lint = {
              enable = true;
              extraPackages = [ pkgs.go ];
            };
          };
        };
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "sinete";
          version = "0.0.0-dev";
          src = ./.;

          # Vendor hash of the Go module set (incl. the paulofduarte/sks fork).
          # Regenerate with `nix build` if go.mod/go.sum change; it prints the new hash.
          vendorHash = "sha256-giOz1di8xBXD3NUM22Uog9ldN3Ux3ZSwkz6S+IfKPOc=";

          # sks talks to the platform secure element via cgo.
          env.CGO_ENABLED = "1";

          # On nixpkgs 26.05 the Darwin SDK (Security / LocalAuthentication, etc.)
          # is provided implicitly by stdenv, so no explicit framework buildInputs
          # are needed — the legacy `darwin.apple_sdk.frameworks` stubs were removed.

          meta = {
            description = "Hardware-backed SSH agent (Secure Enclave / TPM)";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "sinete";
          };
        };

        formatter = treefmtEval.config.build.wrapper;

        checks = {
          formatting = treefmtEval.config.build.check self;
          pre-commit = pre-commit-check;
        };

        devShells.default = pkgs.mkShell {
          inherit (pre-commit-local) shellHook;
          packages = [
            pkgs.go
            pkgs.gopls
            pkgs.golangci-lint
            treefmtEval.config.build.wrapper
          ]
          ++ pre-commit-local.enabledPackages;
        };
      }
    );
}
