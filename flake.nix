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

        # Pre-commit hooks, installed into .git/hooks on entering the dev shell
        # and run as a `nix flake check`. golangci-lint needs the Go/cgo toolchain.
        pre-commit = git-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            treefmt = {
              enable = true;
              package = treefmtEval.config.build.wrapper;
            };
            golangci-lint = {
              enable = true;
              extraPackages = [ pkgs.go ];
            };
            shellcheck.enable = true;
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
          vendorHash = "sha256-X6EqNQMGza2+u1azxfL54siUBuFlZBho7bHR5aM6y38=";

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
          inherit pre-commit;
        };

        devShells.default = pkgs.mkShell {
          inherit (pre-commit) shellHook;
          packages = [
            pkgs.go
            pkgs.gopls
            pkgs.golangci-lint
            treefmtEval.config.build.wrapper
          ]
          ++ pre-commit.enabledPackages;
        };
      }
    );
}
