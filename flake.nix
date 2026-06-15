{
  description = "sinete — hardware-backed SSH agent (Secure Enclave / TPM)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "sinete";
          version = "0.0.0-dev";
          src = ./.;

          # Vendor hash of the Go module set (incl. the paulofduarte/sks fork).
          # Regenerate with `nix build` if go.mod/go.sum change; it prints the new hash.
          vendorHash = "sha256-18hUroLOoT+U/C0MpT0cVmwnxVJUjdFSfFPeMGFl0EY=";

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

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.go
            pkgs.gopls
            pkgs.golangci-lint
          ];
        };
      }
    );
}
