{
  description = "sinete — hardware-backed SSH agent (Secure Enclave / TPM)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
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

          # TODO: replace with the real hash after the first build.
          # `nix build` will fail and print the expected vendorHash; paste it here.
          vendorHash = pkgs.lib.fakeHash;

          # sks talks to the platform secure element via cgo.
          env.CGO_ENABLED = "1";

          # Darwin needs the Security / LocalAuthentication frameworks for the
          # Secure Enclave. (On recent nixpkgs the SDK is implicit — verify and
          # trim this list against the pinned nixpkgs.)
          buildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin (
            with pkgs.darwin.apple_sdk.frameworks;
            [
              Security
              CoreFoundation
              LocalAuthentication
            ]
          );

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
