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
        # golangci-lint and swiftlint — both need a toolchain the flake-check
        # sandbox lacks (the Go module graph; SourceKit for swiftlint).
        pre-commit-local = git-hooks.lib.${system}.run {
          src = ./.;
          hooks =
            sandboxHooks
            // {
              golangci-lint = {
                enable = true;
                extraPackages = [ pkgs.go ];
              };
            }
            // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
              # swiftlint needs SourceKit; the .swift sources are macOS-only anyway.
              swiftlint = {
                enable = true;
                name = "swiftlint";
                entry = "${pkgs.swiftlint}/bin/swiftlint lint --strict";
                files = "\\.swift$";
                pass_filenames = false;
              };
            };
        };

        # `nix run .#bundle -- <profile>`: assemble + sign sinete.app. Folds the
        # old scripts/bundle-and-sign.sh into a flake step. swiftc (for sinete-ui),
        # actool, and codesign use Apple's toolchain (impure: nixpkgs swift is too
        # old for the macOS 26 SwiftUI module, and signing needs your keychain
        # identity) -- driven by the flake rather than a standalone script.
        bundleApp = pkgs.writeShellApplication {
          name = "sinete-bundle";
          runtimeInputs = [ pkgs.coreutils ];
          text = ''
            if [ $# -lt 1 ]; then
              echo "usage: nix run .#bundle -- <path-to.provisionprofile>" >&2
              exit 1
            fi
            profile="$1"
            identity="''${SINETE_SIGN_IDENTITY:-Apple Development: Paulo Duarte (P6K8K4X996)}"
            src="${self}"
            goBin="${self.packages.${system}.default}/bin/sinete"
            app="$PWD/sinete.app"
            bundle_id="me.paulofduarte.sinete"

            if [ ! -f "$profile" ]; then
              echo "provisioning profile not found: $profile" >&2
              exit 1
            fi

            rm -rf "$app"
            mkdir -p "$app/Contents/MacOS" "$app/Contents/Library/LaunchAgents"
            cp -f "$goBin" "$app/Contents/MacOS/sinete"
            chmod u+w "$app/Contents/MacOS/sinete"
            cp -f "$profile" "$app/Contents/embedded.provisionprofile"
            cp -f "$src/launchd/me.paulofduarte.sinete.agent.plist" \
              "$app/Contents/Library/LaunchAgents/me.paulofduarte.sinete.agent.plist"

            # SwiftUI helper, compiled with Apple's toolchain (impure).
            /usr/bin/xcrun swiftc -parse-as-library -O "$src/ui/SineteUI.swift" \
              -o "$app/Contents/MacOS/sinete-ui"

            # App icon (Liquid Glass) via actool, if available.
            icon_keys=""
            if actool="$(/usr/bin/xcrun --find actool 2>/dev/null)"; then
              mkdir -p "$app/Contents/Resources"
              "$actool" "$src/assets/AppIcon.icon" --compile "$app/Contents/Resources" \
                --app-icon AppIcon --output-partial-info-plist "$(mktemp)" \
                --platform macosx --minimum-deployment-target 26.0 >/dev/null 2>&1 || true
              if [ -f "$app/Contents/Resources/Assets.car" ]; then
                icon_keys="$(printf '    <key>CFBundleIconFile</key><string>AppIcon</string>\n    <key>CFBundleIconName</key><string>AppIcon</string>')"
              fi
            fi

            {
              echo '<?xml version="1.0" encoding="UTF-8"?>'
              echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
              echo '<plist version="1.0">'
              echo '<dict>'
              echo '    <key>CFBundleExecutable</key><string>sinete</string>'
              printf '    <key>CFBundleIdentifier</key><string>%s</string>\n' "$bundle_id"
              echo '    <key>CFBundleName</key><string>sinete</string>'
              echo '    <key>CFBundlePackageType</key><string>APPL</string>'
              echo '    <key>CFBundleShortVersionString</key><string>0.0.0-dev</string>'
              echo '    <key>LSUIElement</key><true/>'
              if [ -n "$icon_keys" ]; then printf '%s\n' "$icon_keys"; fi
              echo '</dict>'
              echo '</plist>'
            } >"$app/Contents/Info.plist"

            # Sign inside-out: the unentitled helper first, then the bundle (which
            # signs the main `sinete` with the SE entitlements and seals all).
            /usr/bin/codesign --force --sign "$identity" "$app/Contents/MacOS/sinete-ui"
            /usr/bin/codesign --force --sign "$identity" \
              --entitlements "$src/sinete.entitlements" "$app"

            echo "--- signature / profile ---"
            /usr/bin/codesign -dvvv "$app" 2>&1 | grep -iE "TeamIdentifier|provision" || true

            # Re-register with LaunchServices so Finder shows the rebuilt bundle's
            # icon instead of a cached one (a shell-side rm+recreate at the same
            # path doesn't notify LaunchServices, unlike a delete in Finder).
            lsregister="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
            if [ -x "$lsregister" ]; then "$lsregister" -f "$app" >/dev/null 2>&1 || true; fi

            echo "built + signed: $app"
          '';
        };

        # `nix run` (the default app): sign the nix-built bare binary with the same
        # identity + entitlements as the bundle, then exec it with any args. For
        # quick non-SE checks (list/config/present); SE ops still need the signed
        # .app (a bare binary can't carry the provisioning profile).
        signRunApp = pkgs.writeShellApplication {
          name = "sinete-sign-run";
          runtimeInputs = [ pkgs.coreutils ];
          text = ''
            identity="''${SINETE_SIGN_IDENTITY:-Apple Development: Paulo Duarte (P6K8K4X996)}"
            out="$(mktemp -d)/sinete"
            cp "${self.packages.${system}.default}/bin/sinete" "$out"
            chmod u+w "$out"
            /usr/bin/codesign --force --sign "$identity" \
              --entitlements "${self}/sinete.entitlements" "$out"
            exec "$out" "$@"
          '';
        };
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "sinete";
          version = "0.0.0-dev";
          src = ./.;

          # Vendor hash of the Go module set (sks is upstream facebookincubator/sks;
          # the paulofduarte/sks fork was dropped in v2, so there's no replace).
          # Regenerate with `nix build` if go.mod/go.sum change; it prints the new hash.
          vendorHash = "sha256-1t0H3IEj5FUFS9+hjbfzSDQqt5ERGxBStBbKWTSwL54=";

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

        # macOS only (signing needs the Apple toolchain). `nix run` signs + runs
        # the bare binary; `nix run .#bundle -- <profile>` builds the signed .app.
        apps = pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
          default = {
            type = "app";
            program = "${signRunApp}/bin/sinete-sign-run";
          };
          bundle = {
            type = "app";
            program = "${bundleApp}/bin/sinete-bundle";
          };
        };

        checks = {
          formatting = treefmtEval.config.build.check self;
          pre-commit = pre-commit-check;
        };

        devShells.default = pkgs.mkShell {
          inherit (pre-commit-local) shellHook;
          # OpenSSL is needed by the go-tpm simulator (cgo, the MS-TPM 2.0 reference)
          # that backs the `tpmsim`-tagged NV-counter test. As a buildInput it puts
          # the headers/libs on cgo's search path, so `go test -tags tpmsim` builds
          # without manual CGO_CFLAGS. (Normal, untagged builds don't pull it in.)
          buildInputs = [ pkgs.openssl ];
          packages = [
            pkgs.go
            pkgs.gopls
            pkgs.golangci-lint
            treefmtEval.config.build.wrapper
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [ pkgs.swiftlint ]
          ++ pre-commit-local.enabledPackages;
        };
      }
    );
}
