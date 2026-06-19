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
                # The Go module lives under src/; run golangci-lint from there.
                entry = "${pkgs.writeShellScript "golangci-lint-src" ''
                  cd src && exec ${pkgs.golangci-lint}/bin/golangci-lint run
                ''}";
                pass_filenames = false;
                extraPackages = [ pkgs.go ];
              };
            }
            // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
              # swiftlint needs SourceKit; the .swift sources are macOS-only anyway. Run
              # from src/ (where ui/SineteUI.swift now lives), like golangci-lint.
              swiftlint = {
                enable = true;
                name = "swiftlint";
                entry = "${pkgs.writeShellScript "swiftlint-src" ''
                  cd src && exec ${pkgs.swiftlint}/bin/swiftlint lint --strict
                ''}";
                files = "\\.swift$";
                pass_filenames = false;
              };
            };
        };

        # Where `nix run .#bundle` writes the signed .app, relative to $PWD — kept out
        # of the repo root (#13). Single source of truth for the bundle app + e2e-macos.
        bundleRelPath = "dist/sinete.app";

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
            repo="${self}" # flake source (repo root); the bundle inputs live under src/
            goBin="${self.packages.${system}.default}/bin/sinete"
            app="$PWD/${bundleRelPath}"
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
            cp -f "$repo/src/launchd/me.paulofduarte.sinete.agent.plist" \
              "$app/Contents/Library/LaunchAgents/me.paulofduarte.sinete.agent.plist"

            # SwiftUI helper, compiled with Apple's toolchain (impure).
            /usr/bin/xcrun swiftc -parse-as-library -O "$repo/src/ui/SineteUI.swift" \
              -o "$app/Contents/MacOS/sinete-ui"

            # App icon (Liquid Glass) via actool, if available.
            icon_keys=""
            if actool="$(/usr/bin/xcrun --find actool 2>/dev/null)"; then
              mkdir -p "$app/Contents/Resources"
              "$actool" "$repo/src/assets/AppIcon.icon" --compile "$app/Contents/Resources" \
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
              --entitlements "$repo/sinete.entitlements" "$app"

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

        # `nix run .#e2e-macos -- <profile>`: the on-device Secure-Enclave acceptance
        # test. It builds + signs the bundle (via the bundle app) and then runs
        # `sinete _enclave-check` from it (with a Touch ID prompt). The bundle build is
        # impure (codesign / xcrun / your keychain identity), so this chains the bundle
        # app at runtime rather than depending on a pure derivation — and it needs the
        # same provisioning profile. Local-only: the SE can't be reached from a bare
        # binary and can't be emulated, so there is no CI equivalent.
        e2eMacosApp = pkgs.writeShellApplication {
          name = "sinete-e2e-macos";
          text = ''
            if [ $# -lt 1 ]; then
              echo "usage: nix run .#e2e-macos -- <path-to.provisionprofile>" >&2
              exit 1
            fi
            ${bundleApp}/bin/sinete-bundle "$@"
            exec "./${bundleRelPath}/Contents/MacOS/sinete" _enclave-check
          '';
        };

        # `nix run .#e2e-linux`: the Linux TPM backend acceptance test — boot a Linux
        # kernel + software TPM (swtpm) in QEMU and run the enclave backend against
        # /dev/tpmrm0. The same script the CI `integration` job runs; invoke from a repo
        # checkout (its CWD). Available on every system (the x86_64 guest runs under TCG
        # on an aarch64 macOS box, KVM on an x86_64 Linux host).
        e2eLinuxApp = pkgs.writeShellApplication {
          name = "sinete-e2e-linux";
          runtimeInputs = [
            pkgs.go
            pkgs.nix
            pkgs.bash
            pkgs.coreutils
            pkgs.findutils
            pkgs.gnugrep
            pkgs.gzip
            pkgs.cpio
          ];
          text = "exec bash src/test/qemu/run.sh";
        };
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "sinete";
          version = "0.0.0-dev";
          # The Go module lives under src/ (the repo root holds flake/docs/ui/test).
          src = ./src;

          # Vendor hash of the Go module set. go.mod pins facebookincubator/sks to the
          # paulofduarte/sks fork (the `integration` branch) via a `replace`, until the
          # upstream PRs (#9/#10/#11) land. Regenerate with `nix build` if go.mod/go.sum
          # change; it prints the new hash.
          vendorHash = "sha256-pBAEZpf1eJzojCS6jUcw7dfZ/5SYcR8a2kujwBWzE5I=";

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

        # `nix run` works on every system: on Linux it runs the nix-built binary
        # directly (no wrapper — Linux needs no signing); on macOS it goes through
        # signRunApp, which signs the binary with the SE entitlements first (a bare
        # binary is rejected by the Secure Enclave otherwise). `nix build` produces just
        # the binary on both. `nix run .#e2e-linux` is the Linux acceptance test (all
        # systems). The remaining apps are macOS-only (the Apple toolchain):
        # `nix run .#bundle -- <profile>` builds the signed .app, `nix run .#e2e-macos`
        # the on-device SE acceptance test.
        apps = {
          default = {
            type = "app";
            program =
              if pkgs.stdenv.isDarwin then
                "${signRunApp}/bin/sinete-sign-run"
              else
                "${self.packages.${system}.default}/bin/sinete";
          };
          e2e-linux = {
            type = "app";
            program = "${e2eLinuxApp}/bin/sinete-e2e-linux";
          };
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
          bundle = {
            type = "app";
            program = "${bundleApp}/bin/sinete-bundle";
          };
          e2e-macos = {
            type = "app";
            program = "${e2eMacosApp}/bin/sinete-e2e-macos";
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
