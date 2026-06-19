// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Command sinete is a hardware-backed SSH key manager and agent. Private keys
// are generated in, and never leave, the platform secure element; only public
// keys are exported. The agent advertises every created key and signs with them
// like a normal ssh-agent, gating user presence at sign time (Touch ID once,
// then silent for a per-key TTL).
package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/paulofduarte/sinete/internal/agent"
	"github.com/paulofduarte/sinete/internal/enclave"
	"github.com/paulofduarte/sinete/internal/install"
	"github.com/paulofduarte/sinete/internal/loginitem"
	"github.com/paulofduarte/sinete/internal/presence"
	"github.com/paulofduarte/sinete/internal/registry"
	"golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

func main() {
	// Pin the main goroutine to the main OS thread up front: the agent presents
	// the sign-time Touch ID prompt here, and macOS only draws it from the main
	// thread.
	runtime.LockOSThread()

	// launchd may spawn the bundled agent with no arguments (its plist uses
	// BundleProgram, and ProgramArguments is not always honoured); XPC_SERVICE_NAME
	// identifies our job, so normalise that launch to `agent`.
	if len(os.Args) < 2 && os.Getenv("XPC_SERVICE_NAME") == loginitem.AgentLabel {
		os.Args = append(os.Args, "agent")
	}

	// A Finder double-click launches this (the bundle's main, entitled executable)
	// with no arguments and no controlling terminal; hand off to the SwiftUI panel.
	launchUIIfDoubleClicked()

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmds := map[string]func([]string) error{
		"generate":  cmdGenerate,
		"list":      cmdList,
		"export":    cmdExport,
		"ssh-setup": cmdSshSetup,
		"delete":    cmdDelete,
		"agent":     cmdAgent,
		"service":   cmdService,
		"install":   cmdInstall,
		"uninstall": cmdUninstall,
		"status":    cmdStatus,
		"sign":      cmdSign,
		"present":   cmdPresent,
		"config":    cmdConfig,
		// unlisted diagnostic for the signed-registry enclave layer
		"_enclave-check": cmdEnclaveCheck,
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		usage()
		os.Exit(2)
	}
	if err := cmd(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "sinete: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: sinete <command> [args]

sinete manages the secure-element key storage:

  generate <name>   create an enclave key and print its public key
  list              list created keys (name, type, fingerprint)
  export <name>     print a key's public key
  ssh-setup <name>  write the .pub + print ssh/git config to use the key
  delete <name>     delete a key from the secure element (requires presence)
  config            presence config: show | get | set | unset | key <name> …
  status            show install + key state (--json for the app UI)
  agent             run the ssh-agent (foreground)

The agent advertises every created key, so ssh/git use them automatically once
SSH_AUTH_SOCK (or IdentityAgent) points at it. The first signature with a key
prompts for Touch ID; further signatures are silent until its presence window
(TTL) lapses. ssh-add -l lists them; ssh-add -d/-D forgets a key's window.`)
}

// openConfig loads the signed config (registry.json). Reads reflect exactly what
// the agent enforces: the verified config, or strict mode (authenticate every
// signature) when it is absent or cannot be verified.
func openConfig() (*registry.Config, error) {
	path, err := registry.ConfigPath()
	if err != nil {
		return nil, err
	}
	cfg, trusted, err := registry.OpenConfig(path, enclave.ConfigCrypto{})
	if err != nil {
		return nil, err
	}
	if !trusted {
		fmt.Fprintln(os.Stderr, "warning: the signed config could not be verified; falling back to strict mode (every signature prompts). Re-run `sinete install` or `sinete config set …` to rewrite it.")
	}
	return cfg, nil
}

// saveConfig signs and writes the config (a Touch ID prompt). The master key is
// created on the first write if it does not exist yet.
func saveConfig(cfg *registry.Config) error {
	// Creating the master key needs no presence; signing with it does — so the
	// first `sinete config` on a fresh install creates it, then signs.
	if err := enclave.EnsureMaster(); err != nil {
		return fmt.Errorf("ensure master key: %w", err)
	}
	return cfg.Save()
}

func cmdGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	_ = fs.Parse(args)
	name := fs.Arg(0)
	if name == "" {
		return errors.New("usage: sinete generate <name>")
	}
	if err := registry.ValidName(name); err != nil {
		return err
	}

	// Keys are enumerated from the secure element, so a new key needs no registry
	// write (and thus no presence prompt). Reject a name already in use.
	if _, ok, err := enclave.Find(name); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("key %q already exists", name)
	}

	key, err := enclave.Create(enclave.DefaultLabelPrefix, name)
	if err != nil {
		return err
	}
	pub, err := key.PublicKey()
	if err != nil {
		_ = key.Remove() // roll back a key whose public half we can't read
		return err
	}
	fmt.Println(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + name)
	return nil
}

func cmdList(args []string) error {
	// Keys are enumerated from the secure element, the source of truth for which
	// keys exist (the registry no longer stores them).
	keys, err := enclave.List()
	if err != nil {
		return err
	}
	for _, k := range keys {
		fmt.Printf("%-20s %-22s %s\n", k.Name, k.PublicKey.Type(), ssh.FingerprintSHA256(k.PublicKey))
	}
	return nil
}

func cmdExport(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sinete export <name>")
	}
	name := args[0]
	keys, err := enclave.List()
	if err != nil {
		return err
	}
	for _, k := range keys {
		if k.Name == name {
			fmt.Println(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.PublicKey))) + " " + name)
			return nil
		}
	}
	return fmt.Errorf("no key named %q", name)
}

// cmdSshSetup writes a key's public key to a file and prints the ssh/git config
// needed to use it (commit signing, local verification, optional per-host pin).
func cmdSshSetup(args []string) error {
	fs := flag.NewFlagSet("ssh-setup", flag.ExitOnError)
	out := fs.String("out", "", "path for the public key (default: ~/.ssh/sinete-<name>.pub)")
	_ = fs.Parse(args)
	name := fs.Arg(0)
	if name == "" {
		return errors.New("usage: sinete ssh-setup <name> [--out <path>]")
	}
	// The name flows into the default .pub path and the allowed_signers principal,
	// so a valid (separator/quote/newline-free) name is required; --out only moves
	// where the public key is written, it can't make the snippet safe.
	if err := registry.ValidName(name); err != nil {
		return err
	}

	listed, ok, err := enclave.Find(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no key named %q (create it with: sinete generate %s)", name, name)
	}

	pubPath := *out
	if pubPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		pubPath = filepath.Join(home, ".ssh", "sinete-"+name+".pub")
	}
	if err := os.MkdirAll(filepath.Dir(pubPath), 0o700); err != nil {
		return err
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(listed.PublicKey))) + " " + name
	if err := os.WriteFile(pubPath, []byte(pub+"\n"), 0o644); err != nil { //nolint:gosec // a public key is not secret
		return err
	}
	// Record it so uninstall removes only the .pub files sinete wrote (no-op when
	// there is no install state, e.g. ssh-setup run standalone). A record failure
	// doesn't undo the written key, but it does mean uninstall can't reverse it —
	// warn rather than fail silently.
	if err := install.RecordPub(pubPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not record %s in install state; uninstall may not remove it: %v\n", pubPath, err)
	}

	fmt.Printf("wrote %s\n\n", pubPath)
	fmt.Printf(`# point ssh/git at sinete -- IdentityAgent overrides SSH_AUTH_SOCK, so it
# beats macOS's system agent. Add to ~/.ssh/config (Host * = all hosts):
Host *
    IdentityAgent %[4]s

# commit signing: ssh-keygen -Y sign reads SSH_AUTH_SOCK (not the ssh config),
# so export it in your shell, then point git at the key:
export SSH_AUTH_SOCK=%[4]s
git config gpg.format ssh
git config user.signingkey %[1]s
git config commit.gpgsign true

# verify your own signatures locally
mkdir -p ~/.config/git
echo '%[2]s %[3]s' >> ~/.config/git/allowed_signers

# then add the key (cat %[1]s) on your git host as BOTH an authentication and a signing key.
`, pubPath, name, pub, agentSocketHint())
	return nil
}

// cmdDelete destroys a key in the secure element. It requires user presence, and
// prunes the key's stored config. Unloading a key from the running agent is
// `ssh-add -e`/`-d`, not this.
func cmdDelete(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sinete delete <name>")
	}
	name := args[0]
	listed, ok, err := enclave.Find(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no key named %q", name)
	}

	// Deleting requires user presence. If the key has stored config, pruning it
	// re-signs the registry — the master-key signature IS the prompt; otherwise
	// prompt directly. Either way the user confirms before the key is destroyed.
	cfg, err := openConfig()
	if err != nil {
		return err
	}
	if cfg.HasKey(name) {
		cfg.RemoveKey(name)
		if err := saveConfig(cfg); err != nil {
			return err
		}
	} else if err := presence.Authenticate(fmt.Sprintf("authenticate to delete sinete key %q", name)); err != nil {
		return err
	}

	if err := enclave.OpenLabelTag(listed.Label, enclave.Tag).Remove(); err != nil {
		return err
	}
	fmt.Printf("deleted %s\n", name)
	return nil
}

// cmdSign signs a fixed test message with the named key, foreground. Diagnostic:
// it resolves the key by enumeration (the agent's path) and signs on the main
// thread, isolating the presence prompt from the agent's socket/goroutine context.
func cmdSign(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sinete sign <name>")
	}
	name := args[0]
	listed, ok, err := enclave.Find(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no key named %q", name)
	}
	signer, err := enclave.OpenLabelTag(listed.Label, enclave.Tag).Signer()
	if err != nil {
		return err
	}
	sig, err := signer.Sign(rand.Reader, []byte("sinete sign diagnostic"))
	if err != nil {
		return err
	}
	fmt.Printf("signed with %s (%d-byte signature)\n", sig.Format, len(sig.Blob))
	return nil
}

// cmdEnclaveCheck is an unlisted diagnostic for the signed-registry enclave layer
// (phase 1): it enumerates user keys, ensures+exercises the presence-enforced
// master key, and round-trips the epoch item. Run it from the signed bundle. The
// master-key signature is meant to prompt for Touch ID — that prompt confirms the
// ACL is enforced; pubkey and epoch reads must NOT prompt.
func cmdEnclaveCheck(args []string) error {
	fmt.Println("== enumerate user keys ==")
	keys, err := enclave.List()
	if err != nil {
		return fmt.Errorf("enumerate: %w", err)
	}
	for _, k := range keys {
		created := "?"
		if !k.Created.IsZero() {
			created = k.Created.Format(time.RFC3339)
		}
		fmt.Printf("  %-20s %s  created=%s\n", k.Name, ssh.FingerprintSHA256(k.PublicKey), created)
	}
	fmt.Printf("  (%d key(s))\n", len(keys))

	fmt.Println("== master key ==")
	if err := enclave.EnsureMaster(); err != nil {
		return fmt.Errorf("ensure master: %w", err)
	}
	mpub, err := enclave.MasterPublicKey()
	if err != nil {
		return err
	}
	fmt.Printf("  master pub (no prompt expected): %s\n", ssh.FingerprintSHA256(mpub))

	fmt.Println("== master sign (expect a Touch ID prompt) ==")
	msg := []byte("sinete enclave-check")
	sig, err := enclave.MasterSign(msg)
	if err != nil {
		return fmt.Errorf("master sign: %w", err)
	}
	if err := mpub.Verify(msg, sig); err != nil {
		return fmt.Errorf("master signature does not verify: %w", err)
	}
	fmt.Println("  signature verified")

	// The config round-trip below reads and advances an epoch. The production epoch
	// on Linux is a TPM NV counter that can't be rolled back, so the round-trip runs
	// against a *scratch* epoch (a separate NV index / keychain item) that is removed
	// afterwards — the real registry.json's replay counter is never touched.
	fmt.Println("== signed config round-trip (real master key, scratch epoch, throwaway file) ==")
	crypto, cleanupEpoch, err := enclave.NewScratchConfigCrypto()
	if err != nil {
		return fmt.Errorf("scratch epoch: %w", err)
	}
	defer func() {
		if err := cleanupEpoch(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not remove the scratch epoch after the check: %v\n", err)
		}
	}()

	tmp, err := os.MkdirTemp("", "sinete-cfgcheck")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	cfgPath := filepath.Join(tmp, "registry.json")

	cfg, trusted, err := registry.OpenConfig(cfgPath, crypto)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	if !trusted {
		return fmt.Errorf("an absent config should be trusted")
	}
	cfg.SetKeyConfig("enclave-check", registry.PresenceTTL, "7m")
	fmt.Println("  saving config (expect a Touch ID prompt)...")
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	reopened, trusted, err := registry.OpenConfig(cfgPath, crypto)
	if err != nil {
		return err
	}
	if !trusted {
		return fmt.Errorf("a freshly signed config should be trusted")
	}
	if got := reopened.Effective("enclave-check", registry.PresenceTTL); got != "7m" {
		return fmt.Errorf("config value = %q, want 7m", got)
	}
	fmt.Println("  signed config verified (no prompt)")

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	data[len(data)/2] ^= 0xff // corrupt a byte: breaks the signature (or the JSON)
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		return err
	}
	tampered, trusted, err := registry.OpenConfig(cfgPath, crypto)
	if err != nil {
		return err
	}
	if trusted {
		return fmt.Errorf("a tampered config must not be trusted")
	}
	if got := tampered.Effective("enclave-check", registry.PresenceTTL); got != "" {
		return fmt.Errorf("tampered config value = %q, want built-in default (empty)", got)
	}
	fmt.Println("  tamper correctly rejected -> built-in defaults")

	fmt.Println("all enclave-check steps passed")
	return nil
}

// cmdConfig views and sets presence config. Scope is explicit in the verb:
//
//	config [show]                       print everything
//	config get   <setting>              print the global value
//	config set   <setting> <value>      set the global value (Touch ID)
//	config unset <setting>              clear the global value → strict
//	config key <name> [show]            print a key's override
//	config key <name> get   <setting>   print the effective value for a key
//	config key <name> set   <setting> <value>   relax a key (Touch ID)
//	config key <name> unset <setting>           drop a key's override
//
// presence-ttl resolves fail-closed to 0 (authenticate every signature) when
// unset; presence-max-ttl is GLOBAL only and caps every presence-ttl. --yes (-y)
// skips the confirmation when lowering the ceiling would reduce existing values.
func cmdConfig(args []string) error {
	args, yes := popBoolFlag(args, "--yes", "-y")

	cfg, err := openConfig()
	if err != nil {
		return err
	}

	if len(args) == 0 || args[0] == "show" {
		printConfig(cfg)
		return nil
	}

	switch args[0] {
	case "get":
		if len(args) != 2 {
			return errors.New("usage: sinete config get <setting>")
		}
		if err := requireSetting(args[1]); err != nil {
			return err
		}
		fmt.Println(cfg.Defaults()[args[1]])
		return nil
	case "set":
		return configGlobalSet(cfg, args[1:], yes)
	case "unset":
		if len(args) != 2 {
			return errors.New("usage: sinete config unset <setting>")
		}
		if err := requireSetting(args[1]); err != nil {
			return err
		}
		if cfg.Defaults()[args[1]] == "" {
			return nil // already unset; no-op (avoid a needless Touch ID + epoch bump)
		}
		cfg.UnsetDefault(args[1])
		if err := saveConfig(cfg); err != nil {
			return err
		}
		if args[1] == registry.PresenceMaxTTL {
			fmt.Fprintln(os.Stderr, "note: presence-max-ttl is now unset — the absolute cap is 0, so every signature prompts and any presence-ttl has no effect until you set it again.")
		}
		return nil
	case "key":
		return configKey(cfg, args[1:])
	default:
		return fmt.Errorf("unknown config subcommand %q (want: show, get, set, unset, key)", args[0])
	}
}

// configGlobalSet handles `config set <setting> <value>`. presence-max-ttl is the
// global ceiling (lowering it can reduce existing presence-ttl values); a
// presence-ttl is rejected if it exceeds the ceiling.
func configGlobalSet(cfg *registry.Config, rest []string, yes bool) error {
	if len(rest) != 2 {
		return errors.New("usage: sinete config set <setting> <value>")
	}
	setting, value := rest[0], rest[1]
	d, err := parseSetting(setting, value)
	if err != nil {
		return err
	}
	if setting == registry.PresenceMaxTTL {
		return setCeiling(cfg, d, value, yes)
	}
	if err := checkAgainstCeiling(cfg, d, value); err != nil {
		return err
	}
	cfg.SetDefault(setting, value)
	return saveConfig(cfg)
}

// setCeiling sets the global presence-max-ttl. Lowering it below existing
// presence-ttl values would leave them stricter than the ceiling (inconsistent),
// so it warns and — on confirmation — reduces each to the new ceiling.
func setCeiling(cfg *registry.Config, d time.Duration, value string, yes bool) error {
	if stranded := cfg.TTLsAbove(d); len(stranded) > 0 {
		fmt.Fprintf(os.Stderr, "lowering presence-max-ttl to %s will reduce these presence-ttl values to %s:\n", value, value)
		for _, r := range stranded {
			if r.Key == "" {
				fmt.Fprintf(os.Stderr, "  global default  (was %s)\n", r.Value)
			} else {
				fmt.Fprintf(os.Stderr, "  key %-12s (was %s)\n", r.Key, r.Value)
			}
		}
		if !yes && !confirm("continue?") {
			return errors.New("cancelled")
		}
		for _, r := range stranded {
			if r.Key == "" {
				cfg.SetDefault(registry.PresenceTTL, value)
			} else {
				cfg.SetKeyConfig(r.Key, registry.PresenceTTL, value)
			}
		}
	}
	cfg.SetDefault(registry.PresenceMaxTTL, value)
	return saveConfig(cfg)
}

// checkAgainstCeiling rejects a presence-ttl above the global ceiling and, when no
// ceiling is set, warns that the value has no effect yet (an unset presence-max-ttl
// keeps every key strict).
func checkAgainstCeiling(cfg *registry.Config, d time.Duration, value string) error {
	ceiling, ok := cfg.Ceiling()
	if !ok {
		fmt.Fprintln(os.Stderr, "note: presence-max-ttl is unset, so presence-ttl has no effect yet (every signature still prompts). Set it with `sinete config set presence-max-ttl <d>`.")
		return nil
	}
	if d > ceiling {
		// Print the configured string (e.g. "2h"), not the time.Duration form ("2h0m0s").
		return fmt.Errorf("presence-ttl %s exceeds the presence-max-ttl ceiling (%s); raise the ceiling first or choose a lower value", value, cfg.Defaults()[registry.PresenceMaxTTL])
	}
	return nil
}

// configKey handles the `config key <name> …` forms. The key must exist (a typo
// must not silently configure a phantom key).
func configKey(cfg *registry.Config, rest []string) error {
	if len(rest) == 0 {
		return errors.New("usage: sinete config key <name> [show|get|set|unset] …")
	}
	name := rest[0]
	rest = rest[1:]
	if _, ok, err := enclave.Find(name); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("no key named %q", name)
	}

	verb := "show"
	if len(rest) > 0 {
		verb, rest = rest[0], rest[1:]
	}
	switch verb {
	case "show":
		printKeyConfig(cfg, name)
		return nil
	case "get":
		if len(rest) != 1 {
			return errors.New("usage: sinete config key <name> get <setting>")
		}
		if err := requireSetting(rest[0]); err != nil {
			return err
		}
		fmt.Println(cfg.Effective(name, rest[0]))
		return nil
	case "set":
		if len(rest) != 2 {
			return errors.New("usage: sinete config key <name> set <setting> <value>")
		}
		return configKeySet(cfg, name, rest[0], rest[1])
	case "unset":
		if len(rest) != 1 {
			return errors.New("usage: sinete config key <name> unset <setting>")
		}
		if err := requireSetting(rest[0]); err != nil {
			return err
		}
		if cfg.KeyConfig(name)[rest[0]] == "" {
			return nil // no such override; no-op (avoid a needless Touch ID + epoch bump)
		}
		cfg.UnsetKeyConfig(name, rest[0])
		return saveConfig(cfg)
	default:
		return fmt.Errorf("unknown config key subcommand %q (want: show, get, set, unset)", verb)
	}
}

func configKeySet(cfg *registry.Config, name, setting, value string) error {
	if setting == registry.PresenceMaxTTL {
		return errors.New("presence-max-ttl is global; it caps every key's presence-ttl. Set it with `sinete config set presence-max-ttl <d>`")
	}
	d, err := parseSetting(setting, value)
	if err != nil {
		return err
	}
	if err := checkAgainstCeiling(cfg, d, value); err != nil {
		return err
	}
	cfg.SetKeyConfig(name, setting, value)
	return saveConfig(cfg)
}

// requireSetting validates a setting name.
func requireSetting(s string) error {
	if !registry.ValidSetting(s) {
		return fmt.Errorf("unknown setting %q (valid: %s)", s, strings.Join(registry.Settings, ", "))
	}
	return nil
}

// parseSetting validates the setting name and its duration value (non-negative).
func parseSetting(setting, value string) (time.Duration, error) {
	if err := requireSetting(setting); err != nil {
		return 0, err
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", value, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("duration must not be negative: %q", value)
	}
	return d, nil
}

// popBoolFlag removes every occurrence of any of names from args (anywhere in the
// list, so it works after positional verbs too) and reports whether at least one
// was present.
func popBoolFlag(args []string, names ...string) ([]string, bool) {
	out := make([]string, 0, len(args))
	found := false
	for _, a := range args {
		hit := false
		for _, n := range names {
			if a == n {
				hit = true
				break
			}
		}
		if hit {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

// confirm asks a yes/no question on stderr/stdin. A non-TTY reads as "no" without
// touching stdin (fmt.Scanln would otherwise block forever on a stdin that is open
// but not a terminal), as does any answer other than y/yes — so the caller cancels
// rather than proceeds, the safe default for a config change.
func confirm(prompt string) bool {
	if !isInteractive() {
		return false
	}
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", prompt)
	var resp string
	if _, err := fmt.Scanln(&resp); err != nil {
		return false
	}
	resp = strings.ToLower(strings.TrimSpace(resp))
	return resp == "y" || resp == "yes"
}

func printConfig(cfg *registry.Config) {
	defaults := cfg.Defaults()
	// With the global presence-max-ttl unset, the absolute cap is 0 — every signature
	// prompts — so every presence-ttl is inert. Flag that on the ttl lines so the
	// values don't look active when they aren't.
	ttlInert := defaults[registry.PresenceMaxTTL] == ""
	fmt.Println("global:")
	for _, s := range registry.Settings {
		printSetting(s, defaults[s], ttlInert)
	}
	for _, name := range cfg.Names() {
		if kc := cfg.KeyConfig(name); len(kc) > 0 {
			fmt.Printf("%s:\n", name)
			printKeySettings(kc, ttlInert)
		}
	}
}

func printKeyConfig(cfg *registry.Config, name string) {
	kc := cfg.KeyConfig(name)
	if len(kc) == 0 {
		fmt.Printf("%s: no override (follows the global presence-ttl)\n", name)
		return
	}
	fmt.Printf("%s:\n", name)
	printKeySettings(kc, cfg.Defaults()[registry.PresenceMaxTTL] == "")
}

// printKeySettings prints a key's stored overrides. presence-ttl is the only
// per-key setting: presence-max-ttl is global-only and the registry refuses to
// store it per-key (registry.Config.SetKeyConfig), so that is the only thing shown.
// ttlInert marks it as having no effect while the global presence-max-ttl is unset.
func printKeySettings(kc map[string]string, ttlInert bool) {
	if v := kc[registry.PresenceTTL]; v != "" {
		fmt.Printf("  %-16s %s\n", registry.PresenceTTL, ttlNote(v, ttlInert))
	}
}

// printSetting prints one global setting, making an unset value's strict meaning
// explicit rather than blank, and flagging a set presence-ttl as inert when the
// cap is unset.
func printSetting(s, v string, ttlInert bool) {
	if v == "" {
		fmt.Printf("  %-16s %s\n", s, "(unset → strict: authenticate every signature)")
		return
	}
	if s == registry.PresenceTTL {
		v = ttlNote(v, ttlInert)
	}
	fmt.Printf("  %-16s %s\n", s, v)
}

// ttlNote appends a "no effect" note to a presence-ttl value when the global
// presence-max-ttl is unset (so the cap is 0 and caching is off).
func ttlNote(v string, inert bool) string {
	if inert {
		return v + " (no effect — presence-max-ttl unset)"
	}
	return v
}

// cmdPresent runs the user-presence check directly (no signing). Diagnostic for
// verifying the Touch ID / LocalAuthentication prompt on hardware. With -n it
// authenticates repeatedly in one process, reproducing the agent's re-entry.
func cmdPresent(args []string) error {
	fs := flag.NewFlagSet("present", flag.ExitOnError)
	n := fs.Int("n", 1, "number of times to authenticate in this process")
	_ = fs.Parse(args)
	reason := "sinete presence test"
	if fs.Arg(0) != "" {
		reason = fs.Arg(0)
	}
	for i := 1; i <= *n; i++ {
		if err := presence.Authenticate(reason); err != nil {
			return fmt.Errorf("attempt %d: %w", i, err)
		}
		fmt.Printf("presence verified (%d/%d)\n", i, *n)
	}
	return nil
}

// cmdService manages the launchd login item via SMAppService (macOS). The
// installer uses it to register/unregister the agent bundled in sinete.app so
// macOS attributes the login item to the app. Unlisted: it is an install hook,
// not a daily command.
func cmdService(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sinete service <register|unregister|status>")
	}
	switch args[0] {
	case "register":
		return loginitem.Register()
	case "unregister":
		return loginitem.Unregister()
	case "status":
		s, err := loginitem.Status()
		if err != nil {
			return err
		}
		fmt.Println(s)
		return nil
	default:
		return fmt.Errorf("unknown service action %q (want register, unregister, or status)", args[0])
	}
}

// cmdStatus reports install + key state. With --json it emits the machine form
// the app UI reads to choose between the setup wizard and the ready screen.
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit JSON for the app UI")
	_ = fs.Parse(args)

	type keyInfo struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		Fingerprint string `json:"fingerprint"`
	}
	keys := make([]keyInfo, 0)
	listed, err := enclave.List()
	if err != nil {
		return err
	}
	for _, k := range listed {
		keys = append(keys, keyInfo{k.Name, k.PublicKey.Type(), ssh.FingerprintSHA256(k.PublicKey)})
	}
	st, err := install.LoadState()
	if err != nil {
		return fmt.Errorf("read install state: %w", err)
	}
	loginStatus, lerr := loginitem.Status()
	if lerr != nil {
		loginStatus = "unknown"
	}
	bundle, _ := install.BundlePath()

	out := struct {
		Configured  bool      `json:"configured"`
		Method      string    `json:"method,omitempty"`
		LinkPath    string    `json:"linkPath,omitempty"`
		LoginItem   string    `json:"loginItem"`
		BundlePath  string    `json:"bundlePath,omitempty"`
		UserIsAdmin bool      `json:"userIsAdmin"`
		KeyCount    int       `json:"keyCount"`
		Keys        []keyInfo `json:"keys"`
	}{
		Configured:  st != nil,
		LoginItem:   loginStatus,
		BundlePath:  bundle,
		UserIsAdmin: install.IsAdminUser(),
		KeyCount:    len(keys),
		Keys:        keys,
	}
	if st != nil {
		out.Method = string(st.Method)
		out.LinkPath = st.LinkPath
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	if out.Configured {
		// Mirror cmdInstall: an empty LinkPath means a --skip-link install left an
		// existing link in place, not that the path is missing.
		if out.LinkPath != "" {
			fmt.Printf("configured: yes (%s, %s)\n", out.Method, out.LinkPath)
		} else {
			fmt.Printf("configured: yes (%s, existing link left untouched)\n", out.Method)
		}
	} else {
		fmt.Println("configured: no")
	}
	fmt.Printf("login item: %s\n", out.LoginItem)
	fmt.Printf("keys:       %d\n", out.KeyCount)
	for _, k := range keys {
		fmt.Printf("  %-20s %s %s\n", k.Name, k.Type, k.Fingerprint)
	}
	return nil
}

// cmdInstall runs the app-driven setup: link `sinete` onto PATH (admin
// /usr/local/bin or per-user ~/.local/bin) and register the login item. --plan
// prints the JSON plan (so the UI can confirm an admin prompt or a link
// conflict) without acting; --replace-link overwrites a conflicting link.
func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	plan := fs.Bool("plan", false, "print the install plan as JSON without acting")
	replace := fs.Bool("replace-link", false, "replace an existing different link at the target")
	skipLink := fs.Bool("skip-link", false, "register the login item but leave any existing link untouched")
	ttl := fs.String("presence-ttl", "", "presence idle TTL (e.g. 10m); a fresh interactive install prompts for it when unset")
	maxTTL := fs.String("presence-max-ttl", "", "presence absolute-cap TTL (e.g. 2h); the global ceiling on presence-ttl")
	_ = fs.Parse(args)

	if *replace && *skipLink {
		return errors.New("install: --replace-link and --skip-link are mutually exclusive")
	}

	if *plan {
		p, err := install.PlanInstall()
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(p)
	}
	// Validate any provided TTL flags up front — including the ttl ≤ max-ttl
	// relationship when both are given — so an invalid pair fails before we touch
	// PATH, rather than after the link/login-item changes have already committed.
	haveTTL, haveMax := *ttl != "", *maxTTL != ""
	var dttl, dmax time.Duration
	if haveTTL {
		d, err := parseSetting(registry.PresenceTTL, *ttl)
		if err != nil {
			return err
		}
		dttl = d
	}
	if haveMax {
		d, err := parseSetting(registry.PresenceMaxTTL, *maxTTL)
		if err != nil {
			return err
		}
		dmax = d
	}
	if haveTTL && haveMax && dttl > dmax {
		return fmt.Errorf("presence-ttl %s exceeds presence-max-ttl %s; choose a ttl ≤ the cap", *ttl, *maxTTL)
	}

	st, err := install.Install(*replace, *skipLink)
	if err != nil {
		return err
	}
	if st.LinkPath != "" {
		fmt.Printf("installed: %s link at %s; login item registered\n", st.Method, st.LinkPath)
	} else {
		fmt.Println("installed: login item registered (existing link left untouched)")
	}
	return configurePresenceOnInstall(*ttl, *maxTTL)
}

// configurePresenceOnInstall writes the initial presence config as part of setup.
// Built-in values are suggestions only, never an enforced fallback (unconfigured ⇒
// strict) — and they apply ONLY to a fresh install. Reconfiguring an existing
// config changes just the explicitly-provided values, never injecting a suggestion
// over (or relaxing) a setting the user left unset/strict. Behaviour:
//   - no flags, already configured → leave it untouched (don't nag or clobber);
//   - no flags, fresh, on a TTY → prompt both, pre-filling the suggestions;
//   - no flags, fresh, non-TTY → leave strict and print a hint;
//   - flags given → set those; on a *fresh* install a missing one fills from the
//     suggestion (so a lone --presence-ttl still caches), on an *existing* config a
//     missing one is left as the current value.
func configurePresenceOnInstall(ttlFlag, maxFlag string) error {
	cfg, err := openConfig()
	if err != nil {
		return err
	}
	curTTL := cfg.Defaults()[registry.PresenceTTL]
	curMax := cfg.Defaults()[registry.PresenceMaxTTL]
	// "Configured" means a trusted registry.json already exists — even with both
	// TTLs unset (an intentionally strict setup): re-running install must not nudge
	// it back toward relaxed caching. A missing file (fresh) or an untrusted one
	// (broken → recovery) is not configured, so install offers the suggestions.
	configured := cfg.Trusted() && configFileExists()

	ttl, max := ttlFlag, maxFlag
	switch {
	case ttl == "" && max == "":
		if configured {
			return nil // already set up; setup must not re-prompt or clobber
		}
		if !cfg.Trusted() {
			// A present-but-untrusted file (tampered/stale/corrupt): best-effort
			// recovery — rewrite a valid, signed strict config so the untrusted warning
			// clears, even in the app's non-interactive context. Non-fatal: a denied
			// Touch ID just leaves it untrusted (still safe — strict), to retry later.
			if err := saveConfig(cfg); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not rewrite the signed config (%v); it stays in strict mode. Set TTLs with `sinete config set …`.\n", err)
				return nil
			}
			fmt.Println("recovered: rewrote a valid signed config (strict; set TTLs with `sinete config set …`)")
			return nil
		}
		if !isInteractive() {
			fmt.Fprintln(os.Stderr, "note: presence TTLs are unset, so every signature prompts for Touch ID. Configure them with `sinete config set presence-ttl <d>` and `sinete config set presence-max-ttl <d>`, or re-run `sinete install` interactively.")
			return nil
		}
		fmt.Fprintln(os.Stderr, "Configure presence caching (blank keeps the suggested value):")
		ttl = promptDuration("  presence-ttl  (idle window)", registry.Suggested(registry.PresenceTTL))
		max = promptDuration("  presence-max-ttl (absolute cap)", registry.Suggested(registry.PresenceMaxTTL))
	case !configured:
		// Fresh install with partial flags: fill the missing one from the suggestion
		// so a lone --presence-ttl still caches. On an existing config we leave the
		// unprovided setting as-is (below), never relaxing a strict one.
		if ttl == "" {
			ttl = registry.Suggested(registry.PresenceTTL)
		}
		if max == "" {
			max = registry.Suggested(registry.PresenceMaxTTL)
		}
	}

	// Apply only the values we resolved; an empty one keeps the current value, so
	// reconfiguring a strict setup with a single flag never relaxes the other.
	effTTL, effMax := curTTL, curMax
	changed := false
	if ttl != "" {
		if _, err := parseSetting(registry.PresenceTTL, ttl); err != nil {
			return err
		}
		cfg.SetDefault(registry.PresenceTTL, ttl)
		effTTL, changed = ttl, true
	}
	if max != "" {
		if _, err := parseSetting(registry.PresenceMaxTTL, max); err != nil {
			return err
		}
		cfg.SetDefault(registry.PresenceMaxTTL, max)
		effMax, changed = max, true
	}
	if !changed {
		return nil
	}

	// An inconsistent resulting pair (e.g. a lone --presence-ttl above an existing
	// cap) is non-fatal: the PATH link + login item already committed, so don't fail
	// the install — warn and leave the config unchanged (a both-flags conflict is
	// already rejected up front in cmdInstall, before PATH). Current values come from
	// a trusted config, so they parse; guard anyway.
	if effTTL != "" && effMax != "" {
		dttl, derr := time.ParseDuration(effTTL)
		dmax, merr := time.ParseDuration(effMax)
		if derr == nil && merr == nil && dttl > dmax {
			fmt.Fprintf(os.Stderr, "warning: presence-ttl %s exceeds presence-max-ttl %s; presence config left unchanged. Raise the cap or pass --presence-max-ttl too.\n", effTTL, effMax)
			return nil
		}
	}

	// The PATH link + login item already succeeded; a failed/denied config write
	// (e.g. Touch ID cancelled) shouldn't fail the whole install — strict mode is
	// the safe fallback, and `sinete config set …` can set it later.
	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write presence config (%v); leaving strict mode (every signature prompts). Set it later with `sinete config set …`.\n", err)
		return nil
	}
	fmt.Printf("presence configured: presence-ttl=%s presence-max-ttl=%s\n", ttlForDisplay(effTTL), ttlForDisplay(effMax))
	if effTTL == "" || effMax == "" {
		fmt.Println("note: caching needs both presence-ttl and presence-max-ttl; while one is unset every signature still prompts (strict).")
	}
	return nil
}

// ttlForDisplay renders a TTL value for human output, making an unset one explicit
// rather than blank.
func ttlForDisplay(v string) string {
	if v == "" {
		return "(unset → strict)"
	}
	return v
}

// configFileExists reports whether the signed registry.json is present on disk
// (regardless of whether it verifies) — used to tell a fresh install from an
// existing config whose presence values may both be unset (intentionally strict).
func configFileExists() bool {
	path, err := registry.ConfigPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// promptDuration asks for a duration on stderr/stdin, returning suggestion when the
// user just presses Enter (or input is unavailable). An entered value is validated
// here and the prompt repeats on a bad one, so an invalid interactive answer can't
// slip through to fail later (after install has already touched PATH).
func promptDuration(label, suggestion string) string {
	for {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, suggestion)
		var resp string
		if _, err := fmt.Scanln(&resp); err != nil {
			return suggestion // blank line / no input → accept the suggestion
		}
		if resp = strings.TrimSpace(resp); resp == "" {
			return suggestion
		}
		if d, err := time.ParseDuration(resp); err != nil || d < 0 {
			fmt.Fprintf(os.Stderr, "  invalid duration %q (e.g. 10m, 2h); try again.\n", resp)
			continue
		}
		return resp
	}
}

// cmdUninstall reverses the install: login item, the link sinete created, the
// PATH entry, the .pub files sinete wrote, and the state file. A kept (declined)
// link or .pub is left alone. With --remove-keys it also deletes this user's
// enclave keys (irreversible); other users' keys are untouched (their keychain).
func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	removeKeys := fs.Bool("remove-keys", false, "also delete this user's enclave keys (irreversible)")
	_ = fs.Parse(args)

	if err := install.Uninstall(); err != nil {
		return err
	}
	if !*removeKeys {
		fmt.Println("uninstalled: login item, link, PATH, and generated .pub files removed (keys kept)")
		return nil
	}
	listed, err := enclave.List()
	if err != nil {
		return err
	}
	removed := 0
	for _, k := range listed {
		if err := enclave.OpenLabelTag(k.Label, enclave.Tag).Remove(); err != nil {
			return fmt.Errorf("remove key %q: %w", k.Name, err)
		}
		removed++
	}
	// Also remove the internal master key + epoch item, and the config files.
	if err := enclave.RemoveMaster(); err != nil {
		return fmt.Errorf("remove master key: %w", err)
	}
	if p, perr := registry.ConfigPath(); perr == nil {
		_ = os.Remove(p)
		_ = os.Remove(p + ".lock") // the config write lock file (see Config.Save)
	}
	fmt.Printf("uninstalled and removed %d key(s)\n", removed)
	return nil
}

func cmdAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (default: per-user runtime dir)")
	launchd := fs.Bool("launchd", false, "managed by launchd: capture the session's agent as the delegation upstream")
	_ = fs.Parse(args)

	path := *socket
	usingDefault := path == ""
	if usingDefault {
		path = defaultSocket()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// MkdirAll only sets the mode on directories it creates (and is subject to
	// umask), so tighten the default per-user dir to keep the socket user-only.
	// An explicit --socket dir is left untouched: it may be a shared location
	// like /tmp where chmod would fail or be harmful.
	if usingDefault {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	// When launchd manages us, set up the agent's log file (the bundled plist has
	// no Standard*Path). The XPC_SERVICE_NAME check also covers a no-argument
	// launchd spawn (BundleProgram without an honoured ProgramArguments).
	if *launchd || os.Getenv("XPC_SERVICE_NAME") == loginitem.AgentLabel {
		prepareLaunchSession(path)
	}
	// Clear a stale socket from a previous run, but only if it really is a socket:
	// never delete a regular file the user may have pointed --socket at.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to remove %s: not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	defer ln.Close()

	// Restrict the socket file itself: umask may otherwise leave it group/world
	// reachable, letting other local users connect and trigger signing prompts.
	// Matters most for an explicit --socket in a shared directory like /tmp.
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		_ = os.Remove(path)
		os.Exit(0)
	}()

	// Superset agent: delegate everything we don't own to the session's existing
	// agent -- the SSH_AUTH_SOCK we inherit (normally macOS's com.openssh.ssh-agent)
	// -- so a client that reaches sinete still sees its other keys. Skip it when
	// that socket is us (e.g. a shell already pointing SSH_AUTH_SOCK at sinete).
	var upstream xagent.ExtendedAgent
	if s := os.Getenv("SSH_AUTH_SOCK"); s != "" && !sameSocket(s, path) {
		conn, derr := net.Dial("unix", s)
		if derr != nil {
			fmt.Fprintf(os.Stderr, "sinete agent: no upstream agent at %s: %v\n", s, derr)
		} else {
			upstream = xagent.NewClient(conn)
			fmt.Fprintf(os.Stderr, "delegating non-enclave keys to %s\n", s)
		}
	}

	a := agent.New(agent.NewEnclaveStore(), agent.EnclaveSource{}, presence.Authenticate, upstream)
	fmt.Printf("export SSH_AUTH_SOCK=%s\n", path)

	// Accept and serve connections off the main thread; signing (and its Touch ID
	// prompt) is dispatched back to the main thread by a.Run below.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				fmt.Fprintln(os.Stderr, "sinete agent: accept:", err)
				time.Sleep(10 * time.Millisecond)
				continue
			}
			go func() {
				defer conn.Close()
				// A peer that can't satisfy a presence prompt (a remote/SSH or
				// otherwise headless session) would make presence-gated signing hang
				// on an invisible prompt, so refuse signing our enclave keys for it
				// (List and upstream keys still work). This is a property of the
				// connection's peer, computed once here; see remote.go.
				served := xagent.ExtendedAgent(a)
				if presenceUnavailable(conn) {
					served = remoteRefusingAgent{a}
				}
				_ = xagent.ServeAgent(served, conn)
			}()
		}
	}()

	a.Run() // process signing on the main OS thread; blocks
	return nil
}

// sameSocket reports whether two socket paths name the same file, so the agent
// never delegates to itself (delegating to our own socket would loop List/Sign
// back over the protocol and hang). A string compare misses an SSH_AUTH_SOCK
// spelled as a symlink to our socket, or relatively vs absolutely; os.Stat
// follows symlinks and os.SameFile compares the underlying file identity.
func sameSocket(a, b string) bool {
	if a == b {
		return true
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// defaultSocket returns the per-user agent socket path. On macOS the launchd
// agent and the CLI share a stable path under the user's Caches (the one clients
// point IdentityAgent at); elsewhere it follows XDG_RUNTIME_DIR.
func defaultSocket() string {
	if runtime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "Library", "Caches", "sinete", "agent.sock")
		}
	}
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "sinete", "agent.sock")
}

// agentSocketHint returns sinete's own agent socket path for the ssh/git config
// printed by ssh-setup. IdentityAgent / SSH_AUTH_SOCK must point at sinete, not
// the inherited SSH_AUTH_SOCK (which on macOS is the system agent), so we use the
// per-user default socket the launchd agent listens on.
func agentSocketHint() string {
	return defaultSocket()
}
