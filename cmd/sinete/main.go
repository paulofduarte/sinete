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
  delete <name>     delete a key from the enclave and the index
  config            view/set presence TTLs (--list, --key <name>)
  status            show install + key state (--json for the app UI)
  agent             run the ssh-agent (foreground)

The agent advertises every created key, so ssh/git use them automatically once
SSH_AUTH_SOCK (or IdentityAgent) points at it. The first signature with a key
prompts for Touch ID; further signatures are silent until its presence window
(TTL) lapses. ssh-add -l lists them; ssh-add -d/-D forgets a key's window.`)
}

// openRegistry loads the legacy keys.json index (kept only to migrate its config
// into the signed registry; keys themselves now come from the secure element).
func openRegistry() (*registry.Registry, error) {
	path, err := registry.DefaultPath()
	if err != nil {
		return nil, err
	}
	return registry.Open(path)
}

// openConfig loads the signed config (registry.json). When that file does not
// exist yet it seeds, in memory, any config from the legacy keys.json so reads
// honour it and the next write persists it. A present-but-unverifiable file warns
// and yields built-in defaults.
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
		fmt.Fprintln(os.Stderr, "warning: the signed config could not be verified (tampered, stale, or corrupt); using built-in defaults until you re-run `sinete config`.")
	}
	if _, statErr := os.Stat(path); errors.Is(statErr, os.ErrNotExist) {
		if legacy, lerr := openRegistry(); lerr == nil {
			cfg.MergeLegacy(legacy)
		}
	}
	return cfg, nil
}

// saveConfig signs and writes the config (a Touch ID prompt), then drops the
// legacy keys.json — migration is complete once the signed registry exists.
func saveConfig(cfg *registry.Config) error {
	if err := cfg.Save(); err != nil {
		return err
	}
	if p, err := registry.DefaultPath(); err == nil {
		_ = os.Remove(p)
	}
	return nil
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

	fmt.Println("== epoch item (no prompt expected) ==")
	cur, ok, err := enclave.Epoch()
	if err != nil {
		return fmt.Errorf("epoch get: %w", err)
	}
	fmt.Printf("  current: %d (exists=%v)\n", cur, ok)
	if err := enclave.SetEpoch(cur + 1); err != nil {
		return fmt.Errorf("epoch set: %w", err)
	}
	next, _, err := enclave.Epoch()
	if err != nil {
		return fmt.Errorf("epoch get after set: %w", err)
	}
	if next != cur+1 {
		return fmt.Errorf("epoch did not persist: got %d, want %d", next, cur+1)
	}
	fmt.Printf("  after increment: %d\n", next)

	fmt.Println("== signed config round-trip (real master key, throwaway file) ==")
	tmp, err := os.MkdirTemp("", "sinete-cfgcheck")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	cfgPath := filepath.Join(tmp, "registry.json")
	crypto := enclave.ConfigCrypto{}

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

// cmdConfig views and sets presence config: a global default, or a per-key
// override with --key. Settings are durations (e.g. 10m, 2h).
func cmdConfig(args []string) error {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	keyName := fs.String("key", "", "set/get for a specific key instead of the global default")
	list := fs.Bool("list", false, "print all config")
	_ = fs.Parse(args)

	cfg, err := openConfig()
	if err != nil {
		return err
	}

	if *list {
		printConfig(cfg)
		return nil
	}

	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("usage: sinete config [--key <name>] <setting> [<value>]  (--list to show all)")
	}
	setting := rest[0]
	if !registry.ValidSetting(setting) {
		return fmt.Errorf("unknown setting %q (valid: %s)", setting, strings.Join(registry.Settings, ", "))
	}

	if len(rest) == 1 { // get
		if *keyName != "" {
			// Reject an unknown key rather than silently answering with the global
			// default (which would hide a typo).
			if _, ok, err := enclave.Find(*keyName); err != nil {
				return err
			} else if !ok {
				return fmt.Errorf("no key named %q", *keyName)
			}
			fmt.Println(cfg.Effective(*keyName, setting))
		} else {
			fmt.Println(cfg.Defaults()[setting])
		}
		return nil
	}

	value := rest[1] // set
	if _, err := time.ParseDuration(value); err != nil {
		return fmt.Errorf("invalid duration %q: %w", value, err)
	}
	if *keyName != "" {
		if _, ok, err := enclave.Find(*keyName); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("no key named %q", *keyName)
		}
		cfg.SetKeyConfig(*keyName, setting, value)
	} else {
		cfg.SetDefault(setting, value)
	}
	// Save signs the config with the presence-enforced master key, so this prompts
	// for Touch ID — the human approval that gates every config change.
	return saveConfig(cfg)
}

func printConfig(cfg *registry.Config) {
	defaults := cfg.Defaults()
	fmt.Println("defaults:")
	for _, s := range registry.Settings {
		v := defaults[s]
		if v == "" {
			v = "(built-in)"
		}
		fmt.Printf("  %-16s %s\n", s, v)
	}
	for _, name := range cfg.Names() {
		kc := cfg.KeyConfig(name)
		printed := false
		for _, s := range registry.Settings {
			if v := kc[s]; v != "" {
				if !printed {
					fmt.Printf("%s:\n", name)
					printed = true
				}
				fmt.Printf("  %-16s %s\n", s, v)
			}
		}
	}
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
	st, err := install.Install(*replace, *skipLink)
	if err != nil {
		return err
	}
	if st.LinkPath != "" {
		fmt.Printf("installed: %s link at %s; login item registered\n", st.Method, st.LinkPath)
	} else {
		fmt.Println("installed: login item registered (existing link left untouched)")
	}
	return nil
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
	}
	if p, perr := registry.DefaultPath(); perr == nil {
		_ = os.Remove(p)
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

	a := agent.New(agent.EnclaveStore{}, agent.EnclaveSource{}, presence.Authenticate, upstream)
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
				_ = xagent.ServeAgent(a, conn)
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
