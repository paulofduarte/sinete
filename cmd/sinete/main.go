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

// openRegistry loads the local key index.
func openRegistry() (*registry.Registry, error) {
	path, err := registry.DefaultPath()
	if err != nil {
		return nil, err
	}
	return registry.Open(path)
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

	reg, err := openRegistry()
	if err != nil {
		return err
	}
	if _, ok := reg.Get(name); ok {
		return fmt.Errorf("key %q already exists", name)
	}

	key, err := enclave.Create(enclave.DefaultLabelPrefix, name)
	if err != nil {
		return err
	}
	// Roll back the freshly created enclave key if anything fails before it is
	// indexed, so a partial generate doesn't leave an orphan: remove needs a
	// registry entry, and a re-run would fail because the key already exists.
	committed := false
	defer func() {
		if !committed {
			_ = key.Remove()
		}
	}()

	pub, err := key.PublicKey()
	if err != nil {
		return err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + name

	reg.Add(registry.Entry{
		Name:      name,
		Label:     key.Label(),
		Tag:       enclave.Tag,
		PublicKey: line,
		Created:   time.Now().UTC(),
	})
	if err := reg.Save(); err != nil {
		return err
	}
	committed = true
	fmt.Println(line)
	return nil
}

func cmdList(args []string) error {
	reg, err := openRegistry()
	if err != nil {
		return err
	}
	for _, e := range reg.List() {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.PublicKey))
		if err != nil {
			return fmt.Errorf("registry key %q: %w", e.Name, err)
		}
		fmt.Printf("%-20s %-22s %s\n", e.Name, pub.Type(), ssh.FingerprintSHA256(pub))
	}
	return nil
}

func cmdExport(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sinete export <name>")
	}
	reg, err := openRegistry()
	if err != nil {
		return err
	}
	e, ok := reg.Get(args[0])
	if !ok {
		return fmt.Errorf("no key named %q", args[0])
	}
	fmt.Println(e.PublicKey)
	return nil
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

	reg, err := openRegistry()
	if err != nil {
		return err
	}
	e, ok := reg.Get(name)
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
	pub := strings.TrimRight(e.PublicKey, "\n")
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

// cmdDelete destroys a key: it removes it from the secure element and the index.
// Unloading a key from the running agent is `ssh-add -e`/`-d`, not this.
func cmdDelete(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sinete delete <name>")
	}
	name := args[0]
	reg, err := openRegistry()
	if err != nil {
		return err
	}
	e, ok := reg.Get(name)
	if !ok {
		return fmt.Errorf("no key named %q", name)
	}
	if err := enclave.OpenLabelTag(e.Label, e.Tag).Remove(); err != nil {
		return err
	}
	reg.Remove(name)
	return reg.Save()
}

// cmdSign signs a fixed test message with the named key, foreground. Diagnostic:
// it opens the key by the registry's authoritative label/tag (the agent's path)
// and signs on the main thread, isolating the presence prompt from the agent's
// socket/goroutine context.
func cmdSign(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sinete sign <name>")
	}
	name := args[0]
	reg, err := openRegistry()
	if err != nil {
		return err
	}
	e, ok := reg.Get(name)
	if !ok {
		return fmt.Errorf("no key named %q", name)
	}
	signer, err := enclave.OpenLabelTag(e.Label, e.Tag).Signer()
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

// cmdConfig views and sets presence config: a global default, or a per-key
// override with --key. Settings are durations (e.g. 10m, 2h).
func cmdConfig(args []string) error {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	keyName := fs.String("key", "", "set/get for a specific key instead of the global default")
	list := fs.Bool("list", false, "print all config")
	_ = fs.Parse(args)

	reg, err := openRegistry()
	if err != nil {
		return err
	}

	if *list {
		printConfig(reg)
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
			// Effective falls back to the global default, which would silently
			// answer for a key that doesn't exist (hiding a typo); reject it,
			// matching SetKeyConfig's behaviour.
			if _, ok := reg.Get(*keyName); !ok {
				return fmt.Errorf("no key named %q", *keyName)
			}
			fmt.Println(reg.Effective(*keyName, setting))
		} else {
			fmt.Println(reg.Defaults()[setting])
		}
		return nil
	}

	value := rest[1] // set
	if _, err := time.ParseDuration(value); err != nil {
		return fmt.Errorf("invalid duration %q: %w", value, err)
	}
	if *keyName != "" {
		if err := reg.SetKeyConfig(*keyName, setting, value); err != nil {
			return err
		}
	} else {
		reg.SetDefault(setting, value)
	}
	return reg.Save()
}

func printConfig(reg *registry.Registry) {
	defaults := reg.Defaults()
	fmt.Println("defaults:")
	for _, s := range registry.Settings {
		v := defaults[s]
		if v == "" {
			v = "(built-in)"
		}
		fmt.Printf("  %-16s %s\n", s, v)
	}
	for _, e := range reg.List() {
		if len(e.Config) == 0 {
			continue
		}
		fmt.Printf("%s:\n", e.Name)
		for _, s := range registry.Settings {
			if v := e.Config[s]; v != "" {
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

	reg, err := openRegistry()
	if err != nil {
		return err
	}
	type keyInfo struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		Fingerprint string `json:"fingerprint"`
	}
	keys := make([]keyInfo, 0)
	for _, e := range reg.List() {
		pub, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(e.PublicKey))
		if perr != nil {
			return fmt.Errorf("registry key %q: %w", e.Name, perr)
		}
		keys = append(keys, keyInfo{e.Name, pub.Type(), ssh.FingerprintSHA256(pub)})
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
		fmt.Printf("configured: yes (%s, %s)\n", out.Method, out.LinkPath)
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
	reg, err := openRegistry()
	if err != nil {
		return err
	}
	removed := 0
	for _, e := range reg.List() {
		if err := enclave.OpenLabelTag(e.Label, e.Tag).Remove(); err != nil {
			return fmt.Errorf("remove key %q: %w", e.Name, err)
		}
		reg.Remove(e.Name)
		removed++
	}
	if err := reg.Save(); err != nil {
		return err
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

	regPath, err := registry.DefaultPath()
	if err != nil {
		return err
	}

	// Superset agent: delegate everything we don't own to the session's existing
	// agent -- the SSH_AUTH_SOCK we inherit (normally macOS's com.openssh.ssh-agent)
	// -- so a client that reaches sinete still sees its other keys. Skip it when
	// that socket is us (e.g. a shell already pointing SSH_AUTH_SOCK at sinete).
	var upstream xagent.ExtendedAgent
	if s := os.Getenv("SSH_AUTH_SOCK"); s != "" && s != path {
		conn, derr := net.Dial("unix", s)
		if derr != nil {
			fmt.Fprintf(os.Stderr, "sinete agent: no upstream agent at %s: %v\n", s, derr)
		} else {
			upstream = xagent.NewClient(conn)
			fmt.Printf("delegating non-enclave keys to %s\n", s)
		}
	}

	a := agent.New(agent.RegistryStore{Path: regPath}, agent.EnclaveSource{}, presence.Authenticate, upstream)
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
