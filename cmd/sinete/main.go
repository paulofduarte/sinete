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
	"github.com/paulofduarte/sinete/internal/presence"
	"github.com/paulofduarte/sinete/internal/registry"
	"golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

// defaultPresenceTTL is how long a Touch ID stays valid for a key before the
// next signature prompts again. 10 min mirrors gpg-agent's default signing-key
// cache (default-cache-ttl); made configurable per key via `sinete config`.
const defaultPresenceTTL = 10 * time.Minute

func main() {
	// Pin the main goroutine to the main OS thread up front: the agent presents
	// the sign-time Touch ID prompt here, and macOS only draws it from the main
	// thread.
	runtime.LockOSThread()

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmds := map[string]func([]string) error{
		"generate": cmdGenerate,
		"list":     cmdList,
		"export":   cmdExport,
		"delete":   cmdDelete,
		"agent":    cmdAgent,
		"sign":     cmdSign,
		"present":  cmdPresent,
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
  delete <name>     delete a key from the enclave and the index
  sign <name>       sign a test message with a key (diagnostic)
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

// cmdPresent runs the user-presence check directly (no signing). Diagnostic for
// verifying the Touch ID / LocalAuthentication prompt on hardware.
func cmdPresent(args []string) error {
	reason := "sinete presence test"
	if len(args) > 0 {
		reason = args[0]
	}
	if err := presence.Authenticate(reason); err != nil {
		return err
	}
	fmt.Println("presence verified")
	return nil
}

func cmdAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (default: per-user runtime dir)")
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

	reg, err := openRegistry()
	if err != nil {
		return err
	}
	a := agent.New(reg, agent.EnclaveSource{}, presence.Authenticate, defaultPresenceTTL)
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

// defaultSocket returns the per-user agent socket path.
func defaultSocket() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "sinete", "agent.sock")
}
