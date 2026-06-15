// Command sinete (spike): prove the secure-element round-trip via facebookincubator/sks.
//
// It creates a Touch-ID-gated key inside the Secure Enclave, prints its OpenSSH
// public key, signs a test message (which should trigger a Touch ID prompt), and
// verifies the signature against the exported public key. If this round-trips, the
// real agent is just plumbing on top.
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	"github.com/facebookincubator/sks"
	"golang.org/x/crypto/ssh"
)

const (
	label = "sinete-spike"
	tag   = "dev.sinete.spike"
)

func main() {
	keep := flag.Bool("keep", false, "keep the key after the test (default: remove it so re-runs are clean)")
	flag.Parse()

	// 1. Create a key inside the Secure Enclave, requiring biometrics (Touch ID) to use.
	//    hash=nil -> generate a new key (non-nil would look up an existing one).
	key, err := sks.NewKey(label, tag, true /* useBiometrics */, false /* accessibleWhenUnlockedOnly */, nil)
	if err != nil {
		fail("create key", err)
	}

	// 2. Export only the public key, in OpenSSH authorized_keys format.
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		fail("public key", fmt.Errorf("expected *ecdsa.PublicKey, got %T", key.Public()))
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		fail("ssh public key", err)
	}
	fmt.Printf("public key (%s):\n%s", sshPub.Type(), ssh.MarshalAuthorizedKey(sshPub))

	// 3. Sign a test message. NewSignerFromSigner reuses the enclave-held crypto.Signer
	//    and handles the ECDSA->SSH wire-format conversion. This is where Touch ID fires.
	signer, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		fail("ssh signer", err)
	}
	msg := []byte("sinete secure-enclave round-trip test")
	fmt.Println("signing (expect a Touch ID prompt)...")
	sig, err := signer.Sign(rand.Reader, msg)
	if err != nil {
		fail("sign", err)
	}

	// 4. Verify the signature with the exported public key.
	if err := sshPub.Verify(msg, sig); err != nil {
		fail("verify", err)
	}
	fmt.Printf("OK: signed with %s and verified against the exported public key\n", sig.Format)

	// 5. Clean up unless -keep.
	if *keep {
		fmt.Printf("key kept (label %q) — add the public key above to a server/GitHub to test real ssh\n", label)
		return
	}
	if err := key.Remove(); err != nil {
		fail("remove key", err)
	}
	fmt.Println("key removed (pass -keep to retain it)")
}

func fail(what string, err error) {
	fmt.Fprintf(os.Stderr, "sinete spike: %s: %v\n", what, err)
	os.Exit(1)
}
