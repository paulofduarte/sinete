// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

// This file is the small macOS Security-framework layer for the three things
// upstream sks does not expose, which the signed-registry design needs:
//
//   - enumerateKeys: list sinete's keys (the keychain is the source of truth for
//     which keys exist; sks only looks one up by label+tag).
//   - createPresenceKey: create the *master* key with a user-presence ACL, so
//     every signature with it (i.e. every config write) requires Touch ID. sks
//     always creates presence-less keys.
//   - keychainItemGet/Set: a presence-less generic-password item holding the
//     registry epoch (replay/rollback guard).
//
// Signing with, and reading the public key of, the master key still go through
// sks (by label+tag) — see master.go.
package enclave

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// Typed result-dictionary accessors, so the lookups stay in C and Go never has
// to convert a CF constant to unsafe.Pointer.
static CFStringRef sinete_dict_label(CFDictionaryRef d)   { return (CFStringRef)CFDictionaryGetValue(d, kSecAttrLabel); }
static CFDateRef   sinete_dict_created(CFDictionaryRef d) { return (CFDateRef)CFDictionaryGetValue(d, kSecAttrCreationDate); }
static SecKeyRef   sinete_dict_keyref(CFDictionaryRef d)  { return (SecKeyRef)CFDictionaryGetValue(d, kSecValueRef); }
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"math"
	"unsafe"
)

const (
	nilSecKey           C.SecKeyRef           = 0
	nilSecAccessControl C.SecAccessControlRef = 0
	nilCFData           C.CFDataRef           = 0
	nilCFString         C.CFStringRef         = 0
	nilCFDictionary     C.CFDictionaryRef     = 0
	nilCFError          C.CFErrorRef          = 0
)

// cfEpochToUnix converts a CFAbsoluteTime (seconds since 2001-01-01 UTC) to a
// Unix timestamp (seconds since 1970-01-01 UTC).
const cfEpochToUnix = 978307200

// --- CoreFoundation helpers (local copies; sks's are unexported) ---

func cfString(s string) (C.CFStringRef, error) {
	b := []byte(s)
	var p *C.UInt8
	if len(b) > 0 {
		p = (*C.UInt8)(unsafe.Pointer(&b[0]))
	}
	ref := C.CFStringCreateWithBytes(C.kCFAllocatorDefault, p, C.CFIndex(len(b)), C.kCFStringEncodingUTF8, C.false)
	if ref == nilCFString {
		return nilCFString, fmt.Errorf("enclave: CFStringCreateWithBytes failed")
	}
	return ref, nil
}

func cfData(b []byte) (C.CFDataRef, error) {
	var p *C.UInt8
	if len(b) > 0 {
		p = (*C.UInt8)(unsafe.Pointer(&b[0]))
	}
	ref := C.CFDataCreate(C.kCFAllocatorDefault, p, C.CFIndex(len(b)))
	if ref == nilCFData {
		return nilCFData, fmt.Errorf("enclave: CFDataCreate failed")
	}
	return ref, nil
}

func cfDictionary(m map[C.CFTypeRef]C.CFTypeRef) (C.CFDictionaryRef, error) {
	keys := make([]C.CFTypeRef, 0, len(m))
	vals := make([]C.CFTypeRef, 0, len(m))
	for k, v := range m {
		keys = append(keys, k)
		vals = append(vals, v)
	}
	var kp, vp *unsafe.Pointer
	if len(m) > 0 {
		kp = (*unsafe.Pointer)(unsafe.Pointer(&keys[0]))
		vp = (*unsafe.Pointer)(unsafe.Pointer(&vals[0]))
	}
	ref := C.CFDictionaryCreate(C.kCFAllocatorDefault, kp, vp, C.CFIndex(len(m)),
		&C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
	if ref == nilCFDictionary {
		return nilCFDictionary, fmt.Errorf("enclave: CFDictionaryCreate failed")
	}
	return ref, nil
}

func goStringFromCFString(ref C.CFStringRef) string {
	if ref == nilCFString {
		return ""
	}
	n := C.CFStringGetLength(ref)
	if n == 0 {
		return ""
	}
	maxBytes := C.CFStringGetMaximumSizeForEncoding(n, C.kCFStringEncodingUTF8) + 1
	buf := make([]byte, int(maxBytes))
	var used C.CFIndex
	C.CFStringGetBytes(ref, C.CFRange{location: 0, length: n}, C.kCFStringEncodingUTF8, 0, C.false,
		(*C.UInt8)(unsafe.Pointer(&buf[0])), maxBytes, &used)
	return string(buf[:int(used)])
}

func goBytesFromCFData(ref C.CFDataRef) []byte {
	if ref == nilCFData {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(ref)), C.int(C.CFDataGetLength(ref)))
}

func osError(status C.OSStatus, op string) error {
	if status == C.errSecSuccess {
		return nil
	}
	return fmt.Errorf("enclave: %s: OSStatus %d", op, int(status))
}

// --- enumerate ---

// enumerateKeys lists every secure-element key carrying tag, returning each
// key's label, raw public key and creation time. No user presence is required
// (it reads only public attributes).
func enumerateKeys(tag string) ([]rawKey, error) {
	cfTag, err := cfData([]byte(tag))
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfTag))

	query, err := cfDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):              C.CFTypeRef(C.kSecClassKey),
		C.CFTypeRef(C.kSecAttrKeyType):        C.CFTypeRef(C.kSecAttrKeyTypeEC),
		C.CFTypeRef(C.kSecAttrApplicationTag): C.CFTypeRef(cfTag),
		C.CFTypeRef(C.kSecAttrKeyClass):       C.CFTypeRef(C.kSecAttrKeyClassPrivate),
		// Constrain to the Secure Enclave token so enumeration can only ever return
		// hardware-backed keys ("keys come from the secure element" invariant); a
		// non-SE EC key sharing our tag would otherwise be included.
		C.CFTypeRef(C.kSecAttrTokenID):      C.CFTypeRef(C.kSecAttrTokenIDSecureEnclave),
		C.CFTypeRef(C.kSecReturnRef):        C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecReturnAttributes): C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit):       C.CFTypeRef(C.kSecMatchLimitAll),
	})
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(query, &result)
	if status == C.errSecItemNotFound {
		return nil, nil
	}
	if err := osError(status, "SecItemCopyMatching(all keys)"); err != nil {
		return nil, err
	}
	defer C.CFRelease(result)

	arr := C.CFArrayRef(result)
	n := int(C.CFArrayGetCount(arr))
	keys := make([]rawKey, 0, n)
	for i := 0; i < n; i++ {
		dict := C.CFDictionaryRef(C.CFArrayGetValueAtIndex(arr, C.CFIndex(i)))

		label := goStringFromCFString(C.sinete_dict_label(dict))

		var created int64
		if d := C.sinete_dict_created(dict); d != 0 {
			created = int64(C.CFDateGetAbsoluteTime(d)) + cfEpochToUnix
		}

		ref := C.sinete_dict_keyref(dict)
		if ref == nilSecKey {
			return nil, fmt.Errorf("enclave: key %q has no key reference", label)
		}
		pub, perr := publicKeyBytes(ref)
		if perr != nil {
			return nil, fmt.Errorf("enclave: key %q: %w", label, perr)
		}

		keys = append(keys, rawKey{label: label, pub: pub, created: created})
	}
	return keys, nil
}

// publicKeyBytes returns the raw ANSI X9.63 public key for a private SecKeyRef.
// Reading the public half performs no private-key operation, so no presence.
func publicKeyBytes(priv C.SecKeyRef) ([]byte, error) {
	pubKey := C.SecKeyCopyPublicKey(priv)
	if pubKey == nilSecKey {
		return nil, fmt.Errorf("enclave: SecKeyCopyPublicKey failed")
	}
	defer C.CFRelease(C.CFTypeRef(pubKey))

	var eref C.CFErrorRef
	data := C.SecKeyCopyExternalRepresentation(pubKey, &eref)
	if data == nilCFData {
		if eref != nilCFError {
			C.CFRelease(C.CFTypeRef(eref))
		}
		return nil, fmt.Errorf("enclave: SecKeyCopyExternalRepresentation failed")
	}
	defer C.CFRelease(C.CFTypeRef(data))
	return goBytesFromCFData(data), nil
}

// --- master key creation (presence-enforced) ---

// createPresenceKey generates a permanent Secure-Enclave EC key with a
// user-presence ACL: every signature with it triggers Touch ID (passcode
// fallback), enforced by the OS. Used only for the master config-signing key.
func createPresenceKey(label, tag string) error {
	cfTag, err := cfData([]byte(tag))
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cfTag))

	cfLabel, err := cfString(label)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cfLabel))

	var eref C.CFErrorRef
	flags := C.kSecAccessControlPrivateKeyUsage | C.kSecAccessControlUserPresence
	access := C.SecAccessControlCreateWithFlags(C.kCFAllocatorDefault,
		C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
		C.SecAccessControlCreateFlags(flags), &eref)
	if eref != nilCFError {
		C.CFRelease(C.CFTypeRef(eref))
		return fmt.Errorf("enclave: SecAccessControlCreateWithFlags failed")
	}
	if access == nilSecAccessControl {
		return fmt.Errorf("enclave: SecAccessControlCreateWithFlags returned nil")
	}
	defer C.CFRelease(C.CFTypeRef(access))

	privAttrs, err := cfDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecAttrAccessControl):  C.CFTypeRef(access),
		C.CFTypeRef(C.kSecAttrApplicationTag): C.CFTypeRef(cfTag),
		C.CFTypeRef(C.kSecAttrIsPermanent):    C.CFTypeRef(C.kCFBooleanTrue),
	})
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(privAttrs))

	attrs, err := cfDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecAttrLabel):       C.CFTypeRef(cfLabel),
		C.CFTypeRef(C.kSecAttrTokenID):     C.CFTypeRef(C.kSecAttrTokenIDSecureEnclave),
		C.CFTypeRef(C.kSecAttrKeyType):     C.CFTypeRef(C.kSecAttrKeyTypeEC),
		C.CFTypeRef(C.kSecPrivateKeyAttrs): C.CFTypeRef(privAttrs),
	})
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(attrs))

	privKey := C.SecKeyCreateRandomKey(attrs, &eref)
	if eref != nilCFError {
		C.CFRelease(C.CFTypeRef(eref))
		return fmt.Errorf("enclave: SecKeyCreateRandomKey(master) failed")
	}
	if privKey == nilSecKey {
		return fmt.Errorf("enclave: SecKeyCreateRandomKey(master) returned nil")
	}
	C.CFRelease(C.CFTypeRef(privKey))
	return nil
}

// --- epoch generic-password item (presence-less) ---

func epochQuery(service, account string) (map[C.CFTypeRef]C.CFTypeRef, func(), error) {
	cfService, err := cfString(service)
	if err != nil {
		return nil, nil, err
	}
	cfAccount, err := cfString(account)
	if err != nil {
		C.CFRelease(C.CFTypeRef(cfService))
		return nil, nil, err
	}
	m := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):                     C.CFTypeRef(C.kSecClassGenericPassword),
		C.CFTypeRef(C.kSecAttrService):               C.CFTypeRef(cfService),
		C.CFTypeRef(C.kSecAttrAccount):               C.CFTypeRef(cfAccount),
		C.CFTypeRef(C.kSecUseDataProtectionKeychain): C.CFTypeRef(C.kCFBooleanTrue),
	}
	release := func() {
		C.CFRelease(C.CFTypeRef(cfService))
		C.CFRelease(C.CFTypeRef(cfAccount))
	}
	return m, release, nil
}

// keychainItemGet reads a generic-password item's data. Returns (nil, nil) when
// the item does not exist.
func keychainItemGet(service, account string) ([]byte, error) {
	m, release, err := epochQuery(service, account)
	if err != nil {
		return nil, err
	}
	defer release()
	m[C.CFTypeRef(C.kSecReturnData)] = C.CFTypeRef(C.kCFBooleanTrue)
	m[C.CFTypeRef(C.kSecMatchLimit)] = C.CFTypeRef(C.kSecMatchLimitOne)

	query, err := cfDictionary(m)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(query, &result)
	if status == C.errSecItemNotFound {
		return nil, nil
	}
	if err := osError(status, "SecItemCopyMatching(epoch)"); err != nil {
		return nil, err
	}
	defer C.CFRelease(result)
	return goBytesFromCFData(C.CFDataRef(result)), nil
}

// keychainItemSet writes (insert or update) a presence-less generic-password
// item, accessible after first unlock and bound to this device only.
func keychainItemSet(service, account string, data []byte) error {
	m, release, err := epochQuery(service, account)
	if err != nil {
		return err
	}
	defer release()

	cfValue, err := cfData(data)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cfValue))

	// Try update first.
	query, err := cfDictionary(m)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	update, err := cfDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecValueData): C.CFTypeRef(cfValue),
	})
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(update))

	status := C.SecItemUpdate(query, update)
	if status == C.errSecSuccess {
		return nil
	}
	if status != C.errSecItemNotFound {
		return osError(status, "SecItemUpdate(epoch)")
	}

	// Not present: add it.
	addMap, addRelease, err := epochQuery(service, account)
	if err != nil {
		return err
	}
	defer addRelease()
	addMap[C.CFTypeRef(C.kSecValueData)] = C.CFTypeRef(cfValue)
	addMap[C.CFTypeRef(C.kSecAttrAccessible)] = C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)

	add, err := cfDictionary(addMap)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(add))

	return osError(C.SecItemAdd(add, nil), "SecItemAdd(epoch)")
}

// keychainItemDelete removes a generic-password item. Not-found is not an error.
func keychainItemDelete(service, account string) error {
	m, release, err := epochQuery(service, account)
	if err != nil {
		return err
	}
	defer release()
	query, err := cfDictionary(m)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	status := C.SecItemDelete(query)
	if status == C.errSecItemNotFound {
		return nil
	}
	return osError(status, "SecItemDelete(epoch)")
}

// --- epoch seam (macOS: an 8-byte big-endian keychain item) ---
//
// Parameterized by keychain account so the production epoch (EpochAccount) and the
// diagnostic's scratch epoch (scratchEpochAccount) share one implementation.

// scratchEpochAccount holds the _enclave-check diagnostic's throwaway epoch, kept
// separate from production so the check never disturbs a real registry.json.
const scratchEpochAccount = EpochAccount + "_selfcheck"

// epochGetAt reads an epoch keychain item; (0, false, nil) when absent.
func epochGetAt(account string) (uint64, bool, error) {
	b, err := keychainItemGet(EpochService, account)
	if err != nil {
		return 0, false, err
	}
	if b == nil {
		return 0, false, nil
	}
	if len(b) != 8 {
		return 0, false, fmt.Errorf("enclave: epoch item is %d bytes, want 8", len(b))
	}
	return binary.BigEndian.Uint64(b), true, nil
}

// epochIncrementAt advances an epoch item by one (read+1+store). Non-atomic — the
// keychain has no compare-and-swap — so it must run under the config lock (see
// ConfigCrypto.Increment). Refuses at the max rather than wrap to 0 and *persist* a
// reset counter, which would break replay protection.
func epochIncrementAt(account string) (uint64, error) {
	v, _, err := epochGetAt(account)
	if err != nil {
		return 0, err
	}
	if v == math.MaxUint64 {
		return 0, fmt.Errorf("config epoch exhausted")
	}
	next := v + 1
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], next)
	if err := keychainItemSet(EpochService, account, b[:]); err != nil {
		return 0, err
	}
	return next, nil
}

func epochGet() (uint64, bool, error) { return epochGetAt(EpochAccount) }
func epochIncrement() (uint64, error) { return epochIncrementAt(EpochAccount) }
func epochDelete() error              { return keychainItemDelete(EpochService, EpochAccount) }

// ensureEpoch is a no-op on macOS: the keychain epoch item is created lazily on the
// first Increment (read-absent ⇒ 0, then store 1), so there is nothing to provision
// up front. Only the TPM counter needs explicit provisioning. See the Linux ensureEpoch.
func ensureEpoch() error { return nil }

// Scratch-epoch seam (diagnostic only): a separate keychain account, so the
// _enclave-check round-trip exercises Epoch/Increment without touching production.
func scratchEpochEnsure() error              { return nil }
func scratchEpochGet() (uint64, bool, error) { return epochGetAt(scratchEpochAccount) }
func scratchEpochIncrement() (uint64, error) { return epochIncrementAt(scratchEpochAccount) }
func scratchEpochDelete() error              { return keychainItemDelete(EpochService, scratchEpochAccount) }
