// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

// This file is the small macOS Security-framework layer for the one thing upstream
// sks does not expose, which the signed-registry design needs: a presence-less
// generic-password keychain item holding the registry epoch (the replay/rollback
// guard), via keychainItemGet/Set/Delete.
//
// Key enumeration and the presence-enforced master key now go through sks (see
// master.go); only the epoch item remains here.
package cryptoprocessor

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"math"
	"unsafe"
)

const (
	nilCFData       C.CFDataRef       = 0
	nilCFString     C.CFStringRef     = 0
	nilCFDictionary C.CFDictionaryRef = 0
)

// --- CoreFoundation helpers (local copies; sks's are unexported) ---

func cfString(s string) (C.CFStringRef, error) {
	b := []byte(s)
	var p *C.UInt8
	if len(b) > 0 {
		p = (*C.UInt8)(unsafe.Pointer(&b[0]))
	}
	ref := C.CFStringCreateWithBytes(C.kCFAllocatorDefault, p, C.CFIndex(len(b)), C.kCFStringEncodingUTF8, C.false)
	if ref == nilCFString {
		return nilCFString, fmt.Errorf("cryptoprocessor: CFStringCreateWithBytes failed")
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
		return nilCFData, fmt.Errorf("cryptoprocessor: CFDataCreate failed")
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
		return nilCFDictionary, fmt.Errorf("cryptoprocessor: CFDictionaryCreate failed")
	}
	return ref, nil
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
	return fmt.Errorf("cryptoprocessor: %s: OSStatus %d", op, int(status))
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
		return 0, false, fmt.Errorf("cryptoprocessor: epoch item is %d bytes, want 8", len(b))
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
