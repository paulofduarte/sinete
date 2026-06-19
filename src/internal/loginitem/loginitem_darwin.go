// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package loginitem

/*
#cgo LDFLAGS: -framework ServiceManagement -framework Foundation
#include <stdlib.h>

// Implemented in loginitem_darwin.m. register/unregister return 1 on success, 0
// otherwise (with *err set to a malloc'd message the caller must free). status
// returns the SMAppServiceStatus enum value (>= 0).
int sinete_loginitem_register(const char *plist, char **err);
int sinete_loginitem_unregister(const char *plist, char **err);
int sinete_loginitem_status(const char *plist);
*/
import "C"

import (
	"errors"
	"unsafe"
)

// Register enables the bundled launchd agent as a login item. It must run from
// the signed sinete.app bundle: SMAppService validates the bundle and reads its
// Contents/Library/LaunchAgents/<PlistName>.
func Register() error {
	cPlist := C.CString(PlistName)
	defer C.free(unsafe.Pointer(cPlist))
	var cErr *C.char
	if C.sinete_loginitem_register(cPlist, &cErr) == 1 {
		return nil
	}
	return cErr2Go(cErr, "could not register the login item")
}

// Unregister disables and removes the login item.
func Unregister() error {
	cPlist := C.CString(PlistName)
	defer C.free(unsafe.Pointer(cPlist))
	var cErr *C.char
	if C.sinete_loginitem_unregister(cPlist, &cErr) == 1 {
		return nil
	}
	return cErr2Go(cErr, "could not unregister the login item")
}

// Status reports the login item's registration state as one of "not registered",
// "enabled", "requires approval", "not found", or "unknown".
func Status() (string, error) {
	cPlist := C.CString(PlistName)
	defer C.free(unsafe.Pointer(cPlist))
	switch C.sinete_loginitem_status(cPlist) {
	case 0:
		return "not registered", nil
	case 1:
		return "enabled", nil
	case 2:
		return "requires approval", nil
	case 3:
		return "not found", nil
	default:
		return "unknown", nil
	}
}

func cErr2Go(cErr *C.char, fallback string) error {
	msg := fallback
	if cErr != nil {
		msg = C.GoString(cErr)
		C.free(unsafe.Pointer(cErr))
	}
	return errors.New(msg)
}
