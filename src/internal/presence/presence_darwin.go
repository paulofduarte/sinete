// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package presence

/*
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation -framework CoreFoundation
#include <stdlib.h>

// Implemented in presence_darwin.m. Returns 1 on success, 0 otherwise; on
// failure *err is set to a malloc'd message the caller must free.
int sinete_authenticate(const char *reason, char **err);
*/
import "C"

import (
	"errors"
	"unsafe"
)

// Authenticate runs LocalAuthentication's device-owner policy (Touch ID, with a
// passcode fallback). It blocks, pumping the run loop, until the user responds.
func Authenticate(reason string) error {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))

	var cErr *C.char
	if C.sinete_authenticate(cReason, &cErr) == 1 {
		return nil
	}
	msg := "user presence was not verified"
	if cErr != nil {
		msg = C.GoString(cErr)
		C.free(unsafe.Pointer(cErr))
	}
	return errors.New(msg)
}
