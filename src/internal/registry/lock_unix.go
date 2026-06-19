// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package registry

import (
	"os"
	"syscall"
)

// lockConfig takes an exclusive advisory lock on "<path>.lock", returning an
// unlock function. It serialises concurrent config writers so the epoch read →
// sign → write → advance sequence is atomic (no two writers share an epoch).
func lockConfig(path string) (func(), error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	// flock can be interrupted by a signal (EINTR); retry rather than fail.
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err == nil {
			break
		}
		if err == syscall.EINTR {
			continue
		}
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
