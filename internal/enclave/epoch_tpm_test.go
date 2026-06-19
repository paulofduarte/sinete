// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build tpmsim

// Exercises the platform-neutral NV monotonic-counter algorithm (epoch_tpm.go)
// against the in-process go-tpm simulator, so the tricky TPM interactions are
// verified without a real device or QEMU. Build/run with: go test -tags tpmsim
// ./internal/enclave (needs OpenSSL headers for the cgo simulator).
package enclave

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

const testNVIndex tpm2.TPMHandle = 0x018E7E70

func TestTPMCounterLifecycle(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("open simulator: %v", err)
	}
	defer sim.Close()

	// Absent: Get reports "no epoch yet".
	if v, ok, err := tpmCounterGet(sim, testNVIndex); err != nil || ok || v != 0 {
		t.Fatalf("get(absent) = %d,%v,%v; want 0,false,nil", v, ok, err)
	}

	// EnsureCounter defines + initializes it so it is readable.
	if err := tpmEnsureCounter(sim, testNVIndex); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	base, ok, err := tpmCounterGet(sim, testNVIndex)
	if err != nil || !ok {
		t.Fatalf("get(initialized) = %d,%v,%v; want value,true,nil", base, ok, err)
	}

	// Increment lands exactly on previous+1 (Config.Save's invariant), repeatedly.
	prev := base
	for i := 0; i < 3; i++ {
		got, err := tpmCounterIncrement(sim, testNVIndex)
		if err != nil {
			t.Fatalf("increment %d: %v", i, err)
		}
		if got != prev+1 {
			t.Fatalf("increment %d = %d; want %d (exactly +1)", i, got, prev+1)
		}
		if cur, _, err := tpmCounterGet(sim, testNVIndex); err != nil || cur != got {
			t.Fatalf("get after increment %d = %d,%v; want %d", i, cur, err, got)
		}
		prev = got
	}

	// Anti-rollback: delete + redefine must resume strictly above the old value,
	// never reset to the base — the whole point of a hardware counter.
	high := prev
	if err := tpmCounterDelete(sim, testNVIndex); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok, err := tpmCounterGet(sim, testNVIndex); err != nil || ok {
		t.Fatalf("get(after delete) ok=%v err=%v; want false,nil", ok, err)
	}
	if err := tpmEnsureCounter(sim, testNVIndex); err != nil {
		t.Fatalf("re-ensure: %v", err)
	}
	resumed, _, err := tpmCounterGet(sim, testNVIndex)
	if err != nil {
		t.Fatalf("get(resumed): %v", err)
	}
	if resumed <= high {
		t.Fatalf("counter rolled back: resumed=%d, was %d (must be strictly higher)", resumed, high)
	}

	// Cleanup.
	if err := tpmCounterDelete(sim, testNVIndex); err != nil {
		t.Fatalf("final delete: %v", err)
	}
}
