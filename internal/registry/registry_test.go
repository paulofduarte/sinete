// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"strings"
	"testing"
)

func TestValidName(t *testing.T) {
	valid := []string{"work", "a", "A1", "user@host", "key.1", "a_b-c+d"}
	for _, n := range valid {
		if err := ValidName(n); err != nil {
			t.Errorf("ValidName(%q) = %v, want nil", n, err)
		}
	}
	invalid := []string{
		"", "bad name", "../x", "a/b", "a:b", ".hidden", "_x", "a\nb",
		strings.Repeat("a", 129), // too long
	}
	for _, n := range invalid {
		if err := ValidName(n); err == nil {
			t.Errorf("ValidName(%q) = nil, want error", n)
		}
	}
}

func TestValidSetting(t *testing.T) {
	if !ValidSetting(PresenceTTL) || !ValidSetting(PresenceMaxTTL) {
		t.Error("known settings should be valid")
	}
	if ValidSetting("bogus") {
		t.Error("unknown setting should be invalid")
	}
}

func TestBuiltinDefault(t *testing.T) {
	if got := BuiltinDefault(PresenceTTL); got != "10m" {
		t.Errorf("BuiltinDefault(PresenceTTL) = %q, want 10m", got)
	}
	if got := BuiltinDefault(PresenceMaxTTL); got != "2h" {
		t.Errorf("BuiltinDefault(PresenceMaxTTL) = %q, want 2h", got)
	}
	if got := BuiltinDefault("bogus"); got != "" {
		t.Errorf("BuiltinDefault(unknown) = %q, want \"\"", got)
	}
	// Every recognised setting must have a built-in default to display/enforce.
	for _, s := range Settings {
		if BuiltinDefault(s) == "" {
			t.Errorf("setting %q has no built-in default", s)
		}
	}
}
