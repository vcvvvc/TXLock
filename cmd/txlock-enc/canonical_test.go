package main

import "testing"

func TestCanonicalizeMnemonicNormalizeWhitespaceAndCase(t *testing.T) {
	got, ok := canonicalizeMnemonic("ABANDON abandon \tABOUT ")
	if !ok {
		t.Fatalf("expected ok = true")
	}
	if got != "abandon abandon about" {
		t.Fatalf("unexpected canonical mnemonic: %q", got)
	}

}

func TestCanonicalizeMnemonicEmptyInvalid(t *testing.T) {

	got, ok := canonicalizeMnemonic("")
	if ok {
		t.Fatalf("expected ok = false")
	}

	if got != "" {
		t.Fatalf("unexpected canonical mnemonic: %q", got)
	}
}

func TestCanonicalizeMnemonicWhitespaceOnlyInvalid(t *testing.T) {
	got, ok := canonicalizeMnemonic(" \t")
	if ok {
		t.Fatalf("expected ok = false")
	}

	if got != "" {
		t.Fatalf("unexpected canonical mnemonic: %q", got)
	}
}

func TestCanonicalizeMnemonicAlreadyCanonical(t *testing.T) {
	got, ok := canonicalizeMnemonic("abandon abandon abandon")
	if !ok {
		t.Fatalf("expected ok = true")
	}

	if got != "abandon abandon abandon" {
		t.Fatalf("expected non-empty string")
	}
}
