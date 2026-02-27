package main

import "testing"

func TestBuildPathFromIndex777(t *testing.T) {
	path, ok := buildPathFromIndex("777")
	if !ok {
		t.Fatalf("expected ok=true")
	}
	if path != "m/44'/60'/0'/0/777" {
		t.Fatalf("unexpected path: %s", path)
	}
}

func TestValidateIndexZero(t *testing.T) {
	if !validateIndex("0") {
		t.Fatalf("expected true for index 0")
	}
}

func TestBuildPathFromIndexEmpty(t *testing.T) {
	path, ok := buildPathFromIndex("")

	if ok {
		t.Fatalf("expected ok=false for empty index")
	}
	if path != "" {
		t.Fatalf("expected empty path, got %q", path)
	}
}
