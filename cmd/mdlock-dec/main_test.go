package main

import "testing"

func TestRunMissingMnemonicEnv(t *testing.T) {
	code := run([]string{"-in", "-", "-out", "-"}, func(string) string { return "" })
	if code != 1 {
		t.Fatalf("expected 1, got %d", code)
	}
}

// Why(中文): 解密命令也要先锁定最小成功路径，保证参数层契约稳定。
// Why(English): The decrypt command also needs a locked minimal success path to keep the argument contract stable.
func TestRunSuccessWithMnemonicEnv(t *testing.T) {
	code := run([]string{"-in", "-", "-out", "-", "-mnemonic-env", "MNEM"}, func(string) string {
		return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	})
	if code != 0 {
		t.Fatalf("expected 0, got %d", code)
	}
}
