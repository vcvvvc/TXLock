package main

import (
	"testing"
)

// Why(中文): 固定合法助记词夹具，避免“助记词非法”干扰索引规则与参数层测试目标。
// Why(English): Use one valid mnemonic fixture so index/argument tests are not polluted by mnemonic validity failures.
func fixtureMnemonic() string {
	return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
}

func TestRunMissingMnemonicEnv(t *testing.T) {
	code := run([]string{"-in", "-", "-out", "-"}, func(string) string { return "" })
	if code != 1 {
		t.Fatalf("expected 1, got %d", code)
	}
}

// Why(中文): 先验证最小成功路径，确保后续叠加业务逻辑时不会破坏基础 CLI 可用性。
// Why(English): Verifying the minimal success path early protects baseline CLI usability as logic grows.
func TestRunSuccessWithMnemonicEnv(t *testing.T) {
	code := run([]string{"-in", "-", "-out", "-", "-mnemonic-env", "MNEM"}, func(string) string {
		return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	})
	if code != 0 {
		t.Fatalf("expected 0, got %d", code)
	}
}

func TestRunSuccessWithIndex(t *testing.T) {
	code := run([]string{"-mnemonic-env", "MNEM", "-index="}, func(string) string {
		return fixtureMnemonic()

	})

	if code != 0 {
		t.Fatalf("expected 0, got %d", code)
	}
}

func TestRunInvalidIndexLeadingZero(t *testing.T) {
	code := run([]string{"-mnemonic-env", "MNEM", "-index=001"}, func(string) string {
		return fixtureMnemonic()
	})

	if code != 1 {
		t.Fatalf("expected 1, got %d", code)
	}
}

func TestRunInvalidIndexNonDecimal(t *testing.T) {
	code := run([]string{"-mnemonic-env", "MNEM", "-index=abc"}, func(string) string {
		return fixtureMnemonic()
	})

	if code != 1 {
		t.Fatalf("expected 1, got %d", code)
	}
}

func TestRunInvalidIndexOverflow(t *testing.T) {
	code := run([]string{"-mnemonic-env", "MNEM", "-index=2147483648"}, func(string) string {
		return fixtureMnemonic()
	})

	if code != 1 {
		t.Fatalf("expected 1, got %d", code)
	}
}

func TestRunValidIndexMaxBoundary(t *testing.T) {
	code := run([]string{"-mnemonic-env", "MNEM", "-index=2147483647"}, func(string) string {
		return fixtureMnemonic()
	})

	if code != 0 {
		t.Fatalf("expected 0, got %d", code)
	}
}

func TestRunMnemonicCanonicalizedEmptyReturns2(t *testing.T) {
	code := run([]string{"-mnemonic-env", "MNEM"}, func(string) string {
		return " \t "
	})

	if code != 2 {
		t.Fatalf("expected 2, got %d", code)
	}
}

func TestRunMnemonicCanonicalizedSuccess(t *testing.T) {
	code := run([]string{"-mnemonic-env", "MNEM"}, func(string) string {
		return " ABANDON abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about "
	})

	if code != 0 {
		t.Fatalf("expected 0, got %d", code)
	}
}
