package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"MDLOCK/internal/derive"
	"MDLOCK/internal/mdlock"
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

// Why(中文): 该用例锁定 CRLF 字节级回环，确保 enc 输出的 envelope 能被协议层完整恢复，不发生换行归一化漂移。
// Why(English): This case locks byte-level CRLF round-trip so enc-generated envelopes can be fully recovered without newline normalization drift.
func TestRunRoundTripCRLFViaEnvelope(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.txt")
	outPath := filepath.Join(dir, "out.md")
	plain := "line1\r\nline2\r\n"
	if err := os.WriteFile(inPath, []byte(plain), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	code := run([]string{"-in", inPath, "-out", outPath, "-mnemonic-env", "MNEM"}, func(string) string { return fixtureMnemonic() })
	if code != 0 {
		t.Fatalf("expected 0, got %d", code)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	path, saltB64, nonceB64, ct, ok := mdlock.ParseEnvelopeV1(string(raw))
	if !ok {
		t.Fatalf("expected parse success")
	}
	index := "777"
	openPath := "m/44'/60'/0'/0/777"
	if path != "" {
		index = strings.TrimPrefix(path, "m/44'/60'/0'/0/")
		openPath = path
	}
	sk, err := derive.DeriveSK(fixtureMnemonic(), index)
	if err != nil {
		t.Fatalf("derive sk: %v", err)
	}
	got, err := mdlock.OpenV1(sk, openPath, saltB64, nonceB64, ct)
	if err != nil || string(got) != plain {
		t.Fatalf("round-trip mismatch, err=%v got=%q", err, string(got))
	}
}

// Why(中文): 不传 -out 时必须落在当前目录 lockfile，测试固定该默认策略避免未来行为漂移。
// Why(English): Omitted -out must write under cwd/lockfile; this test freezes default-output behavior against future drift.
func TestRunDefaultOutToTmp(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	inPath := filepath.Join(dir, "input.md")
	if err := os.WriteFile(inPath, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	code := run([]string{"-in", inPath, "-mnemonic-env", "MNEM"}, func(string) string { return fixtureMnemonic() })
	if code != 0 {
		t.Fatalf("expected 0, got %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "lockfile", "lock", "input.md.lock")); err != nil {
		t.Fatalf("expected default output in lockfile/lock, err=%v", err)
	}
}
