package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"TXLOCK/internal/derive"
	"TXLOCK/internal/mdlock"
)

func fixtureMnemonic() string {
	return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
}

// Why(中文): 固定夹具可让解密命令测试专注于 CLI 流程，而非随机性带来的偶发差异。
// Why(English): A fixed fixture keeps decrypt CLI tests focused on workflow semantics instead of randomness-induced variance.
func buildFixtureEnvelope(t *testing.T, plaintext []byte) string {
	t.Helper()
	sk, err := derive.DeriveSK(fixtureMnemonic(), "777")
	if err != nil {
		t.Fatalf("derive fixture sk: %v", err)
	}
	sealed, err := mdlock.SealV1(sk, "m/44'/60'/0'/0/777", plaintext, bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatalf("seal fixture: %v", err)
	}
	ctB64 := base64.RawStdEncoding.EncodeToString(sealed.Ciphertext)
	return mdlock.BuildEnvelopeV1("m/44'/60'/0'/0/777", sealed.SaltB64, sealed.NonceB64, ctB64)
}

func TestRunMissingMnemonicEnv(t *testing.T) {
	code := run([]string{"-in", "-", "-out", "-"}, func(string) string { return "" })
	if code != 1 {
		t.Fatalf("expected 1, got %d", code)
	}
}

// Why(中文): 解密命令也要先锁定最小成功路径，保证参数层契约稳定。
// Why(English): The decrypt command also needs a locked minimal success path to keep the argument contract stable.
func TestRunSuccessWithMnemonicEnv(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.md")
	outPath := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(inPath, []byte(buildFixtureEnvelope(t, []byte("hello mdlock\n"))), 0o644); err != nil {
		t.Fatalf("write fixture input: %v", err)
	}
	code := run([]string{"-in", inPath, "-out", outPath, "-mnemonic-env", "MNEM", "-index", "777"}, func(string) string {
		return fixtureMnemonic()
	})
	if code != 0 {
		t.Fatalf("expected 0, got %d", code)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(got) != "hello mdlock\n" {
		t.Fatalf("unexpected plaintext: %q", string(got))
	}
}

// Why(中文): 篡改头字段必须触发认证/校验失败并映射到 exit 2，确保 envelope 元数据受保护。
// Why(English): Header tampering must fail validation/auth and map to exit 2 so envelope metadata remains protected.
func TestRunTamperedHeaderReturns2(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.md")
	outPath := filepath.Join(dir, "out.txt")
	raw := buildFixtureEnvelope(t, []byte("hello mdlock\n"))
	raw = strings.Replace(raw, "kdf:hkdf-sha256", "kdf:hkdf-sha1", 1)
	if err := os.WriteFile(inPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write tampered input: %v", err)
	}
	code := run([]string{"-in", inPath, "-out", outPath, "-mnemonic-env", "MNEM", "-index", "777"}, func(string) string { return fixtureMnemonic() })
	if code != 2 {
		t.Fatalf("expected 2, got %d", code)
	}
}

// Why(中文): 助记词存在但错误必须归类为处理失败 exit 2，避免与参数缺失 exit 1 混淆。
// Why(English): Present-but-wrong mnemonic must map to processing failure exit 2, distinct from missing-arg exit 1.
func TestRunWrongMnemonicReturns2(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.md")
	outPath := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(inPath, []byte(buildFixtureEnvelope(t, []byte("hello mdlock\n"))), 0o644); err != nil {
		t.Fatalf("write fixture input: %v", err)
	}
	code := run([]string{"-in", inPath, "-out", outPath, "-mnemonic-env", "MNEM", "-index", "777"}, func(string) string {
		return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	})
	if code != 2 {
		t.Fatalf("expected 2, got %d", code)
	}
}

// Why(中文): 密文区出现非 base64 字符必须被严格拒绝，否则会引入宽松解析风险。
// Why(English): Non-base64 characters in ciphertext area must be strictly rejected to avoid permissive parsing risks.
func TestRunInvalidCTBase64Returns2(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.md")
	outPath := filepath.Join(dir, "out.txt")
	raw := buildFixtureEnvelope(t, []byte("hello mdlock\n"))
	raw = strings.Replace(raw, "ct_b64:\n", "ct_b64:\n***\n", 1)
	if err := os.WriteFile(inPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write invalid ct input: %v", err)
	}
	code := run([]string{"-in", inPath, "-out", outPath, "-mnemonic-env", "MNEM", "-index", "777"}, func(string) string { return fixtureMnemonic() })
	if code != 2 {
		t.Fatalf("expected 2, got %d", code)
	}
}

// Why(中文): index 属于用法层参数，非法 index 必须映射为 exit 1 而不是处理失败。
// Why(English): Index is a usage-layer argument; invalid index must map to exit 1, not processing failure.
func TestRunInvalidIndexReturns1(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.md")
	if err := os.WriteFile(inPath, []byte(buildFixtureEnvelope(t, []byte("hello mdlock\n"))), 0o644); err != nil {
		t.Fatalf("write fixture input: %v", err)
	}
	code := run([]string{"-in", inPath, "-out", "-", "-mnemonic-env", "MNEM", "-index", "001"}, func(string) string { return fixtureMnemonic() })
	if code != 1 {
		t.Fatalf("expected 1, got %d", code)
	}
}

// Why(中文): 显式 index 必须稳定走通解密路径，确保“必填 index”策略不会破坏正常流程。
// Why(English): Explicit index must keep decryption stable so the required-index policy doesn't regress normal flow.
func TestRunValidIndexSuccess(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.md")
	outPath := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(inPath, []byte(buildFixtureEnvelope(t, []byte("hello mdlock\n"))), 0o644); err != nil {
		t.Fatalf("write fixture input: %v", err)
	}
	code := run([]string{"-in", inPath, "-out", outPath, "-mnemonic-env", "MNEM", "-index", "777"}, func(string) string { return fixtureMnemonic() })
	if code != 0 {
		t.Fatalf("expected 0, got %d", code)
	}
}

// Why(中文): 不传 -out 时默认写入当前目录 lockfile，测试可防止默认落盘位置被无意修改。
// Why(English): Without -out, output must default to cwd/lockfile; this test prevents accidental changes to default write location.
func TestRunDefaultOutToTmp(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	inPath := filepath.Join(dir, "input.lock")
	if err := os.WriteFile(inPath, []byte(buildFixtureEnvelope(t, []byte("hello mdlock\n"))), 0o644); err != nil {
		t.Fatalf("write fixture input: %v", err)
	}
	code := run([]string{"-in", inPath, "-mnemonic-env", "MNEM", "-index", "777"}, func(string) string { return fixtureMnemonic() })
	if code != 0 {
		t.Fatalf("expected 0, got %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "lockfile", "unlock", "input")); err != nil {
		t.Fatalf("expected default output in lockfile/unlock, err=%v", err)
	}
}
