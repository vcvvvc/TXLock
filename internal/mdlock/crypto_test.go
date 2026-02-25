package mdlock

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Why(中文): 先锁定 HKDF 的确定性和长度约束，后续组合加密流程时可快速定位是否为 KDF 回归。
// Why(English): Lock HKDF determinism and output size early so later encryption regressions can be localized to KDF vs AEAD.
func TestHKDFSHA256Deterministic(t *testing.T) {
	k1 := hkdfSHA256([]byte("ikm"), []byte("salt"), []byte("info"), 32)
	k2 := hkdfSHA256([]byte("ikm"), []byte("salt"), []byte("info"), 32)
	if len(k1) != 32 || len(k2) != 32 {
		t.Fatalf("expected 32-byte outputs, got %d and %d", len(k1), len(k2))
	}
	for i := range k1 {
		if k1[i] != k2[i] {
			t.Fatalf("expected deterministic hkdf output")
		}
	}
}

// Why(中文): 通过精确字符串断言冻结 AAD 模板，确保协议字段与顺序不会在重构中漂移。
// Why(English): Freeze AAD fields and order with an exact string assertion so refactors cannot silently alter protocol bytes.
func TestBuildAADV1Template(t *testing.T) {
	got := string(buildAADV1("m/44'/60'/0'/0/777", "saltx", "noncey"))
	want := "mdlock:v1\n" +
		"chain:ethereum\n" +
		"path:m/44'/60'/0'/0/777\n" +
		"kdf:hkdf-sha256\n" +
		"aead:aes-256-gcm\n" +
		"salt_b64:saltx\n" +
		"nonce_b64:noncey\n"
	if got != want {
		t.Fatalf("unexpected aad template: %q", got)
	}
}

// Why(中文): 路径规则是协议兼容边界，最小集合测试能防止前导零、越界和非数字回归。
// Why(English): Path rules are a protocol-compatibility boundary; minimal cases guard against leading-zero, overflow, and non-digit regressions.
func TestIsPathV1(t *testing.T) {
	if !isPathV1("m/44'/60'/0'/0/777") || !isPathV1("m/44'/60'/0'/0/0") {
		t.Fatalf("expected valid v1 path")
	}
	if isPathV1("m/44'/60'/0'/0/001") || isPathV1("m/44'/60'/0'/0/2147483648") || isPathV1("m/44'/60'/0'/0/abc") {
		t.Fatalf("expected invalid v1 path")
	}
}

// Why(中文): KDF 结果必须稳定且长度固定，才能保证同输入的加密行为可复现并可解密。
// Why(English): KDF output must be deterministic and fixed-length to keep encryption/decryption reproducible for the same inputs.
func TestDeriveKeyV1(t *testing.T) {
	sk := make([]byte, 32)
	salt := make([]byte, 32)
	k1, ok1 := deriveKeyV1(sk, salt)
	k2, ok2 := deriveKeyV1(sk, salt)
	if !ok1 || !ok2 || len(k1) != 32 || len(k2) != 32 {
		t.Fatalf("expected two valid 32-byte keys")
	}
	for i := range k1 {
		if k1[i] != k2[i] {
			t.Fatalf("expected deterministic deriveKeyV1 output")
		}
	}
}

// Why(中文): 先锁定 SealV1 的输入与随机源失败语义，后续接入 AEAD 时可确保错误边界不漂移。
// Why(English): Freeze SealV1 input/RNG failure semantics first so AEAD integration cannot shift error boundaries.
func TestSealV1Boundaries(t *testing.T) {
	if _, err := SealV1(nil, "m/44'/60'/0'/0/777", nil, nil); err != ErrInvalidSK {
		t.Fatalf("expected ErrInvalidSK, got %v", err)
	}
	if _, err := SealV1(make([]byte, 32), "m/44'/60'/0'/0/001", nil, nil); err != ErrInvalidPath {
		t.Fatalf("expected ErrInvalidPath, got %v", err)
	}
	if _, err := SealV1(make([]byte, 32), "m/44'/60'/0'/0/777", nil, nil); err != ErrRandomRead {
		t.Fatalf("expected ErrRandomRead, got %v", err)
	}
}

// Why(中文): 固定随机源下先锁定 SealV1 的最小成功路径，后续补齐密文输出时可避免破坏基础流程。
// Why(English): Lock SealV1 minimal success path with deterministic RNG so later ciphertext wiring cannot break baseline flow.
func TestSealV1SuccessSkeleton(t *testing.T) {
	rng := bytes.NewReader(make([]byte, 64))
	got, err := SealV1(make([]byte, 32), "m/44'/60'/0'/0/777", []byte("hello"), rng)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(got.Salt) != 32 || len(got.Nonce) != 12 {
		t.Fatalf("unexpected salt/nonce lengths: %d/%d", len(got.Salt), len(got.Nonce))
	}
	if got.SaltB64 == "" || got.NonceB64 == "" {
		t.Fatalf("expected non-empty base64 fields")
	}
	if len(got.Ciphertext) != len("hello")+16 {
		t.Fatalf("unexpected ciphertext length: %d", len(got.Ciphertext))
	}
}

// Why(中文): AAD 绑定 path，固定随机输入下更改 path 必须导致密文变化，否则说明 AAD 未正确参与认证。
// Why(English): AAD binds the path; with fixed randomness, changing path must change ciphertext or AAD is not properly authenticated.
func TestSealV1AADBindsPath(t *testing.T) {
	zeros := make([]byte, 64)
	a, err := SealV1(make([]byte, 32), "m/44'/60'/0'/0/777", []byte("hello"), bytes.NewReader(zeros))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, err := SealV1(make([]byte, 32), "m/44'/60'/0'/0/778", []byte("hello"), bytes.NewReader(zeros))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatalf("expected different ciphertexts when path changes under same sk/salt/nonce")
	}
}

// Why(中文): 固定 sk/salt/nonce/plaintext 的向量断言用于冻结协议输出，防止实现细节变更导致历史数据不可解。
// Why(English): A fixed sk/salt/nonce/plaintext vector freezes protocol output and prevents regressions that break historical decryptability.
func TestSealV1DeterministicVector(t *testing.T) {
	sk, _ := hex.DecodeString("b1ec885280602151c894fb7c17d076a2469ae59161d3b418c08e2ce0b2f2ef21")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	nonce, _ := hex.DecodeString("00112233445566778899aabb")
	rnd := append(salt, nonce...)
	got, err := SealV1(sk, "m/44'/60'/0'/0/777", []byte("hello mdlock\n"), bytes.NewReader(rnd))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SaltB64 != "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" {
		t.Fatalf("unexpected salt_b64: %s", got.SaltB64)
	}
	if got.NonceB64 != "ABEiM0RVZneImaq7" {
		t.Fatalf("unexpected nonce_b64: %s", got.NonceB64)
	}
	if gotCT := base64.RawStdEncoding.EncodeToString(got.Ciphertext); gotCT != "hIXlwO1oHMmIR4zci5xu1VN2EFOm8ubLkBQpELE" {
		t.Fatalf("unexpected ct_b64: %s", gotCT)
	}
}

// Why(中文): 固定向量解密断言用于锁定 OpenV1 的协议兼容性，确保历史密文可稳定恢复原文。
// Why(English): Fixed-vector decryption locks OpenV1 protocol compatibility so historical ciphertext remains recoverable.
func TestOpenV1DeterministicVector(t *testing.T) {
	sk, _ := hex.DecodeString("b1ec885280602151c894fb7c17d076a2469ae59161d3b418c08e2ce0b2f2ef21")
	ct, _ := base64.RawStdEncoding.DecodeString("hIXlwO1oHMmIR4zci5xu1VN2EFOm8ubLkBQpELE")
	pt, err := OpenV1(
		sk,
		"m/44'/60'/0'/0/777",
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		"ABEiM0RVZneImaq7",
		ct,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pt) != "hello mdlock\n" {
		t.Fatalf("unexpected plaintext: %q", string(pt))
	}
}

// Why(中文): AAD 绑定字段任一变化都必须认证失败，否则说明协议头未被完整保护。
// Why(English): Any AAD-bound field drift must fail authentication, or protocol headers are not fully protected.
func TestOpenV1RejectsAADDrift(t *testing.T) {
	sk, _ := hex.DecodeString("b1ec885280602151c894fb7c17d076a2469ae59161d3b418c08e2ce0b2f2ef21")
	ct, _ := base64.RawStdEncoding.DecodeString("hIXlwO1oHMmIR4zci5xu1VN2EFOm8ubLkBQpELE")
	if _, err := OpenV1(sk, "m/44'/60'/0'/0/778", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "ABEiM0RVZneImaq7", ct); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt for path drift, got %v", err)
	}
}
