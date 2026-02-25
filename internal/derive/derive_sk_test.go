package derive

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Why(中文): 先锁定参数边界错误，保证调用方可以稳定区分“输入非法”与“实现未接入”。
// Why(English): Lock input-boundary errors first so callers can reliably distinguish invalid input from unimplemented derivation.
func TestDeriveSKInvalidInput(t *testing.T) {
	_, err := DeriveSK("", "777")
	if !errorsIs(err, ErrInvalidMnemonic) {
		t.Fatalf("expected ErrInvalidMnemonic, got %v", err)
	}

	_, err = DeriveSK("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "001")
	if !errorsIs(err, ErrInvalidIndex) {
		t.Fatalf("expected ErrInvalidIndex, got %v", err)
	}
}

// Why(中文): 同一助记词与索引必须稳定映射到同一私钥，否则加解密无法闭环复现。
// Why(English): The same mnemonic/index must map to the same private key deterministically, otherwise enc/dec cannot reproduce keys.
func TestDeriveSKValidInputDeterministic(t *testing.T) {
	sk1, err := DeriveSK("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "777")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	sk2, err := DeriveSK("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "777")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(sk1) != 32 || len(sk2) != 32 {
		t.Fatalf("expected 32-byte sk, got %d and %d", len(sk1), len(sk2))
	}
	if !bytes.Equal(sk1, sk2) {
		t.Fatalf("expected deterministic sk for same input")
	}
	// Why(中文): 固定向量把实现语义冻结，后续重构必须保持与既有协议字节级一致。
	// Why(English): A fixed vector freezes behavior so future refactors must preserve byte-level protocol compatibility.
	wantHex := "b1ec885280602151c894fb7c17d076a2469ae59161d3b418c08e2ce0b2f2ef21"
	if hex.EncodeToString(sk1) != wantHex {
		t.Fatalf("unexpected sk hex: got %s want %s", hex.EncodeToString(sk1), wantHex)
	}
}

// Why(中文): 助记词词数正确但 checksum 错误时，必须在 seed 阶段被拒绝，防止无效输入进入后续派生。
// Why(English): A mnemonic with correct word count but invalid checksum must be rejected at seed stage to block invalid derivation input.
func TestDeriveSKInvalidMnemonicChecksum(t *testing.T) {
	_, err := DeriveSK("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", "777")
	if !errorsIs(err, ErrInvalidMnemonic) {
		t.Fatalf("expected ErrInvalidMnemonic, got %v", err)
	}
}

// Why(中文): 测试只关心错误语义，不关心 error 包装细节，后续接入真实派生时可保持断言稳定。
// Why(English): Tests should bind to error semantics, not wrapping details, so assertions stay stable when real derivation is wired.
func errorsIs(got error, want error) bool {
	return got == want
}
