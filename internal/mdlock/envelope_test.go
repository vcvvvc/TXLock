package mdlock

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// Why(中文): 先冻结分行行为，后续 builder 只需复用该函数即可保证输出行宽恒定。
// Why(English): Freeze line-wrapping behavior first so builder can reuse it and keep output width stable.
func TestWrapB64Lines76(t *testing.T) {
	s := ""
	for i := 0; i < 80; i++ {
		s += "a"
	}
	got := wrapB64Lines76(s)
	if len(got) != 2 || len(got[0]) != 76 || len(got[1]) != 4 {
		t.Fatalf("unexpected wrapped layout: %#v", got)
	}
}

// Why(中文): 先冻结 Builder 的输出骨架，后续 Parser 才能基于稳定格式做严格解析。
// Why(English): Freeze builder output skeleton first so parser can enforce strict rules against a stable format.
func TestBuildEnvelopeV1Shape(t *testing.T) {
	ct := ""
	for i := 0; i < 80; i++ {
		ct += "A"
	}
	got := BuildEnvelopeV1("m/44'/60'/0'/0/777", "saltx", "noncey", ct)
	if got[:5] != "<!--\n" || got[len(got)-4:] != "-->\n" {
		t.Fatalf("unexpected envelope boundary: %q", got)
	}
	if !strings.Contains(got, "\nct_b64:\n") || !strings.Contains(got, "salt_b64:saltx\nnonce_b64:noncey\n") {
		t.Fatalf("missing required header fields: %q", got)
	}
	if !strings.Contains(got, "\n"+ct[:76]+"\n"+ct[76:]+"\n") {
		t.Fatalf("unexpected ct wrapping: %q", got)
	}
}

// Why(中文): 边界规则是严格解析第一关，必须拒绝任何前后额外字节以消除输入歧义。
// Why(English): Boundary checks are parser gate #1 and must reject any extra prefix/suffix bytes to eliminate ambiguity.
func TestExtractEnvelopeBodyV1Boundary(t *testing.T) {
	raw := BuildEnvelopeV1("m/44'/60'/0'/0/777", "saltx", "noncey", "abc")
	body, ok := extractEnvelopeBodyV1(raw)
	if !ok || body == "" {
		t.Fatalf("expected valid envelope body extraction")
	}
	if _, ok := extractEnvelopeBodyV1("x" + raw); ok {
		t.Fatalf("expected reject for prefixed bytes")
	}
	if _, ok := extractEnvelopeBodyV1(raw + "x"); ok {
		t.Fatalf("expected reject for suffixed bytes")
	}
}

// Why(中文): 同时覆盖成功路径与典型非法变体，确保 parser 在协议边界上“只接受一种写法”。
// Why(English): Cover success and canonical invalid variants together so parser enforces a single accepted wire format.
func TestParseHeaderKVV1Strict(t *testing.T) {
	raw := BuildEnvelopeV1("m/44'/60'/0'/0/777", "saltx", "noncey", "abc")
	body, ok := extractEnvelopeBodyV1(raw)
	if !ok {
		t.Fatalf("expected extract ok")
	}
	h, ct, ok := parseHeaderKVV1(body)
	if !ok || h["kdf"] != "hkdf-sha256" || h["aead"] != "aes-256-gcm" || len(ct) != 1 || ct[0] != "abc" {
		t.Fatalf("unexpected parse result")
	}
	badSpace := strings.Replace(raw, "kdf:hkdf-sha256", "kdf: hkdf-sha256", 1)
	if b, ok := extractEnvelopeBodyV1(badSpace); ok {
		if _, _, ok := parseHeaderKVV1(b); ok {
			t.Fatalf("expected reject for whitespace variant")
		}
	}
	badDup := strings.Replace(raw, "\nct_b64:\n", "\nkdf:hkdf-sha256\nct_b64:\n", 1)
	if b, ok := extractEnvelopeBodyV1(badDup); ok {
		if _, _, ok := parseHeaderKVV1(b); ok {
			t.Fatalf("expected reject for duplicate field")
		}
	}
}

// Why(中文): 密文区解码规则必须严格，测试同时覆盖有效拼接与典型非法输入，防止解析宽松化。
// Why(English): Ciphertext decoding must stay strict; test both valid joins and common invalid inputs to prevent parser loosening.
func TestDecodeCTLinesRawB64(t *testing.T) {
	want := []byte("hello-mdlock")
	raw := base64.RawStdEncoding.EncodeToString(want)
	got, ok := decodeCTLinesRawB64([]string{raw[:5], raw[5:]})
	if !ok || string(got) != string(want) {
		t.Fatalf("expected valid ct decode")
	}
	if _, ok := decodeCTLinesRawB64([]string{"abc="}); ok {
		t.Fatalf("expected reject for padding")
	}
	if _, ok := decodeCTLinesRawB64([]string{"ab c"}); ok {
		t.Fatalf("expected reject for whitespace")
	}
	if _, ok := decodeCTLinesRawB64([]string{""}); ok {
		t.Fatalf("expected reject for empty line")
	}
}

// Why(中文): 入口测试要同时验证成功路径与固定常量校验，防止解析器在版本常量上出现“宽松接受”。
// Why(English): Entry-point test must verify both success and fixed-constant checks to prevent lax acceptance of protocol constants.
func TestParseEnvelopeV1(t *testing.T) {
	raw := BuildEnvelopeV1("m/44'/60'/0'/0/777", "saltx", "noncey", base64.RawStdEncoding.EncodeToString([]byte("abc")))
	path, saltB64, nonceB64, ct, ok := ParseEnvelopeV1(raw)
	if !ok || path != "" || saltB64 != "saltx" || nonceB64 != "noncey" || string(ct) != "abc" {
		t.Fatalf("unexpected parse envelope result")
	}
	bad := strings.Replace(raw, "\nct_b64:\n", "\nchain:eth\nct_b64:\n", 1)
	if _, _, _, _, ok := ParseEnvelopeV1(bad); ok {
		t.Fatalf("expected reject for chain drift")
	}
}

// Why(中文): 通过模块内 round-trip 测试锁定加密核心与 envelope 协议协同语义，防止分层改动后出现跨层不兼容。
// Why(English): Lock cross-layer compatibility with a module-level round-trip so crypto and envelope changes cannot silently diverge.
func TestEnvelopeRoundTripV1(t *testing.T) {
	sk, _ := hex.DecodeString("b1ec885280602151c894fb7c17d076a2469ae59161d3b418c08e2ce0b2f2ef21")
	ptIn := []byte("hello mdlock\n")
	sealed, err := SealV1(sk, "m/44'/60'/0'/0/777", ptIn, bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatalf("unexpected seal error: %v", err)
	}
	raw := BuildEnvelopeV1("m/44'/60'/0'/0/777", sealed.SaltB64, sealed.NonceB64, base64.RawStdEncoding.EncodeToString(sealed.Ciphertext))
	path, saltB64, nonceB64, ct, ok := ParseEnvelopeV1(raw)
	if !ok {
		t.Fatalf("unexpected parse failure")
	}
	if path == "" {
		path = "m/44'/60'/0'/0/777"
	}
	ptOut, err := OpenV1(sk, path, saltB64, nonceB64, ct)
	if err != nil {
		t.Fatalf("unexpected open error: %v", err)
	}
	if string(ptOut) != string(ptIn) {
		t.Fatalf("round-trip mismatch: %q != %q", ptOut, ptIn)
	}
}
