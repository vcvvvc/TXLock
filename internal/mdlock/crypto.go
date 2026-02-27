package mdlock

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
)

const infoV1 = "txlock:v1|chain=ethereum|path=bip44|kdf=hkdf-sha256|aead=aes-256-gcm"

var (
	ErrInvalidSK   = errors.New("invalid sk")
	ErrInvalidPath = errors.New("invalid path")
	ErrRandomRead  = errors.New("random read failed")
	ErrEncrypt     = errors.New("encrypt failed")
	ErrDecrypt     = errors.New("decrypt failed")
)

type SealResult struct {
	Salt       []byte
	Nonce      []byte
	Ciphertext []byte
	SaltB64    string
	NonceB64   string
}

// Why(中文): 先独立 HKDF 基元，确保后续加密流程可以复用并用固定向量单测锁定字节语义。
// Why(English): Isolate the HKDF primitive first so encryption flow can reuse it and vector tests can lock byte-level behavior.
func hkdfSHA256(ikm []byte, salt []byte, info []byte, size int) []byte {
	prkMAC := hmac.New(sha256.New, salt)
	_, _ = prkMAC.Write(ikm)
	prk := prkMAC.Sum(nil)
	out := make([]byte, 0, size)
	var t []byte
	for i := byte(1); len(out) < size; i++ {
		h := hmac.New(sha256.New, prk)
		_, _ = h.Write(t)
		_, _ = h.Write(info)
		_, _ = h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:size]
}

// Why(中文): AAD 模板必须字节级冻结，单独函数化可避免后续拼接顺序或换行误改导致解密不兼容。
// Why(English): Keep AAD serialization frozen in one function to prevent accidental ordering/newline drift that breaks compatibility.
func buildAADV1(path string, saltB64 string, nonceB64 string) []byte {
	return []byte("txlock:v1\n" +
		"chain:ethereum\n" +
		"path:" + path + "\n" +
		"kdf:hkdf-sha256\n" +
		"aead:aes-256-gcm\n" +
		"salt_b64:" + saltB64 + "\n" +
		"nonce_b64:" + nonceB64 + "\n")
}

// Why(中文): 路径校验要在加密前收口，避免把非法路径写入 AAD 后形成无法恢复的协议垃圾数据。
// Why(English): Validate path before encryption so malformed paths never enter AAD and produce unrecoverable protocol garbage.
func isPathV1(path string) bool {
	const prefix = "m/44'/60'/0'/0/"
	if len(path) <= len(prefix) || path[:len(prefix)] != prefix {
		return false
	}
	index := path[len(prefix):]
	if len(index) > 1 && index[0] == '0' {
		return false
	}
	var n uint64
	for i := 0; i < len(index); i++ {
		c := index[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + uint64(c-'0')
		if n > 2147483647 {
			return false
		}
	}
	return len(index) > 0
}

// Why(中文): 对称密钥派生独立成一步，后续 AES-GCM 流程只消费固定长度的 K，减少职责耦合。
// Why(English): Isolate symmetric-key derivation so AES-GCM flow consumes a fixed-length K with minimal coupling.
func deriveKeyV1(sk []byte, salt []byte) ([]byte, bool) {
	if len(sk) != 32 || len(salt) != 32 {
		return nil, false
	}
	return hkdfSHA256(sk, salt, []byte(infoV1), 32), true
}

// Why(中文): 先冻结 SealV1 的输入校验与随机源边界，后续逐步填充 AEAD 细节时不改变外部契约。
// Why(English): Freeze SealV1 validation and RNG boundaries first, then fill AEAD internals incrementally without changing the contract.
func SealV1(sk []byte, path string, plaintext []byte, random io.Reader) (*SealResult, error) {
	if len(sk) != 32 {
		return nil, ErrInvalidSK
	}
	if !isPathV1(path) {
		return nil, ErrInvalidPath
	}
	if random == nil {
		return nil, ErrRandomRead
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, ErrRandomRead
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, ErrRandomRead
	}
	key, ok := deriveKeyV1(sk, salt)
	if !ok {
		return nil, ErrInvalidSK
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrEncrypt
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrEncrypt
	}
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	nonceB64 := base64.RawStdEncoding.EncodeToString(nonce)
	aad := buildAADV1(path, saltB64, nonceB64)
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	return &SealResult{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ct,
		SaltB64:    saltB64,
		NonceB64:   nonceB64,
	}, nil
}

// Why(中文): 解密与加密必须共享同一 KDF/AAD 语义，否则即使参数正确也会出现不可恢复的数据分叉。
// Why(English): Decryption must share the exact KDF/AAD semantics with sealing, or valid inputs diverge into unrecoverable states.
func OpenV1(sk []byte, path string, saltB64 string, nonceB64 string, ciphertext []byte) ([]byte, error) {
	if len(sk) != 32 {
		return nil, ErrInvalidSK
	}
	if !isPathV1(path) {
		return nil, ErrInvalidPath
	}
	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil || len(salt) != 32 {
		return nil, ErrDecrypt
	}
	nonce, err := base64.RawStdEncoding.DecodeString(nonceB64)
	if err != nil || len(nonce) != 12 {
		return nil, ErrDecrypt
	}
	key, ok := deriveKeyV1(sk, salt)
	if !ok {
		return nil, ErrInvalidSK
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecrypt
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecrypt
	}
	aad := buildAADV1(path, saltB64, nonceB64)
	pt, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
