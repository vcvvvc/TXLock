package mdlock

import (
	"encoding/base64"
	"strings"
)

// Why(中文): 密文区固定 76 列换行是协议稳定面的核心之一，先独立函数可避免后续封装时行宽漂移。
// Why(English): Fixed 76-char wrapping is part of protocol stability; isolating it prevents width drift in envelope building.
func wrapB64Lines76(raw string) []string {
	if raw == "" {
		return []string{""}
	}
	out := make([]string, 0, (len(raw)+75)/76)
	for i := 0; i < len(raw); i += 76 {
		end := i + 76
		if end > len(raw) {
			end = len(raw)
		}
		out = append(out, raw[i:end])
	}
	return out
}

// Why(中文): 严格序列化入口集中化可确保字段顺序、边界与换行规则在所有调用点完全一致。
// Why(English): Centralizing strict envelope serialization guarantees identical field order, boundaries, and newline rules across call sites.
func BuildEnvelopeV1(path string, saltB64 string, nonceB64 string, ctB64 string) string {
	var b strings.Builder
	b.WriteString("<!--\nmdlock:v1\nchain:ethereum\npath:")
	b.WriteString(path)
	b.WriteString("\nkdf:hkdf-sha256\naead:aes-256-gcm\nsalt_b64:")
	b.WriteString(saltB64)
	b.WriteString("\nnonce_b64:")
	b.WriteString(nonceB64)
	b.WriteString("\nct_b64:\n")
	for _, line := range wrapB64Lines76(ctB64) {
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("-->\n")
	return b.String()
}

// Why(中文): 解析前先做字节级边界校验，阻断注释块前后附加垃圾字节带来的歧义输入。
// Why(English): Enforce byte-level boundaries before parsing to reject ambiguous inputs with extra bytes around the comment block.
func extractEnvelopeBodyV1(raw string) (string, bool) {
	if len(raw) < len("<!--\n-->\n") {
		return "", false
	}
	if raw[:5] != "<!--\n" || raw[len(raw)-4:] != "-->\n" {
		return "", false
	}
	return raw[5 : len(raw)-4], true
}

// Why(中文): 头字段解析必须在语法层零容忍，避免宽松解析把“看起来相同”的输入映射成不同安全语义。
// Why(English): Header parsing must be zero-tolerance at syntax level to avoid loose normalization of security-sensitive inputs.
func parseHeaderKVV1(body string) (map[string]string, []string, bool) {
	lines := strings.Split(body, "\n")
	if len(lines) < 9 || lines[0] != "mdlock:v1" || lines[len(lines)-1] != "" {
		return nil, nil, false
	}
	out := map[string]string{}
	i := 1
	for ; i < len(lines)-1; i++ {
		line := lines[i]
		if line == "ct_b64:" {
			i++
			break
		}
		if line == "" || strings.Contains(line, " ") || strings.Contains(line, "\t") || strings.Count(line, ":") != 1 {
			return nil, nil, false
		}
		kv := strings.SplitN(line, ":", 2)
		if _, exists := out[kv[0]]; exists {
			return nil, nil, false
		}
		switch kv[0] {
		case "chain", "path", "kdf", "aead", "salt_b64", "nonce_b64":
			out[kv[0]] = kv[1]
		default:
			return nil, nil, false
		}
	}
	if i >= len(lines)-1 {
		return nil, nil, false
	}
	return out, lines[i : len(lines)-1], true
}

// Why(中文): 密文区必须按“逐行拼接后一次性 RawStdEncoding 解码”处理，避免宽松逐行解码引入歧义。
// Why(English): Ciphertext lines must be joined then decoded once via RawStdEncoding to avoid ambiguity from loose per-line decoding.
func decodeCTLinesRawB64(lines []string) ([]byte, bool) {
	if len(lines) == 0 {
		return nil, false
	}
	var b strings.Builder
	for _, line := range lines {
		if line == "" || strings.Contains(line, "=") || strings.Contains(line, " ") || strings.Contains(line, "\t") {
			return nil, false
		}
		for i := 0; i < len(line); i++ {
			c := line[i]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
				return nil, false
			}
		}
		b.WriteString(line)
	}
	out, err := base64.RawStdEncoding.DecodeString(b.String())
	if err != nil {
		return nil, false
	}
	return out, true
}

// Why(中文): 总入口集中串联严格边界、字段与密文校验，确保调用方只能拿到已通过协议约束的结构化结果。
// Why(English): Centralize strict boundary/header/ciphertext checks so callers only receive protocol-conformant structured output.
func ParseEnvelopeV1(raw string) (string, string, string, []byte, bool) {
	body, ok := extractEnvelopeBodyV1(raw)
	if !ok {
		return "", "", "", nil, false
	}
	h, ctLines, ok := parseHeaderKVV1(body)
	if !ok {
		return "", "", "", nil, false
	}
	if h["chain"] != "ethereum" || h["kdf"] != "hkdf-sha256" || h["aead"] != "aes-256-gcm" {
		return "", "", "", nil, false
	}
	ct, ok := decodeCTLinesRawB64(ctLines)
	if !ok {
		return "", "", "", nil, false
	}
	return h["path"], h["salt_b64"], h["nonce_b64"], ct, true
}
