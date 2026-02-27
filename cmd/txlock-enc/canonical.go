package main

import "strings"

// Why(中文): 助记词规范化独立成纯函数，先把输入形态收敛为唯一表示，避免后续校验/派生阶段出现“同义输入不同结果”。
// Why(English): Keep mnemonic canonicalization as a pure function so downstream validation/derivation sees one stable representation.
func canonicalizeMnemonic(raw string) (string, bool) {
	parts := strings.Fields(raw)
	for i := range parts {
		parts[i] = strings.ToLower(parts[i])
	}
	out := strings.Join(parts, " ")
	return out, out != ""
}
