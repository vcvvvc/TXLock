package main

import "strconv"

// Why(中文): 路径拼接独立成纯函数，避免在 CLI 流程里散落协议字符串，后续改版本时只改一处。
// Why(English): Keep path composition as a pure function so protocol literals stay centralized and version changes touch one place.
func buildPathFromIndex(index string) (string, bool) {

	if index == "" {
		return "", false
	}

	return "m/44'/60'/0'/0/" + index, true
}

// Why(中文): 索引校验集中化可确保所有入口遵循同一语义，避免参数层与业务层出现规则漂移。
// Why(English): Centralizing index validation guarantees identical semantics across call sites and prevents rule drift.
func validateIndex(index string) bool {
	if len(index) > 1 && index[0] == '0' {
		return false
	} else if len(index) > 0 {
		for i := 0; i < len(index); i++ {
			if (index)[i] < '0' || (index)[i] > '9' {
				return false
			}
		}
	}

	n, err := strconv.ParseInt(index, 10, 64)
	if err != nil || n > 2147483647 {
		return false
	}

	return true
}
