package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"MDLOCK/internal/derive"
	"MDLOCK/internal/mdlock"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv))
}

// Why(中文): enc/dec 共享同一参数失败语义，便于脚本化调用时稳定判定错误类型。
// Why(English): Keeping identical failure semantics across enc/dec provides stable automation behavior.
func run(args []string, getenv func(string) string) int {
	fs := flag.NewFlagSet("mdlock-dec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	inPath := fs.String("in", "-", "")
	outPath := fs.String("out", "", "")
	mnemonicEnv := fs.String("mnemonic-env", "", "")
	pathOverride := fs.String("path-override", "", "")

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 0 {
		return 1
	}
	if *outPath == "" {
		path, err := defaultDecOutPath(*inPath)
		if err != nil {
			return 2
		}
		*outPath = path
	}
	if *mnemonicEnv == "" {
		return 1
	}
	rawMnemonic := getenv(*mnemonicEnv)
	if rawMnemonic == "" {
		return 1
	}
	mnemonicCanonical, ok := canonicalizeMnemonic(rawMnemonic)
	if !ok {
		return 2
	}
	raw, err := readInputBytes(*inPath)
	if err != nil {
		return 2
	}
	path, saltB64, nonceB64, ct, ok := mdlock.ParseEnvelopeV1(string(raw))
	if !ok {
		return 2
	}
	if path == "" && *pathOverride == "" {
		return 1
	}
	if *pathOverride != "" {
		if _, ok := indexFromPathV1(*pathOverride); !ok {
			return 1
		}
		path = *pathOverride
	}
	index, ok := indexFromPathV1(path)
	if !ok {
		return 2
	}
	sk, err := derive.DeriveSK(mnemonicCanonical, index)
	if err != nil {
		return 2
	}
	plain, err := mdlock.OpenV1(sk, path, saltB64, nonceB64, ct)
	if err != nil {
		return 2
	}
	if err := writeOutputBytes(*outPath, plain); err != nil {
		return 2
	}
	return 0
}

// Why(中文): 解密侧必须复用同一助记词归一化语义，保证 enc/dec 对同义输入派生结果一致。
// Why(English): Decrypt side must reuse identical mnemonic normalization so enc/dec derive identical keys for equivalent inputs.
func canonicalizeMnemonic(raw string) (string, bool) {
	parts := strings.Fields(raw)
	for i := range parts {
		parts[i] = strings.ToLower(parts[i])
	}
	out := strings.Join(parts, " ")
	return out, out != ""
}

// Why(中文): 从协议路径中抽取 index 并复用现有索引规则，避免解密侧出现独立且漂移的路径语义。
// Why(English): Extract index from protocol path and reuse existing index rules to prevent drift from a separate path semantic.
func indexFromPathV1(path string) (string, bool) {
	const prefix = "m/44'/60'/0'/0/"
	if len(path) <= len(prefix) || path[:len(prefix)] != prefix {
		return "", false
	}
	index := path[len(prefix):]
	if !validateIndex(index) {
		return "", false
	}
	return index, true
}

// Why(中文): 复用与加密侧一致的索引边界，确保路径恢复后不会出现解密侧“额外容忍”。
// Why(English): Mirror encrypt-side index boundaries so decryption never accepts out-of-contract recovered indexes.
func validateIndex(index string) bool {
	if len(index) > 1 && index[0] == '0' {
		return false
	}
	for i := 0; i < len(index); i++ {
		if index[i] < '0' || index[i] > '9' {
			return false
		}
	}
	n, err := strconv.ParseInt(index, 10, 64)
	return err == nil && n >= 0 && n <= 2147483647
}

// Why(中文): 解密命令输入统一走该函数，确保文件与 stdin 两种来源共享同一失败语义。
// Why(English): Decrypt input goes through one function so file/stdin sources share identical failure semantics.
func readInputBytes(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// Why(中文): 解密输出统一走该函数，确保文件与 stdout 两种目标共享同一写出规则。
// Why(English): Decrypt output goes through one function so file/stdout targets share one write rule.
func writeOutputBytes(path string, data []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// Why(中文): 默认解密输出固定到当前目录 lockfile，保证不传 -out 时产物位置稳定可预期。
// Why(English): Keep default decrypt output under cwd/lockfile so artifact location is stable when -out is omitted.
func defaultDecOutPath(inPath string) (string, error) {
	name := "stdin"
	if inPath != "-" {
		base := filepath.Base(inPath)
		name = strings.TrimSuffix(base, ".lock")
		if name == base {
			name = strings.TrimSuffix(base, ".mdlock")
		}
		if name == base {
			name = strings.TrimSuffix(base, filepath.Ext(base))
		}
	}
	dir := filepath.Join(".", "lockfile")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".dec.md"), nil
}
