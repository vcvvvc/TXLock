package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"TXLOCK/internal/derive"
	"TXLOCK/internal/mdlock"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv))
}

// Why(中文): enc/dec 共享同一参数失败语义，便于脚本化调用时稳定判定错误类型。
// Why(English): Keeping identical failure semantics across enc/dec provides stable automation behavior.
func run(args []string, getenv func(string) string) int {
	fs := flag.NewFlagSet("txlock-dec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	inPath := fs.String("in", "-", "")
	outPath := fs.String("out", "", "")
	mnemonicEnv := fs.String("mnemonic-env", "", "")
	decIndex := fs.String("index", "", "")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			printDecUsage()
			return 0
		}
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
		return failDecUsage("-mnemonic-env is required")
	}
	rawMnemonic := getenv(*mnemonicEnv)
	if rawMnemonic == "" {
		return failDecUsage("mnemonic env is empty: " + *mnemonicEnv)
	}
	mnemonicCanonical, ok := canonicalizeMnemonic(rawMnemonic)
	if !ok {
		return failDecProcess("invalid mnemonic")
	}
	raw, err := readInputBytes(*inPath)
	if err != nil {
		return failDecProcess("read input failed")
	}
	if *decIndex == "" {
		return failDecUsage("-index is required")
	}
	if !validateIndex(*decIndex) {
		return failDecUsage("invalid -index: " + *decIndex)
	}
	path, ok := buildPathFromIndex(*decIndex)
	if !ok {
		return failDecUsage("failed to build path from -index: " + *decIndex)
	}
	_, saltB64, nonceB64, ct, ok := mdlock.ParseEnvelopeV1(string(raw))
	if !ok {
		return failDecProcess("invalid envelope")
	}
	sk, err := derive.DeriveSK(mnemonicCanonical, *decIndex)
	if err != nil {
		return failDecProcess("derive key failed")
	}
	plain, err := mdlock.OpenV1(sk, path, saltB64, nonceB64, ct)
	if err != nil {
		return failDecProcess("decrypt failed (index/mnemonic mismatch or tampered data)")
	}
	if err := writeOutputBytes(*outPath, plain); err != nil {
		return failDecProcess("write output failed")
	}
	return 0
}

// Why(中文): 参数类失败打印明确 stderr 诊断，避免用户只看到退出码却误以为命令未报错。
// Why(English): Print explicit stderr diagnostics for usage failures so users don't mistake silent exit codes for success.
func failDecUsage(msg string) int {
	_, _ = io.WriteString(os.Stderr, "txlock-dec: "+msg+"\n")
	return 1
}

// Why(中文): 处理层失败也输出明确 stderr，避免解密失败只剩退出码导致排障成本上升。
// Why(English): Emit explicit stderr on processing failures so decrypt errors are diagnosable without relying on exit code alone.
func failDecProcess(msg string) int {
	_, _ = io.WriteString(os.Stderr, "txlock-dec: "+msg+"\n")
	return 2
}

// Why(中文): dec 与 enc 保持一致的帮助输出策略，避免用户在禁用默认 flag 输出时无法发现参数约定。
// Why(English): Keep dec help behavior aligned with enc so users can discover flags even when default flag output is suppressed.
func printDecUsage() {
	fmt.Fprintln(os.Stdout, "Usage: txlock-dec -mnemonic-env ENV -index N [-in PATH|-] [-out PATH|-]")
	fmt.Fprintln(os.Stdout, "Flags:")
	fmt.Fprintln(os.Stdout, "  -mnemonic-env string   环境变量名，变量值为助记词 (required)")
	fmt.Fprintln(os.Stdout, "  -index string          派生索引 (required)")
	fmt.Fprintln(os.Stdout, "  -in string             输入文件路径，默认 - (stdin)")
	fmt.Fprintln(os.Stdout, "  -out string            输出文件路径，默认 ./lockfile/unlock/<name-without-.lock>")
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

// Why(中文): 解密侧统一由 index 构造 path，避免依赖信封内 path 字段导致可恢复性和参数语义不一致。
// Why(English): Build path from index on decrypt so behavior no longer depends on envelope path presence or format.
func buildPathFromIndex(index string) (string, bool) {
	const prefix = "m/44'/60'/0'/0/"
	if !validateIndex(index) {
		return "", false
	}
	return prefix + index, true
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

// Why(中文): 默认把解密产物落到 unlock 子目录，与密文产物隔离，便于人工与脚本按目录分流。
// Why(English): Put decrypted artifacts under unlock subdir so plaintext/ciphertext are separated for both humans and automation.
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
	dir := filepath.Join(".", "lockfile", "unlock")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}
