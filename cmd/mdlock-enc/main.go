package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"MDLOCK/internal/derive"
	"MDLOCK/internal/mdlock"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv))

}

// Why(中文): 先冻结参数与退出码语义，后续接入加密逻辑时可避免 CLI 行为漂移。
// Why(English): Locking CLI argument and exit-code semantics early prevents behavior drift when crypto logic is added later.
func run(args []string, getenv func(string) string) int {
	fs := flag.NewFlagSet("mdlock-enc", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	inPath := fs.String("in", "-", "")
	outPath := fs.String("out", "", "")
	mnemonicEnv := fs.String("mnemonic-env", "", "")
	encIndex := fs.String("index", "777", "")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			printEncUsage()
			return 0
		}
		return 1
	}
	if fs.NArg() != 0 {
		return 1
	}
	if *outPath == "" {
		path, err := defaultEncOutPath(*inPath)
		if err != nil {
			return 2
		}
		*outPath = path
	}
	if *mnemonicEnv == "" {
		return failEncUsage("-mnemonic-env is required")
	}
	rawMnemonic := getenv(*mnemonicEnv)
	if rawMnemonic == "" {
		return failEncUsage("mnemonic env is empty: " + *mnemonicEnv)
	}

	mnemonicCanonical, ok := canonicalizeMnemonic(rawMnemonic)
	if !ok {
		return 2
	}
	_ = mnemonicCanonical

	if *encIndex == "" {
		*encIndex = "777"
	}

	if !validateIndex(*encIndex) {
		return failEncUsage("invalid -index: " + *encIndex)
	}

	path, ok := buildPathFromIndex(*encIndex)
	if ok == false {
		return failEncUsage("failed to build path from -index: " + *encIndex)
	}

	_ = path
	sk, err := derive.DeriveSK(mnemonicCanonical, *encIndex)
	if err != nil {
		return 2
	}
	plain, err := readInputBytes(*inPath)
	if err != nil {
		return 2
	}
	sealed, err := mdlock.SealV1(sk, path, plain, rand.Reader)
	if err != nil {
		return 2
	}
	ctB64 := base64.RawStdEncoding.EncodeToString(sealed.Ciphertext)
	envelope := mdlock.BuildEnvelopeV1(path, sealed.SaltB64, sealed.NonceB64, ctB64)
	if err := writeOutputBytes(*outPath, []byte(envelope)); err != nil {
		return 2
	}

	return 0
}

// Why(中文): 参数类失败之前输出明确错误文本，避免仅靠退出码导致“看起来没报错”的误判。
// Why(English): Emit explicit usage errors before returning so failures are visible instead of relying on exit code alone.
func failEncUsage(msg string) int {
	_, _ = io.WriteString(os.Stderr, "mdlock-enc: "+msg+"\n")
	return 1
}

// Why(中文): 在保持原有退出码语义的同时，单独处理帮助请求，避免被静默丢弃造成“命令无响应”误判。
// Why(English): Handle help explicitly so usage isn't swallowed by discarded flag output while preserving existing exit-code semantics.
func printEncUsage() {
	fmt.Fprintln(os.Stdout, "Usage: mdlock-enc -mnemonic-env ENV [-in PATH|-] [-out PATH|-] [-index N]")
	fmt.Fprintln(os.Stdout, "Flags:")
	fmt.Fprintln(os.Stdout, "  -mnemonic-env string   环境变量名，变量值为助记词 (required)")
	fmt.Fprintln(os.Stdout, "  -in string             输入文件路径，默认 - (stdin)")
	fmt.Fprintln(os.Stdout, "  -out string            输出文件路径，默认 ./lockfile/lock/<name>.lock")
	fmt.Fprintln(os.Stdout, "  -index string          派生索引，默认 777")
}

// Why(中文): 把输入源选择逻辑集中化，确保文件与 stdin 两种路径遵循同一错误语义。
// Why(English): Centralize input source selection so file and stdin paths share identical error semantics.
func readInputBytes(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// Why(中文): 把输出目标选择逻辑集中化，确保文件与 stdout 两种路径遵循同一写出规则。
// Why(English): Centralize output target selection so file and stdout writes follow one consistent rule.
func writeOutputBytes(path string, data []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// Why(中文): 默认把加密产物落到 lock 子目录，和解密产物物理隔离，降低覆盖和误读风险。
// Why(English): Put encrypted artifacts under lock subdir to separate from decrypted outputs and reduce overwrite/read confusion.
func defaultEncOutPath(inPath string) (string, error) {
	name := "stdin"
	if inPath != "-" {
		base := filepath.Base(inPath)
		name = base
	}
	dir := filepath.Join(".", "lockfile", "lock")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".lock"), nil
}
