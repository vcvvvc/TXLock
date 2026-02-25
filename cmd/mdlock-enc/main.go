package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"io"
	"os"

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
	outPath := fs.String("out", "-", "")
	mnemonicEnv := fs.String("mnemonic-env", "", "")
	encIndex := fs.String("index", "777", "")

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 0 {
		return 1
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
	_ = mnemonicCanonical

	if *encIndex == "" {
		*encIndex = "777"
	}

	if !validateIndex(*encIndex) {
		return 1
	}

	path, ok := buildPathFromIndex(*encIndex)
	if ok == false {
		return 1
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
