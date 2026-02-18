package main

import (
	"flag"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv))

}

// Why(中文): 先冻结参数与退出码语义，后续接入加密逻辑时可避免 CLI 行为漂移。
// Why(English): Locking CLI argument and exit-code semantics early prevents behavior drift when crypto logic is added later.
func run(args []string, getenv func(string) string) int {
	fs := flag.NewFlagSet("mdlock-enc", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	_ = fs.String("in", "-", "")
	_ = fs.String("out", "-", "")
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

	return 0
}
