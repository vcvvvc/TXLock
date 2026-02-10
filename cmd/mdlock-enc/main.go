package main

import (
	"flag"
	"io"
	"os"
	"strconv"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv))

}

func buildPathFromIndex(index string) (string, bool) {

	if index == "" {
		return "", false
	}

	return "m/44'/60'/0'/0/" + index, true
}

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
	if getenv(*mnemonicEnv) == "" {
		return 1
	}

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
