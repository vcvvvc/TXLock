package main

import (
	"flag"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv))
}

// Why(中文): enc/dec 共享同一参数失败语义，便于脚本化调用时稳定判定错误类型。
// Why(English): Keeping identical failure semantics across enc/dec provides stable automation behavior.
func run(args []string, getenv func(string) string) int {
	fs := flag.NewFlagSet("mdlock-dec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	_ = fs.String("in", "-", "")
	_ = fs.String("out", "-", "")
	mnemonicEnv := fs.String("mnemonic-env", "", "")

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
	return 0
}
