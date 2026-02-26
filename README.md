# MDLock

> 目标：10 年后仅凭 BIP39 助记词离线恢复同一私钥并解密；不依赖特定钱包产品；加密文件保持 Markdown 稳定格式。

## 使用方法

### 1. 准备助记词环境变量

```bash
export MNEM=''
```

`mdlock-enc` / `mdlock-dec` 都通过 `-mnemonic-env` 读取环境变量名，不直接在参数里传助记词。

### 2. 编译二进制（推荐）

```bash
go build -o ./bin/mdlock-enc ./cmd/mdlock-enc
go build -o ./bin/mdlock-dec ./cmd/mdlock-dec
```

编译后可直接运行：

```bash
./bin/mdlock-enc -in docs/proxy_sol.md -mnemonic-env MNEM -index 777
./bin/mdlock-dec -in lockfile/proxy_sol.mdlock -mnemonic-env MNEM
```

### 4. 快速命令（加密 + 解密）

```bash
./bin/mdlock-dec -in lockfile/proxy_sol.mdlock -mnemonic-env MNEM
```

### 5. 输出策略（默认与覆盖）

- 不传 `-out`：默认输出到当前目录 `./lockfile/`
  - enc：`<输入文件名去扩展>.mdlock`
  - dec：`<输入文件名去 .mdlock 后缀>.dec.md`
- 传 `-out`：严格按你提供的路径输出（含 `-out -` 输出到 stdout）

示例（显式覆盖默认）：

```bash
./bin/mdlock-enc -in docs/proxy_sol.md -out ./lockfile/custom.mdlock -mnemonic-env MNEM
./bin/mdlock-dec -in lockfile/custom.mdlock -out ./lockfile/custom.dec.md -mnemonic-env MNEM
```

### 6. 字节级回环校验

```bash
cmp -s docs/proxy_sol.md lockfile/proxy_sol.dec.md && echo OK
```

### 7. 退出码约定

- `0`: 成功
- `1`: 参数/用法错误（如缺少 `-mnemonic-env`、非法 `path-override`）
- `2`: 处理失败（如助记词非法、解析失败、认证失败、I/O 失败）
