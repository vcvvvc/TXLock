# MDLock

> 仅凭 BIP39/44 助记词离线加密工具。
> 凭助记词+path+index 稳定恢复并解密。
> 不依赖特定钱包产品，正常生成的 ETH 钱包即可；输入支持任意文本格式（如 `.txt/.md/.json`），输出统一为 `.lock` 容器文件。

## 使用方法

### 1. 准备助记词环境变量(12/24位)

```bash
export MNEM=''
```

`mdlock-enc` / `mdlock-dec` 都通过 `-mnemonic-env` 读取环境变量名，不直接在参数里传助记词。

### 2. 编译二进制（推荐）

```bash
go build -o ./bin/mdlock-enc ./cmd/mdlock-enc
go build -o ./bin/mdlock-dec ./cmd/mdlock-dec
```

编译后可直接运行测试：

```bash
./bin/mdlock-enc -in docs/proxy_sol.md -mnemonic-env MNEM -index 777
./bin/mdlock-dec -in lockfile/proxy_sol.md.lock -mnemonic-env MNEM -path-override "m/44'/60'/0'/0/777"
```

### 4. 快速命令（加密 + 解密）

```bash
./bin/mdlock-dec -in lockfile/proxy_sol.md.lock -mnemonic-env MNEM -path-override "m/44'/60'/0'/0/777"
```

### 5. 输出策略（默认与覆盖）

- 不传 `-out`：默认输出到当前目录 `./lockfile/`
  - enc：`<输入文件名>.lock`（例如 `proxy_sol.md.lock`）
  - dec：`<输入文件名去 .lock 后缀>.dec.md`
- 传 `-out`：严格按你提供的路径输出（含 `-out -` 输出到 stdout）

示例（显式覆盖默认）：

```bash
./bin/mdlock-enc -in docs/proxy_sol.md -out ./lockfile/custom.lock -mnemonic-env MNEM
./bin/mdlock-dec -in lockfile/custom.lock -out ./lockfile/custom.dec.md -mnemonic-env MNEM -path-override "m/44'/60'/0'/0/777"
```

### 6. 字节级回环校验

```bash
cmp -s docs/proxy_sol.md lockfile/proxy_sol.dec.md && echo OK
```

### 7. 退出码约定

- `0`: 成功
- `1`: 参数/用法错误（如缺少 `-mnemonic-env`、非法 `path-override`）
- `2`: 处理失败（如助记词非法、解析失败、认证失败、I/O 失败）
