# TXLock

> 仅凭 BIP39/44 助记词离线加解密工具。
> 凭助记词+path+index 稳定恢复并解密。
> 不依赖特定钱包产品，正常生成的 ETH 钱包即可；输入支持任意文本格式（如 `.txt/.md/.json`），输出统一为 `.lock` 容器文件。

## 使用方法

## 1. 准备助记词环境变量(12/24位)

```bash
export MNEM='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
export MNEM='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'

```

`txlock-enc` / `txlock-dec` 都通过 `-mnemonic-env` 读取环境变量名，不直接在参数里传助记词。

### 2. 直接运行（go run）

```bash
go run ./cmd/txlock-enc -in docs/test-vectors.md -mnemonic-env MNEM -index 777
go run ./cmd/txlock-dec -in lockfile/lock/test-vectors.md.lock -mnemonic-env MNEM -index 777
```

### 3. 可选：编译二进制

```bash
go build -o ./bin/txlock-enc ./cmd/txlock-enc
go build -o ./bin/txlock-dec ./cmd/txlock-dec

./bin/txlock-enc -in docs/test-vectors.md -mnemonic-env MNEM -index 777
./bin/txlock-dec -in lockfile/lock/test-vectors.md.lock -mnemonic-env MNEM -index 777
```

### 4. 输出策略（默认与覆盖）

- 不传 `-out`：默认输出到当前目录 `./lockfile/`
  - enc：`./lockfile/lock/<输入文件名>.lock`
  - dec：`./lockfile/unlock/<输入文件名去 .lock 后缀>`
- 传 `-out`：严格按你提供的路径输出（含 `-out -` 输出到 stdout）

示例（显式覆盖默认）：

```bash
./bin/txlock-enc -in docs/test-vectors.md -out ./lockfile/lock/custom.lock -mnemonic-env MNEM
./bin/txlock-dec -in lockfile/lock/custom.lock -out ./lockfile/unlock/custom -mnemonic-env MNEM -index 777
```

### 5. 字节级回环校验

```bash
cmp -s docs/test-vectors.md lockfile/unlock/test-vectors.md && echo OK
```

### 6. 全局安装(可选)

```bash
sudo install -m 0755 bin/txlock-enc /usr/local/bin/txlock-enc && sudo install -m 0755 bin/txlock-dec /usr/local/bin/txlock-dec 
```

### 7. 错误码

- `0`: 成功
- `1`: 参数/用法错误（如缺少 `-mnemonic-env`、缺少/非法 `-index`）
- `2`: 处理失败（如助记词非法、解析失败、认证失败、I/O 失败）
