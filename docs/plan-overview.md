# TXLock 计划（MVP v1，精简版）

> 目标：10 年后仅凭 BIP39 助记词离线恢复同一私钥并解密；不依赖特定钱包产品；加密文件保持 Markdown 稳定格式。

## 1. 不可变约束（v1 冻结）
- 仅依赖公开标准：BIP39 / BIP32 / BIP44（coin type = 60）。
- BIP39 passphrase 固定为空串 `""`。
- 路径族固定：`m/44'/60'/0'/0/i`（`i` 为十进制非负整数, 默认i = 777）。
- 参数自包含：文件头必须保存完整 `path`，恢复不依赖“记忆路径”。
- 运行必须支持纯离线（不依赖网络或第三方服务）。

## 2. 密钥派生规则（v1）
- 输入：BIP39 English 助记词（仅 12 或 24 词）+ `path`。
- `canonical mnemonic`（v1 冻结）定义：
  - 对原始输入先做 Unicode NFKD。
  - 按任意空白分词。
  - 每个词转 ASCII 小写（v1 仅 English）。
  - 使用单个 ASCII 空格拼接为唯一字符串 `mnemonic_canonical`。
- 合法性：词表校验与 checksum 校验必须基于 `mnemonic_canonical`。
- `mnemonic -> seed`：严格按 BIP39（PBKDF2-HMAC-SHA512, iter=2048, dkLen=64），且 PBKDF2 的 password 必须使用 `mnemonic_canonical`（禁止使用原始输入字符串）。
- `seed -> master -> child`：严格按 BIP32 / BIP44 固定路径派生，得到 32-byte 叶子私钥 `sk`。
- `index` 规则：`0 <= i <= 2147483647`，十进制规范（除 `0` 外禁止前导零）。
- v1 不支持非 English 词表；扩展词表时必须升级版本（例如 `v2`）。

## 3. 加密构造（已迁移）
- 具体加密方案已迁移到 `dec-plan.md`，`plan-overview.md` 仅保留总览与边界约束。

## 4. 文件格式（Markdown 保证格式稳定）
- 输出为单个 HTML 注释块，头字段固定：
  - `txlock:v1`
  - `chain:ethereum`
  - `kdf:hkdf-sha256`
  - `aead:aes-256-gcm`
  - `salt_b64:<raw-base64>`
  - `nonce_b64:<raw-base64>`
  - `ct_b64:`
  - `<raw-base64 多行密文>`
- 编码约束：
  - `salt_b64` / `nonce_b64` / `ct_b64` 使用 RawStdEncoding（无 `=`）。
  - 写入时 `ct_b64` 每行 76 字符，最后一行可短。
  - 文件为 UTF-8 无 BOM，行尾 `\n`。
  - 文件必须以 `<!--\n` 开始，以 `-->\n` 结束，前后不得有任何额外字节。
- 解析约束：
  - 行必须严格为 `txlock:v1` 或 `key:value`；不允许行首/行尾空白。
  - `ct_b64:` 后直到 `-->` 的所有行都视为密文区。
  - 不允许未知字段或重复字段。
  - 任一校验失败即处理失败。

## 5. CLI（两个程序）
- `txlock-enc`：加密。
- `txlock-dec`：解密。
- 通用参数：
  - `-in <path>`（默认 `-`）
  - `-out <path>`（默认 `-`）
  - `--mnemonic-env <ENV>`
  - `--help` / `--version`
- `txlock-enc`：
  - `--index <N>`（默认 `777`）
- `txlock-dec`：
  - 默认读取文件头 `path`
  - 可选 `--path-override <PATH>`（仅用于救援覆盖，非法则参数错误）

## 6. 错误与输出策略
- 退出码：
  - `0`：成功
  - `1`：参数/用法错误
  - `2`：处理失败（I/O、解析、校验、认证、解密等）
- 助记词错误归类：
  - 缺失（env 未提供或为空）=> `exit 1`
  - 存在但非法（长度/词表/checksum）=> `exit 2`
- 失败时不输出失败细节，仅依赖退出码。
- 成功时仅输出结果内容（当 `-out -`）。

## 7. 测试最小集合
1. BIP39 向量：`mnemonic -> seed` 匹配官方结果。
2. 路径派生：固定 `mnemonic + path` 得到确定 `sk`。
3. round-trip：`enc -> dec` 字节级一致（含 CRLF 输入）。
4. 篡改检测：头字段或密文任意改动必须失败（`exit 2`）。
5. 错助记词：解密失败（`exit 2`）。
6. 严格解析：文件边界异常、额外字节、字段空白变体、非 base64 密文行均必须失败。
7. 归一化一致性：大小写/多空白变体经 `mnemonic_canonical` 后必须派生相同 seed。

### 7.1 测试夹具冻结（最小集）
- 助记词：固定 1 条 English 助记词（12 或 24 词），作为 v1 测试夹具基线。
- 路径：固定 `index = 777`，即 `m/44'/60'/0'/0/777`。
- 参数策略：除 `--index` 外不新增业务参数；测试仅围绕现有参数与固定夹具展开。
- 约束：夹具助记词可用于测试与示例，禁止与任何真实资产共用。
- 职责分层：`docs/test-vectors.md` 负责确定性密码学向量；`docs/proxy-sol.md` 负责 Markdown 明文输入样本（文件级 round-trip 测试）。

## 8. 交付物
- `plan-overview.md`：本精简规范。
- `dec-plan.md`：加密方案细节（v1）。
- `docs/recovery.md`：离线恢复说明（含 BIP39/BIP32/BIP44 固定参数）。
- `cmd/txlock-enc`、`cmd/txlock-dec`：两个独立 CLI。
- `docs/test-vectors.md`：测试夹具（固定助记词与向量）。
- `docs/proxy-sol.md`：待加密明文样本（多格式语料）。
- `*_test.go`：覆盖派生、加解密、篡改、错误码。
