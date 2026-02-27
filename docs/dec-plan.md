# TXLock 加密方案（MVP v1，实施版）

## 1. 文档定位
- 本文定义 TXLock v1 的加密与认证实现细节。
- 派生私钥来源见 `plan-overview.md`：输入为 32-byte `sk`（叶子私钥字节）。
- 本文只定义加密方案，不定义助记词与 BIP 派生流程。

## 2. 设计目标与边界
- 目标：
  - 机密性：明文只可由持有正确助记词与路径者恢复。
  - 完整性：头字段、参数、密文任一篡改都应导致认证失败。
  - 可移植性：只依赖标准密码原语和固定常量。
- 非目标：
  - 不提供前向保密（同一 `sk` 泄露后历史可解）。
  - 不隐藏元信息（`path`、算法名在头中明文可见）。

## 3. 常量与参数（v1 冻结）
- `VERSION = "txlock:v1"`
- `KDF = "hkdf-sha256"`
- `AEAD = "aes-256-gcm"`
- `INFO = "txlock:v1|chain=ethereum|path=bip44|kdf=hkdf-sha256|aead=aes-256-gcm"`
- `salt_len = 32` bytes
- `nonce_len = 12` bytes
- 对称密钥长度：32 bytes
- Base64：`RawStdEncoding`（无 `=` padding）

## 4. 输入与输出
- 输入：
  - `sk`：32 bytes（来自 `plan-overview.md` 派生）。
  - `plaintext`：原始字节流（不规范化）。
- 输出：
  - `salt`（32 bytes）
  - `nonce`（12 bytes）
  - `ciphertext_with_tag`（`GCM.Seal` 输出）
  - 对应头字段（用于封装为 Markdown）

## 5. 封装边界与语法（严格模式，v1 冻结）
- 整个密文文件必须满足：
  - 第一个字节开始即 `<!--\n`
  - 最后结束即 `-->\n`
  - 除该注释块外不得有任何额外字节（前后都不允许）。
- 注释块内行语法：
  - 允许两类行：`txlock:v1`（magic 行）或 `key:value`（字段行）。
  - 行首与行尾禁止空白字符（空格、Tab、`\r`）。
  - `key` 与 `:` 之间、`:` 与 `value` 之间都不允许空白。
- 密文字段：
  - `ct_b64:` 为密文区起点。
  - 从 `ct_b64:` 下一行开始，直到 `-->\n` 之前的所有行都属于密文区。
  - 密文区每行必须仅包含 base64 字符集（`A-Z a-z 0-9 + /`），不得出现其他字符。
  - 解码时按“逐行拼接后一次性 RawStdEncoding 解码”处理，不做空白容忍。

## 6. 加密流程（规范）
1. 参数校验：`len(sk) == 32`，`path` 格式合法，否则失败。
2. 生成 `salt`：`crypto/rand` 读取 32 bytes。
3. 生成密钥 `K`：`HKDF-SHA256(IKM=sk, salt=salt, info=INFO)` 取前 32 bytes。
4. 生成 `nonce`：`crypto/rand` 读取 12 bytes。
5. 将 `salt` 和 `nonce` 编码为无填充 base64：`salt_b64`、`nonce_b64`。
6. 构造 AAD（见第 7 节，字节级固定）。
7. 执行 `AES-256-GCM` 加密：  
   `ct = GCM.Seal(nil, nonce, plaintext, aad)`
8. 输出 `salt`、`nonce`、`ct` 及对应头字段。

## 7. AAD 字节级格式（冻结）
- AAD 序列化必须逐字节等于以下模板（`\n` 为 ASCII 0x0A）：

```text
txlock:v1\n
chain:ethereum\n
path:<PATH>\n
kdf:hkdf-sha256\n
aead:aes-256-gcm\n
salt_b64:<SALT_B64>\n
nonce_b64:<NONCE_B64>\n
```

- 约束：
  - `<PATH>` 必须是规范形式，无额外空格。
  - `<SALT_B64>` / `<NONCE_B64>` 必须是 RawStdEncoding 规范串。
  - 验证时必须做“解码后再编码相等”检查，防止非规范等价串。

## 8. 解密流程（规范）
1. 先验证文件边界与语法（第 5 节）；不满足则立即失败。
2. 解析头字段并验证字段集合完整且无重复/未知字段。
3. 校验固定字段值：`VERSION/CHAIN/KDF/AEAD` 必须匹配 v1 常量。
4. 校验并解码 `salt_b64`、`nonce_b64`，并按第 5 节规则解码密文区。
5. 重新派生 `K`（与加密流程第 3 步一致）。
6. 用头字段重建 AAD（必须与加密规则一致）。
7. 调用 `GCM.Open(nil, nonce, ct, aad)`：
  - 成功：返回明文字节。
  - 失败：认证失败（统一处理失败语义）。

## 9. 失败语义（与 CLI 对齐）
- 参数/用法错误：`exit 1`
  - 缺失输入、`path` 非法、必填参数缺失。
- 处理失败：`exit 2`
  - 随机源失败、边界/语法非法、base64 非法、字段不匹配、认证失败、I/O 失败。
- 输出策略：失败不打印原因，仅用退出码表达。

## 10. 安全约束
- `salt` 与 `nonce` 必须来自 CSPRNG，严禁复用固定值。
- 相同 `sk` 下允许 `salt` 重复概率极低，但 `nonce` 在同一 `(K,nonce)` 上复用会破坏 GCM 安全性；实现必须确保每次加密新随机 `nonce`。
- 解密前必须先做边界与语法校验再解码，避免宽松解析导致歧义或绕过。
- 失败信息不外泄（统一错误码）以减少攻击面枚举。

## 11. 兼容性与版本升级
- 以下内容属于 v1 协议面冻结：
  - `INFO` 常量
  - 文件边界规则（必须 `<!--\n` 开始、`-->\n` 结束且无额外字节）
  - 字段行语法（仅 magic 行或 `key:value`，零空白容忍）
  - `ct_b64:` 到 `-->` 的密文区边界定义
  - AAD 字段集合及顺序
  - `AES-256-GCM`、`salt_len`、`nonce_len`
  - Base64 规范（RawStdEncoding）
- 任一项变更必须升级 `VERSION`（如 `txlock:v2`），并同时定义：
  - 新旧版本判别规则
  - 向后兼容或迁移策略
  - 对应测试向量

## 12. 测试要求（加密方案维度）
1. 固定 `sk/salt/nonce/plaintext/path` 应得到稳定 `ct`（向量测试）。
2. 仅改动 AAD 任意单字节，`GCM.Open` 必须失败。
3. `salt_b64` / `nonce_b64` 非规范编码应拒绝。
4. 同明文重复加密应产生不同 `nonce` 与不同密文（概率性测试）。
5. CRLF/LF 输入在字节保持层面可正确 round-trip。
6. 文件前后追加任意字节必须失败。
7. 字段行出现行首/行尾空白或 `key: value` 这类空白变体必须失败。
8. `ct_b64:` 后混入非 base64 字符必须失败。

### 12.1 测试向量输入策略（最小集）
- 助记词与路径：测试夹具固定 1 条 English 助记词，路径固定 `m/44'/60'/0'/0/777`。
- `salt/nonce`：仅在测试中允许注入固定字节值以获得稳定 `ct` 断言；生产路径必须始终使用 `crypto/rand`。
- 参数范围：除 `--index` 外不引入新业务参数；测试覆盖基于现有 CLI 参数与固定夹具。
- 文件级输入：`docs/proxy-sol.md` 作为 Markdown 明文样本参与 round-trip 与封装边界测试。
