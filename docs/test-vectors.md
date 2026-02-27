# MDLOCK v1 测试夹具（最小集）

## 1. 固定输入
- `mnemonic`（English, 12 词）  
  `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`
- `index`  
  `777`
- `path`  
  `m/44'/60'/0'/0/777`
- `passphrase`  
  `""`（空串，按 v1 冻结）

## 2. 固定加密向量输入（仅测试）
- `salt_hex`（32 bytes）  
  `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- `nonce_hex`（12 bytes）  
  `00112233445566778899aabb`
- `plaintext_utf8`  
  `hello mdlock\n`

## 3. 约束
- `salt_hex` 与 `nonce_hex` 仅用于测试向量，生产实现必须始终使用 `crypto/rand`。
- 测试断言按规范固定：`RawStdEncoding`、AAD 模板、严格注释边界与字段语法。
- `docs/proxy-sol.md` 作为待加密明文语料库，可包含多种格式输入，用于 round-trip 与解析稳定性测试。
- 本文件仅承载“确定性向量夹具”；不要把 `docs/proxy-sol.md` 的业务文本内容复制到这里。
