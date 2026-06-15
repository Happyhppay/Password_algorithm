# 密码算法示例参数

本文件列出前端“载入示例”使用的主要参数。对称算法覆盖 CBC、ECB、加密、解密、块加密、块解密。

## AES-128

| 操作 | 模式 | data | data_format | key | iv | output_format |
| --- | --- | --- | --- | --- | --- | --- |
| encrypt | CBC | `assignment message` | text | `00112233445566778899aabbccddeeff` | `00000000000000000000000000000000` | hex |
| decrypt | CBC | `b60eb4a0cce080b4d0e0d4d227c9abc554a3a24fb29f418d8bc49199817a17e7` | hex | `00112233445566778899aabbccddeeff` | `00000000000000000000000000000000` | text |
| encrypt | ECB | `assignment message` | text | `00112233445566778899aabbccddeeff` | - | hex |
| decrypt | ECB | `b60eb4a0cce080b4d0e0d4d227c9abc559b70671ecc8871f7b3ce8d8e069885d` | hex | `00112233445566778899aabbccddeeff` | - | text |
| encrypt_block | - | `00112233445566778899aabbccddeeff` | hex | `000102030405060708090a0b0c0d0e0f` | - | hex |
| decrypt_block | - | `69c4e0d86a7b0430d8cdb78070b4c55a` | hex | `000102030405060708090a0b0c0d0e0f` | - | hex |

## SM4

| 操作 | 模式 | data | data_format | key | iv | output_format |
| --- | --- | --- | --- | --- | --- | --- |
| encrypt | CBC | `assignment message` | text | `0123456789abcdeffedcba9876543210` | `00000000000000000000000000000000` | hex |
| decrypt | CBC | `a474d9a1967d0c837bd259dd3d73d28b106a096ac7d11e7022e2a0f5f7652ade` | hex | `0123456789abcdeffedcba9876543210` | `00000000000000000000000000000000` | text |
| encrypt | ECB | `assignment message` | text | `0123456789abcdeffedcba9876543210` | - | hex |
| decrypt | ECB | `a474d9a1967d0c837bd259dd3d73d28bb75c13b6d81d62292e568dad6dc3ba3d` | hex | `0123456789abcdeffedcba9876543210` | - | text |
| encrypt_block | - | `0123456789abcdeffedcba9876543210` | hex | `0123456789abcdeffedcba9876543210` | - | hex |
| decrypt_block | - | `681edf34d206965e86b3e94f536e4246` | hex | `0123456789abcdeffedcba9876543210` | - | hex |

## RC6

| 操作 | 模式 | data | data_format | key | iv | output_format |
| --- | --- | --- | --- | --- | --- | --- |
| encrypt | CBC | `assignment message` | text | `00112233445566778899aabbccddeeff` | `00000000000000000000000000000000` | hex |
| decrypt | CBC | `4bea59323134a7909cb611f76b22878784ab179773399f4078fa17b5be2070ab` | hex | `00112233445566778899aabbccddeeff` | `00000000000000000000000000000000` | text |
| encrypt | ECB | `assignment message` | text | `00112233445566778899aabbccddeeff` | - | hex |
| decrypt | ECB | `4bea59323134a7909cb611f76b22878749495392dcd7761d6220ad2907724be7` | hex | `00112233445566778899aabbccddeeff` | - | text |
| encrypt_block | - | `00000000000000000000000000000000` | hex | `00000000000000000000000000000000` | - | hex |
| decrypt_block | - | `8fc3a53656b1f778c129df4e9848a41e` | hex | `00000000000000000000000000000000` | - | hex |

## 其他算法

- SHA1/SHA256/SHA3/RIPEMD160：`data = abc`
- HMAC-SHA1/HMAC-SHA256：`data = abc`，`key = secret`
- PBKDF2：`password = password`，`salt = salt`，`iterations = 10000`，`dklen = 32`
- Base64 encode：`data = hello`
- Base64 decode：`data = aGVsbG8=`
- UTF-8 encode：`data = 密码`
- UTF-8 decode：`data = e5af86e7a081`，`data_format = hex`

## 公钥密码算法

前端已内置以下公钥密码示例参数，点击“载入示例”即可自动填入。

### RSA-1024bit

- `generate_keypair`：`bits = 1024`
- `encrypt`：自动填入明文 `assignment message` 和 RSA 公钥 JSON
- `decrypt`：自动填入 RSA 密文、私钥 JSON、`data_format = hex`、`output_format = text`

### RSA-SHA1

- `generate_keypair`：`bits = 1024`
- `sign`：自动填入消息 `assignment message` 和 RSA 私钥 JSON
- `verify`：自动填入消息、公钥 JSON、十六进制签名和 `signature_format = hex`

### ECC-160bit

- `generate_keypair`：无需手动参数
- `ecdh`：自动填入 Alice 私钥 JSON 和 Bob 公钥 JSON

### ECDSA

- `generate_keypair`：无需手动参数
- `sign`：自动填入消息、ECC-160 私钥 JSON 和 `hash = sha1`
- `verify`：自动填入消息、ECC-160 公钥 JSON、ECDSA 签名 JSON 和 `hash = sha1`
