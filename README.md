# 网络信息安全密码算法编程

本项目按 `网络信息安全密码算法编程.md` 的技术范围实现了可见、可测、可接口调用的密码算法演示程序。

## 已实现算法

- 对称加密：AES-128、SM4、RC6-32/20/16，支持 ECB/CBC 与 PKCS#7 填充
- 哈希算法：SHA1、SHA256、SHA3-256、RIPEMD160
- 消息认证和口令派生：HMAC-SHA1、HMAC-SHA256、PBKDF2
- 编码算法：Base64、UTF-8
- 公钥密码：RSA-1024 加解密、RSA-SHA1 签名验签、ECC-160(secp160r1)、ECDSA、ECDH

## 目录结构

```text
crypto_lab/
  aes.py          AES-128 实现
  sm4.py          SM4 实现
  rc6.py          RC6 实现
  rsa.py          RSA-1024 与 RSA-SHA1
  ecc.py          ECC-160、ECDSA、ECDH
  hash_codecs.py  哈希、HMAC、PBKDF2、编码
  api.py          第三方程序统一调用接口
crypto_cli.py     命令行接口
tests.py          自检和执行结果示例
```

## 运行自检

```powershell
python tests.py
```

自检包含 AES 与 SM4 官方测试向量、RC6 往返测试、统一接口调用、哈希/编码、公钥加解密和签名验签。

## 命令行示例

AES 加密：

```powershell
python crypto_cli.py AES encrypt --data "北邮信息安全" --key 00112233445566778899aabbccddeeff --key-format hex
```

SHA256：

```powershell
python crypto_cli.py SHA256 digest --data abc
```

Base64：

```powershell
python crypto_cli.py Base64 encode --data hello
```

RSA 生成密钥：

```powershell
python crypto_cli.py RSA generate_keypair --bits 1024
```

## 第三方接口调用

Python 程序可直接调用 `crypto_lab.api.call_algorithm`：

```python
from crypto_lab.api import call_algorithm

resp = call_algorithm("SHA256", "digest", {"data": "abc"})
print(resp)
```

返回格式统一：

```json
{
  "status": 0,
  "message": "ok",
  "result": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
}
```

其中 `status = 0` 表示成功，`status = 1` 表示输入错误、算法名错误或执行失败。

也可以通过 JSON 请求调用 CLI：

```powershell
python crypto_cli.py --json "{\"algorithm\":\"SHA1\",\"operation\":\"digest\",\"params\":{\"data\":\"abc\"}}"
```

## 前端展示

启动本地 Web 演示服务：

```powershell
python web_server.py --port 8000
```

浏览器打开：

```text
http://127.0.0.1:8000
```

页面会通过 `/api/call` 调用后端算法接口，支持选择算法、切换操作、载入示例参数并查看统一 JSON 返回结果。对称加密示例覆盖 AES、SM4、RC6 的 CBC/ECB、加密/解密、块加密/块解密；公钥密码部分在前端中单独展示为 `RSA-1024bit`、`ECC-160bit`、`RSA-SHA1`、`ECDSA` 四项。

## 说明

本项目用于课程作业和算法过程展示，代码强调可读性、可测性和接口完整性。生产系统应优先使用经过安全审计的密码库，并避免自行实现底层密码算法。
