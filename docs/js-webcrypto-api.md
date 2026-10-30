# JS Web Crypto API

`Scardice-core` 提供 `crypto` 与 `crypto.subtle`。Goja 提供完整密钥、签名、加密和派生接口；QuickJS 提供随机数、UUID 与摘要接口。

完整自检脚本：[CryptoAPI测试.js](https://raw.githubusercontent.com/lyjjl/Scardice-Plugins/main/%E7%A4%BA%E4%BE%8B/CryptoAPI%E6%B5%8B%E8%AF%95.js)。

## 引擎入口与能力

| 引擎 | 入口 | `crypto.subtle` 方法 |
| --- | --- | --- |
| Goja | `globalThis.crypto`、`require("crypto")`；两者指向同一对象 | `digest`、`generateKey`、`importKey`、`exportKey`、`sign`、`verify`、`encrypt`、`decrypt`、`deriveBits`、`deriveKey`、`wrapKey`、`unwrapKey` |
| QuickJS | `globalThis.crypto`、`require("crypto")`、ESM `crypto`；CommonJS 与 ESM 均接受 `node:crypto` | `digest` |

两种引擎均提供 `crypto.getRandomValues()` 与 `crypto.randomUUID()`。QuickJS 的 `crypto.subtle` 方法集合以表中定义为界；访问其他成员得到 `undefined`，调用该值产生 JavaScript `TypeError`。

`crypto` 的授权由运行时内建能力决定，与 SealPack 的 `file_read`、`file_write` 和 `network` 权限相互独立。

## 顶层 API

### `crypto.getRandomValues(typedArray)`

该方法使用密码学安全随机源填充传入视图，并返回同一对象。单次 `byteLength` 上限为 65,536。

| 引擎 | 接受的视图 | 参数错误 |
| --- | --- | --- |
| Goja | `Int8Array`、`Uint8Array`、`Uint8ClampedArray`、`Int16Array`、`Uint16Array`、`Int32Array`、`Uint32Array`、`BigInt64Array`、`BigUint64Array` | 类型或长度错误同步抛出 `TypeError` |
| QuickJS | TypedArray | 类型错误同步抛出 `TypeError`；超限同步抛出 `RangeError` |

### `crypto.randomUUID()`

返回 RFC 4122 version 4 UUID 字符串。QuickJS 要求参数数量为 0，参数数量校验错误同步抛出 `TypeError`。

## `crypto.subtle` 方法

Goja 的方法始终返回 `Promise`，参数、算法、密钥格式和密码运算错误进入 rejected 状态。QuickJS 的有效 `digest` 调用返回 fulfilled Promise；参数校验和 Host Service 错误同步抛出异常。`verify` 对签名差异解析为 `false`。

| 方法 | 签名 | 结果 |
| --- | --- | --- |
| 摘要 | `digest(algorithm, data)` | `Promise<ArrayBuffer>` |
| 生成密钥 | `generateKey(algorithm, extractable, keyUsages)` | `Promise<CryptoKey \| CryptoKeyPair>` |
| 导入密钥 | `importKey(format, keyData, algorithm, extractable, keyUsages)` | `Promise<CryptoKey>` |
| 导出密钥 | `exportKey(format, key)` | `Promise<ArrayBuffer \| JsonWebKey>` |
| 签名 | `sign(algorithm, key, data)` | `Promise<ArrayBuffer>` |
| 验签 | `verify(algorithm, key, signature, data)` | `Promise<boolean>` |
| 加密 | `encrypt(algorithm, key, data)` | `Promise<ArrayBuffer>` |
| 解密 | `decrypt(algorithm, key, data)` | `Promise<ArrayBuffer>` |
| 派生比特 | `deriveBits(algorithm, baseKey, length)` | `Promise<ArrayBuffer>` |
| 派生密钥 | `deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages)` | `Promise<CryptoKey>` |
| 包裹密钥 | `wrapKey(format, key, wrappingKey, wrapAlgorithm)` | `Promise<ArrayBuffer>` |
| 解包密钥 | `unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages)` | `Promise<CryptoKey>` |

QuickJS 的 `digest` 接受字符串算法名和 `ArrayBuffer` / TypedArray 数据。参数数量为 2。Goja 方法接受字符串算法名或带 `name` 的算法对象。

## Goja 密钥格式

| 格式 | 密钥类型与约束 |
| --- | --- |
| `raw` | 对称密钥；`ECDSA`、`ECDH`、`Ed25519`、`X25519` 公钥；`Ed25519` 私钥接受 32-byte seed 或 64-byte 私钥；`X25519` 私钥接受 32 bytes |
| `jwk` | `oct`、`RSA`、`EC`、`OKP`；RSA 私钥接受完整 CRT 参数或 `n/e/d`，后者由 Core 恢复质因数 |
| `pkcs1` | RSA 私钥或公钥 |
| `sec1` | `ECDSA` / `ECDH` 私钥 |
| `pkcs8` | RSA、`ECDSA`、`ECDH`、`Ed25519`、`X25519` 私钥 |
| `spki` | RSA、`ECDSA`、`ECDH`、`Ed25519`、`X25519` 公钥 |

`X25519` raw 私钥导入使用 `{ name: "X25519", keyType: "private" }` 或 `{ name: "X25519", type: "private" }` 明确私钥类型。`exportKey("jwk")` 填充 `alg`，例如 `A256GCM`、`HS256`、`RS256`、`ES256`、`EdDSA`。

`ECDSA` 与 `ECDH` 接受 `P-256`、`P-384`、`P-521`，并接受对应别名 `secp256r1`、`secp384r1`、`secp521r1`。

`extractable: false` 把密钥材料保留在运行时对象内。`exportKey` 与 `wrapKey` 对该密钥返回 rejected Promise，错误文本为 `key is not extractable`。

## 算法能力

### 摘要

| 引擎 | 算法 |
| --- | --- |
| Goja | `MD5`、`SHA-1`、`SHA-224`、`SHA-256`、`SHA-384`、`SHA-512` |
| QuickJS | `MD5`、`SHA-1`、`SHA-224`、`SHA-256`、`SHA-384`、`SHA-512` |

### Goja 对称加密

- `AES-CBC`
- `AES-GCM`
- `AES-CTR`
- `AES-KW`
- `DES-CBC`
- `3DES-CBC`，别名为 `DES-EDE3-CBC`、`TripleDES-CBC`

AES 密钥长度为 128、192 或 256 bits。`AES-GCM` 接受 32、64、96、104、112、120、128-bit tag；12-byte 之外的 `iv` 使用 128-bit tag。

### Goja 签名

- `HMAC`
- `RSASSA-PKCS1-v1_5`
- `RSA-PSS`
- `ECDSA`
- `Ed25519`

`ECDSA` 签名采用 `r || s` 定长拼接格式。

### Goja 非对称加密

- `RSA-OAEP`
- `RSAES-PKCS1-v1_5`

### Goja 密钥派生

- `PBKDF2`
- `HKDF`
- `ECDH`
- `X25519`

## 高风险兼容算法

以下能力用于既有数据格式和外部协议互操作。新数据的安全配置采用 SHA-256 或更强摘要、AES-GCM，以及 `RSA-OAEP` + `SHA-256`。

| 类别 | 兼容算法 | 风险边界 |
| --- | --- | --- |
| 摘要 | `MD5`、`SHA-1` | 碰撞安全强度低于现代完整性与签名要求 |
| 对称加密 | `DES-CBC`、`3DES-CBC` | DES 密钥空间较小；3DES 使用 64-bit block，数据量增长会提高块碰撞风险 |
| 非对称加密 | `RSAES-PKCS1-v1_5` | 可观察的解密结果差异会形成 padding-oracle 风险 |
| 哈希组合 | `HMAC + MD5`、`HMAC + SHA-1`、`PBKDF2 + MD5`、`PBKDF2 + SHA-1`、`RSASSA-PKCS1-v1_5 + SHA-1`、`RSA-PSS + SHA-1`、`RSA-OAEP + SHA-1` | 安全评估需同时覆盖哈希强度、协议上下文和参数成本 |

## `RSAES-PKCS1-v1_5` WARN 日志

Goja 在以下调用解析到 `RSAES-PKCS1-v1_5` 或其别名时，为每次调用写入一条 Core **WARN**：

- `crypto.subtle.encrypt`
- `crypto.subtle.decrypt`
- `crypto.subtle.wrapKey`
- `crypto.subtle.unwrapKey`

全局 `crypto` 与 `require("crypto")` 使用同一日志规则。算法别名归一化后写入 WARN，再执行密码运算；密文格式、Promise 结果和错误语义由所选算法决定。

日志字段限定为方法、规范化算法、`RSA-OAEP` + `SHA-256` 替代方案、插件名称、插件文件和 JS 调用位置。CommonJS 包装位置可能显示 `<eval>`，插件名称与文件提供归属信息；临时脚本记录可取得的调用位置。Core logger 按每次调用独立写入 WARN。

## `RSA-OAEP` + `SHA-256` 配置

`RSA-OAEP` 使用标准 `crypto.subtle` 方法。

| 操作 | 参数 |
| --- | --- |
| 生成 RSA 密钥 | `{ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }` |
| 导入 RSA 密钥 | `{ name: "RSA-OAEP", hash: "SHA-256" }`；格式按密钥选择 `spki`、`pkcs8` 或 `jwk` |
| 加密 / 解密 | `encrypt("RSA-OAEP", publicKey, data)` / `decrypt("RSA-OAEP", privateKey, ciphertext)` |
| 包裹 / 解包密钥 | `wrapKey` / `unwrapKey` 的包裹算法使用 `"RSA-OAEP"` |

通信双方使用相同哈希和 `label`；省略 `label` 时采用空值。2048-bit RSA 与 SHA-256 的单次明文上限为 190 bytes。较大载荷使用 AES-GCM 加密，再用 RSA-OAEP 包裹 AES 密钥。

`RSAES-PKCS1-v1_5` 与 OAEP 使用独立密文格式。持久化记录以算法和格式版本路由解密；v1.5 记录由 v1.5 参数读取，再在受控写入边界生成 OAEP 记录。通信双方共同约定 OAEP、SHA-256 与 `label`。

### Goja 可运行示例

以下示例演示短消息加解密和 AES 密钥包裹：

```js
(async () => {
  const rsaKeys = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    false,
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
  );

  const message = new TextEncoder().encode("受保护的短消息");
  const encrypted = await crypto.subtle.encrypt(
    "RSA-OAEP", rsaKeys.publicKey, message
  );
  const decrypted = await crypto.subtle.decrypt(
    "RSA-OAEP", rsaKeys.privateKey, encrypted
  );
  console.log("OAEP 解密:", new TextDecoder().decode(decrypted));
  // 输出：OAEP 解密: 受保护的短消息

  // wrapKey 的输入密钥使用 extractable: true；unwrap 后的密钥使用 false。
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
  const wrapped = await crypto.subtle.wrapKey(
    "raw", aesKey, rsaKeys.publicKey, "RSA-OAEP"
  );
  const restoredKey = await crypto.subtle.unwrapKey(
    "raw", wrapped, rsaKeys.privateKey, "RSA-OAEP",
    "AES-GCM", false, ["encrypt", "decrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const payload = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, aesKey, message
  );
  const restoredMessage = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv }, restoredKey, payload
  );
  console.log("OAEP 密钥解包:", new TextDecoder().decode(restoredMessage));
  // 输出：OAEP 密钥解包: 受保护的短消息
})().catch(error => console.error("RSA-OAEP 示例错误:", error));
```

## Goja 摘要、HMAC 与 AES 示例

```js
(async () => {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new Uint8Array([1, 2, 3])
  );

  const hmacKey = await crypto.subtle.generateKey(
    { name: "HMAC", hash: { name: "SHA-256" }, length: 256 },
    true,
    ["sign", "verify"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    hmacKey,
    new Uint8Array([1, 2, 3])
  );

  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-CBC", length: 128 },
    true,
    ["encrypt", "decrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    aesKey,
    new Uint8Array([1, 2, 3])
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv },
    aesKey,
    ciphertext
  );

  console.log(digest.byteLength, signature.byteLength, plaintext.byteLength);
})().catch(error => console.error("Web Crypto 示例错误:", error));
```

## 错误与执行边界

| 条件 | 结果 |
| --- | --- |
| `getRandomValues` 的输入类型超出引擎表列范围 | 同步 `TypeError` |
| `getRandomValues` 的 `byteLength` 大于 65,536 | Goja 同步 `TypeError`；QuickJS 同步 `RangeError` |
| 算法名超出能力表 | Goja 返回 rejected Promise，错误包含 `unsupported algorithm: <name>`；QuickJS `digest` 同步抛出 `TypeError` |
| Goja 导出或包裹 `extractable: false` 密钥 | rejected Promise：`key is not extractable` |
| QuickJS 调用 `digest` 之外的 `crypto.subtle` 方法 | JavaScript `TypeError` |
| 签名内容与签名值存在差异 | `verify` 解析为 `false` |
| 密钥格式、密钥类型、长度、IV、tag、padding 或认证校验错误 | rejected Promise，错误文本描述对应参数或密码运算 |

密码运算与随机生成归类为进程内计算，live callback 中的参数和密码运算错误归类为确定性 callback error。Projection replay 与 rebuild 通过事件解码器和 projector 恢复状态。
