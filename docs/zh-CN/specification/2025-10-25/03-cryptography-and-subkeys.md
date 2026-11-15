---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: zh-CN
canonical: true
chapter: 3
---

# 第 3 章 自主权密码学套件与目的子密钥派生

## 3.1 自主权持有者证明信任模型（Normative）

FayID 1.0 采用纯自主权持有者证明（Self-Sovereign Holder-of-Key）信任模型：

1. 身份的创建与控制完全取决于对应 Ed25519 私钥的持有证明，不依赖任何中心化注册机构签名。
2. 任何声称持有或归属于某 `HumanID`、`iFayID`、`coFayID` 或 `OrganizationID` 的状态变更操作（注册、委派、层级挂载、转授、吊销），`MUST` 附带由对应控制密钥生成的有效密码学证明；缺少证明或验签失败时 `MUST` 拒绝并返回 `HUMAN_ID_OWNERSHIP_NOT_PROVEN`、`OWNERSHIP_NOT_PROVEN` 或 `TARGET_OWNERSHIP_NOT_PROVEN`。

## 3.2 强制密码学算法清单（Normative）

FayID 1.0 固定采用以下零外部黑盒依赖的标准密码学原语组合：

| 用途 | 强制算法 | 规范输出规模 |
| --- | --- | --- |
| 非对称签名与持有者证明 | Ed25519（RFC 8032 PureEdDSA） | 32 字节原始公钥，64 字节签名 |
| 标识摘要与承诺计算 | SHA-256（FIPS 180-4） | 32 字节摘要 |
| 确定性子密钥派生 | HKDF-SHA256（RFC 5869） | 32 字节目的种子 |
| 传统主题哈希与动态码鉴别 | HMAC-SHA256（RFC 2104） | 32 字节消息认证码（按需截断至 20 字节） |
| JSON 签名载荷规范化 | JCS（RFC 8785 JSON Canonicalization Scheme） | UTF-8 确定性字节序列 |

主种子（`masterSeed`）与盲化盐值（`userBlindSalt`）的原始熵长度 `MUST` 不少于 **256 比特（32 字节）**；低于 32 字节的输入 `MUST` 拒绝并返回 `INSUFFICIENT_ENTROPY`。

## 3.3 HKDF-SHA256 域分离目的子密钥派生（Normative）

为确保根私钥与主种子永不直接暴露在高频签名或外部协议打包流程中，持有者代理 `MUST` 从 32 字节及以上的主种子通过 HKDF-SHA256 派生彼此密码学隔离的 32 字节目的子密钥：

```text
subkeySeed32 = HKDF-SHA256(
  ikm  = masterSeedBytes,
  salt = SHA-256(UTF8("fayid.subkey.salt:" || domain)),
  info = UTF8(domain || ":" || context),
  len  = 32
)
```

规范定义了五个受保护的域分离常量（`SubkeyDomain`）：

| 常量名 | 域分离字符串（`domain`） | 用途与安全边界 |
| --- | --- | --- |
| `ENTITY` | `ifay.fayid.entity.v1` | 派生 `HumanID`、`iFay`、`coFay`、`OrganizationID` 的实体控制 Ed25519 密钥对 |
| `EGO_PACKAGE_SIGNING` | `ifay.ego.package-signing.v1` | 专用于签署 `.ego` 人格/状态出站文件包的专用 Ed25519 签名子密钥 |
| `DYNAMIC_CODE` | `ifay.fayid.dynamic-code.v1` | 派生动态码签发与核验上下文对称密钥材料 |
| `AUTH_EXCHANGE` | `ifay.fayid.auth-exchange.v1` | 派生鉴权兑换授权（`grt_`）与核验回执（`vrf_`）签名密钥材料 |
| `GMC_NATURAL_PERSON` | `ifay.gmc.natural-person.v1` | 派生面向 `GMChain` 的自然人盲化锚点伪随机密钥材料 |

实现 `MUST` 遵守两条硬隔离约束：

1. **强制域检查**：调用子密钥派生接口时，`domain` 与 `context` `MUST` 为非空字符串，且 `domain` `MUST` 属于已知受控域集合；未提供合法域分离标识的调用 `MUST` 拒绝并返回 `DOMAIN_SEPARATION_REQUIRED`。
2. **Ego 包根密钥零出站（Root-Key Isolation）**：签署 `.ego` 出站包时，实现 `MUST` 仅使用 `ifay.ego.package-signing.v1` 派生的子密钥生成签名信封（包含 `version: "1.0"`、`domain: "ifay.ego.package-signing.v1"`、`signerFayId`、`keyId`、`signingPublicKeyHex`、`manifestDigestSha256`、`signedAt`、`signatureHex`）。任何出站包、公开实体记录或核验回执中**严禁**出现 `masterSeed`、`seed`、`privateKey`、`secretKey` 或 `mnemonic` 等私钥材料字段；核验方遇到携带私钥材料的出站信封时 `MUST` 判定违规并拒绝。

## 3.4 RFC 8785 JCS 规范化签名约定（Normative）

所有跨实现校验的结构化签名载荷（包括所有权绑定证明、双向层级同意书、Ego 包清单签名载荷及 `vrf_` 核验回执签名载荷）在送入 Ed25519 `sign` / `verify` 或 SHA-256 之前，`MUST` 先经 RFC 8785 JCS 规范化为唯一确定的 UTF-8 字节串：

1. 对象属性键按 UTF-16 代码单元字典序升序排列，且值为 `undefined` 的可选键在序列化前省略；
2. 数值遵循 ECMAScript 规范最小无歧义十进制表示（`-0` 规范化为 `"0"`，禁止 `NaN` 与 `Infinity`）；
3. 数组元素顺序严格保留，字符转义遵循标准最小 JSON 转义规则，键名与分隔符之间不含任何多余空白。
