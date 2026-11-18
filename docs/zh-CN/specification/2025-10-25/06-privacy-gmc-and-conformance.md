---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: zh-CN
canonical: true
chapter: 6
---

# 第 6 章 隐私红线、`GMChain` 接口、错误码与一致性判定

## 6.1 出站载荷与日志脱敏硬红线（Normative）

所有实现 `MUST` 在协议序列化层与可观测性日志层同时执行以下不可绕过的隐私红线：

1. **明文 `hid_` 永不出站、永不入日志**：任何网络出站请求、公开目录快照、`.ego` 导出包、跨主体核验回执（`vrf_`）、崩溃转储及审计日志中，**严禁**写入明文 `hid_<base32>` 字符串。外部交互一律使用 `ifay_`、`cofay_`、`dyn_`、`hidproof_` 或盲化锚点 `gmcref_`。
2. **主种子与私钥零出站**：主种子（`masterSeed`）、助记词、原始私钥（`privateKey` / `secretKey`）以及 `userBlindSalt` **必须**严格驻留于受控本地持有者代理的安全存储内，**严禁**进入任何序列化公开记录或网络载荷。
3. **跨命名空间不可关联**：不同外部消费域必须使用各自独立的域分离常量或盐值，防止外部观察者通过比对标识符拼出同一**人类原型**的全网行为画像。

## 6.2 `公誉链`（`GMChain`）只读边界与盲化锚点 `gmcref_`（Normative）

`公誉链`（`GMChain`）需要确保同一自然人无论创建多少个 `iFay`，在自然人维度的治理权重与反女巫归一化中仅被计为一个自然人锚点，同时又不能获知该自然人的明文 `hid_`。为此，FayID 1.0 定义确定性盲化锚点 `gmcref_<base32>`：

```text
prk    = HKDF-SHA256(ikm = userBlindSalt, salt = SHA-256("fayid.gmc.salt.v1"), info = "ifay.gmc.natural-person.v1:" || namespace, len = 32)
digest = HMAC-SHA256(key = prk, data = UTF8("gmcref:" || canonicalHumanId))
gmcref = "gmcref_" || base32EncodeNoPad(digest)
```

规范性边界如下：

1. **确定性与不可逆性**：给定相同的合法 `HumanID`、不少于 32 字节的 `userBlindSalt` 与相同的 `namespace`（默认为 `"gmchain.main"`），派生出的 `gmcref_` 完全确定且恒定；缺少 `userBlindSalt` 的第三方（包括 `GMChain` 节点）在计算上无法从 `gmcref_` 反推出 `hid_`，也无法将其与该自然人名下的公开 `ifay_` 记录直接关联。
2. **严格只读接口边界**：FayID 对 `GMChain` 仅提供单向锚点派生与吊销状态核验输入，**不读写** `GMChain` 账本状态，也**不参与**`美誉值`（`MeriToken`）的计算、增减或分配。`美誉值`（`MeriToken`）是非货币化的社会贡献度量指标，不是加密货币、金融结算工具或可兑换法币资产。
3. **仅限自然人派生**：`deriveBlindGmcRef` 的主体输入 `MUST` 为合法的 `HumanID`（`hid_`）；传入 `ifay_`、`cofay_` 或 `org_` `MUST` 拒绝并返回 `MALFORMED_FAYID_STRING`。

## 6.3 规范错误码注册表（Normative）

符合 FayID 1.0 的实现 `MUST` 保持以下 24 项稳定错误码常量（14 项基础协议错误码 + 10 项账户、密码学域与级联治理错误码）：

| 错误码常量 | 触发条件摘要 |
| --- | --- |
| `INSUFFICIENT_ENTROPY` | 主种子、盲化盐值或随机熵长度低于 256 比特（32 字节）下限 |
| `HUMAN_ID_OWNERSHIP_NOT_PROVEN` | 注册或操作要求出示 `HumanID` 持有者签名但缺失或验签失败 |
| `OWNERSHIP_NOT_PROVEN` | 实体控制权或转移操作缺少当前所有者有效签名证明 |
| `TARGET_OWNERSHIP_NOT_PROVEN` | 签发 `grt_` 等操作未证明对目标 `iFay` / `coFay` 的持有权（最高优先返回以防绑定探测） |
| `LEGACY_SUBJECT_MISMATCH` | 传统凭据规范化主题哈希与已绑定的 `LegacySubjectRef` 不一致 |
| `DYNAMIC_CODE_EXPIRED` | `dyn_` 核验时间晚于其 `expiresAt` 截止时间 |
| `DYNAMIC_CODE_INVALID` | `dyn_` 格式未知、HMAC 校验失败、受众不匹配或请求 TTL 超过 600 秒上限 |
| `VERIFICATION_RATE_LIMITED` | 连续核验失败次数达到限速窗口阈值（默认 600 秒内 5 次失败触发指数退避） |
| `IDENTITY_REVOKED` | 基础层通用身份已吊销状态标识 |
| `LEGACY_AUTH_FAILED` | 外部传统凭据（密码、证书、令牌、合约证明等）上游鉴权未通过 |
| `GRANT_EXPIRED` | `grt_` 授权核验时间晚于其 `expiresAt` 截止时间 |
| `GRANT_REVOKED` | `grt_` 授权已被单独吊销 |
| `GRANT_INVALID` | `grt_` 不存在、结构非法、目标类型不允许或请求 `resourceRef` 超出授权作用域 |
| `MALFORMED_FAYID_STRING` | 标识符前缀/Base32 主体非法、`resourceRef` 语法违规或传入了非预期前缀类型 |
| `OWNER_TYPE_NOT_ALLOWED` | 试图将 `iFay` 或 `coFay` 设为 `coFay` 的所有者（违反单层所有权不变量） |
| `HIERARCHY_CONSENT_MISSING` | 组织层级挂载缺少子组织或父组织任一方的有效同意签名 |
| `HIERARCHY_CYCLE_CONFLICT` | 组织层级挂载指向自身或自身后代节点，构成环路 |
| `AUTHORITY_GRANT_UNAUTHORIZED` | 非 `coFay` 直接所有者（例如 `managers` 成员）试图修改或转授 `managers` 权限 |
| `STEWARD_TYPE_NOT_ALLOWED` | 组织 `Steward` 未指定为有效未吊销的自然人 `HumanID`（`hid_`） |
| `ENTITY_REVOKED` | 目标实体或其上游归属 `HumanID` / `OrganizationID` 已被直接或级联吊销 |
| `DYNAMIC_CODE_REPLAYED` | 同一单次 `dyn_` 动态码被重复提交核验（防重放拦截） |
| `DYNAMIC_CODE_TARGET_NOT_ALLOWED` | 试图为不支持动态码的主体（如 `OrganizationID`）签发 `dyn_` |
| `DOMAIN_SEPARATION_REQUIRED` | HKDF 子密钥派生缺少合法 `SubkeyDomain` 或非空上下文标识 |
| `RECEIPT_INVALID` | `vrf_` 核验回执结构残缺、前缀非法或 Ed25519 签名验签失败 |

## 6.4 一致性判定条件（Conformance）（Normative）

任一软件库、服务或持有者代理若声明符合 **FayID 1.0**，则 `MUST` 满足以下全部可验证条件：

1. **版本与 Schema 合规**：生成的所有公开实体记录与凭据信封均携带 `version: "1.0"`，并通过 [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json) 校验。
2. **标识符与资源匹配合规**：完整实现第 2 章八类前缀规范化、严格拒绝不修复输入规则及 `resourceRef` 的 `EXACT` / `PREFIX` 边界匹配。
3. **密码学与根密钥隔离合规**：完整实现第 3 章 Ed25519、SHA-256、HKDF-SHA256 五类域分离子密钥派生与 RFC 8785 JCS 签名，且在 `.ego` 包等全部出站载荷中严格使用 `ifay.ego.package-signing.v1` 子密钥，保证根种子与私钥零出站。
4. **账户模型与级联吊销合规**：完整强制执行第 4 章单层 `coFay` 所有权、自然人 `Steward`、双向同意单父无环组织树，以及第 5 章 `dyn_` 防重放、`grt_` / `vrf_` 作用域兑换与四类主体的确定性级联吊销。
5. **官方测试向量全绿**：100% 通过本仓库 [vectors/hierarchy/](../../../../vectors/hierarchy) 与 [vectors/crypto-and-revocation-vectors.json](../../../../vectors/crypto-and-revocation-vectors.json) 中的全部正向与负向一致性测试向量。
