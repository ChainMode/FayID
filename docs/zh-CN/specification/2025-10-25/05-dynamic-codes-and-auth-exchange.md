---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: zh-CN
canonical: true
chapter: 5
---

# 第 5 章 不可关联动态码、鉴权兑换与级联吊销

## 5.1 不可关联动态码（`dyn_`）签发与核验（Normative）

由于明文 `hid_` 永不出站，**人类原型**及其名下 `iFay`、`coFay` 在跨边界出示身份时使用短时效、加盐防关联的动态码（`dyn_<base32>`）：

1. **合法目标主体**：动态码仅允许为未吊销的 `HumanID`（`hid_`）、`iFayID`（`ifay_`）或 `coFayID`（`cofay_`）签发。为 `OrganizationID`（`org_`）请求签发动态码 `MUST` 拒绝并返回 `DYNAMIC_CODE_TARGET_NOT_ALLOWED`（组织标识本身为公开主体，无需假名动态码）。
2. **加盐不可关联构造**：每次签发均生成至少 16 字节的密码学随机 `nonce`，并在 `ifay.fayid.dynamic-code.v1` 域密钥下对规范化载体 `{audience, expiresAt, issuedAt, nonceHex, targetId, version: "1.0"}` 计算 HMAC-SHA256，截断前 20 字节编码为 `dyn_<base32>`。被动窃听者在缺乏核验上下文密钥的情况下，无法通过观察两次出示的 `dyn_` 字符串判断它们是否源自同一主体。
3. **严格有效窗口上限**：`expiresAt - issuedAt` `MUST` 大于 `0` 且不超过 **`600` 秒（`DYNAMIC_CODE_MAX_TTL_SECONDS = 600`）**；超限签发请求 `MUST` 拒绝并返回 `DYNAMIC_CODE_INVALID`。
4. **单次消费与防重放**：核验方校验 `dyn_` 时：
   - 若主体本身或其上游归属主体已被吊销，`MUST` 拒绝并返回 `ENTITY_REVOKED`；
   - 若核验时间晚于 `expiresAt`，`MUST` 拒绝并返回 `DYNAMIC_CODE_EXPIRED`；
   - 若 `audience` 不匹配（当令牌绑定了预期受众时）或令牌未知，`MUST` 返回 `DYNAMIC_CODE_INVALID`；
   - 每个 `dyn_` 的随机 `nonce` 仅允许成功核验消费**一次**；第二次及后续重复提交同一 `dyn_` `MUST` 拒绝并返回 `DYNAMIC_CODE_REPLAYED`。
5. **核验结果隐私保护**：当 `dyn_` 绑定的底层主体为 `HumanID` 时，核验成功响应**严禁**向调用方返回明文 `hid_`，而 `MUST` 返回主体类别 `"HUMAN"` 及由盲化盐值确定性派生的 `gmcref_<base32>` 锚点。

## 5.2 传统凭据绑定与鉴权兑换授权（`grt_` / `vrf_`）（Normative）

Auth Exchange 允许持有者将外部存量系统凭据安全桥接为作用域受限的 FayID 授权凭据（`grt_<base32>`），并在资源访问时生成可离线验签的核验回执（`vrf_<base32>`）：

1. **传统主题隐私哈希（`LegacySubjectRef`）**：外部凭据主体 `MUST` 规范化并经密钥 HMAC 处理为 `<legacySourceKind>:<issuerOrAuthority>:<subjectHash>`，其中 `subjectHash = base32NoPad(HMAC-SHA256(legacySecret, canonicalSubject))`。`LegacySubjectRef` **严禁**直接拼接明文邮箱、手机号、X.509 DN、OAuth 原始令牌或区块链明文钱包地址。
2. **默认信任等级映射（`LegacyTrustLevel`）**：
   - `PASSWORD` → `LOW`（授权 TTL 上限为 **`900` 秒**，`LOW_TRUST_GRANT_MAX_TTL_SECONDS`）；
   - `ACCESS_TOKEN`、`AUTHORIZATION` → `MEDIUM`（授权 TTL 上限为 **`3600` 秒**，`GRANT_MAX_TTL_SECONDS`）；
   - `CERTIFICATE`、`SMART_CONTRACT` → `HIGH`（授权 TTL 上限为 **`3600` 秒**）。
   实现 `MAY` 根据风险策略下调信任等级或缩短 TTL，但在无额外多因素持有者证明时 `MUST NOT` 越级上调。
3. **目标持有证明优先检查（防探测）**：签发 `grt_` 时，目标主体仅限未吊销的 `iFayID` 或 `coFayID`，且请求方 `MUST` 出示目标主体的持有者签名证明。若目标持有证明缺失或无效，系统 `MUST` 优先返回 `TARGET_OWNERSHIP_NOT_PROVEN`，防止攻击者通过错误码差异探测某传统账号是否已与特定 FayID 绑定。
4. **作用域化核验与 `vrf_` 回执签发**：调用 `verifyAuthGrant` 核验 `grt_` 时，系统依次检查：
   - 授权记录是否存在且格式合法（否则返回 `GRANT_INVALID`）；
   - 目标实体及其上游所有者是否已被吊销（若实体已吊销，优先返回 `ENTITY_REVOKED`）；
   - 授权本身是否已被显式吊销（否则返回 `GRANT_REVOKED`）；
   - 当前时间是否超过 `expiresAt`（否则返回 `GRANT_EXPIRED`）；
   - 请求的 `requestedResourceRef` 是否按第 2.3 节 `scopeMode`（`EXACT` / `PREFIX`）匹配授权的 `resourceRef`（不匹配返回 `GRANT_INVALID`）。
   全部通过后，系统使用 `ifay.fayid.auth-exchange.v1` 域 Ed25519 密钥对规范化核验结论签名，返回 `vrf_<base32>` 回执；任何第三方均可调用 `verifyAuthReceipt(receipt)` 独立校验回执签名与结构完整性，篡改任一字段 `MUST` 返回 `RECEIPT_INVALID`。

## 5.3 确定性级联吊销（Cascading Revocation）（Normative）

吊销是单调不可逆的终态操作。当任一实体被吊销时，系统 `MUST` 立即按归属与层级关系确定性执行级联失效，不得遗留任何悬空活跃子实体或活跃授权凭据：

| 被吊销的根触发实体 | 级联失效的下游实体范围 | 对运维授权与活跃凭据的强制连带处置 |
| --- | --- | --- |
| **`HumanID`（`hid_`）** | 该人类原型名下全部 `iFay`（`ifay_`）及直接归属该 `hid_` 的全部 `coFay`（`cofay_`） | 从所有未吊销 `coFay.managers` 中移除上述被级联吊销的 `ifay_`；吊销所有指向上述 `ifay_` / `cofay_` 的活跃 `grt_` 与未消费 `dyn_` |
| **`OrganizationID`（`org_`）** | 该组织自身、组织层级树中全部后代子组织（递归子树），以及直接归属于该组织或任一后代子组织的全部 `coFay` | 吊销所有指向上述被级联吊销 `cofay_` 的活跃 `grt_` 与未消费 `dyn_` |
| **`iFayID`（`ifay_`）** | 该 `iFay` 自身 | 从所有未吊销 `coFay.managers` 列表中立即移除该 `ifay_`；吊销所有以该 `ifay_` 为 `targetFayId` 的活跃 `grt_` 与未消费 `dyn_` |
| **`coFayID`（`cofay_`）** | 该 `coFay` 自身 | 吊销所有以该 `cofay_` 为 `targetFayId` 的活跃 `grt_` 与未消费 `dyn_` |

级联吊销完成后：
1. 对任何已被直接或级联吊销的实体签发新的 `dyn_`、`grt_`、注册新下属实体或核验既有凭据时，`MUST` 确定性拒绝并返回 `ENTITY_REVOKED`（对被单独手动吊销但目标实体仍存活的授权则返回 `GRANT_REVOKED`）。
2. 被吊销实体即使仍在原定 TTL 时间窗内，其凭据也**立即失效**，不得继续通过核验。
