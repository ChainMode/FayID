---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: zh-CN
canonical: true
chapter: 2
---

# 第 2 章 标识符语法、编码与资源引用规范

## 2.1 八类规范标识符前缀表（Normative）

所有 FayID 密码学标识符与衍生凭据字符串 `MUST` 采用 `<prefix>_<body>` 结构。除 `org_` 允许可读小写组织标识字符集 `[a-z0-9-]+` 外，其余七类标识符主体 `MUST` 采用**小写、无 `=` 填充的 RFC 4648 Base32** 字符集（`[a-z2-7]+`）：

| 类型常量 | 字符串前缀 | 主体正则 | 典型字节长度与语义 |
| --- | --- | --- | --- |
| `HUMAN_ID` | `hid_` | `^[a-z2-7]+$` | `SHA-256(humanPublicKey)`（32 字节 → 52 个 Base32 字符），**人类原型**根身份标识 |
| `IFAY_ID` | `ifay_` | `^[a-z2-7]+$` | `SHA-256("ifay:" \|\| humanId \|\| ":" \|\| publicKey)`（32 字节），个人数字分身标识 |
| `COFAY_ID` | `cofay_` | `^[a-z2-7]+$` | `SHA-256("cofay:" \|\| ownerId \|\| ":" \|\| publicKey)`（32 字节），共享角色数字体标识 |
| `ORGANIZATION_ID` | `org_` | `^[a-z0-9-]+$` | 组织主体标识（支持确定性哈希主体或规范化组织短名） |
| `DYNAMIC_CODE` | `dyn_` | `^[a-z2-7]+$` | 20 字节 HMAC 截断标签（32 个 Base32 字符），短时不可关联出示令牌 |
| `VERIFICATION_CODE` | `vrf_` | `^[a-z2-7]+$` | 20 字节核验回执摘要，绑定 `grt_` 或 `cofay_` 状态核验结果 |
| `AUTHORIZATION_GRANT` | `grt_` | `^[a-z2-7]+$` | 20 字节作用域化传统凭据兑换授权标识 |
| `OPAQUE_REF` | `gmcref_` | `^[a-z2-7]+$` | 32 字节盲化自然人锚点（52 个 Base32 字符），专供 `GMChain` 治理去重 |

此外，在 `iFay` 注册记录与离线包中，用于替代明文 `hid_` 的单向承诺采用 `hidproof_<lowercase-base32-nopad>` 格式（正则 `^hidproof_[a-z2-7]{16,}$`）。

## 2.2 规范化与严格拒绝规则（Normative）

解析函数 `normalizeFayID(input)` `MUST` 满足以下确定性规则：

1. **类型与非空检查**：非字符串输入或空字符串 `MUST` 立即返回错误码 `MALFORMED_FAYID_STRING`。
2. **大小写折叠**：解析器 `MUST` 将 ASCII 大写字母折叠为小写（`input.toLowerCase()`），再匹配上表八类前缀。
3. **严格拒绝，严禁静默修复**：解析器**严禁**自动裁剪首尾空白字符、剔除连字符（`org_` 主体合法连字符除外）、剥离 `=` 填充符或替换易混淆字符（如将 `0`/`1`/`8`/`9` 替换为 Base32 字母）。凡包含空白、`=`、未知前缀、空主体或越界字符（例如 `hid_` 主体出现 `0`、`1`、`8`、`9`）的字符串，`MUST` 一律拒绝并返回 `MALFORMED_FAYID_STRING`。
4. **往返不变量（Round-Trip Invariant）**：对任意合法规范化标识符 `x`，再次执行 `normalizeFayID(x)` `MUST` 返回 `ok: true` 且 `value.canonical === x`；对任意字节数组 `b` 执行无填充小写 Base32 编码后再解码，`MUST` 逐字节还原 `b`，且末尾补零位 `MUST` 全为 `0`（非零残留位 `MUST` 拒绝解码）。

## 2.3 `resourceRef` 资源命名空间与作用域匹配（Normative）

鉴权兑换中的目标资源由 `resourceRef` 标识。`normalizeResourceRef(input)` 与 `matchesResourceRef(grantedResourceRef, requestedResourceRef, scopeMode)` `MUST` 遵循以下规则：

1. **语法结构**：`resourceRef` 采用 `<namespace>:<path>` 结构：
   - `<namespace>` 在折叠为小写后 `MUST` 匹配 `^[a-z][a-z0-9+.-]*$`；
   - `:` 右侧 `<path>` `MUST` 非空、不含任何空白字符、不以 `/` 结尾（单字符根路径除外），且**严禁**包含空路径段（`//`）或相对遍历段（`.` 或 `..`）。
   - 违反上述任一条件 `MUST` 返回 `MALFORMED_FAYID_STRING`。
2. **大小写敏感性**：`<namespace>` 部分规范化为小写；`:` 右侧的 `<path>` **必须**保留原始大小写。
3. **作用域匹配模式（`scopeMode`）**：
   - `EXACT`（默认）：仅当规范化后的 `requestedResourceRef === grantedResourceRef` 时匹配成功。
   - `PREFIX`：仅当规范化后的请求资源等于授权资源本身，或在 `/` 路径段边界上以其为前缀（即 `requested.startsWith(granted + "/")`）时匹配成功。例如授权 `cap:repo/fayid` 在 `PREFIX` 模式下匹配 `cap:repo/fayid/issues`，但**绝不**匹配兄弟路径 `cap:repo/fayid-ext`（防止字符串前缀越权）。

## 2.4 遗留 64 位十六进制公钥标识桥接（Normative）

为兼容早期仅持有 32 字节原始 Ed25519 公钥十六进制串（64 个十六进制字符）的存量记录，工具包提供显式桥接函数 `adaptLegacyHexIdentifier(hex64, prefix)`：

1. 输入 `hex64` 去除空白后 `MUST` 精确匹配 `^[0-9a-fA-F]{64}$`，且目标 `prefix` 仅允许 `hid_`、`ifay_` 或 `cofay_`，否则返回 `MALFORMED_FAYID_STRING`。
2. 桥接过程对解码后的 32 字节原始公钥计算 `SHA-256`，再编码为 `<prefix><base32-nopad>`，与原生根身份计算公式完全一致。
3. 协议正式线格式载荷中**不得**直接传输裸 64 位十六进制字符串充当 FayID；桥接必须在进入协议边界前显式完成。
