---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: zh-CN
canonical: true
---

# FayID 1.0 协议规范

FayID 是 iFay 生态的自主权（Self-Sovereign / Holder-of-Key）问责身份协议。协议在不依赖任何中心化身份签发机构（CA / IdP）的前提下，将每一个个体数字分身（`iFay`）一对多不可转移地绑定至唯一的**人类原型**（`Human Prime`，`hid_`），并将每一个共享角色数字体（`coFay`）单层直连归属至单一可问责的 `HumanID`（`hid_`）或 `OrganizationID`（`org_`）。

本目录收录 **FayID 1.0 正式版（Final，编辑版次 `2025-10-25`）** 的简体中文权威规范。其他语种译本与本目录保持章节与条款一一对齐；如遇跨语种语义分歧，以本简体中文版为准。

## 规范章节目录

| 章节 | 文件 | 核心范围 |
| --- | --- | --- |
| 第 1 章 | [01-conventions-and-versioning.md](./01-conventions-and-versioning.md) | 适用范围、RFC 2119 / RFC 8174 规范性关键词与中文动词映射、核心术语定义、两段式 `1.0` 协议版本与协商规则 |
| 第 2 章 | [02-identifiers-and-encoding.md](./02-identifiers-and-encoding.md) | 八类规范前缀与无填充小写 RFC 4648 Base32 编码、严格拒绝与往返不变量、`resourceRef` 规范化与匹配、64 位十六进制兼容桥接 |
| 第 3 章 | [03-cryptography-and-subkeys.md](./03-cryptography-and-subkeys.md) | 自主权 Ed25519 持有者证明架构、主种子熵要求、HKDF-SHA256 域分离目的子密钥派生（含 `ifay.ego.package-signing.v1`）、RFC 8785 JCS 规范化签名 |
| 第 4 章 | [04-entities-ownership-and-hierarchy.md](./04-entities-ownership-and-hierarchy.md) | 四类主体、`HumanID : iFayID = 1:N` 绑定、单层 `coFay` 所有权与 `managers` 正交授权、自然人 `Steward`、双向同意的单父无环组织层级树 |
| 第 5 章 | [05-dynamic-codes-and-auth-exchange.md](./05-dynamic-codes-and-auth-exchange.md) | 不可关联动态码（`dyn_`）签发与防重放校验、传统凭据 HMAC 主题绑定、作用域化鉴权授权凭据（`grt_`）、核验回执（`vrf_`）与级联吊销 |
| 第 6 章 | [06-privacy-gmc-and-conformance.md](./06-privacy-gmc-and-conformance.md) | 出站载荷与日志脱敏硬红线、`公誉链`（`GMChain`）只读边界与盲化自然人锚点（`gmcref_`）、24 项规范错误码注册表与一致性判定要求 |

## 配套规范化工件

| 工件路径 | 说明 |
| --- | --- |
| [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json) | FayID 1.0 冻结版 JSON Schema（Draft 2020-12，强制 `version: "1.0"`） |
| [schema/2025-10-25/schema.json](../../../../schema/2025-10-25/schema.json) | 与 `schemas/fayid-1.0.json` 字节级同步的版本化 Schema 镜像 |
| [schema/2025-10-25/schema.ts](../../../../schema/2025-10-25/schema.ts) | TypeScript 规范常量与类型定义镜像 |
| [src/fayid-toolkit.mjs](../../../../src/fayid-toolkit.mjs) | 零外部运行时依赖的 Node.js `node:crypto` 参考实现 |
| [vectors/](../../../../vectors/) | 跨实现确定性一致性测试向量（`account-hierarchy-vectors.json` 与 `crypto-and-revocation-vectors.json`） |
