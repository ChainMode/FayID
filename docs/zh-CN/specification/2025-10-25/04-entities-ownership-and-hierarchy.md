---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: zh-CN
canonical: true
chapter: 4
---

# 第 4 章 身份实体、单层所有权与组织层级树

## 4.1 `HumanID` 与 `iFay` 的一对多绑定（Normative）

1. **根身份生成**：**人类原型**通过本地持有者代理生成或派生 Ed25519 公钥 `pk_human`，计算 `hid_ || base32NoPad(SHA-256(pk_human))` 得到 `HumanID`。
2. **`1:N` 不可转移绑定**：同一 `HumanID` `MAY` 注册并拥有任意数量的 `iFay`（`HumanID : iFayID = 1:N`）。注册 `iFay` 时，`MUST` 同时提供该 `HumanID` 私钥与新 `iFay` 私钥对同一绑定消息的联合签名证明；缺少任一有效证明 `MUST` 拒绝并返回 `HUMAN_ID_OWNERSHIP_NOT_PROVEN`。
3. **默认跨 `iFay` 不可关联**：公开的 `IFayRecord` 仅保存加盐单向承诺 `humanIdProofRef`（`hidproof_<base32>`）而不包含明文 `hid_`。除非**人类原型**主动出示联合证明，第三方无法仅凭两个 `ifay_` 公开记录判定它们是否属于同一**人类原型**。
4. **不可转让性**：`iFay` 一旦与 `HumanID` 绑定，其归属关系终身固定，**严禁**变更至其他 `HumanID` 或任何 `OrganizationID`。

## 4.2 `coFay` 单层直连所有权与 `managers` 正交授权（Normative）

为确保每一个共享角色数字体都具备唯一、可穿透问责的最终责任主体，FayID 1.0 对 `coFay` 强制实施**单层直连所有权（Single-Layer Ownership）**模型：

1. **合法所有者类型限制**：`coFay` 的 `ownerId` `MUST` 仅为 `HumanID`（`hid_`）或 `OrganizationID`（`org_`），对应 `ownerKind` 为 `"HUMAN"` 或 `"ORGANIZATION"`。任何试图以 `iFay`（`ifay_`）或另一 `coFay`（`cofay_`）作为 `coFay` 所有者的请求，`MUST` 立即拒绝并返回 `OWNER_TYPE_NOT_ALLOWED`（禁止多层嵌套 `coFay` 所有权链）。
2. **所有权转移**：当前所有者（`hid_` 或 `org_`）`MAY` 通过签署所有权变更证明，将 `coFay` 转移给新的合法所有者（`hid_` 或 `org_`），转移后 `version` 保持 `"1.0"` 且更新所有者绑定记录。
3. **正交运维管理列表（`managers: iFayID[]`）**：
   - `coFay` 的所有者（`hid_` 或 `org_`）`MAY` 授权零个或多个 `iFayID` 进入 `managers` 列表，承担日常配置与运行管理职责。
   - 仅当前直接所有者具备增删 `managers` 的权限；已被列为 `manager` 的 `iFay` **严禁**自行追加、移除或转授其他 `manager`，任何越权转授尝试 `MUST` 拒绝并返回 `AUTHORITY_GRANT_UNAUTHORIZED`（单跳无再委派原则）。
   - `managers` 列表中的 `iFay` 仅享有运维操作权限，不改变 `coFay` 的法律或治理所有权归属。

## 4.3 组织实体（`OrganizationID`）与自然人 `Steward`（Normative）

1. **强制自然人治理代表（`Steward`）**：每个注册的 `OrganizationRecord` `MUST` 指定一名自然人治理代表 `stewardHumanId`，其值 `MUST` 为已注册且未吊销的 `HumanID`（`hid_`）。任何尝试将 `ifay_`、`cofay_` 或 `org_` 设为 `Steward` 的操作 `MUST` 拒绝并返回 `STEWARD_TYPE_NOT_ALLOWED`。
2. **代表变更**：组织可通过组织控制密钥签署变更指令更换 `stewardHumanId`，新代表同样 `MUST` 为有效且未吊销的 `HumanID`。

## 4.4 自包含单父无环组织层级树（Normative）

FayID 1.0 在本仓库规范内自包含定义组织间的层级治理关系：

1. **单父树拓扑**：每个 `OrganizationRecord` 包含 `parentOrgId: OrganizationID | null`。每个子组织在同一时刻最多只能拥有一个直接父组织，整体构成若干棵有向无环树（森林）。协议**不设** 16 层之类的人为固定深度上限。
2. **强制双向同意（Mutual Two-Party Consent）**：建立或变更 `childOrg.parentOrgId = parentOrgId` 时，`MUST` 同时附带子组织控制密钥签署的挂载请求签名与目标父组织控制密钥签署的接纳同意签名。缺少任一方同意或验签失败时，`MUST` 拒绝并返回 `HIERARCHY_CONSENT_MISSING`。
3. **无环检测（Cycle Rejection）**：将 `parentOrgId` 指向组织自身，或指向该组织当前任意后代子组织以致形成环路的挂载请求，`MUST` 确定性拒绝并返回 `HIERARCHY_CYCLE_CONFLICT`。
4. **所有权不随组织树自动上卷**：子组织名下直接拥有的 `coFay` 仍以该子组织 `org_` 为直接所有者；父组织不会因为组织层级挂载而自动获得子组织名下 `coFay` 的直接所有权或跳过单层所有权记录。
