# FayID 1.0 快速上手指南

**FayID 1.0**（`2025-10-25` 正式版）是 iFay 生态的自持密钥（Holder-of-Key）问责身份协议。每个个体 `iFay` 均与唯一的**人类原型**（`Human Prime`）建立 `1:N` 不可转让绑定，每个共享角色 `coFay` 均单层归属于明确的 `HumanID` 或 `OrganizationID`，而根私钥始终保存在本地**宿主**（`Host`）设备的安全边界内。

## 1. 环境要求与本地验证

参考实现位于 [`src/fayid-toolkit.mjs`](../../src/fayid-toolkit.mjs)，基于 Node.js 20+ 原生 `node:crypto`（`Ed25519`、`SHA-256`、`HKDF-SHA256`、RFC 8785 JCS），零外部运行时依赖。在仓库根目录运行全量单元与一致性向量测试：

```bash
npm test
```

## 2. 规范标识符前缀速查

所有密码学标识符统一采用 `<prefix>_<lowercase-rfc4648-base32-nopad>` 编码（`org_` 额外允许小写语义段）：

| 前缀 | 实体或凭证类型 | 问责与隐私边界 |
| --- | --- | --- |
| `hid_` | `HumanID` | 人类原型根身份（`SHA-256(publicKey)`）；**严禁离开本地宿主外发或写入公开日志** |
| `ifay_` | `IFayID` | 个体 `iFay` 身份，与所属 `hid_` 建立 `1:N` 不可转让绑定 |
| `cofay_` | `CoFayID` | 共享角色 `coFay` 身份，单层归属 `hid_` 或 `org_`，管理权轴 `managers: iFayID[]` 正交 |
| `org_` | `OrganizationID` | 组织实体身份，须绑定自然人代表 `Steward`（`hid_`），构成双向同意单亲无环树 |
| `dyn_` | `DynamicCode` | 短生命周期（`<= 600s`）、单次防重放、不可关联的对外出示动态码 |
| `grt_` / `vrf_` | `AuthorizationGrant` / `VerificationCode` | 限定资源范围（`EXACT` / `PREFIX`）的鉴权交换授权与可离线核验回执 |
| `gmcref_` | `OpaqueRef` | 面向公誉链（`GMChain`）自然人权重归一化的盲化不可逆锚点（`ifay.gmc.natural-person.v1`） |

## 3. 创建自持密钥 Ed25519 身份示例

```js
import { randomBytes } from "node:crypto";
import {
  AccountDirectory,
  deriveEntityKeypair,
  deriveHumanIdentityFromSeed,
} from "../../src/fayid-toolkit.mjs";

const rootSeed = randomBytes(32); // 仅驻留本地宿主安全存储，永不序列化外发
const human = deriveHumanIdentityFromSeed(rootSeed); // human.humanId => "hid_..."（仅本地持有）
const ifay = deriveEntityKeypair(rootSeed, "ifay", 0).value; // ifay.entityId => "ifay_..."

const directory = new AccountDirectory();
directory.registerHuman(human.humanId);
directory.registerIFay(ifay.entityId, human.humanId);

const dyn = directory.issueDynamicCode({
  subjectId: ifay.entityId,
  ttlSec: 120,
});
console.log("Outbound unlinkable token:", dyn.value.code); // "dyn_..."
```

## 4. 延伸阅读

- **架构蓝图**：[`./blueprint/`](./blueprint/) — 了解身份与所有权模型、凭证生命周期及鉴权交换设计动机。
- **正式协议规范（Final 1.0）**：[`./specification/2025-10-25/README.md`](./specification/2025-10-25/README.md) — 查阅分章规范正文、[`schemas/fayid-1.0.json`](../../schemas/fayid-1.0.json) 与测试向量要求。
