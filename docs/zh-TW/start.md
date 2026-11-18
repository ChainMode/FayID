# FayID 1.0 快速上手指南

**FayID 1.0**（`2025-10-25` 正式版）是 iFay 生態的自持密鑰（Holder-of-Key）問責身份協議。每個個體 `iFay` 均與唯一的**人類原型**（`Human Prime`）建立 `1:N` 不可轉讓綁定，每個共享角色 `coFay` 均單層歸屬於明確的 `HumanID` 或 `OrganizationID`，而根私鑰始終保存在本地**宿主**（`Host`）設備的安全邊界內。

## 1. 環境需求與本地驗證

參考實現位於 [`src/fayid-toolkit.mjs`](../../src/fayid-toolkit.mjs)，基於 Node.js 20+ 原生 `node:crypto`（`Ed25519`、`SHA-256`、`HKDF-SHA256`、RFC 8785 JCS），零外部執行期依賴。在倉庫根目錄執行完整單元與一致性向量測試：

```bash
npm test
```

## 2. 規範標識符前綴速查

所有密碼學標識符統一採用 `<prefix>_<lowercase-rfc4648-base32-nopad>` 編碼（`org_` 額外允許小寫語義段）：

| 前綴 | 實體或憑證類型 | 問責與隱私邊界 |
| --- | --- | --- |
| `hid_` | `HumanID` | 人類原型根身份（`SHA-256(publicKey)`）；**嚴禁離開本地宿主外發或寫入公開日誌** |
| `ifay_` | `IFayID` | 個體 `iFay` 身份，與所屬 `hid_` 建立 `1:N` 不可轉讓綁定 |
| `cofay_` | `CoFayID` | 共享角色 `coFay` 身份，單層歸屬 `hid_` 或 `org_`，管理權軸 `managers: iFayID[]` 正交 |
| `org_` | `OrganizationID` | 組織實體身份，須綁定自然人代表 `Steward`（`hid_`），構成雙向同意單親無環樹 |
| `dyn_` | `DynamicCode` | 短生命週期（`<= 600s`）、單次防重放、不可關聯的對外出示動態碼 |
| `grt_` / `vrf_` | `AuthorizationGrant` / `VerificationCode` | 限定資源範圍（`EXACT` / `PREFIX`）的鑑權交換授權與可離線核驗回執 |
| `gmcref_` | `OpaqueRef` | 面向公譽鏈（`GMChain`）自然人權重歸一化的盲化不可逆錨點（`ifay.gmc.natural-person.v1`） |

## 3. 建立自持密鑰 Ed25519 身份範例

```js
import { randomBytes } from "node:crypto";
import {
  AccountDirectory,
  deriveEntityKeypair,
  deriveHumanIdentityFromSeed,
} from "../../src/fayid-toolkit.mjs";

const rootSeed = randomBytes(32); // 僅駐留本地宿主安全儲存，永不序列化外發
const human = deriveHumanIdentityFromSeed(rootSeed); // human.humanId => "hid_..."（僅本地持有）
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

## 4. 延伸閱讀

- **架構藍圖**：[`./blueprint/`](./blueprint/) — 了解身份與所有權模型、憑證生命週期及鑑權交換設計動機。
- **正式協議規範（Final 1.0）**：[`./specification/2025-10-25/README.md`](./specification/2025-10-25/README.md) — 查閱分章規範正文、[`schemas/fayid-1.0.json`](../../schemas/fayid-1.0.json) 與測試向量要求。
