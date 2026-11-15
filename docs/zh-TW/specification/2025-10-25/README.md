---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: zh-TW
canonical: false
---

# FayID 1.0 協定規範

FayID 是 iFay 生態系的自主權（Self-Sovereign / Holder-of-Key）問責身分協定。協定在不依賴任何中心化身分簽發機構（CA / IdP）的前提下，將每一個個體數位分身（`iFay`）一對多不可轉移地綁定至唯一的**人類原型**（`Human Prime`，`hid_`），並將每一個共享角色數位體（`coFay`）單層直連歸屬至單一可問責的 `HumanID`（`hid_`）或 `OrganizationID`（`org_`）。

本目錄收錄 **FayID 1.0 正式版（Final，編輯版次 `2025-10-25`）** 的繁體中文（臺灣）規範譯本，與簡體中文權威規範（`zh-CN`）保持章節與條款一一對齊；如遇跨語種語義分歧，以簡體中文權威版為準。

## 規範章節目錄

| 章節 | 檔案 | 核心範圍 |
| --- | --- | --- |
| 第 1 章 | [01-conventions-and-versioning.md](./01-conventions-and-versioning.md) | 適用範圍、RFC 2119 / RFC 8174 規範性關鍵字與中文動詞對應、核心術語定義、兩段式 `1.0` 協定版本與協商規則 |
| 第 2 章 | [02-identifiers-and-encoding.md](./02-identifiers-and-encoding.md) | 八類規範前綴與無填充小寫 RFC 4648 Base32 編碼、嚴格拒絕與往返不變量、`resourceRef` 正規化與比對、64 位十六進位相容橋接 |
| 第 3 章 | [03-cryptography-and-subkeys.md](./03-cryptography-and-subkeys.md) | 自主權 Ed25519 持有者證明架構、主種子熵要求、HKDF-SHA256 域分離目的子金鑰派生（含 `ifay.ego.package-signing.v1`）、RFC 8785 JCS 正規化數位簽章 |
| 第 4 章 | [04-entities-ownership-and-hierarchy.md](./04-entities-ownership-and-hierarchy.md) | 四類主體、`HumanID : iFayID = 1:N` 綁定、單層 `coFay` 所有權與 `managers` 正交授權、自然人 `Steward`、雙向同意的單父無環組織層級樹 |
| 第 5 章 | [05-dynamic-codes-and-auth-exchange.md](./05-dynamic-codes-and-auth-exchange.md) | 不可關聯動態碼（`dyn_`）簽發與防重放校驗、傳統憑證 HMAC 主題綁定、作用域化鑑權授權憑證（`grt_`）、核驗回執（`vrf_`）與連鎖撤銷 |
| 第 6 章 | [06-privacy-gmc-and-conformance.md](./06-privacy-gmc-and-conformance.md) | 出站酬載與日誌去識別化硬紅線、`公譽鏈`（`GMChain`）唯讀邊界與盲化自然人錨點（`gmcref_`）、24 項規範錯誤碼註冊表與一致性判定要求 |

## 配套規範化工件

| 工件路徑 | 說明 |
| --- | --- |
| [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json) | FayID 1.0 凍結版 JSON Schema（Draft 2020-12，強制 `version: "1.0"`） |
| [schema/2025-10-25/schema.json](../../../../schema/2025-10-25/schema.json) | 與 `schemas/fayid-1.0.json` 位元組級同步的版本化 Schema 鏡像 |
| [schema/2025-10-25/schema.ts](../../../../schema/2025-10-25/schema.ts) | TypeScript 規範常數與型別定義鏡像 |
| [src/fayid-toolkit.mjs](../../../../src/fayid-toolkit.mjs) | 零外部執行階段相依性的 Node.js `node:crypto` 參考實作 |
| [vectors/](../../../../vectors/) | 跨實作確定性一致性測試向量（`account-hierarchy-vectors.json` 與 `crypto-and-revocation-vectors.json`） |
