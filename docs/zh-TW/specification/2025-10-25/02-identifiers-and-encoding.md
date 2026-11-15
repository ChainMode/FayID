---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: zh-TW
canonical: false
chapter: 2
---

# 第 2 章 識別碼語法、編碼與資源參照規範

## 2.1 八類規範識別碼前綴表（Normative）

所有 FayID 密碼學識別碼與衍生憑證字串 `MUST` 採用 `<prefix>_<body>` 結構。除 `org_` 允許易讀小寫組織識別字元集 `[a-z0-9-]+` 外，其餘七類識別碼主體 `MUST` 採用**小寫、無 `=` 填充的 RFC 4648 Base32** 字元集（`[a-z2-7]+`）：

| 型別常數 | 字串前綴 | 主體正規表示式 | 典型位元組長度與語義 |
| --- | --- | --- | --- |
| `HUMAN_ID` | `hid_` | `^[a-z2-7]+$` | `SHA-256(humanPublicKey)`（32 位元組 → 52 個 Base32 字元），**人類原型**根身分識別碼 |
| `IFAY_ID` | `ifay_` | `^[a-z2-7]+$` | `SHA-256("ifay:" \|\| humanId \|\| ":" \|\| publicKey)`（32 位元組），個人數位分身識別碼 |
| `COFAY_ID` | `cofay_` | `^[a-z2-7]+$` | `SHA-256("cofay:" \|\| ownerId \|\| ":" \|\| publicKey)`（32 位元組），共享角色數位體識別碼 |
| `ORGANIZATION_ID` | `org_` | `^[a-z0-9-]+$` | 組織主體識別碼（支援確定性雜湊主體或正規化組織短名） |
| `DYNAMIC_CODE` | `dyn_` | `^[a-z2-7]+$` | 20 位元組 HMAC 截斷標籤（32 個 Base32 字元），短時不可關聯出示權杖 |
| `VERIFICATION_CODE` | `vrf_` | `^[a-z2-7]+$` | 20 位元組核驗回執摘要，綁定 `grt_` 或 `cofay_` 狀態核驗結果 |
| `AUTHORIZATION_GRANT` | `grt_` | `^[a-z2-7]+$` | 20 位元組作用域化傳統憑證兌換授權識別碼 |
| `OPAQUE_REF` | `gmcref_` | `^[a-z2-7]+$` | 32 位元組盲化自然人錨點（52 個 Base32 字元），專供 `GMChain` 治理去重 |

此外，在 `iFay` 註冊紀錄與離線套件中，用於替代明文 `hid_` 的單向承諾採用 `hidproof_<lowercase-base32-nopad>` 格式（正規表示式 `^hidproof_[a-z2-7]{16,}$`）。

## 2.2 正規化與嚴格拒絕規則（Normative）

解析函式 `normalizeFayID(input)` `MUST` 滿足以下確定性規則：

1. **型別與非空檢查**：非字串輸入或空字串 `MUST` 立即回傳錯誤碼 `MALFORMED_FAYID_STRING`。
2. **大小寫折疊**：解析器 `MUST` 將 ASCII 大寫字母折疊為小寫（`input.toLowerCase()`），再比對上表八類前綴。
3. **嚴格拒絕，嚴禁靜默修復**：解析器**嚴禁**自動修剪首尾空白字元、剔除連字號（`org_` 主體合法連字號除外）、剝離 `=` 填充符或替換易混淆字元（如將 `0`/`1`/`8`/`9` 替換為 Base32 字母）。凡包含空白、`=`、未知前綴、空主體或越界字元（例如 `hid_` 主體出現 `0`、`1`、`8`、`9`）的字串，`MUST` 一律拒絕並回傳 `MALFORMED_FAYID_STRING`。
4. **往返不變量（Round-Trip Invariant）**：對任意合法正規化識別碼 `x`，再次執行 `normalizeFayID(x)` `MUST` 回傳 `ok: true` 且 `value.canonical === x`；對任意位元組陣列 `b` 執行無填充小寫 Base32 編碼後再解碼，`MUST` 逐位元組還原 `b`，且末尾補零位元 `MUST` 全為 `0`（非零殘留位元 `MUST` 拒絕解碼）。

## 2.3 `resourceRef` 資源命名空間與作用域比對（Normative）

鑑權兌換中的目標資源由 `resourceRef` 識別。`normalizeResourceRef(input)` 與 `matchesResourceRef(grantedResourceRef, requestedResourceRef, scopeMode)` `MUST` 遵循以下規則：

1. **語法結構**：`resourceRef` 採用 `<namespace>:<path>` 結構：
   - `<namespace>` 在折疊為小寫後 `MUST` 符合 `^[a-z][a-z0-9+.-]*$`；
   - `:` 右側 `<path>` `MUST` 非空、不含任何空白字元、不以 `/` 結尾（單字元根路徑除外），且**嚴禁**包含空路徑段（`//`）或相對走訪段（`.` 或 `..`）。
   - 違反上述任一條件 `MUST` 回傳 `MALFORMED_FAYID_STRING`。
2. **大小寫敏感性**：`<namespace>` 部分正規化為小寫；`:` 右側的 `<path>` **必須**保留原始大小寫。
3. **作用域比對模式（`scopeMode`）**：
   - `EXACT`（預設）：僅當正規化後的 `requestedResourceRef === grantedResourceRef` 時比對成功。
   - `PREFIX`：僅當正規化後的請求資源等於授權資源本身，或在 `/` 路徑段邊界上以其為前綴（即 `requested.startsWith(granted + "/")`）時比對成功。例如授權 `cap:repo/fayid` 在 `PREFIX` 模式下符合 `cap:repo/fayid/issues`，但**絕不**符合同層路徑 `cap:repo/fayid-ext`（防止字串前綴越權）。

## 2.4 既有 64 位十六進位公鑰識別碼橋接（Normative）

為相容早期僅持有 32 位元組原始 Ed25519 公鑰十六進位字串（64 個十六進位字元）的既有紀錄，工具套件提供顯式橋接函式 `adaptLegacyHexIdentifier(hex64, prefix)`：

1. 輸入 `hex64` 去除空白後 `MUST` 精確符合 `^[0-9a-fA-F]{64}$`，且目標 `prefix` 僅允許 `hid_`、`ifay_` 或 `cofay_`，否則回傳 `MALFORMED_FAYID_STRING`。
2. 橋接過程對解碼後的 32 位元組原始公鑰計算 `SHA-256`，再編碼為 `<prefix><base32-nopad>`，與原生根身分計算公式完全一致。
3. 協定正式線格式酬載中**不得**直接傳輸裸 64 位十六進位字串充當 FayID；橋接必須在進入協定邊界前顯式完成。
