---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: zh-TW
canonical: false
chapter: 6
---

# 第 6 章 隱私紅線、`GMChain` 介面、錯誤碼與一致性判定

## 6.1 出站酬載與日誌去識別化硬紅線（Normative）

所有實作 `MUST` 在協定序列化層與可觀測性日誌層同時執行以下不可繞過的隱私紅線：

1. **明文 `hid_` 永不出站、永不入日誌**：任何網路出站請求、公開目錄快照、`.ego` 匯出套件、跨主體核驗回執（`vrf_`）、當機傾印及稽核日誌中，**嚴禁**寫入明文 `hid_<base32>` 字串。外部互動一律使用 `ifay_`、`cofay_`、`dyn_`、`hidproof_` 或盲化錨點 `gmcref_`。
2. **主種子與私鑰零出站**：主種子（`masterSeed`）、助記詞、原始私鑰（`privateKey` / `secretKey`）以及 `userBlindSalt` **必須**嚴格駐留於受控本機持有者代理的安全儲存空間內，**嚴禁**進入任何序列化公開紀錄或網路酬載。
3. **跨命名空間不可關聯**：不同外部消費域必須使用各自獨立的域分離常數或鹽值，防止外部觀察者透過比對識別碼拼湊出同一**人類原型**的全網行為側寫。

## 6.2 `公譽鏈`（`GMChain`）唯讀邊界與盲化錨點 `gmcref_`（Normative）

`公譽鏈`（`GMChain`）需要確保同一自然人無論建立多少個 `iFay`，在自然人維度的治理權重與反女巫正規化中僅被計為一個自然人錨點，同時又不能獲知該自然人的明文 `hid_`。為此，FayID 1.0 定義確定性盲化錨點 `gmcref_<base32>`：

```text
prk    = HKDF-SHA256(ikm = userBlindSalt, salt = SHA-256("fayid.gmc.salt.v1"), info = "ifay.gmc.natural-person.v1:" || namespace, len = 32)
digest = HMAC-SHA256(key = prk, data = UTF8("gmcref:" || canonicalHumanId))
gmcref = "gmcref_" || base32EncodeNoPad(digest)
```

規範性邊界如下：

1. **確定性與不可逆性**：給定相同的合法 `HumanID`、不少於 32 位元組的 `userBlindSalt` 與相同的 `namespace`（預設為 `"gmchain.main"`），派生出的 `gmcref_` 完全確定且恆定；缺少 `userBlindSalt` 的第三方（包括 `GMChain` 節點）在計算上無法從 `gmcref_` 反推出 `hid_`，也無法將其與該自然人名下的公開 `ifay_` 紀錄直接關聯。
2. **嚴格唯讀介面邊界**：FayID 對 `GMChain` 僅提供單向錨點派生與撤銷狀態核驗輸入，**不讀寫** `GMChain` 帳本狀態，也**不參與**`美譽值`（`MeriToken`）的計算、增減或分配。`美譽值`（`MeriToken`）是非貨幣化的社會貢獻度量指標，不是加密貨幣、金融結算工具或可兌換法幣資產。
3. **僅限自然人派生**：`deriveBlindGmcRef` 的主體輸入 `MUST` 為合法的 `HumanID`（`hid_`）；傳入 `ifay_`、`cofay_` 或 `org_` `MUST` 拒絕並回傳 `MALFORMED_FAYID_STRING`。

## 6.3 規範錯誤碼註冊表（Normative）

符合 FayID 1.0 的實作 `MUST` 保持以下 24 項穩定錯誤碼常數（14 項基礎協定錯誤碼 + 10 項帳戶、密碼學域與連鎖治理錯誤碼）：

| 錯誤碼常數 | 觸發條件摘要 |
| --- | --- |
| `INSUFFICIENT_ENTROPY` | 主種子、盲化鹽值或隨機熵長度低於 256 位元（32 位元組）下限 |
| `HUMAN_ID_OWNERSHIP_NOT_PROVEN` | 註冊或操作要求出示 `HumanID` 持有者簽章但缺失或驗章失敗 |
| `OWNERSHIP_NOT_PROVEN` | 實體控制權或轉移操作缺少目前所有者有效簽章證明 |
| `TARGET_OWNERSHIP_NOT_PROVEN` | 簽發 `grt_` 等操作未證明對目標 `iFay` / `coFay` 的持有權（最高優先回傳以防綁定探測） |
| `LEGACY_SUBJECT_MISMATCH` | 傳統憑證正規化主題雜湊與已綁定的 `LegacySubjectRef` 不一致 |
| `DYNAMIC_CODE_EXPIRED` | `dyn_` 核驗時間晚於其 `expiresAt` 截止時間 |
| `DYNAMIC_CODE_INVALID` | `dyn_` 格式未知、HMAC 校驗失敗、受眾不符或請求 TTL 超過 600 秒上限 |
| `VERIFICATION_RATE_LIMITED` | 連續核驗失敗次數達到限速視窗門檻值（預設 600 秒內 5 次失敗觸發指數退避） |
| `IDENTITY_REVOKED` | 基礎層通用身分已撤銷狀態識別 |
| `LEGACY_AUTH_FAILED` | 外部傳統憑證（密碼、X.509 憑證、權杖、合約證明等）上游鑑權未通過 |
| `GRANT_EXPIRED` | `grt_` 授權核驗時間晚於其 `expiresAt` 截止時間 |
| `GRANT_REVOKED` | `grt_` 授權已被單獨撤銷 |
| `GRANT_INVALID` | `grt_` 不存在、結構非法、目標型別不允許或請求 `resourceRef` 超出授權作用域 |
| `MALFORMED_FAYID_STRING` | 識別碼前綴/Base32 主體非法、`resourceRef` 語法違規或傳入了非預期前綴型別 |
| `OWNER_TYPE_NOT_ALLOWED` | 試圖將 `iFay` 或 `coFay` 設為 `coFay` 的所有者（違反單層所有權不變量） |
| `HIERARCHY_CONSENT_MISSING` | 組織層級掛載缺少子組織或父組織任一方的有效同意簽章 |
| `HIERARCHY_CYCLE_CONFLICT` | 組織層級掛載指向自身或自身後代節點，構成環路 |
| `AUTHORITY_GRANT_UNAUTHORIZED` | 非 `coFay` 直接所有者（例如 `managers` 成員）試圖修改或轉授 `managers` 權限 |
| `STEWARD_TYPE_NOT_ALLOWED` | 組織 `Steward` 未指定為有效未撤銷的自然人 `HumanID`（`hid_`） |
| `ENTITY_REVOKED` | 目標實體或其上游歸屬 `HumanID` / `OrganizationID` 已被直接或連鎖撤銷 |
| `DYNAMIC_CODE_REPLAYED` | 同一單次 `dyn_` 動態碼被重複提交核驗（防重放攔截） |
| `DYNAMIC_CODE_TARGET_NOT_ALLOWED` | 試圖為不支援動態碼的主體（如 `OrganizationID`）簽發 `dyn_` |
| `DOMAIN_SEPARATION_REQUIRED` | HKDF 子金鑰派生缺少合法 `SubkeyDomain` 或非空脈絡識別 |
| `RECEIPT_INVALID` | `vrf_` 核驗回執結構殘缺、前綴非法或 Ed25519 數位簽章驗章失敗 |

## 6.4 一致性判定條件（Conformance）（Normative）

任一軟體函式庫、服務或持有者代理若聲明符合 **FayID 1.0**，則 `MUST` 滿足以下全部可驗證條件：

1. **版本與 Schema 合規**：產生的所有公開實體紀錄與憑證信封均攜帶 `version: "1.0"`，並通過 [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json) 校驗。
2. **識別碼與資源比對合規**：完整實作第 2 章八類前綴正規化、嚴格拒絕不修復輸入規則及 `resourceRef` 的 `EXACT` / `PREFIX` 邊界比對。
3. **密碼學與根金鑰隔離合規**：完整實作第 3 章 Ed25519、SHA-256、HKDF-SHA256 五類域分離子金鑰派生與 RFC 8785 JCS 數位簽章，且在 `.ego` 套件等全部出站酬載中嚴格使用 `ifay.ego.package-signing.v1` 子金鑰，保證根種子與私鑰零出站。
4. **帳戶模型與連鎖撤銷合規**：完整強制執行第 4 章單層 `coFay` 所有權、自然人 `Steward`、雙向同意單父無環組織樹，以及第 5 章 `dyn_` 防重放、`grt_` / `vrf_` 作用域兌換與四類主體的確定性連鎖撤銷。
5. **官方測試向量全綠**：100% 通過本儲存庫 [vectors/hierarchy/](../../../../vectors/hierarchy) 與 [vectors/crypto-and-revocation-vectors.json](../../../../vectors/crypto-and-revocation-vectors.json) 中的全部正向與負向一致性測試向量。
