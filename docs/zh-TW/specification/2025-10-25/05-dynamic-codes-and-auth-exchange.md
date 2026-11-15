---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: zh-TW
canonical: false
chapter: 5
---

# 第 5 章 不可關聯動態碼、鑑權兌換與連鎖撤銷

## 5.1 不可關聯動態碼（`dyn_`）簽發與核驗（Normative）

由於明文 `hid_` 永不出站，**人類原型**及其名下 `iFay`、`coFay` 在跨邊界出示身分時使用短時效、加鹽防關聯的動態碼（`dyn_<base32>`）：

1. **合法目標主體**：動態碼僅允許為未撤銷的 `HumanID`（`hid_`）、`iFayID`（`ifay_`）或 `coFayID`（`cofay_`）簽發。為 `OrganizationID`（`org_`）請求簽發動態碼 `MUST` 拒絕並回傳 `DYNAMIC_CODE_TARGET_NOT_ALLOWED`（組織識別碼本身為公開主體，無需假名動態碼）。
2. **加鹽不可關聯建構**：每次簽發均產生至少 16 位元組的密碼學隨機 `nonce`，並在 `ifay.fayid.dynamic-code.v1` 域金鑰下對正規化酬載 `{audience, expiresAt, issuedAt, nonceHex, targetId, version: "1.0"}` 計算 HMAC-SHA256，截斷前 20 位元組編碼為 `dyn_<base32>`。被動竊聽者在缺乏核驗脈絡金鑰的情況下，無法透過觀察兩次出示的 `dyn_` 字串判斷它們是否源自同一主體。
3. **嚴格有效視窗上限**：`expiresAt - issuedAt` `MUST` 大於 `0` 且不超過 **`600` 秒（`DYNAMIC_CODE_MAX_TTL_SECONDS = 600`）**；超限簽發請求 `MUST` 拒絕並回傳 `DYNAMIC_CODE_INVALID`。
4. **單次消費與防重放**：核驗方校驗 `dyn_` 時：
   - 若主體本身或其上游歸屬主體已被撤銷，`MUST` 拒絕並回傳 `ENTITY_REVOKED`；
   - 若核驗時間晚於 `expiresAt`，`MUST` 拒絕並回傳 `DYNAMIC_CODE_EXPIRED`；
   - 若 `audience` 不符（當權杖綁定了預期受眾時）或權杖未知，`MUST` 回傳 `DYNAMIC_CODE_INVALID`；
   - 每個 `dyn_` 的隨機 `nonce` 僅允許成功核驗消費**一次**；第二次及後續重複提交同一 `dyn_` `MUST` 拒絕並回傳 `DYNAMIC_CODE_REPLAYED`。
5. **核驗結果隱私保護**：當 `dyn_` 綁定的底層主體為 `HumanID` 時，核驗成功回應**嚴禁**向呼叫端回傳明文 `hid_`，而 `MUST` 回傳主體類別 `"HUMAN"` 及由盲化鹽值確定性派生的 `gmcref_<base32>` 錨點。

## 5.2 傳統憑證綁定與鑑權兌換授權（`grt_` / `vrf_`）（Normative）

Auth Exchange 允許持有者將外部既有系統憑證安全橋接為作用域受限的 FayID 授權憑證（`grt_<base32>`），並在資源存取時產生可離線驗章的核驗回執（`vrf_<base32>`）：

1. **傳統主題隱私雜湊（`LegacySubjectRef`）**：外部憑證主體 `MUST` 正規化並經金鑰 HMAC 處理為 `<legacySourceKind>:<issuerOrAuthority>:<subjectHash>`，其中 `subjectHash = base32NoPad(HMAC-SHA256(legacySecret, canonicalSubject))`。`LegacySubjectRef` **嚴禁**直接串接明文電子郵件地址、手機號碼、X.509 DN、OAuth 原始權杖或區塊鏈明文錢包位址。
2. **預設信任等級對應（`LegacyTrustLevel`）**：
   - `PASSWORD` → `LOW`（授權 TTL 上限為 **`900` 秒**，`LOW_TRUST_GRANT_MAX_TTL_SECONDS`）；
   - `ACCESS_TOKEN`、`AUTHORIZATION` → `MEDIUM`（授權 TTL 上限為 **`3600` 秒**，`GRANT_MAX_TTL_SECONDS`）；
   - `CERTIFICATE`、`SMART_CONTRACT` → `HIGH`（授權 TTL 上限為 **`3600` 秒**）。
   實作 `MAY` 依據風險政策下調信任等級或縮短 TTL，但在無額外多因素持有者證明時 `MUST NOT` 越級上調。
3. **目標持有證明優先檢查（防探測）**：簽發 `grt_` 時，目標主體僅限未撤銷的 `iFayID` 或 `coFayID`，且請求方 `MUST` 出示目標主體的持有者簽章證明。若目標持有證明缺失或無效，系統 `MUST` 優先回傳 `TARGET_OWNERSHIP_NOT_PROVEN`，防止攻擊者透過錯誤碼差異探測某傳統帳號是否已與特定 FayID 綁定。
4. **作用域化核驗與 `vrf_` 回執簽發**：呼叫 `verifyAuthGrant` 核驗 `grt_` 時，系統依序檢查：
   - 授權紀錄是否存在且格式合法（否則回傳 `GRANT_INVALID`）；
   - 目標實體及其上游所有者是否已被撤銷（若實體已撤銷，優先回傳 `ENTITY_REVOKED`）；
   - 授權本身是否已被顯式撤銷（否則回傳 `GRANT_REVOKED`）；
   - 目前時間是否超過 `expiresAt`（否則回傳 `GRANT_EXPIRED`）；
   - 請求的 `requestedResourceRef` 是否依第 2.3 節 `scopeMode`（`EXACT` / `PREFIX`）符合授權的 `resourceRef`（不符則回傳 `GRANT_INVALID`）。
   全部通過後，系統使用 `ifay.fayid.auth-exchange.v1` 域 Ed25519 金鑰對正規化核驗結論進行數位簽章，回傳 `vrf_<base32>` 回執；任何第三方均可呼叫 `verifyAuthReceipt(receipt)` 獨立校驗回執簽章與結構完整性，竄改任一欄位 `MUST` 回傳 `RECEIPT_INVALID`。

## 5.3 確定性連鎖撤銷（Cascading Revocation）（Normative）

撤銷是單調不可逆的終態操作。當任一實體被撤銷時，系統 `MUST` 立即依歸屬與層級關係確定性執行連鎖失效，不得遺留任何懸空作用中子實體或作用中授權憑證：

| 被撤銷的根觸發實體 | 連鎖失效的下游實體範圍 | 對維運授權與作用中憑證的強制連帶處置 |
| --- | --- | --- |
| **`HumanID`（`hid_`）** | 該人類原型名下全部 `iFay`（`ifay_`）及直接歸屬該 `hid_` 的全部 `coFay`（`cofay_`） | 從所有未撤銷 `coFay.managers` 中移除上述被連鎖撤銷的 `ifay_`；撤銷所有指向上述 `ifay_` / `cofay_` 的作用中 `grt_` 與未消費 `dyn_` |
| **`OrganizationID`（`org_`）** | 該組織自身、組織層級樹中全部後代子組織（遞迴子樹），以及直接歸屬於該組織或任一後代子組織的全部 `coFay` | 撤銷所有指向上述被連鎖撤銷 `cofay_` 的作用中 `grt_` 與未消費 `dyn_` |
| **`iFayID`（`ifay_`）** | 該 `iFay` 自身 | 從所有未撤銷 `coFay.managers` 清單中立即移除該 `ifay_`；撤銷所有以該 `ifay_` 為 `targetFayId` 的作用中 `grt_` 與未消費 `dyn_` |
| **`coFayID`（`cofay_`）** | 該 `coFay` 自身 | 撤銷所有以該 `cofay_` 為 `targetFayId` 的作用中 `grt_` 與未消費 `dyn_` |

連鎖撤銷完成後：
1. 對任何已被直接或連鎖撤銷的實體簽發新的 `dyn_`、`grt_`、註冊新下屬實體或核驗既有憑證時，`MUST` 確定性拒絕並回傳 `ENTITY_REVOKED`（對被單獨手動撤銷但目標實體仍存活的授權則回傳 `GRANT_REVOKED`）。
2. 被撤銷實體即使仍在原定 TTL 時間視窗內，其憑證也**立即失效**，不得繼續通過核驗。
