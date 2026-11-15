---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: zh-TW
canonical: false
chapter: 4
---

# 第 4 章 身分實體、單層所有權與組織層級樹

## 4.1 `HumanID` 與 `iFay` 的一對多綁定（Normative）

1. **根身分產生**：**人類原型**透過本機持有者代理產生或派生 Ed25519 公鑰 `pk_human`，計算 `hid_ || base32NoPad(SHA-256(pk_human))` 得到 `HumanID`。
2. **`1:N` 不可轉移綁定**：同一 `HumanID` `MAY` 註冊並擁有任意數量的 `iFay`（`HumanID : iFayID = 1:N`）。註冊 `iFay` 時，`MUST` 同時提供該 `HumanID` 私鑰與新 `iFay` 私鑰對同一綁定訊息的聯合簽章證明；缺少任一有效證明 `MUST` 拒絕並回傳 `HUMAN_ID_OWNERSHIP_NOT_PROVEN`。
3. **預設跨 `iFay` 不可關聯**：公開的 `IFayRecord` 僅保存加鹽單向承諾 `humanIdProofRef`（`hidproof_<base32>`）而不包含明文 `hid_`。除非**人類原型**主動出示聯合證明，第三方無法僅憑兩個 `ifay_` 公開紀錄判定它們是否屬於同一**人類原型**。
4. **不可轉讓性**：`iFay` 一旦與 `HumanID` 綁定，其歸屬關係終身固定，**嚴禁**變更至其他 `HumanID` 或任何 `OrganizationID`。

## 4.2 `coFay` 單層直連所有權與 `managers` 正交授權（Normative）

為確保每一個共享角色數位體都具備唯一、可穿透問責的最終責任主體，FayID 1.0 對 `coFay` 強制實施**單層直連所有權（Single-Layer Ownership）**模型：

1. **合法所有者型別限制**：`coFay` 的 `ownerId` `MUST` 僅為 `HumanID`（`hid_`）或 `OrganizationID`（`org_`），對應 `ownerKind` 為 `"HUMAN"` 或 `"ORGANIZATION"`。任何試圖以 `iFay`（`ifay_`）或另一 `coFay`（`cofay_`）作為 `coFay` 所有者的請求，`MUST` 立即拒絕並回傳 `OWNER_TYPE_NOT_ALLOWED`（禁止多層巢狀 `coFay` 所有權鏈）。
2. **所有權轉移**：目前所有者（`hid_` 或 `org_`）`MAY` 透過簽署所有權變更證明，將 `coFay` 轉移給新的合法所有者（`hid_` 或 `org_`），轉移後 `version` 保持 `"1.0"` 且更新所有者綁定紀錄。
3. **正交維運管理清單（`managers: iFayID[]`）**：
   - `coFay` 的所有者（`hid_` 或 `org_`）`MAY` 授權零個或多個 `iFayID` 進入 `managers` 清單，承擔日常設定與執行管理職責。
   - 僅目前直接所有者具備增刪 `managers` 的權限；已被列為 `manager` 的 `iFay` **嚴禁**自行追加、移除或轉授其他 `manager`，任何越權轉授嘗試 `MUST` 拒絕並回傳 `AUTHORITY_GRANT_UNAUTHORIZED`（單跳無再委派原則）。
   - `managers` 清單中的 `iFay` 僅享有維運操作權限，不改變 `coFay` 的法律或治理所有權歸屬。

## 4.3 組織實體（`OrganizationID`）與自然人 `Steward`（Normative）

1. **強制自然人治理代表（`Steward`）**：每個註冊的 `OrganizationRecord` `MUST` 指定一名自然人治理代表 `stewardHumanId`，其值 `MUST` 為已註冊且未撤銷的 `HumanID`（`hid_`）。任何嘗試將 `ifay_`、`cofay_` 或 `org_` 設為 `Steward` 的操作 `MUST` 拒絕並回傳 `STEWARD_TYPE_NOT_ALLOWED`。
2. **代表變更**：組織可透過組織控制金鑰簽署變更指令更換 `stewardHumanId`，新代表同樣 `MUST` 為有效且未撤銷的 `HumanID`。

## 4.4 自包含單父無環組織層級樹（Normative）

FayID 1.0 在本儲存庫規範內自包含定義組織間的層級治理關係：

1. **單父樹拓撲**：每個 `OrganizationRecord` 包含 `parentOrgId: OrganizationID | null`。每個子組織在同一時刻最多只能擁有一個直接父組織，整體構成若干棵有向無環樹（森林）。協定**不設** 16 層之類的人為固定深度上限。
2. **強制雙向同意（Mutual Two-Party Consent）**：建立或變更 `childOrg.parentOrgId = parentOrgId` 時，`MUST` 同時附帶子組織控制金鑰簽署的掛載請求簽章與目標父組織控制金鑰簽署的接納同意簽章。缺少任一方同意或驗章失敗時，`MUST` 拒絕並回傳 `HIERARCHY_CONSENT_MISSING`。
3. **無環偵測（Cycle Rejection）**：將 `parentOrgId` 指向組織自身，或指向該組織目前任意後代子組織以致形成環路的掛載請求，`MUST` 確定性拒絕並回傳 `HIERARCHY_CYCLE_CONFLICT`。
4. **所有權不隨組織樹自動上捲**：子組織名下直接擁有的 `coFay` 仍以該子組織 `org_` 為直接所有者；父組織不會因為組織層級掛載而自動取得子組織名下 `coFay` 的直接所有權或跳過單層所有權紀錄。
