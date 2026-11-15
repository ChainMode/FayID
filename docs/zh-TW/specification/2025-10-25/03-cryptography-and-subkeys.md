---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: zh-TW
canonical: false
chapter: 3
---

# 第 3 章 自主權密碼學套件與目的子金鑰派生

## 3.1 自主權持有者證明信任模型（Normative）

FayID 1.0 採用純自主權持有者證明（Self-Sovereign Holder-of-Key）信任模型：

1. 身分的建立與控制完全取決於對應 Ed25519 私鑰的持有證明，不依賴任何中心化註冊機構簽章。
2. 任何聲稱持有或歸屬於某 `HumanID`、`iFayID`、`coFayID` 或 `OrganizationID` 的狀態變更操作（註冊、委派、層級掛載、轉授、撤銷），`MUST` 附帶由對應控制金鑰產生的有效密碼學證明；缺少證明或驗章失敗時 `MUST` 拒絕並回傳 `HUMAN_ID_OWNERSHIP_NOT_PROVEN`、`OWNERSHIP_NOT_PROVEN` 或 `TARGET_OWNERSHIP_NOT_PROVEN`。

## 3.2 強制密碼學演算法清單（Normative）

FayID 1.0 固定採用以下零外部黑箱相依性的標準密碼學原語組合：

| 用途 | 強制演算法 | 規範輸出規模 |
| --- | --- | --- |
| 非對稱數位簽章與持有者證明 | Ed25519（RFC 8032 PureEdDSA） | 32 位元組原始公鑰，64 位元組簽章 |
| 識別碼摘要與承諾計算 | SHA-256（FIPS 180-4） | 32 位元組摘要 |
| 確定性子金鑰派生 | HKDF-SHA256（RFC 5869） | 32 位元組目的種子 |
| 傳統主題雜湊與動態碼鑑別 | HMAC-SHA256（RFC 2104） | 32 位元組訊息鑑別碼（依需求截斷至 20 位元組） |
| JSON 簽章酬載正規化 | JCS（RFC 8785 JSON Canonicalization Scheme） | UTF-8 確定性位元組序列 |

主種子（`masterSeed`）與盲化鹽值（`userBlindSalt`）的原始熵長度 `MUST` 不少於 **256 位元（32 位元組）**；低於 32 位元組的輸入 `MUST` 拒絕並回傳 `INSUFFICIENT_ENTROPY`。

## 3.3 HKDF-SHA256 域分離目的子金鑰派生（Normative）

為確保根私鑰與主種子永不直接暴露在高頻簽章或外部協定封裝流程中，持有者代理 `MUST` 從 32 位元組及以上的主種子透過 HKDF-SHA256 派生彼此密碼學隔離的 32 位元組目的子金鑰：

```text
subkeySeed32 = HKDF-SHA256(
  ikm  = masterSeedBytes,
  salt = SHA-256(UTF8("fayid.subkey.salt:" || domain)),
  info = UTF8(domain || ":" || context),
  len  = 32
)
```

規範定義了五個受保護的域分離常數（`SubkeyDomain`）：

| 常數名 | 域分離字串（`domain`） | 用途與安全邊界 |
| --- | --- | --- |
| `ENTITY` | `ifay.fayid.entity.v1` | 派生 `HumanID`、`iFay`、`coFay`、`OrganizationID` 的實體控制 Ed25519 金鑰對 |
| `EGO_PACKAGE_SIGNING` | `ifay.ego.package-signing.v1` | 專用於簽署 `.ego` 人格/狀態出站檔案套件的專用 Ed25519 簽章子金鑰 |
| `DYNAMIC_CODE` | `ifay.fayid.dynamic-code.v1` | 派生動態碼簽發與核驗脈絡對稱金鑰材料 |
| `AUTH_EXCHANGE` | `ifay.fayid.auth-exchange.v1` | 派生鑑權兌換授權（`grt_`）與核驗回執（`vrf_`）簽章金鑰材料 |
| `GMC_NATURAL_PERSON` | `ifay.gmc.natural-person.v1` | 派生面向 `GMChain` 的自然人盲化錨點偽隨機金鑰材料 |

實作 `MUST` 遵守兩條硬隔離約束：

1. **強制域檢查**：呼叫子金鑰派生介面時，`domain` 與 `context` `MUST` 為非空字串，且 `domain` `MUST` 屬於已知受控域集合；未提供合法域分離識別的呼叫 `MUST` 拒絕並回傳 `DOMAIN_SEPARATION_REQUIRED`。
2. **Ego 套件根金鑰零出站（Root-Key Isolation）**：簽署 `.ego` 出站套件時，實作 `MUST` 僅使用 `ifay.ego.package-signing.v1` 派生的子金鑰產生簽章信封（包含 `version: "1.0"`、`domain: "ifay.ego.package-signing.v1"`、`signerFayId`、`keyId`、`signingPublicKeyHex`、`manifestDigestSha256`、`signedAt`、`signatureHex`）。任何出站套件、公開實體紀錄或核驗回執中**嚴禁**出現 `masterSeed`、`seed`、`privateKey`、`secretKey` 或 `mnemonic` 等私鑰材料欄位；核驗方遇到攜帶私鑰材料的出站信封時 `MUST` 判定違規並拒絕。

## 3.4 RFC 8785 JCS 正規化數位簽章約定（Normative）

所有跨實作校驗的結構化簽章酬載（包括所有權綁定證明、雙向層級同意書、Ego 套件清單簽章酬載及 `vrf_` 核驗回執簽章酬載）在送入 Ed25519 `sign` / `verify` 或 SHA-256 之前，`MUST` 先經 RFC 8785 JCS 正規化為唯一確定的 UTF-8 位元組串：

1. 物件屬性鍵依 UTF-16 編碼單元字典序升冪排列，且值為 `undefined` 的可選鍵在序列化前省略；
2. 數值遵循 ECMAScript 規範最小無歧義十進位表示（`-0` 正規化為 `"0"`，禁止 `NaN` 與 `Infinity`）；
3. 陣列元素順序嚴格保留，字元跳脫遵循標準最小 JSON 跳脫規則，鍵名與分隔符之間不含任何多餘空白。
