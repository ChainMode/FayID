---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: ja
canonical: false
chapter: 6
---

# 第 6 章 プライバシー境界、`GMChain` インターフェース、エラーコードおよび適合性判定

## 6.1 送信ペイロードおよびログ匿名化の厳格な境界（Normative）

すべての実装は、プロトコルのシリアライズ層と可観測性ログ層の双方において、バイパス不可能な以下のプライバシー境界を同時に適用**しなければならない**（`MUST`）。

1. **平文 `hid_` の外部送出ゼロ・ログ記録ゼロ**：いかなるネットワーク送信リクエスト、公開ディレクトリスナップショット、`.ego` エクスポートパッケージ、主体間検証レシート（`vrf_`）、クラッシュダンプ、および監査ログにも、平文の `hid_<base32>` 文字列を書き込んでは**ならない**。外部とのやり取りには一律して `ifay_`、`cofay_`、`dyn_`、`hidproof_`、またはブラインドアンカー `gmcref_` を使用する。
2. **マスターシードおよび秘密鍵の外部送出ゼロ**：マスターシード（`masterSeed`）、ニーモニック、生秘密鍵（`privateKey` / `secretKey`）、および `userBlindSalt` は、管理下のローカル保持者エージェントのセキュアストレージ内に厳格に留め**なければならず**、いかなるシリアライズ済み公開レコードやネットワークペイロードにも含めては**ならない**。
3. **名前空間横断の非リンク性**：外部の利用ドメインごとに独立したドメイン分離定数またはソルトを使用し、外部の観測者が識別子を照合して同一の**人間プライム**のネットワーク横断的な行動プロファイルを構築することを防止**しなければならない**。

## 6.2 `公誉チェーン`（`GMChain`）の読み取り専用境界とブラインドアンカー `gmcref_`（Normative）

`公誉チェーン`（`GMChain`）では、同一の自然人がいくつの `iFay` を作成しても、自然人単位でのガバナンス重み付けおよびシビル攻撃対策の正規化において単一の自然人アンカーとして計上される必要があり、かつ当該自然人の平文 `hid_` を知得できてはならない。このため、FayID 1.0 は決定論的ブラインドアンカー `gmcref_<base32>` を以下のように定義する。

```text
prk    = HKDF-SHA256(ikm = userBlindSalt, salt = SHA-256("fayid.gmc.salt.v1"), info = "ifay.gmc.natural-person.v1:" || namespace, len = 32)
digest = HMAC-SHA256(key = prk, data = UTF8("gmcref:" || canonicalHumanId))
gmcref = "gmcref_" || base32EncodeNoPad(digest)
```

規定上の境界は以下のとおりである。

1. **決定論性と不可逆性**：同一の正当な `HumanID`、32 バイト以上の `userBlindSalt`、および同一の `namespace`（デフォルトは `"gmchain.main"`）が与えられた場合、派生される `gmcref_` は完全に決定論的かつ一定である。`userBlindSalt` を持たない第三者（`GMChain` ノードを含む）は、計算上 `gmcref_` から `hid_` を逆算できず、当該自然人配下の公開 `ifay_` レコードと直接関連付けることもできない。
2. **厳格な読み取り専用インターフェース境界**：FayID は `GMChain` に対して一方向アンカーの派生および失効状態検証の入力のみを提供し、`GMChain` の台帳状態の**読み書きを行わず**、`美誉値`（`MeriToken`）の計算・増減・配分にも**関与しない**。`美誉値`（`MeriToken`）は非貨幣的な社会貢献の評価指標であり、暗号資産・金融決済手段・法定通貨への換金や投機的取引の対象となる資産ではない。
3. **自然人限定の派生**：`deriveBlindGmcRef` の主体入力は正当な `HumanID`（`hid_`）で**なければならない**（`MUST`）。`ifay_`、`cofay_`、または `org_` が渡された場合は拒否し、`MALFORMED_FAYID_STRING` を返さ**なければならない**（`MUST`）。

## 6.3 規定エラーコードレジストリ（Normative）

FayID 1.0 に準拠する実装は、以下の 24 項目の安定したエラーコード定数（基本プロトコルエラーコード 14 項目 + アカウント・暗号ドメイン・カスケードガバナンスエラーコード 10 項目）を維持**しなければならない**（`MUST`）。

| エラーコード定数 | 発生条件の概要 |
| --- | --- |
| `INSUFFICIENT_ENTROPY` | マスターシード、ブラインドソルト、または乱数エントロピー長が下限の 256 ビット（32 バイト）未満である |
| `HUMAN_ID_OWNERSHIP_NOT_PROVEN` | 登録または操作で `HumanID` 保持者署名の提示が求められるが、欠落しているか署名検証に失敗した |
| `OWNERSHIP_NOT_PROVEN` | エンティティ制御権または移転操作において現在の所有者の有効な署名証明が欠落している |
| `TARGET_OWNERSHIP_NOT_PROVEN` | `grt_` 発行などの操作で対象の `iFay` / `coFay` に対する保持権が証明されていない（バインディング推測防止のため最優先で返却） |
| `LEGACY_SUBJECT_MISMATCH` | 従来型クレデンシャルの正規化サブジェクトハッシュがバインド済みの `LegacySubjectRef` と一致しない |
| `DYNAMIC_CODE_EXPIRED` | `dyn_` の検証時刻がその有効期限 `expiresAt` を過ぎている |
| `DYNAMIC_CODE_INVALID` | `dyn_` の形式が未知、HMAC 検証失敗、オーディエンス不一致、または要求 TTL が上限の 600 秒を超えている |
| `VERIFICATION_RATE_LIMITED` | 連続検証失敗回数がレート制限ウィンドウの閾値に達した（デフォルトは 600 秒以内に 5 回失敗で指数バックオフ発動） |
| `IDENTITY_REVOKED` | 基本層の汎用アイデンティティ失効済み状態識別子 |
| `LEGACY_AUTH_FAILED` | 外部の従来型クレデンシャル（パスワード、証明書、トークン、コントラクト証明など）の上流認証に失敗した |
| `GRANT_EXPIRED` | `grt_` 認可の検証時刻がその有効期限 `expiresAt` を過ぎている |
| `GRANT_REVOKED` | `grt_` 認可が個別に失効されている |
| `GRANT_INVALID` | `grt_` が存在しない、構造が不正、対象種別が不許可、または要求 `resourceRef` が認可スコープ外である |
| `MALFORMED_FAYID_STRING` | 識別子プレフィックス／Base32 本体が不正、`resourceRef` の構文違反、または想定外のプレフィックス種別が渡された |
| `OWNER_TYPE_NOT_ALLOWED` | `iFay` または `coFay` を `coFay` の所有者に設定しようとした（単層所有権不変条件への違反） |
| `HIERARCHY_CONSENT_MISSING` | 組織階層のアタッチにおいて子組織または親組織のいずれか一方の有効な同意署名が欠落している |
| `HIERARCHY_CYCLE_CONFLICT` | 組織階層のアタッチが自組織または自組織の子孫ノードを指しており、巡回（ループ）を形成する |
| `AUTHORITY_GRANT_UNAUTHORIZED` | `coFay` の直接所有者以外（`managers` メンバーなど）が `managers` 権限の変更または再委任を試みた |
| `STEWARD_TYPE_NOT_ALLOWED` | 組織の `Steward` が有効かつ未失効の自然人 `HumanID`（`hid_`）として指定されていない |
| `ENTITY_REVOKED` | 対象エンティティまたはその上流帰属の `HumanID` / `OrganizationID` が直接またはカスケード失効されている |
| `DYNAMIC_CODE_REPLAYED` | 同一のワンタイム `dyn_` ダイナミックコードが重複して検証送信された（リプレイ防止による遮断） |
| `DYNAMIC_CODE_TARGET_NOT_ALLOWED` | ダイナミックコード非対応の主体（`OrganizationID` など）に対して `dyn_` を発行しようとした |
| `DOMAIN_SEPARATION_REQUIRED` | HKDF サブ鍵派生において正当な `SubkeyDomain` または非空のコンテキスト識別子が欠落している |
| `RECEIPT_INVALID` | `vrf_` 検証レシートの構造欠損、不正なプレフィックス、または Ed25519 署名検証の失敗 |

## 6.4 適合性判定条件（Conformance）（Normative）

いかなるソフトウェアライブラリ、サービス、または保持者エージェントも、**FayID 1.0** への適合を宣言する場合は、以下の検証可能なすべての条件を満たさ**なければならない**（`MUST`）。

1. **バージョンおよび Schema 適合**：生成するすべての公開エンティティレコードおよびクレデンシャルエンベロープが `version: "1.0"` を保持し、[schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json) による検証を通過すること。
2. **識別子およびリソースマッチング適合**：第 2 章で規定する 8 種類のプレフィックス正規化、暗黙的修復を行わない厳格拒否規則、および `resourceRef` の `EXACT` / `PREFIX` 境界マッチングを完全に実装すること。
3. **暗号スイートおよびルート鍵分離適合**：第 3 章で規定する Ed25519、SHA-256、HKDF-SHA256 による 5 種類のドメイン分離サブ鍵派生、および RFC 8785 JCS 署名を完全に実装し、`.ego` パッケージを含むすべての送信ペイロードで `ifay.ego.package-signing.v1` サブ鍵を厳格に使用して、ルートシードおよび秘密鍵の外部送出ゼロを保証すること。
4. **アカウントモデルおよびカスケード失効適合**：第 4 章の単層 `coFay` 所有権、自然人 `Steward`、双方向同意に基づく単一親・非巡回組織ツリー、ならびに第 5 章の `dyn_` リプレイ防止、`grt_` / `vrf_` スコープ付き交換、および 4 種類の主体に対する決定論的カスケード失効を完全に強制すること。
5. **公式テストベクター全件合格**：本リポジトリの [vectors/account-hierarchy-vectors.json](../../../../vectors/account-hierarchy-vectors.json) および [vectors/crypto-and-revocation-vectors.json](../../../../vectors/crypto-and-revocation-vectors.json) に含まれるすべての正常系および異常系適合性テストベクターに 100% 合格すること。
