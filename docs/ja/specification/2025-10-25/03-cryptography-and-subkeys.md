---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: ja
canonical: false
chapter: 3
---

# 第 3 章 自己主権型暗号スイートおよび目的別サブ鍵派生

## 3.1 自己主権型保持者証明の信頼モデル（Normative）

FayID 1.0 は純粋な自己主権型保持者証明（Self-Sovereign Holder-of-Key）の信頼モデルを採用する。

1. アイデンティティの作成および制御は対応する Ed25519 秘密鍵の保持証明に完全に依存し、いかなる中央集権的登録機関の署名にも依存しない。
2. 特定の `HumanID`、`iFayID`、`coFayID`、または `OrganizationID` の保持または帰属を主張するすべての状態変更操作（登録、委任、階層アタッチ、権限付与、失効）には、対応する制御鍵によって生成された有効な暗号学的証明を添付**しなければならない**（`MUST`）。証明が欠落している場合や署名検証に失敗した場合は操作を拒否し、`HUMAN_ID_OWNERSHIP_NOT_PROVEN`、`OWNERSHIP_NOT_PROVEN`、または `TARGET_OWNERSHIP_NOT_PROVEN` を返さ**なければならない**（`MUST`）。

## 3.2 必須暗号アルゴリズム一覧（Normative）

FayID 1.0 は外部ブラックボックス依存ゼロの標準暗号プリミティブの組み合わせを固定採用する。

| 用途 | 必須アルゴリズム | 規定出力サイズ |
| --- | --- | --- |
| 非対称署名および保持者証明 | Ed25519（RFC 8032 PureEdDSA） | 32 バイト生公開鍵、64 バイト署名 |
| 識別子ダイジェストおよびコミットメント計算 | SHA-256（FIPS 180-4） | 32 バイトダイジェスト |
| 決定論的サブ鍵派生 | HKDF-SHA256（RFC 5869） | 32 バイト目的別シード |
| 従来型サブジェクトハッシュおよびダイナミックコード認証 | HMAC-SHA256（RFC 2104） | 32 バイトメッセージ認証コード（必要に応じて 20 バイトに切り詰め） |
| JSON 署名ペイロード正規化 | JCS（RFC 8785 JSON Canonicalization Scheme） | UTF-8 決定論的バイト列 |

マスターシード（`masterSeed`）およびブラインドソルト（`userBlindSalt`）の生エントロピー長は **256 ビット（32 バイト）**以上で**なければならない**（`MUST`）。32 バイト未満の入力は拒否し、`INSUFFICIENT_ENTROPY` を返さ**なければならない**（`MUST`）。

## 3.3 HKDF-SHA256 ドメイン分離による目的別サブ鍵派生（Normative）

ルート秘密鍵およびマスターシードが高頻度の署名処理や外部プロトコルのパッケージング処理に直接露出しないことを保証するため、保持者エージェントは 32 バイト以上のマスターシードから HKDF-SHA256 を用いて、暗号学的に相互分離された 32 バイトの目的別サブ鍵を派生させ**なければならない**（`MUST`）。

```text
subkeySeed32 = HKDF-SHA256(
  ikm  = masterSeedBytes,
  salt = SHA-256(UTF8("fayid.subkey.salt:" || domain)),
  info = UTF8(domain || ":" || context),
  len  = 32
)
```

本仕様は保護された 5 つのドメイン分離定数（`SubkeyDomain`）を定義する。

| 定数名 | ドメイン分離文字列（`domain`） | 用途とセキュリティ境界 |
| --- | --- | --- |
| `ENTITY` | `ifay.fayid.entity.v1` | `HumanID`、`iFay`、`coFay`、`OrganizationID` のエンティティ制御用 Ed25519 鍵ペアの派生 |
| `EGO_PACKAGE_SIGNING` | `ifay.ego.package-signing.v1` | `.ego` 人格／状態エクスポートパッケージの署名に特化した専用 Ed25519 署名サブ鍵 |
| `DYNAMIC_CODE` | `ifay.fayid.dynamic-code.v1` | ダイナミックコードの発行および検証コンテキスト用の対称鍵材料の派生 |
| `AUTH_EXCHANGE` | `ifay.fayid.auth-exchange.v1` | 認証交換認可（`grt_`）および検証レシート（`vrf_`）用の署名鍵材料の派生 |
| `GMC_NATURAL_PERSON` | `ifay.gmc.natural-person.v1` | `GMChain` 向け自然人ブラインドアンカー用の擬似乱数鍵材料の派生 |

実装は以下の 2 つの厳格な分離制約を遵守**しなければならない**（`MUST`）。

1. **必須ドメイン検査**：サブ鍵派生インターフェースを呼び出す際、`domain` および `context` は非空文字列で**なければならず**（`MUST`）、かつ `domain` は既知の管理対象ドメイン集合に属さ**なければならない**（`MUST`）。正当なドメイン分離識別子を指定しない呼び出しは拒否し、`DOMAIN_SEPARATION_REQUIRED` を返さ**なければならない**（`MUST`）。
2. **Ego パッケージにおけるルート鍵の外部送出ゼロ（Root-Key Isolation）**：`.ego` 送信パッケージに署名する際、実装は `ifay.ego.package-signing.v1` から派生したサブ鍵のみを使用して署名エンベロープ（`version: "1.0"`、`domain: "ifay.ego.package-signing.v1"`、`signerFayId`、`keyId`、`signingPublicKeyHex`、`manifestDigestSha256`、`signedAt`、`signatureHex` を含む）を生成**しなければならない**（`MUST`）。いかなる送信パッケージ、公開エンティティレコード、または検証レシートにも、`masterSeed`、`seed`、`privateKey`、`secretKey`、`mnemonic` などの秘密鍵材料フィールドを含めては**ならない**。検証者は秘密鍵材料を含む送信エンベロープに遭遇した場合、規約違反と判定して拒否**しなければならない**（`MUST`）。

## 3.4 RFC 8785 JCS 正規化署名規約（Normative）

実装間で検証されるすべての構造化署名ペイロード（所有権バインディング証明、双方向階層同意書、Ego パッケージマニフェスト署名ペイロード、および `vrf_` 検証レシート署名ペイロードを含む）は、Ed25519 の `sign` / `verify` または SHA-256 に入力する前に、まず RFC 8785 JCS によって一意かつ決定論的な UTF-8 バイト列へ正規化**しなければならない**（`MUST`）。

1. オブジェクトのプロパティキーは UTF-16 コード単位の辞書順（昇順）にソートし、値が `undefined` である任意キーはシリアライズ前に省略する。
2. 数値は ECMAScript 仕様に基づく最小かつ一意な 10 進表記に従う（`-0` は `"0"` に正規化し、`NaN` および `Infinity` は禁止する）。
3. 配列要素の順序は厳密に保持し、文字エスケープは標準の最小 JSON エスケープ規則に従い、キー名と区切り文字の間に余分な空白を一切含めない。
