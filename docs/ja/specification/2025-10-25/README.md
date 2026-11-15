---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: ja
canonical: false
---

# FayID 1.0 プロトコル仕様

FayID は、iFay エコシステムにおける自己主権型（Self-Sovereign / Holder-of-Key）の説明責任アイデンティティプロトコルである。本プロトコルは、いかなる中央集権的な ID 発行機関（CA / IdP）にも依存することなく、各個体デジタル分身（`iFay`）を唯一の**人間プライム**（`Human Prime`、`hid_`）へ一対多かつ譲渡不能な形でバインドし、各共有ロールデジタル体（`coFay`）を説明責任を負う単一の `HumanID`（`hid_`）または `OrganizationID`（`org_`）へ単層で直接帰属させる。

本ディレクトリには **FayID 1.0 正式版（Final、編集版次 `2025-10-25`）** の日本語版仕様を収録する。本訳本は簡体字中国語の正本仕様と章および条項が一対一で対応しており、言語間で意味上の相違が生じた場合は簡体字中国語の正本を基準とする。

## 仕様章構成

| 章 | ファイル | 主な対象範囲 |
| --- | --- | --- |
| 第 1 章 | [01-conventions-and-versioning.md](./01-conventions-and-versioning.md) | 適用範囲、RFC 2119 / RFC 8174 規定キーワードと日本語規範表現の対応、中核用語定義、2 セグメント形式 `1.0` プロトコルバージョンとネゴシエーション規則 |
| 第 2 章 | [02-identifiers-and-encoding.md](./02-identifiers-and-encoding.md) | 8 種類の規定プレフィックスとパディングなし小文字 RFC 4648 Base32 エンコーディング、厳格拒否とラウンドトリップ不変条件、`resourceRef` の正規化とマッチング、64 桁 16 進数レガシー互換ブリッジ |
| 第 3 章 | [03-cryptography-and-subkeys.md](./03-cryptography-and-subkeys.md) | 自己主権型 Ed25519 保持者証明アーキテクチャ、マスターシードのエントロピー要件、HKDF-SHA256 ドメイン分離による目的別サブ鍵派生（`ifay.ego.package-signing.v1` を含む）、RFC 8785 JCS 正規化署名 |
| 第 4 章 | [04-entities-ownership-and-hierarchy.md](./04-entities-ownership-and-hierarchy.md) | 4 種類の主体、`HumanID : iFayID = 1:N` バインディング、単層 `coFay` 所有権と `managers` 直交権限付与、自然人 `Steward`、双方向同意に基づく単一親・非巡回の組織階層ツリー |
| 第 5 章 | [05-dynamic-codes-and-auth-exchange.md](./05-dynamic-codes-and-auth-exchange.md) | 非リンク型ダイナミックコード（`dyn_`）の発行とリプレイ防止検証、従来型クレデンシャルの HMAC サブジェクトバインディング、スコープ付き認可クレデンシャル（`grt_`）、検証レシート（`vrf_`）およびカスケード失効 |
| 第 6 章 | [06-privacy-gmc-and-conformance.md](./06-privacy-gmc-and-conformance.md) | 送信ペイロードおよびログ匿名化の厳格な境界、`公誉チェーン`（`GMChain`）の読み取り専用境界とブラインド自然人アンカー（`gmcref_`）、24 項目の規定エラーコードレジストリと適合性判定要件 |

## 付随する規定アーティファクト

| アーティファクトパス | 説明 |
| --- | --- |
| [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json) | FayID 1.0 凍結版 JSON Schema（Draft 2020-12、`version: "1.0"` を強制） |
| [schema/2025-10-25/schema.json](../../../../schema/2025-10-25/schema.json) | `schemas/fayid-1.0.json` とバイト単位で同期されたバージョン付き Schema ミラー |
| [schema/2025-10-25/schema.ts](../../../../schema/2025-10-25/schema.ts) | TypeScript 規定定数および型定義ミラー |
| [src/fayid-toolkit.mjs](../../../../src/fayid-toolkit.mjs) | 外部ランタイム依存ゼロの Node.js `node:crypto` リファレンス実装 |
| [vectors/](../../../../vectors/) | 実装横断の決定論的適合性テストベクター（`account-hierarchy-vectors.json` および `crypto-and-revocation-vectors.json`） |
