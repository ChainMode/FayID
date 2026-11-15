---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: ja
canonical: false
chapter: 4
---

# 第 4 章 アイデンティティエンティティ、単層所有権および組織階層ツリー

## 4.1 `HumanID` と `iFay` の一対多バインディング（Normative）

1. **ルートアイデンティティの生成**：**人間プライム**はローカルの保持者エージェントを通じて Ed25519 公開鍵 `pk_human` を生成または派生させ、`hid_ || base32NoPad(SHA-256(pk_human))` を計算して `HumanID` を得る。
2. **`1:N` の譲渡不能バインディング**：同一の `HumanID` は任意の数の `iFay` を登録・所有**してもよい**（`MAY`）（`HumanID : iFayID = 1:N`）。`iFay` を登録する際は、当該 `HumanID` の秘密鍵と新規 `iFay` の秘密鍵による同一バインディングメッセージへの共同署名証明を同時に提供**しなければならない**（`MUST`）。いずれかの有効な証明が欠落している場合は拒否し、`HUMAN_ID_OWNERSHIP_NOT_PROVEN` を返さ**なければならない**（`MUST`）。
3. **デフォルトにおける `iFay` 間の非リンク性**：公開される `IFayRecord` はソルト付き一方向コミットメント `humanIdProofRef`（`hidproof_<base32>`）のみを保持し、平文の `hid_` を含まない。**人間プライム**が能動的に共同証明を提示しない限り、第三者は 2 つの `ifay_` 公開レコードのみからそれらが同一の**人間プライム**に属するかどうかを判定できない。
4. **譲渡不能性**：`iFay` は一度 `HumanID` にバインドされると、その帰属関係は恒久的に固定され、他の `HumanID` やいかなる `OrganizationID` へも変更**してはならない**。

## 4.2 `coFay` の単層直接所有権および `managers` 直交権限付与（Normative）

すべての共有ロールデジタル体が一意かつ透過的に説明責任を追及できる最終責任主体を持つことを保証するため、FayID 1.0 は `coFay` に対して**単層直接所有権（Single-Layer Ownership）**モデルを強制する。

1. **正当な所有者種別の制限**：`coFay` の `ownerId` は `HumanID`（`hid_`）または `OrganizationID`（`org_`）のみで**なければならず**（`MUST`）、対応する `ownerKind` は `"HUMAN"` または `"ORGANIZATION"` となる。`iFay`（`ifay_`）または別の `coFay`（`cofay_`）を `coFay` の所有者として設定しようとするいかなる要求も直ちに拒否し、`OWNER_TYPE_NOT_ALLOWED` を返さ**なければならない**（`MUST`）（多層ネストされた `coFay` 所有権チェーンの禁止）。
2. **所有権の移転**：現在の所有者（`hid_` または `org_`）は所有権変更証明に署名することにより、`coFay` を新たな正当な所有者（`hid_` または `org_`）へ移転**してもよい**（`MAY`）。移転後も `version` は `"1.0"` を維持し、所有者バインディングレコードを更新する。
3. **直交する運用管理リスト（`managers: iFayID[]`）**：
   - `coFay` の所有者（`hid_` または `org_`）は、日常の設定および運用管理の責務を担わせるため、0 個以上の `iFayID` に権限を付与して `managers` リストへ登録**してもよい**（`MAY`）。
   - `managers` の追加・削除権限を持つのは現在の直接所有者のみである。すでに `manager` として登録されている `iFay` が独断で他の `manager` を追加・削除・再委任することは**してはならず**、権限外の再委任の試みはすべて拒否して `AUTHORITY_GRANT_UNAUTHORIZED` を返さ**なければならない**（`MUST`）（1 ホップ・再委任禁止の原則）。
   - `managers` リスト内の `iFay` は運用操作権限のみを有し、`coFay` の法的またはガバナンス上の所有権帰属を変更しない。

## 4.3 組織エンティティ（`OrganizationID`）および自然人 `Steward`（Normative）

1. **必須の自然人ガバナンス代表（`Steward`）**：登録されるすべての `OrganizationRecord` は自然人のガバナンス代表 `stewardHumanId` を 1 名指定**しなければならず**（`MUST`）、その値は登録済みかつ未失効の `HumanID`（`hid_`）で**なければならない**（`MUST`）。`ifay_`、`cofay_`、または `org_` を `Steward` に設定しようとする操作はすべて拒否し、`STEWARD_TYPE_NOT_ALLOWED` を返さ**なければならない**（`MUST`）。
2. **代表の交代**：組織は組織制御鍵で署名された変更指示によって `stewardHumanId` を交代させることができ、新たな代表も同様に有効かつ未失効の `HumanID` で**なければならない**（`MUST`）。

## 4.4 自己完結型の単一親・非巡回組織階層ツリー（Normative）

FayID 1.0 は本リポジトリ仕様内で自己完結する形で組織間の階層ガバナンス関係を定義する。

1. **単一親ツリートポロジ**：各 `OrganizationRecord` は `parentOrgId: OrganizationID | null` を保持する。各子組織は同一時点において最大 1 つの直接の親組織のみを持つことができ、全体として複数の有向非巡回ツリー（森）を構成する。本プロトコルは 16 階層のような人為的な固定深さ上限を**設けない**。
2. **必須の双方向同意（Mutual Two-Party Consent）**：`childOrg.parentOrgId = parentOrgId` を確立または変更する際は、子組織の制御鍵で署名されたアタッチ要求署名と、対象の親組織の制御鍵で署名された受入同意署名の双方を同時に添付**しなければならない**（`MUST`）。いずれか一方の同意が欠落している場合や署名検証に失敗した場合は拒否し、`HIERARCHY_CONSENT_MISSING` を返さ**なければならない**（`MUST`）。
3. **巡回検出（Cycle Rejection）**：`parentOrgId` に自組織そのもの、または自組織の現在の子孫組織のいずれかを指定してループを形成するようなアタッチ要求は、決定論的に拒否し、`HIERARCHY_CYCLE_CONFLICT` を返さ**なければならない**（`MUST`）。
4. **組織ツリーに沿った所有権の自動ロールアップ非適用**：子組織が直接所有する `coFay` は引き続き当該子組織 `org_` を直接所有者とする。親組織は組織階層のアタッチによって子組織配下の `coFay` の直接所有権を自動的に取得することはなく、単層所有権レコードをバイパスすることもない。
