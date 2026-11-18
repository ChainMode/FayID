# FayID 1.0 クイックスタートガイド

**FayID 1.0**（`2025-10-25` 正式版）は、iFay エコシステムにおける自己主権型（Holder-of-Key）アカウンタビリティ ID プロトコルです。すべての個人 `iFay` は一意の **Human Prime**（人間プライム）に `1:N` かつ譲渡不可で紐付けられ、共有ロール `coFay` は単一階層で `HumanID` または `OrganizationID` に帰属し、ルート秘密鍵はローカルの **Host**（ホスト端末）のセキュリティ境界内に厳格に保持されます。

## 1. 動作要件とテストの実行

リファレンス実装 [`src/fayid-toolkit.mjs`](../../src/fayid-toolkit.mjs) は Node.js 20+ 標準の `node:crypto`（`Ed25519`、`SHA-256`、`HKDF-SHA256`、RFC 8785 JCS）のみで構築されており、外部ランタイム依存はありません。リポジトリルートで単体テストと適合性テストベクターを実行します。

```bash
npm test
```

## 2. 正規識別子プレフィックス一覧

すべての暗号識別子は `<prefix>_<lowercase-rfc4648-base32-nopad>` 形式に従います（`org_` は小文字スラグ `[a-z0-9-]+` も許可）。

| プレフィックス | エンティティ / トークン | 責任帰属とプライバシー境界 |
| --- | --- | --- |
| `hid_` | `HumanID` | `Human Prime` のルート識別子（`SHA-256(publicKey)`）。**ローカル Host の外部へ送信・公開ログ出力することは厳禁** |
| `ifay_` | `IFayID` | 所有元の `hid_` と `1:N` で譲渡不可に紐付く個人 `iFay` 識別子 |
| `cofay_` | `CoFayID` | `hid_` または `org_` が単一層で所有する共有 `coFay`（管理権限 `managers: iFayID[]` は直交） |
| `org_` | `OrganizationID` | 自然人 `Steward`（`hid_`）を置く組織識別子（双方合意に基づく単一親非巡回ツリー） |
| `dyn_` | `DynamicCode` | 短寿命（`<= 600s`）・使い捨て・リプレイ防止付きの非連結提示トークン |
| `grt_` / `vrf_` | `AuthorizationGrant` / `VerificationCode` | スコープ限定（`EXACT` / `PREFIX`）の認証交換グラントとオフライン検証可能な Ed25519 レシート |
| `gmcref_` | `OpaqueRef` | 公誉チェーン（`GMChain`）における自然人重み正規化用のブラインドアンカー（`ifay.gmc.natural-person.v1`） |

## 3. Holder-of-Key Ed25519 識別子の生成例

```js
import { randomBytes } from "node:crypto";
import {
  AccountDirectory,
  deriveEntityKeypair,
  deriveHumanIdentityFromSeed,
} from "../../src/fayid-toolkit.mjs";

const rootSeed = randomBytes(32); // ローカル Host のセキュアストレージ内にのみ保持
const human = deriveHumanIdentityFromSeed(rootSeed); // human.humanId => "hid_..."（外部送信禁止）
const ifay = deriveEntityKeypair(rootSeed, "ifay", 0).value; // ifay.entityId => "ifay_..."

const directory = new AccountDirectory();
directory.registerHuman(human.humanId);
directory.registerIFay(ifay.entityId, human.humanId);

const dyn = directory.issueDynamicCode({
  subjectId: ifay.entityId,
  ttlSec: 120,
});
console.log("Outbound unlinkable token:", dyn.value.code); // "dyn_..."
```

## 4. 関連ドキュメント

- **アーキテクチャブループリント**：[`./blueprint/`](./blueprint/) — 所有権と権限の分離、クレデンシャルライフサイクル、認証交換の設計背景。
- **正式プロトコル仕様（Final 1.0）**：[`./specification/2025-10-25/README.md`](./specification/2025-10-25/README.md) — 規範条項全文、[`schemas/fayid-1.0.json`](../../schemas/fayid-1.0.json)、および適合性要件。
