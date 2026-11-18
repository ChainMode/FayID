# FayID 1.0 Quickstart Guide

**FayID 1.0** (`2025-10-25` Final) is the Self-Sovereign (Holder-of-Key) accountability identity protocol for the iFay ecosystem. Every individual `iFay` is bound `1:N` and non-transferably to a unique **Human Prime**, every shared-role `coFay` is bound in a single ownership layer to an accountable `HumanID` or `OrganizationID`, and root private keys remain strictly inside the local **Host** device boundary.

## 1. Prerequisites & Verification

The reference implementation in [`src/fayid-toolkit.mjs`](../../src/fayid-toolkit.mjs) uses Node.js 20+ built-in `node:crypto` (`Ed25519`, `SHA-256`, `HKDF-SHA256`, RFC 8785 JCS) with zero external runtime dependencies. Run the full unit and conformance vector suite from the repository root:

```bash
npm test
```

## 2. Canonical Identifier Prefixes

All cryptographic identifiers follow `<prefix>_<lowercase-rfc4648-base32-nopad>` (`org_` additionally supports lowercase `[a-z0-9-]+` slugs):

| Prefix | Entity / Token | Accountability & Privacy Rule |
| --- | --- | --- |
| `hid_` | `HumanID` | Root identity of a `Human Prime` (`SHA-256(publicKey)`); **never egresses outbound from the local Host or into public logs** |
| `ifay_` | `IFayID` | Individual `iFay` paired `1:N` and non-transferably with its owning `hid_` |
| `cofay_` | `CoFayID` | Shared-role `coFay` owned in a single layer by `hid_` or `org_`, with orthogonal `managers: iFayID[]` |
| `org_` | `OrganizationID` | Accountable organization anchored by a natural-person `Steward` (`hid_`) in a mutual-consent single-parent acyclic tree |
| `dyn_` | `DynamicCode` | Short-lived (`<= 600s`), single-use, replay-protected unlinkable presentation token |
| `grt_` / `vrf_` | `AuthorizationGrant` / `VerificationCode` | Scoped (`EXACT` / `PREFIX`) Auth Exchange grant and offline-verifiable Ed25519 receipt |
| `gmcref_` | `OpaqueRef` | Blind natural-person anchor (`ifay.gmc.natural-person.v1`) for read-only `GMChain` normalization |

## 3. Create a Holder-of-Key Ed25519 Identity

```js
import { randomBytes } from "node:crypto";
import {
  AccountDirectory,
  deriveEntityKeypair,
  deriveHumanIdentityFromSeed,
} from "../../src/fayid-toolkit.mjs";

const rootSeed = randomBytes(32); // Kept strictly inside local Host secure storage
const human = deriveHumanIdentityFromSeed(rootSeed); // human.humanId => "hid_..." (never egresses)
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

## 4. Next Steps

- **Architectural Blueprint**: [`./blueprint/`](./blueprint/) — design rationale for ownership vs. authority, credentials lifecycle, and Auth Exchange.
- **Normative Specification (Final 1.0)**: [`./specification/2025-10-25/README.md`](./specification/2025-10-25/README.md) — full protocol clauses, [`schemas/fayid-1.0.json`](../../schemas/fayid-1.0.json), and conformance requirements.
