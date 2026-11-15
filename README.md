# FayID

Self-Sovereign (Holder-of-Key) accountability identity protocol (**FayID `1.0` Final**, edition `2025-10-25`) for the iFay ecosystem, binding every individual `iFay` (`1:N`) non-transferably to a unique **Human Prime** (`hid_`) and every shared-role `coFay` in a single ownership layer to one accountable `HumanID` (`hid_`) or `OrganizationID` (`org_`).

## Canonical Identifier Format

All cryptographic FayID identifiers follow `<prefix>_<lowercase-rfc4648-base32-nopad>` (`org_` additionally permits lowercase slug characters `[a-z0-9-]+`):

| Prefix | Entity | Accountability Semantics |
| --- | --- | --- |
| `hid_` | `HumanID` | Root identity of a `Human Prime` (`SHA-256(publicKey)`, 256-bit; never emitted outbound or logged) |
| `ifay_` | `IFayID` | Individual `Fay` strictly paired `1:N` and non-transferably with its owning `HumanID` |
| `cofay_` | `CoFayID` | Shared-role `Fay` bound directly in a single layer to a `HumanID` or `OrganizationID`, with orthogonal `managers: iFayID[]` |
| `org_` | `OrganizationID` | Accountable organizational entity with a natural-person `Steward` (`hid_`) in a mutual-consent single-parent acyclic tree |
| `dyn_` | `DynamicCode` | Short-lived (`<= 600s`), single-use, nonce-salted unlinkable presentation token for `hid_`, `ifay_`, or `cofay_` |
| `vrf_` | `VerificationCode` | Offline-verifiable Ed25519 verification receipt bound to scoped Auth Exchange checks |
| `grt_` | `AuthorizationGrant` | Scoped legacy-credential exchange grant (`EXACT` / `PREFIX`) with Holder-of-Key target proof |
| `gmcref_` | `OpaqueRef` | Deterministic blind natural-person anchor (`ifay.gmc.natural-person.v1`) for read-only `GMChain` normalization |

## Cryptographic Suite & Reference Toolkit (`src/fayid-toolkit.mjs`)

Implemented with zero external runtime dependencies on pure Node.js `node:crypto` (`Ed25519`, `SHA-256`, `HKDF-SHA256`, `HMAC-SHA256`, RFC 8785 JCS):

- **Deterministic Purpose Subkeys (`HKDF-SHA256`)**: Isolates entity keys (`ifay.fayid.entity.v1`), `.ego` outbound package signing keys (`ifay.ego.package-signing.v1` so master seeds and root private keys never enter outbound payloads), Dynamic Code keys (`ifay.fayid.dynamic-code.v1`), Auth Exchange keys (`ifay.fayid.auth-exchange.v1`), and `GMChain` natural-person anchors (`ifay.gmc.natural-person.v1`).
- **Single-Layer `coFay` Ownership & Organization Tree**: Enforces `HumanID : iFayID = 1:N`, single-layer `coFay` ownership (`HumanID | OrganizationID`, rejecting `iFay`/`coFay` owners with `OWNER_TYPE_NOT_ALLOWED`), single-hop `managers` delegation (`AUTHORITY_GRANT_UNAUTHORIZED`), natural-person `Steward` (`STEWARD_TYPE_NOT_ALLOWED`), and mutual-consent cycle-free organization trees (`HIERARCHY_CONSENT_MISSING`, `HIERARCHY_CYCLE_CONFLICT`).
- **Dynamic Codes, Auth Exchange & Cascading Revocation**: Issues anti-replay `dyn_` tokens (`DYNAMIC_CODE_EXPIRED`, `DYNAMIC_CODE_REPLAYED`), scoped `grt_` grants and `vrf_` verification receipts, and deterministic cascading revocation across `HumanID`, `OrganizationID` subtrees, `iFayID`, and `coFayID` (`ENTITY_REVOKED`, `GRANT_REVOKED`).

## Repository Layout

| Path | Description |
| --- | --- |
| `docs/{locale}/specification/2025-10-25/` | Normative **FayID `1.0` Final** specification across 9 locales (`zh-CN` canonical, plus `zh-TW`, `ja`, `ko`, `en`, `de`, `es`, `fr`, `ru`) |
| `docs/{locale}/blueprint/` | Architectural blueprint across 9 locales (`zh-CN` canonical) |
| `schemas/fayid-1.0.json` | Frozen FayID `1.0` JSON Schema (Draft 2020-12, `version: "1.0"`) |
| `schema/2025-10-25/` | Synchronized `2025-10-25` edition JSON Schema, TypeScript definitions, and overview |
| `src/` | Zero-dependency Node.js `node:crypto` FayID `1.0` reference implementation (`fayid-toolkit.mjs` + `.d.ts`) |
| `vectors/` | Deterministic cross-implementation conformance vectors (`account-hierarchy-vectors.json`, `crypto-and-revocation-vectors.json`) |
| `tests/` | Comprehensive unit and conformance test suites (`node --test`) |

## Quick Start

```bash
npm test
```

## Governance & Security

- Contribution guidelines & DCO 1.1 sign-off: [CONTRIBUTING.md](./CONTRIBUTING.md)
- Private vulnerability reporting: [SECURITY.md](./SECURITY.md)
- Community standards: [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)

## License

This repository uses a dual-track open-source license (`Copyright (c) 2025-2026 ChainMode contributors`):

- **Source Code, Schemas & Test Vectors** (`src/`, `schemas/`, `schema/`, `vectors/`, `tests/`): Licensed under the **MIT License** — see [LICENSE](./LICENSE).
- **Specifications & Architectural Blueprints** (`docs/`): Licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)** — see [LICENSE-DOCS](./LICENSE-DOCS).
