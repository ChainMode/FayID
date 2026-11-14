# FayID

Self-Sovereign (Holder-of-Key) accountability identity protocol for the iFay ecosystem, binding every `iFay` to a unique Human Prime (`hid_`) and every `coFay` to a single verifiable owner (`hid_` or `org_`).

## Canonical Identifier Format

All cryptographic FayID identifiers follow `<prefix>_<lowercase-rfc4648-base32-nopad>` (`org_` additionally permits lowercase slug characters `[a-z0-9-]+`):

| Prefix | Entity | Accountability Semantics |
| --- | --- | --- |
| `hid_` | `HumanID` | Root identity of a Human Prime (`SHA-256(publicKey)`, 256-bit) |
| `ifay_` | `IFayID` | Individual Fay strictly paired 1:N with its owning `HumanID` |
| `cofay_` | `CoFayID` | Shared Fay bound directly to either a `HumanID` or `OrganizationID` |
| `org_` | `OrganizationID` | Accountable legal/organizational entity |
| `dyn_` | `DynamicCode` | Short-lived unlinkable resolution token derived via Holder-of-Key |
| `vrf_` | `VerificationCode` | Versioned verification token for `CoFayID` |
| `grt_` | `AuthorizationGrant` | Scoped credential exchange grant (`EXACT` / `PREFIX`) |
| `gmcref_` | `OpaqueRef` | Privacy-preserving `HumanID` commitment for GMChain normalization |

## Repository Layout

| Path | Description |
| --- | --- |
| `docs/{locale}/blueprint/` | Architectural blueprint across 9 locales (`zh-CN` canonical) |
| `docs/zh-CN/specification/draft/` | Draft FayID v1 protocol specification |
| `schema/draft/` | JSON Schema, TypeScript types, conformance testkit, and visual testkit |

## Quick Start

```bash
cd schema/draft/testkit
npm test
```
