---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: en
canonical: false
---

# FayID 1.0 Protocol Specification

FayID is the self-sovereign (Holder-of-Key) accountability identity protocol for the iFay ecosystem. Without relying on any centralized certificate authority (CA) or identity provider (IdP), FayID binds every individual digital persona (`iFay`) one-to-many and non-transferably to a unique **Human Prime** (`hid_`), and binds every shared-role digital entity (`coFay`) directly in a single ownership layer to one accountable `HumanID` (`hid_`) or `OrganizationID` (`org_`).

This directory contains the US English edition of the **FayID 1.0 Final Specification (Edition `2025-10-25`)**. All chapters and normative clauses correspond one-to-one with the canonical Simplified Chinese (`zh-CN`) specification; in the event of any cross-language discrepancy, the `zh-CN` edition governs.

## Specification Chapters

| Chapter | File | Normative Scope |
| --- | --- | --- |
| Chapter 1 | [01-conventions-and-versioning.md](./01-conventions-and-versioning.md) | Scope, RFC 2119 / RFC 8174 normative keywords, core terminology boundaries, and two-segment `1.0` protocol versioning and negotiation |
| Chapter 2 | [02-identifiers-and-encoding.md](./02-identifiers-and-encoding.md) | Eight canonical prefixes, lowercase unpadded RFC 4648 Base32 encoding, strict rejection and round-trip invariants, `resourceRef` matching, and 64-hex legacy bridging |
| Chapter 3 | [03-cryptography-and-subkeys.md](./03-cryptography-and-subkeys.md) | Self-sovereign Ed25519 Holder-of-Key trust model, master seed entropy, HKDF-SHA256 purpose-subkey derivation (including `ifay.ego.package-signing.v1`), and RFC 8785 JCS canonical signing |
| Chapter 4 | [04-entities-ownership-and-hierarchy.md](./04-entities-ownership-and-hierarchy.md) | Four entity classes, `HumanID : iFayID = 1:N` binding, single-layer `coFay` ownership and orthogonal `managers` delegation, natural-person `Steward`, and mutual-consent single-parent acyclic organization hierarchy |
| Chapter 5 | [05-dynamic-codes-and-auth-exchange.md](./05-dynamic-codes-and-auth-exchange.md) | Unlinkable Dynamic Code (`dyn_`) issuance and anti-replay verification, HMAC legacy subject binding, scoped Authorization Grants (`grt_`), verification receipts (`vrf_`), and cascading revocation |
| Chapter 6 | [06-privacy-gmc-and-conformance.md](./06-privacy-gmc-and-conformance.md) | Outbound payload and log redaction boundaries, read-only `GMChain` boundary and blind natural-person anchor (`gmcref_`), 24-entry normative error code registry, and conformance criteria |

## Companion Normative Artifacts

| Artifact Path | Description |
| --- | --- |
| [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json) | Frozen FayID 1.0 JSON Schema (Draft 2020-12, enforcing `version: "1.0"`) |
| [schema/2025-10-25/schema.json](../../../../schema/2025-10-25/schema.json) | Byte-synchronized edition mirror of `schemas/fayid-1.0.json` |
| [schema/2025-10-25/schema.ts](../../../../schema/2025-10-25/schema.ts) | Normative TypeScript constants and interface mirror |
| [src/fayid-toolkit.mjs](../../../../src/fayid-toolkit.mjs) | Zero-dependency Node.js `node:crypto` reference implementation |
| [vectors/](../../../../vectors/) | Deterministic cross-implementation conformance vectors (`account-hierarchy-vectors.json` and `crypto-and-revocation-vectors.json`) |
