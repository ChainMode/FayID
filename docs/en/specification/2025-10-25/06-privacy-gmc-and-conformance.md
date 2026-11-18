---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: en
canonical: false
chapter: 6
---

# Chapter 6: Privacy Boundaries, `GMChain` Interface, Error Codes, and Conformance

## 6.1 Outbound Payload and Log Redaction Boundaries (Normative)

Every conformant implementation `MUST` enforce the following non-bypassable privacy rules across both wire serialization and observability logging:

1. **Plaintext `hid_` never leaves the local boundary and never enters logs**: Network payloads, public directory snapshots, `.ego` export packages, cross-party verification receipts (`vrf_`), crash dumps, and audit logs `MUST NOT` contain plaintext `hid_<base32>` strings. External interactions `MUST` use `ifay_`, `cofay_`, `dyn_`, `hidproof_`, or blind anchors `gmcref_`.
2. **Zero outbound seed or private-key material**: Master seeds (`masterSeed`), mnemonics, raw private keys (`privateKey` / `secretKey`), and `userBlindSalt` values `MUST` remain confined within local `Holder Agent` secure storage and `MUST NOT` appear in serialized public records or outbound payloads.
3. **Cross-namespace unlinkability**: Distinct external consumption domains `MUST` apply distinct domain separation strings or salts so external observers cannot correlate identifiers across namespaces to profile a `Human Prime`.

## 6.2 Read-Only `GMChain` Boundary and Blind `gmcref_` Anchor (Normative)

`GMChain` normalizes natural-person governance weight and Sybil resistance so a single natural person counts as one natural-person anchor regardless of how many `iFay` personas they operate, without ever learning plaintext `hid_`. FayID 1.0 derives the deterministic blind anchor `gmcref_<base32>` as follows:

```text
prk    = HKDF-SHA256(ikm = userBlindSalt, salt = SHA-256("fayid.gmc.salt.v1"), info = "ifay.gmc.natural-person.v1:" || namespace, len = 32)
digest = HMAC-SHA256(key = prk, data = UTF8("gmcref:" || canonicalHumanId))
gmcref = "gmcref_" || base32EncodeNoPad(digest)
```

Normative invariants:

1. **Determinism and irreversibility**: Given the same canonical `HumanID`, `userBlindSalt` (`>= 32` bytes), and `namespace` (defaulting to `"gmchain.main"`), `deriveBlindGmcRef` produces an identical `gmcref_` string. Without `userBlindSalt`, external parties (including `GMChain` nodes) cannot invert `gmcref_` to recover `hid_` or correlate it with public `ifay_` records owned by that `Human Prime`.
2. **Strict read-only ledger boundary**: FayID supplies only one-way anchor derivation and revocation status inputs to `GMChain`; FayID does not mutate `GMChain` ledger state and does not compute, mint, or distribute `MeriToken`. `MeriToken` is a non-monetary social contribution metric, not a cryptocurrency, not fiat-exchangeable, not a financial settlement rail, and not a speculative asset.
3. **Natural-person scope only**: `deriveBlindGmcRef` accepts only a valid `HumanID` (`hid_`); passing an `ifay_`, `cofay_`, or `org_` identifier `MUST` fail with `MALFORMED_FAYID_STRING`.

## 6.3 Normative Error Code Registry (Normative)

Conformant FayID 1.0 implementations `MUST` preserve the following 24 stable error code constants (14 baseline protocol codes plus 10 account, domain-separation, and cascading-governance codes):

| Error Code Constant | Trigger Condition |
| --- | --- |
| `INSUFFICIENT_ENTROPY` | Master seed, blind salt, or random entropy is shorter than 256 bits (32 bytes) |
| `HUMAN_ID_OWNERSHIP_NOT_PROVEN` | Required `HumanID` Holder-of-Key signature is missing or fails verification |
| `OWNERSHIP_NOT_PROVEN` | Entity control or ownership transfer lacks a valid signature from the current owner |
| `TARGET_OWNERSHIP_NOT_PROVEN` | `grt_` issuance lacks valid Holder-of-Key proof for `targetFayId` (returned with top precedence to prevent binding probing) |
| `LEGACY_SUBJECT_MISMATCH` | Canonicalized legacy credential subject HMAC does not match the bound `LegacySubjectRef` |
| `DYNAMIC_CODE_EXPIRED` | `dyn_` verification timestamp exceeds `expiresAt` |
| `DYNAMIC_CODE_INVALID` | `dyn_` syntax/HMAC is invalid, `audience` mismatches, or requested TTL exceeds 600 seconds |
| `VERIFICATION_RATE_LIMITED` | Consecutive verification failures hit the rate-limit threshold (5 failures within 600s triggers exponential backoff) |
| `IDENTITY_REVOKED` | Baseline identity revocation status indicator |
| `LEGACY_AUTH_FAILED` | Upstream authentication of the legacy credential (password, certificate, token, smart contract) failed |
| `GRANT_EXPIRED` | `grt_` verification timestamp exceeds `expiresAt` |
| `GRANT_REVOKED` | Individual `grt_` grant has been explicitly revoked |
| `GRANT_INVALID` | `grt_` is unknown, malformed, targets an invalid entity type, or `requestedResourceRef` falls outside the granted scope |
| `MALFORMED_FAYID_STRING` | Identifier prefix/Base32 body is invalid, `resourceRef` syntax fails validation, or an unexpected prefix kind was supplied |
| `OWNER_TYPE_NOT_ALLOWED` | Attempted to assign an `iFay` or `coFay` as owner of a `coFay` (violating single-layer ownership) |
| `HIERARCHY_CONSENT_MISSING` | Organization attachment lacks a valid signature from either the child organization or parent organization |
| `HIERARCHY_CYCLE_CONFLICT` | Organization attachment points to itself or an existing descendant, creating a cycle |
| `AUTHORITY_GRANT_UNAUTHORIZED` | Non-owner (such as an entry in `coFay.managers`) attempted to modify or re-delegate `managers` |
| `STEWARD_TYPE_NOT_ALLOWED` | Organization `Steward` is not a valid, unrevoked natural-person `HumanID` (`hid_`) |
| `ENTITY_REVOKED` | Target entity or its upstream owning `HumanID` / `OrganizationID` has been directly or cascadely revoked |
| `DYNAMIC_CODE_REPLAYED` | Single-use `dyn_` token was presented more than once |
| `DYNAMIC_CODE_TARGET_NOT_ALLOWED` | Attempted to issue a `dyn_` token for a disallowed target type such as `OrganizationID` |
| `DOMAIN_SEPARATION_REQUIRED` | HKDF subkey derivation omitted a valid `SubkeyDomain` or non-empty context string |
| `RECEIPT_INVALID` | `vrf_` verification receipt is malformed or fails Ed25519 signature verification |

## 6.4 Conformance Criteria (Normative)

An implementation, library, or `Holder Agent` claiming conformance to **FayID 1.0** `MUST` satisfy all five verifiable conditions below:

1. **Version and schema compliance**: Every emitted public entity record and credential envelope carries `version: "1.0"` and validates against [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json).
2. **Identifier and resource matching compliance**: Implements Chapter 2 eight-prefix normalization, strict rejection without silent input repair, and segment-safe `EXACT` / `PREFIX` matching on `resourceRef`.
3. **Cryptographic and root-key isolation compliance**: Implements Chapter 3 Ed25519, SHA-256, five HKDF-SHA256 purpose-subkey domains, and RFC 8785 JCS canonical signing, using `ifay.ego.package-signing.v1` exclusively for `.ego` package signatures with zero seed or private-key leakage.
4. **Account hierarchy and cascading revocation compliance**: Enforces Chapter 4 single-layer `coFay` ownership, natural-person `Steward`, and mutual-consent single-parent acyclic organization trees, plus Chapter 5 anti-replay `dyn_` verification, scoped `grt_` / `vrf_` exchange, and deterministic cascading revocation across all four entity classes.
5. **100% conformance vector pass rate**: Passes every positive and negative test scenario in [vectors/hierarchy/](../../../../vectors/hierarchy) and [vectors/crypto-and-revocation-vectors.json](../../../../vectors/crypto-and-revocation-vectors.json).
