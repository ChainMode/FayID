---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: en
canonical: false
chapter: 3
---

# Chapter 3: Self-Sovereign Cryptographic Suite and Purpose-Subkey Derivation

## 3.1 Self-Sovereign Holder-of-Key Trust Model (Normative)

FayID 1.0 operates on a pure self-sovereign Holder-of-Key trust model:

1. Identity creation and control depend solely on cryptographic proof of possession of the corresponding Ed25519 private key, with zero reliance on centralized issuer signatures.
2. Every state-mutating operation claiming authority over a `HumanID`, `iFayID`, `coFayID`, or `OrganizationID` (registration, manager delegation, hierarchy attachment, ownership transfer, or revocation) `MUST` carry a valid signature from the controlling keypair; missing or invalid proofs `MUST` be rejected with `HUMAN_ID_OWNERSHIP_NOT_PROVEN`, `OWNERSHIP_NOT_PROVEN`, or `TARGET_OWNERSHIP_NOT_PROVEN`.

## 3.2 Mandatory Cryptographic Primitives (Normative)

FayID 1.0 standardizes on standard cryptographic primitives available without external black-box dependencies:

| Function | Mandatory Primitive | Canonical Output Size |
| --- | --- | --- |
| Asymmetric signatures & Holder-of-Key proofs | Ed25519 (RFC 8032 PureEdDSA) | 32-byte raw public key, 64-byte signature |
| Identifier digests & salted commitments | SHA-256 (FIPS 180-4) | 32-byte digest |
| Deterministic purpose-subkey derivation | HKDF-SHA256 (RFC 5869) | 32-byte derived seed |
| Legacy subject hashing & Dynamic Code MACs | HMAC-SHA256 (RFC 2104) | 32-byte MAC (truncated to 20 bytes where specified) |
| Canonical JSON signing payloads | JCS (RFC 8785 JSON Canonicalization Scheme) | Deterministic UTF-8 byte sequence |

Raw entropy for `masterSeed` and `userBlindSalt` inputs `MUST` be at least **256 bits (32 bytes)**; inputs shorter than 32 bytes `MUST` fail with `INSUFFICIENT_ENTROPY`.

## 3.3 HKDF-SHA256 Domain-Separated Purpose Subkeys (Normative)

To guarantee that master seeds and root private keys never enter high-frequency signing paths or outbound archive bundles, a `Holder Agent` `MUST` derive cryptographically isolated 32-byte purpose subkeys from a master seed (`>= 32` bytes) via HKDF-SHA256:

```text
subkeySeed32 = HKDF-SHA256(
  ikm  = masterSeedBytes,
  salt = SHA-256(UTF8("fayid.subkey.salt:" || domain)),
  info = UTF8(domain || ":" || context),
  len  = 32
)
```

FayID 1.0 defines five normative `SubkeyDomain` constants:

| Constant | Domain Separation String (`domain`) | Purpose and Security Boundary |
| --- | --- | --- |
| `ENTITY` | `ifay.fayid.entity.v1` | Derives entity-controlling Ed25519 keypairs for `HumanID`, `iFay`, `coFay`, and `OrganizationID` |
| `EGO_PACKAGE_SIGNING` | `ifay.ego.package-signing.v1` | Dedicated Ed25519 signing subkey exclusively for outbound `.ego` persona and state packages |
| `DYNAMIC_CODE` | `ifay.fayid.dynamic-code.v1` | Derives symmetric key material for Dynamic Code (`dyn_`) issuance and verification contexts |
| `AUTH_EXCHANGE` | `ifay.fayid.auth-exchange.v1` | Derives signing key material for Authorization Grants (`grt_`) and verification receipts (`vrf_`) |
| `GMC_NATURAL_PERSON` | `ifay.gmc.natural-person.v1` | Derives pseudorandom key material for blind natural-person anchors (`gmcref_`) on `GMChain` |

Implementations `MUST` enforce two hard isolation invariants:

1. **Mandatory domain separation**: Calls to subkey derivation `MUST` supply non-empty `domain` and `context` strings where `domain` belongs to the registered `SubkeyDomain` set; missing or unrecognized domains `MUST` fail with `DOMAIN_SEPARATION_REQUIRED`.
2. **Zero root-key exposure in outbound Ego packages**: Outbound `.ego` packages `MUST` be signed exclusively with a subkey derived under `ifay.ego.package-signing.v1`, producing a signature envelope containing `version: "1.0"`, `domain: "ifay.ego.package-signing.v1"`, `signerFayId`, `keyId`, `signingPublicKeyHex`, `manifestDigestSha256`, `signedAt`, and `signatureHex`. Outbound packages, public entity records, and verification receipts `MUST NOT` contain `masterSeed`, `seed`, `privateKey`, `secretKey`, or `mnemonic` fields; verifiers `MUST` reject any envelope carrying private key material.

## 3.4 RFC 8785 JCS Canonical Signing Rules (Normative)

Every structured payload verified across implementations (ownership binding proofs, mutual hierarchy consents, Ego package manifest signing payloads, and `vrf_` verification receipt payloads) `MUST` be serialized to deterministic UTF-8 bytes under RFC 8785 JCS prior to Ed25519 signing/verification or SHA-256 hashing:

1. Object property names are sorted in ascending lexicographical order by UTF-16 code units, omitting properties whose value is `undefined`;
2. Finite numbers use minimal ECMAScript decimal representation (`-0` serializes as `"0"`, and `NaN`/`Infinity` are rejected);
3. Array element order is preserved verbatim, strings use minimal standard JSON escaping, and zero insignificant whitespace is emitted between tokens.
