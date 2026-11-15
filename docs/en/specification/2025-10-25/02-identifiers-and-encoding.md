---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: en
canonical: false
chapter: 2
---

# Chapter 2: Identifier Syntax, Base32 Encoding, and Resource References

## 2.1 Canonical Identifier Prefixes (Normative)

Every FayID cryptographic identifier and derived credential string `MUST` follow the `<prefix>_<body>` syntax. Except for `org_`, which permits lowercase slug characters `[a-z0-9-]+`, the body of every identifier `MUST` use **lowercase unpadded RFC 4648 Base32** (`[a-z2-7]+`):

| Kind Constant | Prefix | Body Pattern | Typical Payload Size and Accountability Semantics |
| --- | --- | --- | --- |
| `HUMAN_ID` | `hid_` | `^[a-z2-7]+$` | `SHA-256(humanPublicKey)` (32 bytes -> 52 Base32 chars); root identity of a `Human Prime` |
| `IFAY_ID` | `ifay_` | `^[a-z2-7]+$` | `SHA-256("ifay:" \|\| humanId \|\| ":" \|\| publicKey)` (32 bytes); individual digital persona |
| `COFAY_ID` | `cofay_` | `^[a-z2-7]+$` | `SHA-256("cofay:" \|\| ownerId \|\| ":" \|\| publicKey)` (32 bytes); shared-role digital entity |
| `ORGANIZATION_ID` | `org_` | `^[a-z0-9-]+$` | Accountable organization identifier (deterministic hash body or normalized lowercase slug) |
| `DYNAMIC_CODE` | `dyn_` | `^[a-z2-7]+$` | 20-byte truncated HMAC tag (32 Base32 chars); short-lived unlinkable presentation token |
| `VERIFICATION_CODE` | `vrf_` | `^[a-z2-7]+$` | 20-byte verification receipt digest bound to a verified `grt_` or `cofay_` check |
| `AUTHORIZATION_GRANT` | `grt_` | `^[a-z2-7]+$` | 20-byte scoped legacy-credential exchange grant identifier |
| `OPAQUE_REF` | `gmcref_` | `^[a-z2-7]+$` | 32-byte blind natural-person anchor (52 Base32 chars) for `GMChain` deduplication |

In addition, public `iFay` registration records and offline bundles represent the one-way salted commitment to their owning `HumanID` using `hidproof_<lowercase-base32-nopad>` (`^hidproof_[a-z2-7]{16,}$`) so plaintext `hid_` never appears in public records.

## 2.2 Normalization and Strict Rejection Rules (Normative)

`normalizeFayID(input)` `MUST` enforce the following deterministic rules:

1. **Type and non-empty check**: Non-string inputs and empty strings `MUST` immediately fail with `MALFORMED_FAYID_STRING`.
2. **ASCII case folding**: The parser `MUST` fold ASCII uppercase letters to lowercase (`input.toLowerCase()`) before matching the eight canonical prefixes.
3. **Strict rejection without silent repair**: A parser `MUST NOT` strip leading or trailing whitespace, remove hyphens (outside valid `org_` bodies), strip `=` padding characters, or substitute look-alike digits (such as mapping `0`, `1`, `8`, or `9` to Base32 letters). Any input containing whitespace, `=` padding, an unknown prefix, an empty body, or out-of-alphabet characters `MUST` fail with `MALFORMED_FAYID_STRING`.
4. **Round-trip invariants**: For every valid canonical identifier `x`, calling `normalizeFayID(x)` again `MUST` return `ok: true` with `value.canonical === x`. Encoding any byte array `b` with unpadded lowercase Base32 and decoding it back `MUST` recover `b` byte-for-byte, and any non-zero trailing slack bits during Base32 decoding `MUST` be rejected.

## 2.3 `resourceRef` Syntax and Scope Matching (Normative)

Target resources in Auth Exchange are addressed by `resourceRef`. `normalizeResourceRef(input)` and `matchesResourceRef(grantedResourceRef, requestedResourceRef, scopeMode)` `MUST` enforce:

1. **Grammar**: `resourceRef` follows `<namespace>:<path>`:
   - `<namespace>`, after lowercase folding, `MUST` match `^[a-z][a-z0-9+.-]*$`;
   - `<path>` to the right of `:` `MUST` be non-empty, contain zero whitespace characters, not end with `/` (unless the path is `/` alone), and `MUST NOT` contain empty segments (`//`) or dot-traversal segments (`.` or `..`).
   - Any violation `MUST` return `MALFORMED_FAYID_STRING`.
2. **Case sensitivity**: `<namespace>` is normalized to lowercase, whereas `<path>` `MUST` preserve exact case.
3. **Scope matching (`scopeMode`)**:
   - `EXACT` (default): Matches if and only if normalized `requestedResourceRef === grantedResourceRef`.
   - `PREFIX`: Matches if and only if normalized `requestedResourceRef` equals `grantedResourceRef` or begins with `grantedResourceRef + "/"` on an explicit `/` segment boundary. For example, a `PREFIX` grant on `cap:repo/fayid` matches `cap:repo/fayid/issues`, and `MUST NOT` match sibling path `cap:repo/fayid-ext`.

## 2.4 Legacy 64-Hex Public Key Bridging (Normative)

To migrate early records storing raw 32-byte Ed25519 public keys as 64 hexadecimal characters, implementations provide `adaptLegacyHexIdentifier(hex64, prefix)`:

1. After trimming outer whitespace, `hex64` `MUST` match `^[0-9a-fA-F]{64}$`, and `prefix` `MUST` be one of `hid_`, `ifay_`, or `cofay_`; otherwise the call `MUST` fail with `MALFORMED_FAYID_STRING`.
2. The adapter computes `SHA-256` over the decoded 32-byte public key and encodes the digest as `<prefix><base32-nopad>`, matching native root identifier derivation.
3. Conformant FayID 1.0 wire payloads `MUST NOT` transmit bare 64-hex strings in place of canonical FayID identifiers; conversion `MUST` occur explicitly at the ingestion boundary.
