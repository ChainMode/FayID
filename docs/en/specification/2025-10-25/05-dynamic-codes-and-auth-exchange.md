---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: en
canonical: false
chapter: 5
---

# Chapter 5: Unlinkable Dynamic Codes, Auth Exchange, and Cascading Revocation

## 5.1 Unlinkable Dynamic Code (`dyn_`) Issuance and Verification (Normative)

Because plaintext `hid_` never leaves the local trust boundary, a `Human Prime` and their `iFay` or `coFay` entities present short-lived, nonce-salted Dynamic Codes (`dyn_<base32>`) across trust boundaries:

1. **Permitted target entities**: Dynamic Codes `MAY` be issued only for unrevoked `HumanID` (`hid_`), `iFayID` (`ifay_`), or `coFayID` (`cofay_`) subjects. Requesting a Dynamic Code for an `OrganizationID` (`org_`) `MUST` fail with `DYNAMIC_CODE_TARGET_NOT_ALLOWED` (organization identifiers are public by design).
2. **Nonce-salted unlinkable construction**: Each issuance generates at least 16 bytes of cryptographic random `nonce`, computes HMAC-SHA256 under the `ifay.fayid.dynamic-code.v1` domain key over canonical JCS payload `{audience, expiresAt, issuedAt, nonceHex, targetId, version: "1.0"}`, and encodes the leading 20 bytes as `dyn_<base32>`. Passive observers lacking the verification key context cannot correlate two `dyn_` tokens presented by the same subject.
3. **Strict TTL ceiling**: `expiresAt - issuedAt` `MUST` be strictly positive and `MUST NOT` exceed **`600` seconds (`DYNAMIC_CODE_MAX_TTL_SECONDS = 600`)**; out-of-range TTL requests `MUST` fail with `DYNAMIC_CODE_INVALID`.
4. **Single-use anti-replay verification**: When verifying a `dyn_` token:
   - If the underlying subject or its upstream owner has been revoked, verification `MUST` fail with `ENTITY_REVOKED`;
   - If verification occurs after `expiresAt`, verification `MUST` fail with `DYNAMIC_CODE_EXPIRED`;
   - If `audience` mismatches (when bound to a target audience) or the token is unknown, verification `MUST` fail with `DYNAMIC_CODE_INVALID`;
   - Each `dyn_` nonce `MUST` succeed at most **once**; any second or subsequent presentation of the same `dyn_` token `MUST` fail with `DYNAMIC_CODE_REPLAYED`.
5. **Privacy-preserving resolution for `HumanID`**: When the underlying subject of a verified `dyn_` token is a `HumanID`, the verification response `MUST NOT` disclose plaintext `hid_`; instead, it `MUST` return subject kind `"HUMAN"` alongside the deterministic blind anchor `gmcref_<base32>`.

## 5.2 Legacy Credential Binding and Auth Exchange (`grt_` / `vrf_`) (Normative)

Auth Exchange bridges external legacy credentials into scoped FayID Authorization Grants (`grt_<base32>`) and produces offline-verifiable verification receipts (`vrf_<base32>`):

1. **HMAC-hashed `LegacySubjectRef`**: External subject identifiers `MUST` be canonicalized and hashed via keyed HMAC into `<legacySourceKind>:<issuerOrAuthority>:<subjectHash>`, where `subjectHash = base32NoPad(HMAC-SHA256(legacySecret, canonicalSubject))`. `LegacySubjectRef` `MUST NOT` embed plaintext email addresses, phone numbers, X.509 Distinguished Names, raw OAuth tokens, or plaintext blockchain wallet addresses.
2. **Default `LegacyTrustLevel` mapping**:
   - `PASSWORD` -> `LOW` (grant TTL ceiling: **`900` seconds**, `LOW_TRUST_GRANT_MAX_TTL_SECONDS`);
   - `ACCESS_TOKEN`, `AUTHORIZATION` -> `MEDIUM` (grant TTL ceiling: **`3600` seconds**, `GRANT_MAX_TTL_SECONDS`);
   - `CERTIFICATE`, `SMART_CONTRACT` -> `HIGH` (grant TTL ceiling: **`3600` seconds**).
   Implementations `MAY` downgrade trust levels or shorten TTLs under local risk policy, and `MUST NOT` elevate trust levels without additional multi-factor holder proof.
3. **Target ownership proof precedence (anti-probing)**: `grt_` grants `MAY` target only unrevoked `iFayID` or `coFayID` entities, and issuance `MUST` verify a Holder-of-Key signature proving control over `targetFayId`. If target ownership proof is missing or invalid, issuance `MUST` return `TARGET_OWNERSHIP_NOT_PROVEN` before evaluating legacy subject bindings, preventing attackers from probing whether a legacy account is bound to a specific FayID.
4. **Scoped grant verification and `vrf_` receipts**: `verifyAuthGrant` evaluates, in order:
   - Grant existence and syntactic validity (otherwise `GRANT_INVALID`);
   - Revocation status of `targetFayId` and its upstream owner (returning `ENTITY_REVOKED` if revoked);
   - Explicit grant revocation status (otherwise `GRANT_REVOKED`);
   - Expiration against `expiresAt` (otherwise `GRANT_EXPIRED`);
   - Scope match between `requestedResourceRef` and `resourceRef` under Section 2.3 `scopeMode` (`EXACT` or `PREFIX`, returning `GRANT_INVALID` on mismatch).
   Upon success, the verifier signs the canonical receipt payload under the `ifay.fayid.auth-exchange.v1` Ed25519 key and returns a `vrf_<base32>` receipt. Any relying party can call `verifyAuthReceipt(receipt)` to validate the Ed25519 signature and structure offline; any tampered field `MUST` fail with `RECEIPT_INVALID`.

## 5.3 Deterministic Cascading Revocation (Normative)

Revocation is monotonic and irreversible. Revoking any entity `MUST` synchronously cascade across all downstream entities and active credentials without leaving orphaned active records:

| Revoked Trigger Entity | Cascaded Downstream Entities | Mandatory Collateral Cleanup on Managers and Credentials |
| --- | --- | --- |
| **`HumanID` (`hid_`)** | Every `iFay` (`ifay_`) bound to that `hid_`, plus every `coFay` (`cofay_`) directly owned by that `hid_` | Strip all cascaded `ifay_` IDs from every surviving `coFay.managers` list; revoke all active `grt_` grants and unconsumed `dyn_` tokens targeting any cascaded `ifay_` or `cofay_` |
| **`OrganizationID` (`org_`)** | The organization itself, its entire descendant organization subtree (recursively), and every `coFay` directly owned by the organization or any descendant organization | Revoke all active `grt_` grants and unconsumed `dyn_` tokens targeting any cascaded `cofay_` |
| **`iFayID` (`ifay_`)** | That `iFay` instance | Strip that `ifay_` immediately from every surviving `coFay.managers` list; revoke all active `grt_` grants and unconsumed `dyn_` tokens targeting that `ifay_` |
| **`coFayID` (`cofay_`)** | That `coFay` instance | Revoke all active `grt_` grants and unconsumed `dyn_` tokens targeting that `cofay_` |

After revocation completes:
1. Issuing new `dyn_` tokens, issuing new `grt_` grants, registering subordinate entities, or verifying existing credentials against any directly or cascadely revoked entity `MUST` fail deterministically with `ENTITY_REVOKED` (while standalone revocation of an individual grant whose target entity remains active returns `GRANT_REVOKED`).
2. Credentials bound to a revoked entity become invalid **immediately**, even when their original `expiresAt` timestamp has not yet elapsed.
