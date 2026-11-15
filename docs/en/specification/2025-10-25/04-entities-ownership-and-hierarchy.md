---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: en
canonical: false
chapter: 4
---

# Chapter 4: Identity Entities, Single-Layer Ownership, and Organization Hierarchy

## 4.1 `HumanID` to `iFay` One-to-Many Binding (Normative)

1. **Root identity derivation**: A `Human Prime` generates or derives an Ed25519 public key `pk_human` inside a local `Holder Agent` and computes `hid_ || base32NoPad(SHA-256(pk_human))` as their `HumanID`.
2. **Non-transferable `1:N` binding**: A single `HumanID` `MAY` register and own arbitrarily many `iFay` instances (`HumanID : iFayID = 1:N`). Registering an `iFay` `MUST` include joint Ed25519 signatures from both the owning `HumanID` private key and the new `iFay` private key over the canonical binding payload; missing or invalid proofs `MUST` fail with `HUMAN_ID_OWNERSHIP_NOT_PROVEN`.
3. **Cross-`iFay` unlinkability by default**: Public `IFayRecord` objects store only the salted one-way commitment `humanIdProofRef` (`hidproof_<base32>`) and `MUST NOT` expose plaintext `hid_`. Without a joint proof voluntarily presented by the `Human Prime`, external observers cannot determine whether two public `ifay_` records belong to the same `Human Prime`.
4. **Permanent non-transferability**: Once bound to a `HumanID`, an `iFay` `MUST NOT` be transferred to another `HumanID` or to any `OrganizationID`.

## 4.2 Single-Layer `coFay` Ownership and Orthogonal `managers` Delegation (Normative)

To guarantee direct, pierceable accountability for every shared-role entity, FayID 1.0 enforces **Single-Layer Ownership** for `coFay`:

1. **Permitted owner types**: `coFay.ownerId` `MUST` be either a `HumanID` (`hid_`) or an `OrganizationID` (`org_`), with `ownerKind` set to `"HUMAN"` or `"ORGANIZATION"`. Any attempt to register or transfer a `coFay` under an `iFay` (`ifay_`) or another `coFay` (`cofay_`) `MUST` fail immediately with `OWNER_TYPE_NOT_ALLOWED` (nested `coFay` ownership chains are forbidden).
2. **Ownership transfer**: The current direct owner (`hid_` or `org_`) `MAY` transfer a `coFay` to a new valid owner (`hid_` or `org_`) via a signed transfer proof, preserving `version: "1.0"` and updating the ownership binding.
3. **Orthogonal operational managers (`managers: iFayID[]`)**:
   - The direct owner (`hid_` or `org_`) of a `coFay` `MAY` authorize zero or more `iFayID` identifiers in `managers` to perform day-to-day operational administration.
   - Only the direct owner has authority to add or remove entries in `managers`; an `iFay` listed in `managers` `MUST NOT` add, remove, or re-delegate other managers. Any unauthorized delegation attempt `MUST` fail with `AUTHORITY_GRANT_UNAUTHORIZED` (single-hop delegation without sub-delegation).
   - Operational membership in `managers` never alters legal or governance ownership of the `coFay`.

## 4.3 `OrganizationID` and Natural-Person `Steward` (Normative)

1. **Mandatory natural-person `Steward`**: Every registered `OrganizationRecord` `MUST` designate a natural-person governance representative `stewardHumanId` referencing a registered, unrevoked `HumanID` (`hid_`). Any attempt to assign an `ifay_`, `cofay_`, or `org_` as `Steward` `MUST` fail with `STEWARD_TYPE_NOT_ALLOWED`.
2. **Steward rotation**: An organization `MAY` rotate `stewardHumanId` via a command signed by the organization's controlling keypair, provided the replacement is also a valid, unrevoked `HumanID`.

## 4.4 Self-Contained Single-Parent Acyclic Organization Hierarchy (Normative)

FayID 1.0 defines inter-organization hierarchy directly within this specification:

1. **Single-parent tree topology**: Each `OrganizationRecord` carries `parentOrgId: OrganizationID | null`. Every child organization has at most one direct parent organization at any point in time, forming a forest of directed acyclic trees. The protocol imposes **no artificial fixed depth cap** (such as 16 levels).
2. **Mutual two-party consent**: Attaching or reparenting `childOrg.parentOrgId = parentOrgId` `MUST` carry valid Ed25519 consent signatures from both the child organization's controlling key and the target parent organization's controlling key. Missing or invalid consent from either party `MUST` fail with `HIERARCHY_CONSENT_MISSING`.
3. **Deterministic cycle rejection**: Any attachment setting `parentOrgId` to the organization itself or to any of its current descendants `MUST` fail deterministically with `HIERARCHY_CYCLE_CONFLICT`.
4. **No implicit `coFay` ownership rollup**: A `coFay` owned by a child organization retains that child `org_` as its direct `ownerId`; attaching an organization to a parent tree does not implicitly transfer or roll up direct ownership of the child's `coFay` records.
