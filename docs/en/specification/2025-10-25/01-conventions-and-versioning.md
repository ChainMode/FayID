---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: en
canonical: false
chapter: 1
---

# Chapter 1: Normative Conventions, Core Terminology, and Version Governance

## 1.1 Scope and Non-Goals

FayID 1.0 defines self-sovereign identity identifiers, purpose-bound subkey derivation, entity ownership and organization hierarchy invariants, unlinkable dynamic codes, legacy credential authorization exchange, cascading revocation, and privacy-preserving natural-person anchors for `GMChain` across the iFay ecosystem.

The following concerns are explicitly outside the scope of FayID 1.0:

1. **Transport framing and session handshakes**: Inter-agent message framing and transport security belong to the Faying protocol suite; FayID supplies identity primitives, signature envelopes, and verification receipts.
2. **Runtime process scheduling**: Process orchestration of `iFay` and `coFay` instances on terminal devices is governed by the FayGer runtime.
3. **Reputation accounting and governance weight calculation**: Accumulation and governance weighting of `MeriToken` are defined independently by `GMChain`. FayID maintains a read-only boundary toward `GMChain` and outputs only the blind anchor `gmcref_`.
4. **Centralized identity proofing (KYC)**: FayID 1.0 assumes no centralized registry or root certificate authority.

## 1.2 Normative Keywords (Normative)

The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `SHOULD NOT`, `RECOMMENDED`, `NOT RECOMMENDED`, `MAY`, and `OPTIONAL` in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals, as summarized below:

| RFC 2119 / RFC 8174 Keyword | Normative Meaning |
| --- | --- |
| `MUST` / `SHALL` / `REQUIRED` | Absolute protocol requirement; any violation renders an implementation non-conformant |
| `MUST NOT` / `SHALL NOT` | Absolute protocol prohibition; any violation renders an implementation non-conformant |
| `SHOULD` / `RECOMMENDED` | Strong default requirement that ought to be followed unless justified by documented engineering reasons |
| `SHOULD NOT` / `NOT RECOMMENDED` | Behavior that ought to be avoided unless justified by documented engineering reasons |
| `MAY` / `OPTIONAL` | Truly discretionary feature; interoperable peers must accommodate both its presence and omission |

## 1.3 Core Terminology (Normative)

All implementations, schemas, and derivative documents `MUST` enforce the following terminology boundaries:

- **`Human Prime`**: The real natural person identified by a `HumanID` (`hid_`) who owns and controls individual digital personas. Specifications, code comments, and API fields `MUST` consistently use `Human Prime` when referring to the natural person.
- **`Host`**: Refers **exclusively** to a terminal device, operating system environment, or client application on which a `Fay` instance runs or is mounted. Implementations and documentation `MUST NOT` use `Host` to refer to a natural person or `Human Prime`.
- **`Fay` (`Fay = iFay + coFay`)**: The collective term for all accountable digital entities with verifiable identity in the iFay ecosystem, partitioned into two mutually exclusive subsets:
  - **`iFay` (Individual Fay, `ifay_`)**: A personal digital persona bound non-transferably `1:N` to a single `HumanID` (`HumanID : iFayID = 1:N`).
  - **`coFay` (Shared-Role Fay, `cofay_`)**: A collaborative, service, or public-role digital entity bound directly to a single `HumanID` or a single `OrganizationID`, supporting ownership transfer and orthogonal operational management delegation.
- **`OrganizationID` (`org_`)**: A legal or governance entity accountable for organizational assets, represented by a natural-person `Steward` and eligible to participate in a single-parent acyclic organization tree.
- **`Holder Agent`**: A local key-management and self-issuance software component controlled by a `Human Prime` or organization and running on a controlled `Host` (terminal device or application), rather than a centralized remote authority.
- **`GMChain` and `MeriToken`**: `GMChain` is the public reputation ledger recording social contributions across the ecosystem; `MeriToken` (measured in `Merit Unit`) is a non-monetary social contribution metric that is not a cryptocurrency, not fiat-exchangeable, not produced through mining, not a financial settlement rail, and not a speculative asset.

## 1.4 Protocol Versioning and Negotiation (Normative)

### 1.4.1 Three Orthogonal Axes

FayID separates three distinct axes that `MUST NOT` be conflated:

1. **Protocol Wire Version (`MAJOR.MINOR`)**: Uses a two-segment `MAJOR.MINOR` string (`"1.0"` for FayID 1.0) with **no `PATCH` segment**. Only `"1.0"` `MUST` appear in wire-format `version` envelope fields and JSON Schema `const` constraints.
2. **Document Status**: Indicates specification maturity (such as `Draft` or `Final`). Document status appears only in specification front matter and `MUST NOT` enter wire-format payloads.
3. **Edition Date**: Uses an ISO `YYYY-MM-DD` date (`2025-10-25` for this edition) to identify specification archive directories and schema snapshot paths, and `MUST NOT` enter wire-format payloads.

### 1.4.2 Major and Minor Evolution Criteria

- **Minor increment (`MINOR`)**: Restricted to backward-compatible additive extensions (such as optional envelope fields, new purpose-subkey domain constants, or optional credential metadata). Peers implementing an earlier `1.x` minor version remain able to validate signatures and core invariants while ignoring unknown optional fields.
- **Major increment (`MAJOR`)**: Any breaking change (altering identifier regular expressions, replacing baseline hash or signature primitives, modifying HKDF domain strings, tightening existing required fields, or changing cascading revocation outcomes) `MUST` increment `MAJOR`.
- **Editorial revisions**: Edition updates within the same `MAJOR.MINOR` version are restricted to non-normative clarifications and `MUST NOT` alter conformance outcomes.

### 1.4.3 Version Handshake and Forward Compatibility

1. Peers exchanging FayID records, envelopes, or receipts `MUST` validate the `version` field. Conformant FayID 1.0 records `MUST` set `version` to `"1.0"` exactly (`"1"`, `"1.0.0"`, and `"v1.0"` are invalid).
2. Implementations supporting multiple minor versions within `MAJOR = 1` `MUST` negotiate the highest mutually supported `1.x` version and maintain backward compatibility down to `"1.0"`.
3. Upon encountering an unknown or unsupported `MAJOR` version, a verifier `MUST` reject the payload immediately and `MUST NOT` attempt silent fallback or bypass signature verification.
4. Verifiers parsing payloads within the same `MAJOR` version `MUST` ignore unrecognized optional extension fields during business validation, while preserving all fields present in a signed object when computing RFC 8785 JCS canonical bytes for signature verification.
5. Rolling upgrades across `1.x` minor versions `MUST NOT` prematurely invalidate previously issued, unexpired `dyn_`, `grt_`, or `vrf_` credentials.
