# Security Policy

## Supported Versions

Security fixes and advisories are actively maintained for the frozen **FayID `1.0`** specification and reference toolkit on `main`:

| Component / Artifact | Version / Edition | Supported |
| --- | --- | --- |
| FayID Specification & JSON Schemas (`schemas/fayid-1.0.json`, `schema/2025-10-25/`) | `1.0` (`2025-10-25` Final) | Yes |
| `@ifay/fayid` Reference Toolkit & Vectors (`src/`, `vectors/`) | `main` / `0.1.x` | Yes |
| Legacy draft baselines | Pre-`1.0` drafts | No |

## Security Scope

`FayID` serves as the self-sovereign accountability root of the ecosystem. In-scope vulnerabilities include:

1. **Ed25519 Holder-of-Key & HKDF-SHA256 Subkey Isolation**:
   - Weaknesses in key derivation, domain separation across `ifay.fayid.entity.v1`, `ifay.ego.package-signing.v1`, `ifay.fayid.dynamic-code.v1`, `ifay.fayid.auth-exchange.v1`, and `ifay.gmc.natural-person.v1`, or RFC 8785 JCS canonicalization discrepancies.
2. **`hid_` Non-Egress Privacy & `gmcref_` Unlinkability**:
   - Any code path or protocol flow that leaks a raw `hid_` (`HumanID`) into outbound network payloads, logs, or `.ego` packages, or allows correlation/reversal of a blind `gmcref_` natural-person anchor back to `hid_`.
3. **Unlinkability & Anti-Replay of `dyn_`, `grt_`, and `vrf_`**:
   - Replay acceptance (`DYNAMIC_CODE_REPLAYED`), TTL bypass (`DYNAMIC_CODE_EXPIRED` beyond `<= 600s`), linkability across `dyn_` presentations, or scope escalation between `EXACT` and `PREFIX` resource references in `grt_` Auth Exchange grants and `vrf_` verification receipts.
4. **Accountability Invariants & Cascading Revocation**:
   - Bypass of `HumanID : iFayID = 1:N` non-transferability, single-layer `coFay` ownership (`OWNER_TYPE_NOT_ALLOWED`), single-hop `iFay` manager delegation (`AUTHORITY_GRANT_UNAUTHORIZED`), cycle-free mutual-consent `OrganizationID` steward trees, or incomplete cascading revocation (`ENTITY_REVOKED`, `GRANT_REVOKED`).

## Reporting a Vulnerability

**Please do NOT report undisclosed cryptographic, privacy, or authorization vulnerabilities through public GitHub Issues or Pull Requests.**

- **Primary Channel (Recommended)**: Submit a report privately via **GitHub Private Vulnerability Reporting (Security Advisories)**:
  - https://github.com/ChainMode/FayID/security/advisories/new
- **Fallback Email Channel**: If GitHub Security Advisories is unavailable to you, email **[jah.g@ifay.ai](mailto:jah.g@ifay.ai)** with `[SECURITY][FayID]` in the subject line.

Please include minimal test vectors or reproduction scripts, affected identifiers/prefixes, and impact analysis.

## Coordinated Disclosure Policy

- **Acknowledgment**: Within **72 hours** of receiving your report.
- **Triage & Assessment**: Initial validation and severity assessment within **7 calendar days**.
- **Coordinated Disclosure Window**: **90 days** from initial report to coordinated advisory publication and conformance vector updates.
- **Credit**: Reporters are credited in the published security advisory unless anonymity is requested.
