# FayID

[![Docs CI](https://github.com/ChainMode/FayID/actions/workflows/docs-ci.yml/badge.svg)](https://github.com/ChainMode/FayID/actions/workflows/docs-ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Docs: CC BY 4.0](https://img.shields.io/badge/Docs-CC%20BY%204.0-lightgrey.svg)](./LICENSE-DOCS)
[![Website: ifay.ai](https://img.shields.io/badge/Website-ifay.ai-blue)](https://ifay.ai)

**FayID** (`1.0` Final, edition `2025-10-25`) is the self-sovereign (Holder-of-Key) cryptographic identity, stealth opt-in platform registration, and legacy credential vault protocol of the **iFay** ecosystem. It binds every personal `iFay` (`1:N`, non-transferably) to a single **Human Prime** (`hid_`) and every public-role `coFay` in a single ownership layer to one accountable `HumanID` (`hid_`) or `OrganizationID` (`org_`).

## Canonical Identifier Format

All cryptographic FayID identifiers follow `<prefix>_<lowercase-rfc4648-base32-nopad>` (`org_` additionally permits lowercase slug characters `[a-z0-9-]+`):

| Prefix | Entity | Accountability Semantics |
| --- | --- | --- |
| `hid_` | `HumanID` | Root identity of a `Human Prime` (`SHA-256(publicKey)`, 256-bit; never emitted outbound or logged) |
| `ifay_` | `IFayID` | Individual `Fay` strictly paired `1:N` and non-transferably with its owning `HumanID` |
| `cofay_` | `CoFayID` | Shared-role `Fay` bound directly in a single layer to a `HumanID` or `OrganizationID`, with orthogonal `managers: iFayID[]` |
| `org_` | `OrganizationID` | Accountable organizational entity with a natural-person `Steward` (`hid_`) in a mutual-consent single-parent acyclic tree |
| `dyn_` / `dync_` | `DynamicCode` | Short-lived (`<= 600s`), single-use, nonce-salted unlinkable presentation token for `hid_`, `ifay_`, or `cofay_` |
| `reg_` | `PlatformRegistration` | Dual-signed opt-in platform registration attestation (`REAL_NAME`, `EXPERT`, `COMMERCE`, `SERVICE`) |
| `vrf_` | `VerificationCode` | Offline-verifiable Ed25519 verification receipt bound to scoped Auth Exchange checks |
| `grt_` / `ag_` | `AuthorizationGrant` | Scoped legacy-credential exchange grant (`EXACT` / `PREFIX`) for the local `Auth Exchange` proxy |
| `gmcref_` | `OpaqueRef` | Deterministic blind natural-person anchor (`ifay.gmc.natural-person.v1`) for read-only `GMChain` normalization |

## Quick Start & 1-Command Live Demo

Zero external runtime dependencies (pure Node.js `node:crypto` + `node:http`):

```bash
# Run full conformance, unit, integration & vector suites
npm test

# Run the end-to-end live demo (Verify with FayID + Opt-In Registration + Auth Exchange Proxy)
npm run demo
```

## Developer Integration: 5-Line `Verify with FayID` Middleware

Protect any Node.js `http`, Express, or Fetch API endpoint in 5 lines — verifying Holder-of-Key `Ed25519` request signatures (`ifay_`, `cofay_`), privacy-preserving `Dynamic Code` (`dyn_` / `dync_` without ever exposing plaintext `hid_`), Opt-In Platform Registration attestations, and monotonic revocation (`IDENTITY_REVOKED`):

```js
import http from "node:http";
import { createFayIdVerifier } from "./src/index.mjs";

const verifyFayId = createFayIdVerifier({ requiredPlatformCategory: "EXPERT" });
http.createServer(async (req, res) => {
  if (!(await verifyFayId(req, res)).ok) return; // Rejects forged, replayed, or IDENTITY_REVOKED requests
  res.end(JSON.stringify({ verifiedCaller: req.fayid.subjectRef }));
}).listen(3000);
```

### Stealth-by-Default & Opt-In Platform Registration

Every `iFay` and `coFay` is **stealth by default** (`STEALTH_UNREGISTERED`) and invisible across public directories until explicitly registered (like binding a phone number) to a `REAL_NAME`, `EXPERT`, `COMMERCE`, or `SERVICE` platform:

```js
import {
  PLATFORM_CATEGORIES,
  PlatformRegistry,
  issuePlatformRegistration,
  verifyPlatformRegistration,
  revokePlatformRegistration,
} from "./src/index.mjs";

const registry = new PlatformRegistry();
const { value: attestation } = issuePlatformRegistration({
  subjectId: ifayKey.entityId,
  subjectSigner: ifayKey,
  platformId: "org_expert-guild",
  platformCategory: PLATFORM_CATEGORIES.EXPERT,
  platformSigner: orgKey,
  handle: "@ifay-architect",
  scopes: ["consult:architecture"],
  registry,
});
const verified = verifyPlatformRegistration(attestation, { registry });
revokePlatformRegistration(attestation, ifayKey.entityId, { registry }); // Instant opt-out back to stealth
```

## End-User CLI & `Auth Exchange` Local Credential Bridge Proxy

Seal legacy credentials (`PASSWORD`, `OAUTH_TOKEN`, `API_KEY`, `CERTIFICATE`, `SMART_CONTRACT`) inside a local `AES-256-GCM` vault and exchange them for time-bounded `Authorization Grant` tickets (`ag_...`). Your `iFay` calls upstream APIs through the local HTTP proxy using **only** `Bearer ag_...` — **never** seeing raw passwords, OAuth tokens, or API keys:

```bash
# 1. Generate a self-sovereign iFay keypair & unlinkable Dynamic Code
node ./bin/fayid-cli.mjs keygen --prefix ifay --seed my-local-example-passphrase
node ./bin/fayid-cli.mjs dynamic-code --seed my-local-example-passphrase --dync

# 2. Seal an upstream API key inside the local AES-256-GCM vault
node ./bin/fayid-auth-exchange.mjs seal \
  --vault ./.fayid-vault.enc.json \
  --kind API_KEY \
  --resource https://api.upstream.example/v1 \
  --secret example-upstream-api-credential

# 3. Exchange for a time-bounded Authorization Grant ticket (ag_...)
node ./bin/fayid-auth-exchange.mjs exchange \
  --vault ./.fayid-vault.enc.json \
  --credential cred_<id> \
  --target ifay_<id> \
  --ttl 600

# 4. Run the local Credential Bridge Proxy daemon & revoke grants instantly
node ./bin/fayid-auth-exchange.mjs proxy --vault ./.fayid-vault.enc.json --port 4770
node ./bin/fayid-auth-exchange.mjs revoke --vault ./.fayid-vault.enc.json --grant ag_<ticket>
```

## Repository Layout

| Path | Description |
| --- | --- |
| `docs/{locale}/specification/2025-10-25/` | Normative **FayID `1.0` Final** specification across 9 locales (`zh-CN` canonical, plus `zh-TW`, `ja`, `ko`, `en`, `de`, `es`, `fr`, `ru`) |
| `docs/{locale}/blueprint/` | Architectural blueprint across 9 locales (`zh-CN` canonical) |
| `schemas/fayid-1.0.json` | Frozen FayID `1.0` JSON Schema (Draft 2020-12, `version: "1.0"`) |
| `schema/2025-10-25/` | Synchronized `2025-10-25` edition JSON Schema, TypeScript definitions, and overview |
| `src/` | Zero-dependency FayID `1.0` SDK: `fayid-toolkit.mjs`, `verify-with-fayid.mjs`, `platform-registration.mjs`, `auth-exchange-vault.mjs`, and `demo.mjs` |
| `bin/` | Executable CLIs: `fayid-cli.mjs` (`fayid`) and `fayid-auth-exchange.mjs` (`fayid-auth-exchange`) |
| `vectors/` | Deterministic cross-implementation conformance vectors (`account-hierarchy-vectors.json`, `crypto-and-revocation-vectors.json`) |
| `tests/` | Comprehensive unit, integration, and conformance test suites (`node --test`) |

## Governance & Security

- Contribution guidelines & DCO 1.1 sign-off: [CONTRIBUTING.md](./CONTRIBUTING.md)
- Private vulnerability reporting: [SECURITY.md](./SECURITY.md)
- Community standards: [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)

## License

This repository uses a dual-track open-source license (`Copyright (c) 2025-2026 ChainMode contributors`):

- **Source Code, CLIs, Schemas & Test Vectors** (`src/`, `bin/`, `schemas/`, `schema/`, `vectors/`, `tests/`): Licensed under the **MIT License** — see [LICENSE](./LICENSE).
- **Specifications & Architectural Blueprints** (`docs/`): Licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)** — see [LICENSE-DOCS](./LICENSE-DOCS).
