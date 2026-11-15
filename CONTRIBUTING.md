# Contributing to FayID

Thank you for contributing to **FayID**! All community members are expected to follow our [Code of Conduct](./CODE_OF_CONDUCT.md). If you discover a cryptographic, authorization, or privacy vulnerability, please report it privately via [SECURITY.md](./SECURITY.md).

## Local Setup & Verification

`FayID` requires **Node.js `>= 20.0.0`** and uses zero external runtime dependencies (`node:crypto` + `node:test`).

```bash
# Clone your fork
git clone https://github.com/ChainMode/FayID.git
cd FayID

# Run all unit tests, draft testkit checks, and cross-implementation conformance vectors
npm test

# Verify deterministic conformance vectors standalone
node vectors/_tools/verify.mjs
```

When modifying schemas or cryptographic utilities, ensure `schemas/fayid-1.0.json`, `schema/2025-10-25/`, `src/fayid-toolkit.mjs`, and `vectors/` remain 100% synchronized.

## Contribution Workflow

1. **Fork & Branch**: Fork `https://github.com/ChainMode/FayID.git` and create a focused branch from `main`.
2. **Conventional Commits**: Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`).
3. **Sign Off Your Commits (DCO 1.1)**: Always commit with `git commit -s` to append your `Signed-off-by` trailer.
4. **Pull Request**: Open a Pull Request against `main` with clear test evidence (`npm test` output).

## Developer Certificate of Origin v1.1 (DCO 1.1) & Licensing

We adopt the **Developer Certificate of Origin Version 1.1 (DCO 1.1)** (`https://developercertificate.org/`). **No separate CLA is required.**

Every commit must include a `Signed-off-by` line (`git commit -s`):

```text
Signed-off-by: Jane Doe <jane.doe@example.com>
```

By signing off, you certify that you have the right to submit your work under our **Inbound = Outbound** dual-track licenses (`Copyright (c) 2025-2026 ChainMode contributors`):

- **Source Code, Schemas & Test Vectors** (`src/`, `schemas/`, `schema/`, `vectors/`, `tests/`): Licensed under the **MIT License** ([LICENSE](./LICENSE)).
- **Specifications & Architectural Blueprints** (`docs/`): Licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)** ([LICENSE-DOCS](./LICENSE-DOCS)).

## Ecosystem Terminology Alignment

Please adhere to canonical ecosystem terminology in all specifications, schemas, and code comments:

- **`Human Prime` (`人类原型`)**: Use `Human Prime` (`人类原型`) when referring to the living human individual anchored by a `hid_` (`HumanID`).
- **`Host` (`宿主`)**: Reserve `Host` (`宿主`) strictly for terminal hardware devices, operating systems, or runtime application environments.
- **`Fay = iFay + coFay`**: Use `Fay` as the umbrella category, `iFay` (`ifay_`) for an individual avatar bound `1:N` to a Human Prime, and `coFay` (`cofay_`) for a single-layer public or organizational role avatar.
- **`GMChain` (`公誉链`) & `MeriToken (μ)` (`美誉值`)**: Refer to the Global Merit Chain as `GMChain` (`公誉链`) and `MeriToken` (`μ` / `Merit Unit`) strictly as a non-monetary measure of social contribution.
