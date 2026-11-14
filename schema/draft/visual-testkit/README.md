# FayID Visual Demo Kit

This folder contains a local visual demo for the FayID draft protocol.

## Run

```sh
cd schema/draft/visual-testkit
node start-demo.mjs
```

The script starts a local static server and opens:

```text
http://127.0.0.1:8765
```

## What It Demonstrates

- What a FayID looks like: Human ID, iFay ID, coFay ID, Organization ID, Dynamic Code, Grant, and OpaqueRef.
- How a holder gets a Dynamic Code and exchanges an Authorization Grant.
- How a target resource verifies a Grant online and fails closed after revocation.
- How GMC discovery returns OpaqueRef instead of Human ID.
- How logs redact Human ID, Dynamic Code, Verification Code, OpaqueRef, mnemonic, and private key.
- Why forged Grants, replayed proofs, over-broad scopes, and secret leaks are blocked.
- How the demo switches languages using BCP 47 language tags aligned with the documentation set.

## Internationalization

The visual testkit supports the same languages as the documentation:

```text
en, zh-CN, zh-TW, ja, ko, es, fr, de, ru
```

Language is selected from the header control, persisted in local storage, and can be preselected with `?lang=zh-CN`.

## Current Implementation

The current demo is dependency-free HTML, CSS, and JavaScript. It is intentionally easy to run from a cloned repository.

For a production-quality developer experience, the next iteration should migrate the UI to React components while keeping the reference protocol helpers framework-independent.
