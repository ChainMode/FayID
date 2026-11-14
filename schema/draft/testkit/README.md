# FayID Conformance Testkit (Draft)

This is a dependency-free starter conformance kit for the draft FayID protocol.

Run:

```sh
npm test
```

The initial suite covers:

- String prefix parsing and invalid string rejection.
- Entity/string round-trip behavior for reference entities.
- `resourceRef` normalization and `EXACT` / `PREFIX` scope matching.
- Baseline constants mirrored from the protocol draft.
- Required error code surface.

Future layers should add property-based tests and implementation adapter tests.
