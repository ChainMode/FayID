import test from "node:test";
import assert from "node:assert/strict";
import {
  errorCodes,
  parseFayID,
  serializeFayID,
} from "../reference/fayid.js";

test("parseFayID recognizes every v1 prefix", () => {
  const cases = [
    ["hid_ABCD2345", "HUMAN_ID", "hid_abcd2345"],
    ["ifay_abcd2345", "IFAY_ID", "ifay_abcd2345"],
    ["cofay_abcd2345", "COFAY_ID", "cofay_abcd2345"],
    ["org_team-alpha1", "ORGANIZATION_ID", "org_team-alpha1"],
    ["dyn_abcd2345", "DYNAMIC_CODE", "dyn_abcd2345"],
    ["vrf_abcd2345", "VERIFICATION_CODE", "vrf_abcd2345"],
    ["grt_abcd2345", "AUTHORIZATION_GRANT", "grt_abcd2345"],
    ["gmcref_abcd2345", "OPAQUE_REF", "gmcref_abcd2345"],
  ];

  for (const [input, kind, value] of cases) {
    assert.deepEqual(parseFayID(input), { ok: true, value: { kind, value } });
  }
});

test("parseFayID rejects malformed strings without repair", () => {
  const cases = [
    "",
    "hid_",
    "hid_abc!",
    "dyn_abc=",
    "unknown_abc",
    "org_bad space",
    "gmcref_ABC!",
  ];

  for (const input of cases) {
    assert.deepEqual(parseFayID(input), {
      ok: false,
      error: errorCodes.MALFORMED_FAYID_STRING,
    });
  }
});

test("serializeFayID round-trips representative string-bearing entities", () => {
  const cases = [
    { kind: "HUMAN_ID", id: "hid_abcd2345" },
    { kind: "IFAY_ID", id: "ifay_abcd2345" },
    { kind: "COFAY_ID", id: "cofay_abcd2345" },
    { kind: "ORGANIZATION_ID", id: "org_team-alpha1" },
    { kind: "DYNAMIC_CODE", code: "dyn_abcd2345" },
    { kind: "OPAQUE_REF", value: "gmcref_abcd2345" },
  ];

  for (const entity of cases) {
    const serialized = serializeFayID(entity);
    assert.equal(serialized.ok, true);
    const parsed = parseFayID(serialized.value.value);
    assert.deepEqual(parsed, serialized);
  }
});
