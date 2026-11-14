import test from "node:test";
import assert from "node:assert/strict";
import {
  errorCodes,
  matchesResourceRef,
  normalizeResourceRef,
} from "../reference/fayid.js";

test("normalizeResourceRef canonicalizes HTTP(S) resource refs", () => {
  assert.deepEqual(
    normalizeResourceRef("HTTPS://Example.COM:443/app/../app/read"),
    { ok: true, value: "https://example.com/app/read" },
  );
  assert.deepEqual(normalizeResourceRef("https://user@example.com/app"), {
    ok: false,
    error: errorCodes.MALFORMED_FAYID_STRING,
  });
});

test("EXACT scope requires identical normalized resource refs", () => {
  assert.equal(
    matchesResourceRef(
      "https://example.com/app/read",
      "https://example.com/app/read",
      "EXACT",
    ),
    true,
  );
  assert.equal(
    matchesResourceRef(
      "https://example.com/app",
      "https://example.com/app/read",
      "EXACT",
    ),
    false,
  );
});

test("PREFIX scope matches only complete path segments", () => {
  assert.equal(
    matchesResourceRef(
      "https://example.com/app",
      "https://example.com/app/read",
      "PREFIX",
    ),
    true,
  );
  assert.equal(
    matchesResourceRef(
      "https://example.com/app",
      "https://example.com/application",
      "PREFIX",
    ),
    false,
  );
  assert.equal(
    matchesResourceRef(
      "https://example.com/app",
      "https://other.example.com/app/read",
      "PREFIX",
    ),
    false,
  );
});
