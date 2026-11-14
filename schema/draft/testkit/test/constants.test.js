import test from "node:test";
import assert from "node:assert/strict";
import {
  baselineLimits,
  errorCodes,
  prefixes,
} from "../reference/fayid.js";

test("error code surface matches draft protocol", () => {
  assert.deepEqual(Object.values(errorCodes).sort(), [
    "DYNAMIC_CODE_EXPIRED",
    "DYNAMIC_CODE_INVALID",
    "GRANT_EXPIRED",
    "GRANT_INVALID",
    "GRANT_REVOKED",
    "HUMAN_ID_OWNERSHIP_NOT_PROVEN",
    "IDENTITY_REVOKED",
    "INSUFFICIENT_ENTROPY",
    "LEGACY_AUTH_FAILED",
    "LEGACY_SUBJECT_MISMATCH",
    "MALFORMED_FAYID_STRING",
    "OWNERSHIP_NOT_PROVEN",
    "TARGET_OWNERSHIP_NOT_PROVEN",
    "VERIFICATION_RATE_LIMITED",
  ]);
});

test("prefix surface matches draft protocol", () => {
  assert.deepEqual(Object.values(prefixes).sort(), [
    "cofay_",
    "dyn_",
    "gmcref_",
    "grt_",
    "hid_",
    "ifay_",
    "org_",
    "vrf_",
  ]);
});

test("baseline security limits are not weaker than protocol maximums", () => {
  assert.equal(baselineLimits.DYNAMIC_CODE_MAX_TTL_SECONDS, 600);
  assert.equal(baselineLimits.PROOF_CHALLENGE_MAX_TTL_SECONDS, 300);
  assert.equal(baselineLimits.GRANT_MAX_TTL_SECONDS, 3600);
  assert.equal(baselineLimits.LOW_TRUST_GRANT_MAX_TTL_SECONDS, 900);
  assert.equal(baselineLimits.VERIFY_GRANT_CACHE_MAX_SECONDS, 60);
  assert.equal(baselineLimits.VERIFICATION_CODE_FAILURE_THRESHOLD, 5);
});
