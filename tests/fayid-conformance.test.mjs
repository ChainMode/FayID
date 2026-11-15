import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import {
  AccountDirectory,
  accountErrorCodes,
  base32EncodeNoPad,
  deriveDynamicCode,
  deriveHumanIdentityFromSeed,
  deriveOpaqueRef,
  fromLegacyHexIdentity,
  parseCanonicalFayID,
} from "../src/fayid-toolkit.mjs";

const ROOT = resolve(import.meta.dirname, "..");

test("Self-Sovereign Holder-of-Key: derives Ed25519 HumanID, DynamicCode, and blind OpaqueRef without central secret", () => {
  const seedA = Buffer.alloc(32, 0x11);
  const seedB = Buffer.alloc(32, 0x22);
  const gmcSaltSecret = Buffer.alloc(32, 0x5a);

  const humanA1 = deriveHumanIdentityFromSeed(seedA);
  const humanA2 = deriveHumanIdentityFromSeed(seedA);
  const humanB = deriveHumanIdentityFromSeed(seedB);

  assert.equal(humanA1.humanId, humanA2.humanId);
  assert.match(humanA1.humanId, /^hid_[a-z2-7]{52}$/);
  assert.notEqual(humanA1.humanId, humanB.humanId);

  const dyn1 = deriveDynamicCode(seedA, humanA1.humanId, Buffer.alloc(16, 1), 1000, 1600);
  const dyn2 = deriveDynamicCode(seedA, humanA1.humanId, Buffer.alloc(16, 2), 1000, 1600);
  assert.match(dyn1.code, /^dyn_[a-z2-7]+$/);
  assert.notEqual(dyn1.code, dyn2.code);
  assert.ok(!JSON.stringify({ code: dyn1.code }).includes(humanA1.humanId));

  const opaqueA1 = deriveOpaqueRef(humanA1.idBytes, gmcSaltSecret);
  const opaqueA2 = deriveOpaqueRef(humanA2.idBytes, gmcSaltSecret);
  const opaqueB = deriveOpaqueRef(humanB.idBytes, gmcSaltSecret);
  assert.equal(opaqueA1, opaqueA2);
  assert.notEqual(opaqueA1, opaqueB);
  assert.match(opaqueA1, /^gmcref_[a-z2-7]{52}$/);
});

test("Canonical prefix+Base32 parser & deterministic 64-hex transition adapter", () => {
  const raw32 = Buffer.alloc(32, 0xab);
  const b32 = base32EncodeNoPad(raw32);
  const parsed = parseCanonicalFayID(`IFAY_${b32.toUpperCase()}`);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.value.kind, "IFAY_ID");
  assert.equal(parsed.value.value, `ifay_${b32}`);

  const converted = fromLegacyHexIdentity("ifay", "ab".repeat(32));
  assert.equal(converted.ok, true);
  assert.equal(converted.value, `ifay_${b32}`);
});

test("Single-layer coFay ownership forbids coFay nesting and iFay owner (ADR 0001)", () => {
  const dir = new AccountDirectory();
  const hid = `hid_${"a".repeat(32)}`;
  const ifay = `ifay_${"b".repeat(32)}`;
  const org = "org_acme-labs";
  const cofay1 = `cofay_${"c".repeat(32)}`;
  const cofay2 = `cofay_${"d".repeat(32)}`;

  dir.registerHuman(hid);
  dir.registerIFay(ifay, hid);
  assert.equal(dir.registerOrganization(org, hid).ok, true);

  assert.equal(dir.registerCoFay(cofay1, hid, hid).ok, true);
  const nested = dir.registerCoFay(cofay2, cofay1, cofay1);
  assert.equal(nested.ok, false);
  assert.equal(nested.error, accountErrorCodes.OWNER_TYPE_NOT_ALLOWED);

  const ifayOwned = dir.registerCoFay(cofay2, ifay, ifay);
  assert.equal(ifayOwned.ok, false);
  assert.equal(ifayOwned.error, accountErrorCodes.OWNER_TYPE_NOT_ALLOWED);
});

test("Authority separation: granting/revoking iFay manager preserves owner and forbids re-delegation", () => {
  const dir = new AccountDirectory();
  const hid = `hid_${"a".repeat(32)}`;
  const ifayA = `ifay_${"b".repeat(32)}`;
  const ifayB = `ifay_${"e".repeat(32)}`;
  const cofay = `cofay_${"c".repeat(32)}`;

  dir.registerHuman(hid);
  dir.registerIFay(ifayA, hid);
  dir.registerIFay(ifayB, hid);
  dir.registerCoFay(cofay, hid, hid);

  const grantRes = dir.grantCoFayManager(cofay, ifayA, hid);
  assert.equal(grantRes.ok, true);
  assert.equal(dir.getCoFay(cofay).owner, hid);
  assert.equal(dir.canActForCoFay(cofay, ifayA), true);

  // Manager iFayA CANNOT re-delegate to iFayB!
  const redelegate = dir.grantCoFayManager(cofay, ifayB, ifayA);
  assert.equal(redelegate.ok, false);
  assert.equal(redelegate.error, accountErrorCodes.AUTHORITY_GRANT_UNAUTHORIZED);

  // Revoke immediately invalidates authority while preserving owner
  assert.equal(dir.revokeCoFayManager(cofay, ifayA, hid).ok, true);
  assert.equal(dir.canActForCoFay(cofay, ifayA), false);
  assert.equal(dir.getCoFay(cofay).owner, hid);

  // Organization steward MUST be HumanID
  const badOrg = dir.registerOrganization("org_bad-steward", ifayA);
  assert.equal(badOrg.ok, false);
  assert.equal(badOrg.error, accountErrorCodes.STEWARD_TYPE_NOT_ALLOWED);
});

test("Self-contained Organization Hierarchy: two-party consent, cycle rejection, depth > 16, no coFay rollup", () => {
  const dir = new AccountDirectory();
  const hid = `hid_${"a".repeat(32)}`;
  dir.registerHuman(hid);

  // Build 22-level deep chain (> 16!) to verify zero artificial depth cap
  const orgs = Array.from({ length: 22 }, (_, i) => `org_level-${i}`);
  for (const o of orgs) {
    assert.equal(dir.registerOrganization(o, hid).ok, true);
  }
  for (let i = 1; i < orgs.length; i++) {
    const res = dir.setOrganizationParent({
      org: orgs[i],
      parent: orgs[i - 1],
      childSigned: true,
      parentSigned: true,
    });
    assert.equal(res.ok, true);
  }

  const chain = dir.getAncestorChain(orgs[21]);
  assert.equal(chain.length, 22);
  assert.equal(chain[0], "org_level-0");
  assert.equal(chain[21], "org_level-21");

  // Single-party consent rejected
  const missingConsent = dir.setOrganizationParent({
    org: orgs[1],
    parent: orgs[0],
    childSigned: true,
    parentSigned: false,
  });
  assert.equal(missingConsent.ok, false);
  assert.equal(missingConsent.error, accountErrorCodes.HIERARCHY_CONSENT_MISSING);

  // Indirect cycle rejected (making root's parent = leaf)
  const cycle = dir.setOrganizationParent({
    org: orgs[0],
    parent: orgs[21],
    childSigned: true,
    parentSigned: true,
  });
  assert.equal(cycle.ok, false);
  assert.equal(cycle.error, accountErrorCodes.HIERARCHY_CYCLE_CONFLICT);

  // Child org coFay ownership stays at child org, NEVER rolls up to parent
  const childCofay = `cofay_${"f".repeat(32)}`;
  assert.equal(dir.registerCoFay(childCofay, orgs[21], hid).ok, true);
  assert.equal(dir.getCoFay(childCofay).owner, "org_level-21");
});

test("All FayID conformance vector directories verify cleanly via vectors/_tools/verify.mjs", () => {
  const output = execFileSync(process.execPath, [resolve(ROOT, "vectors/_tools/verify.mjs")], {
    encoding: "utf8",
  });
  assert.match(output, /Verified \d+ FayID vector scenarios: 0 failed/);
});
