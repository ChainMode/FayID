import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  AccountDirectory,
  accountErrorCodes,
  canonicalizeJcs,
  deriveBlindGmcRef,
  deriveEgoPackageSigningKey,
  deriveEntityKeypair,
  deriveHumanIdentityFromSeed,
  derivePurposeSubkey,
  subkeyDomains,
  verifyAuthReceipt,
  verifyEd25519Signature,
  verifyEgoPackageEnvelope,
} from "../src/fayid-toolkit.mjs";

const ROOT = resolve(import.meta.dirname, "..");

test("Purpose subkey derivation: deterministic HKDF-SHA256 domain separation & Ego signing subkey zero root leakage", () => {
  const masterSeed = Buffer.alloc(32, 0x42);
  const masterHex = masterSeed.toString("hex");

  // Insufficient entropy rejected
  const shortRes = derivePurposeSubkey(Buffer.alloc(16, 0x42), subkeyDomains.ENTITY, "hid:0");
  assert.equal(shortRes.ok, false);
  assert.equal(shortRes.error, accountErrorCodes.INSUFFICIENT_ENTROPY);

  // Empty domain rejected
  const emptyDom = derivePurposeSubkey(masterSeed, "", "hid:0");
  assert.equal(emptyDom.ok, false);
  assert.equal(emptyDom.error, accountErrorCodes.DOMAIN_SEPARATION_REQUIRED);

  // Deterministic entity keypair derivation
  const hidKey1 = deriveEntityKeypair(masterSeed, "hid", 0);
  const hidKey2 = deriveEntityKeypair(masterSeed, "hid", 0);
  const ifayKey0 = deriveEntityKeypair(masterSeed, "ifay", 0);
  const ifayKey1 = deriveEntityKeypair(masterSeed, "ifay", 1);
  const cofayKey0 = deriveEntityKeypair(masterSeed, "cofay", 0);

  assert.equal(hidKey1.ok, true);
  assert.equal(hidKey1.value.entityId, hidKey2.value.entityId);
  assert.equal(hidKey1.value.publicKeyHex, hidKey2.value.publicKeyHex);
  assert.match(hidKey1.value.entityId, /^hid_[a-z2-7]{52}$/);
  assert.match(ifayKey0.value.entityId, /^ifay_[a-z2-7]{52}$/);
  assert.match(cofayKey0.value.entityId, /^cofay_[a-z2-7]{52}$/);
  assert.notEqual(ifayKey0.value.entityId, ifayKey1.value.entityId);
  assert.notEqual(hidKey1.value.publicKeyHex, ifayKey0.value.publicKeyHex);

  // Domain-separated Ego package signing subkey (ifay.ego.package-signing.v1)
  const egoKeyA = deriveEgoPackageSigningKey(masterSeed, ifayKey0.value.entityId, 0);
  const egoKeyB = deriveEgoPackageSigningKey(masterSeed, ifayKey0.value.entityId, 0);
  const egoKeyRot = deriveEgoPackageSigningKey(masterSeed, ifayKey0.value.entityId, 1);

  assert.equal(egoKeyA.ok, true);
  assert.equal(egoKeyA.value.domain, "ifay.ego.package-signing.v1");
  assert.equal(egoKeyA.value.publicKeyHex, egoKeyB.value.publicKeyHex);
  assert.notEqual(egoKeyA.value.publicKeyHex, egoKeyRot.value.publicKeyHex);

  // Must differ from both root key and entity control key!
  const rootHuman = deriveHumanIdentityFromSeed(masterSeed);
  assert.notEqual(egoKeyA.value.publicKeyHex, rootHuman.publicKeyRaw.toString("hex"));
  assert.notEqual(egoKeyA.value.publicKeyHex, ifayKey0.value.publicKeyHex);

  // Rejects HumanID or OrganizationID as Ego package signer
  assert.equal(deriveEgoPackageSigningKey(masterSeed, hidKey1.value.entityId, 0).ok, false);
  assert.equal(deriveEgoPackageSigningKey(masterSeed, "org_acme", 0).ok, false);

  // Sign & verify Ego package manifest; outbound payload + public record contain ZERO root/private material
  const manifest = { egoVersion: "1.0.0", traitsDigest: "sha256:1234abcd" };
  const envelope = egoKeyA.value.signEgoPackageManifest(manifest);
  assert.equal(verifyEgoPackageEnvelope(envelope, manifest), true);
  assert.equal(verifyEgoPackageEnvelope(envelope, { egoVersion: "1.0.0", traitsDigest: "tampered" }), false);

  const serializedPublic = JSON.stringify({
    publicRecord: egoKeyA.value.toPublicRecord(),
    keyJson: egoKeyA.value,
    envelope,
  });
  assert.ok(!serializedPublic.includes(masterHex));
  assert.ok(!serializedPublic.includes(hidKey1.value.entityId));
  assert.ok(!serializedPublic.includes("privateKey"));
  assert.ok(!serializedPublic.includes("seed"));
});

test("Unlinkable Dynamic Code (dyn_): supports HumanID/iFayID/coFayID, rejects org, enforces TTL and anti-replay", () => {
  const dir = new AccountDirectory({ authoritySecret: Buffer.alloc(32, 0x29) });
  const seed = Buffer.alloc(32, 0x51);
  const hid = deriveEntityKeypair(seed, "hid", 0).value.entityId;
  const ifay = deriveEntityKeypair(seed, "ifay", 0).value.entityId;
  const cofay = deriveEntityKeypair(seed, "cofay", 0).value.entityId;

  dir.registerHuman(hid);
  dir.registerIFay(ifay, hid);
  dir.registerOrganization("org_studio", hid);
  dir.registerCoFay(cofay, hid, hid);

  const holderSecret = Buffer.alloc(32, 0x99);
  const d1 = dir.issueDynamicCode({
    subjectId: hid,
    holderSecret,
    nonce: Buffer.alloc(16, 0x01),
    issuedAtSec: 1000,
    expiresAtSec: 1300,
  });
  const d2 = dir.issueDynamicCode({
    subjectId: hid,
    holderSecret,
    nonce: Buffer.alloc(16, 0x02),
    issuedAtSec: 1000,
    expiresAtSec: 1300,
  });
  const dIfay = dir.issueDynamicCode({
    subjectId: ifay,
    holderSecret,
    nonce: Buffer.alloc(16, 0x03),
    issuedAtSec: 1000,
    expiresAtSec: 1300,
  });
  const dCofay = dir.issueDynamicCode({
    subjectId: cofay,
    holderSecret,
    nonce: Buffer.alloc(16, 0x04),
    issuedAtSec: 1000,
    expiresAtSec: 1300,
  });

  assert.equal(d1.ok, true);
  assert.equal(d2.ok, true);
  assert.equal(dIfay.ok, true);
  assert.equal(dCofay.ok, true);
  assert.match(d1.value.code, /^dyn_[a-z2-7]+$/);
  assert.notEqual(d1.value.code, d2.value.code);

  // Passive observer cannot see hid_ in outbound token
  const outboundJson = JSON.stringify(d1.value);
  assert.ok(!outboundJson.includes(hid));

  // OrganizationID is forbidden from deriving DynamicCode
  const orgDyn = dir.issueDynamicCode({
    subjectId: "org_studio",
    holderSecret,
    nonce: Buffer.alloc(16, 0x05),
    issuedAtSec: 1000,
    expiresAtSec: 1300,
  });
  assert.equal(orgDyn.ok, false);
  assert.equal(orgDyn.error, accountErrorCodes.DYNAMIC_CODE_TARGET_NOT_ALLOWED);

  // Excessive TTL (> 600s) or inverted window rejected
  assert.equal(
    dir.issueDynamicCode({
      subjectId: ifay,
      holderSecret,
      nonce: Buffer.alloc(16, 0x06),
      issuedAtSec: 1000,
      expiresAtSec: 1700,
    }).error,
    accountErrorCodes.DYNAMIC_CODE_INVALID,
  );
  assert.equal(
    dir.issueDynamicCode({
      subjectId: ifay,
      holderSecret,
      nonce: Buffer.alloc(16, 0x07),
      issuedAtSec: 1000,
      expiresAtSec: 1000,
    }).error,
    accountErrorCodes.DYNAMIC_CODE_INVALID,
  );

  // Replay nonce at issuance rejected
  assert.equal(
    dir.issueDynamicCode({
      subjectId: hid,
      holderSecret,
      nonce: Buffer.alloc(16, 0x01),
      issuedAtSec: 1005,
      expiresAtSec: 1305,
    }).error,
    accountErrorCodes.DYNAMIC_CODE_REPLAYED,
  );

  // Valid presentation succeeds once; HumanID resolves to blind gmcref_, never plaintext hid_
  const v1 = dir.verifyDynamicCode(d1.value.code, 1150);
  assert.equal(v1.ok, true);
  assert.equal(v1.value.subjectKind, "HUMAN_ID");
  assert.match(v1.value.resolvedRef, /^gmcref_[a-z2-7]+$/);
  assert.ok(!JSON.stringify(v1.value).includes(hid));

  // Replay presentation rejected
  const v1Replay = dir.verifyDynamicCode(d1.value.code, 1151);
  assert.equal(v1Replay.ok, false);
  assert.equal(v1Replay.error, accountErrorCodes.DYNAMIC_CODE_REPLAYED);

  // Expired presentation rejected
  const v2Expired = dir.verifyDynamicCode(d2.value.code, 1301);
  assert.equal(v2Expired.ok, false);
  assert.equal(v2Expired.error, accountErrorCodes.DYNAMIC_CODE_EXPIRED);

  // iFay and coFay dynamic codes resolve cleanly within TTL
  const vIfay = dir.verifyDynamicCode(dIfay.value.code, 1200);
  assert.equal(vIfay.ok, true);
  assert.equal(vIfay.value.resolvedRef, ifay);

  const vCofay = dir.verifyDynamicCode(dCofay.value.code, 1200);
  assert.equal(vCofay.ok, true);
  assert.equal(vCofay.value.resolvedRef, cofay);
});

test("Auth Exchange Grant (grt_), Verification Receipt (vrf_), and Cascading Revocation across Human/Org/iFay/coFay", () => {
  const dir = new AccountDirectory({ authoritySecret: Buffer.alloc(32, 0x73) });
  const seedAlice = Buffer.alloc(32, 0xa1);
  const seedBob = Buffer.alloc(32, 0xb2);

  const hidAlice = deriveEntityKeypair(seedAlice, "hid", 0).value.entityId;
  const ifayAlice1 = deriveEntityKeypair(seedAlice, "ifay", 0).value.entityId;
  const ifayAlice2 = deriveEntityKeypair(seedAlice, "ifay", 1).value.entityId;
  const cofayDirect = deriveEntityKeypair(seedAlice, "cofay", 0).value.entityId;
  const cofayOrgParent = deriveEntityKeypair(seedAlice, "cofay", 1).value.entityId;
  const cofayOrgChild = deriveEntityKeypair(seedAlice, "cofay", 2).value.entityId;

  const hidBob = deriveEntityKeypair(seedBob, "hid", 0).value.entityId;
  const ifayBob = deriveEntityKeypair(seedBob, "ifay", 0).value.entityId;
  const cofayBob = deriveEntityKeypair(seedBob, "cofay", 0).value.entityId;

  dir.registerHuman(hidAlice);
  dir.registerIFay(ifayAlice1, hidAlice);
  dir.registerIFay(ifayAlice2, hidAlice);
  dir.registerCoFay(cofayDirect, hidAlice, hidAlice);
  dir.grantCoFayManager(cofayDirect, ifayAlice1, hidAlice);

  dir.registerHuman(hidBob);
  dir.registerIFay(ifayBob, hidBob);
  dir.registerOrganization("org_holding", hidBob);
  dir.registerOrganization("org_branch", hidBob);
  dir.setOrganizationParent({
    org: "org_branch",
    parent: "org_holding",
    childSigned: true,
    parentSigned: true,
  });
  dir.registerCoFay(cofayOrgParent, "org_holding", hidBob);
  dir.registerCoFay(cofayOrgChild, "org_branch", hidBob);
  dir.registerCoFay(cofayBob, hidBob, hidBob);

  // Issue scoped grants
  const grtIfay1 = dir.issueAuthGrant({
    targetId: ifayAlice1,
    actorId: ifayAlice1,
    resourceRef: "https://vault.example.com/ mail/".replace(" ", ""),
    scopeMode: "PREFIX",
    legacySourceKind: "ACCESS_TOKEN",
    legacyIssuer: "oauth.example.com",
    legacySubject: "alice-sub-001",
    issuedAtSec: 2000,
    expiresAtSec: 3800,
  });
  assert.equal(grtIfay1.ok, true);
  assert.match(grtIfay1.value.grantId, /^grt_[a-z2-7]+$/);
  assert.ok(!JSON.stringify(grtIfay1.value).includes("alice-sub-001"));

  const grtHidAlice = dir.issueAuthGrant({
    targetId: hidAlice,
    actorId: hidAlice,
    resourceRef: "https://account.example.com/settings",
    scopeMode: "EXACT",
    legacySourceKind: "CERTIFICATE",
    legacyIssuer: "ca.example.com",
    legacySubject: "cert-serial-99",
    issuedAtSec: 2000,
    expiresAtSec: 3800,
  });
  assert.equal(grtHidAlice.ok, true);
  // Outbound grant record MUST NOT contain plaintext hidAlice!
  assert.ok(!JSON.stringify(grtHidAlice.value).includes(hidAlice));

  const grtCofayDirect = dir.issueAuthGrant({
    targetId: cofayDirect,
    actorId: ifayAlice1,
    resourceRef: "https://desk.example.com/tickets",
    scopeMode: "PREFIX",
    issuedAtSec: 2000,
    expiresAtSec: 3800,
  });
  assert.equal(grtCofayDirect.ok, true);

  const grtCofayChild = dir.issueAuthGrant({
    targetId: cofayOrgChild,
    actorId: hidBob,
    resourceRef: "https://erp.example.com/orders",
    scopeMode: "PREFIX",
    issuedAtSec: 2000,
    expiresAtSec: 3800,
  });
  assert.equal(grtCofayChild.ok, true);

  const grtCofayBob = dir.issueAuthGrant({
    targetId: cofayBob,
    actorId: hidBob,
    resourceRef: "https://ops.example.com/run",
    scopeMode: "EXACT",
    issuedAtSec: 2000,
    expiresAtSec: 3800,
  });
  assert.equal(grtCofayBob.ok, true);

  // Verify grant produces cryptographic Verification Receipt (vrf_)
  const verOk = dir.verifyAuthGrant({
    grantId: grtIfay1.value.grantId,
    requestedResourceRef: "https://vault.example.com/mail/inbox",
    nowSec: 2100,
  });
  assert.equal(verOk.ok, true);
  assert.match(verOk.value.receipt.receiptId, /^vrf_[a-z2-7]+$/);
  assert.equal(verifyAuthReceipt(verOk.value.receipt), true);
  assert.equal(
    verifyAuthReceipt({ ...verOk.value.receipt, requestedResourceRef: "https://evil.example.com/" }),
    false,
  );

  // Scope mismatch & expiry checks
  assert.equal(
    dir.verifyAuthGrant({
      grantId: grtIfay1.value.grantId,
      requestedResourceRef: "https://vault.example.com/mailbox",
      nowSec: 2100,
    }).error,
    accountErrorCodes.GRANT_INVALID,
  );
  assert.equal(
    dir.verifyAuthGrant({
      grantId: grtIfay1.value.grantId,
      requestedResourceRef: "https://vault.example.com/mail/inbox",
      nowSec: 3801,
    }).error,
    accountErrorCodes.GRANT_EXPIRED,
  );

  // 1) Revoke iFay (ifayAlice1): strips manager authority & revokes its grants, keeping hidAlice & ifayAlice2 active
  const revIfay = dir.revokeEntity(ifayAlice1, hidAlice);
  assert.equal(revIfay.ok, true);
  assert.equal(dir.canActForCoFay(cofayDirect, ifayAlice1), false);
  assert.equal(
    dir.verifyAuthGrant({
      grantId: grtIfay1.value.grantId,
      requestedResourceRef: "https://vault.example.com/mail/inbox",
      nowSec: 2200,
    }).error,
    accountErrorCodes.GRANT_REVOKED,
  );
  // Grant issued via actor ifayAlice1 is also cascade-revoked!
  assert.equal(
    dir.verifyAuthGrant({
      grantId: grtCofayDirect.value.grantId,
      requestedResourceRef: "https://desk.example.com/tickets/1",
      nowSec: 2200,
    }).error,
    accountErrorCodes.GRANT_REVOKED,
  );
  // New grant request for revoked iFay returns ENTITY_REVOKED
  assert.equal(
    dir.issueAuthGrant({
      targetId: ifayAlice1,
      actorId: hidAlice,
      resourceRef: "https://vault.example.com/mail",
      issuedAtSec: 2200,
      expiresAtSec: 2500,
    }).error,
    accountErrorCodes.ENTITY_REVOKED,
  );
  // hidAlice's own grant is STILL valid!
  assert.equal(
    dir.verifyAuthGrant({
      grantId: grtHidAlice.value.grantId,
      requestedResourceRef: "https://account.example.com/settings",
      nowSec: 2200,
    }).ok,
    true,
  );

  // 2) Revoke coFay (cofayBob): invalidates cofayBob and its grant
  const revCofay = dir.revokeEntity(cofayBob, hidBob);
  assert.equal(revCofay.ok, true);
  assert.equal(dir.isEntityRevoked(cofayBob), true);
  assert.equal(
    dir.verifyAuthGrant({
      grantId: grtCofayBob.value.grantId,
      requestedResourceRef: "https://ops.example.com/run",
      nowSec: 2200,
    }).error,
    accountErrorCodes.GRANT_REVOKED,
  );

  // 3) Revoke Organization (org_holding): cascades to child org_branch, cofayOrgParent, cofayOrgChild, and grtCofayChild
  const revOrg = dir.revokeEntity("org_holding", hidBob);
  assert.equal(revOrg.ok, true);
  assert.equal(dir.isEntityRevoked("org_holding"), true);
  assert.equal(dir.isEntityRevoked("org_branch"), true);
  assert.equal(dir.isEntityRevoked(cofayOrgParent), true);
  assert.equal(dir.isEntityRevoked(cofayOrgChild), true);
  assert.equal(
    dir.verifyAuthGrant({
      grantId: grtCofayChild.value.grantId,
      requestedResourceRef: "https://erp.example.com/orders/42",
      nowSec: 2200,
    }).error,
    accountErrorCodes.GRANT_REVOKED,
  );

  // 4) Revoke HumanID (hidAlice): cascades to ifayAlice2, cofayDirect, and grtHidAlice
  const grtIfay2 = dir.issueAuthGrant({
    targetId: ifayAlice2,
    actorId: ifayAlice2,
    resourceRef: "https://notes.example.com/sync",
    issuedAtSec: 2200,
    expiresAtSec: 3000,
  });
  assert.equal(grtIfay2.ok, true);

  const revHuman = dir.revokeEntity(hidAlice, hidAlice);
  assert.equal(revHuman.ok, true);
  assert.equal(dir.isEntityRevoked(hidAlice), true);
  assert.equal(dir.isEntityRevoked(ifayAlice2), true);
  assert.equal(dir.isEntityRevoked(cofayDirect), true);
  assert.equal(
    dir.verifyAuthGrant({
      grantId: grtHidAlice.value.grantId,
      requestedResourceRef: "https://account.example.com/settings",
      nowSec: 2300,
    }).error,
    accountErrorCodes.GRANT_REVOKED,
  );
  assert.equal(
    dir.verifyAuthGrant({
      grantId: grtIfay2.value.grantId,
      requestedResourceRef: "https://notes.example.com/sync",
      nowSec: 2300,
    }).error,
    accountErrorCodes.GRANT_REVOKED,
  );
});

test("Blind gmcref_ derivation: deterministic per HumanID + blind salt, domain-separated, rejects non-HumanID", () => {
  const seed1 = Buffer.alloc(32, 0x19);
  const seed2 = Buffer.alloc(32, 0x29);
  const hid1 = deriveEntityKeypair(seed1, "hid", 0).value.entityId;
  const ifay1 = deriveEntityKeypair(seed1, "ifay", 0).value.entityId;
  const hid2 = deriveEntityKeypair(seed2, "hid", 0).value.entityId;

  const blindSaltA = Buffer.alloc(32, 0xc3);
  const blindSaltB = Buffer.alloc(32, 0xd4);

  const ref1A = deriveBlindGmcRef(hid1, blindSaltA);
  const ref1A_repeat = deriveBlindGmcRef(hid1.toUpperCase(), blindSaltA);
  const ref1B = deriveBlindGmcRef(hid1, blindSaltB);
  const ref2A = deriveBlindGmcRef(hid2, blindSaltA);
  const refCustomNs = deriveBlindGmcRef(hid1, blindSaltA, "ifay.gmc.subnet-alpha.v1");

  assert.equal(ref1A.ok, true);
  assert.match(ref1A.value, /^gmcref_[a-z2-7]{52}$/);
  assert.equal(ref1A.value, ref1A_repeat.value);
  assert.notEqual(ref1A.value, ref1B.value);
  assert.notEqual(ref1A.value, ref2A.value);
  assert.notEqual(ref1A.value, refCustomNs.value);
  assert.ok(!ref1A.value.includes(hid1.slice(4)));

  // Rejects iFayID (gmcref_ anchors natural persons only) and short salts
  assert.equal(deriveBlindGmcRef(ifay1, blindSaltA).ok, false);
  assert.equal(deriveBlindGmcRef(hid1, Buffer.alloc(8, 1)).error, accountErrorCodes.INSUFFICIENT_ENTROPY);
});

test("Frozen JSON Schemas (schemas/fayid-1.0.json & schema/2025-10-25/schema.json) are synchronized and normative", () => {
  const frozenSchema = JSON.parse(readFileSync(resolve(ROOT, "schemas/fayid-1.0.json"), "utf8"));
  const editionSchema = JSON.parse(readFileSync(resolve(ROOT, "schema/2025-10-25/schema.json"), "utf8"));

  assert.equal(frozenSchema.properties.version.const, "1.0");
  assert.deepEqual(frozenSchema.$defs, editionSchema.$defs);
  assert.ok(frozenSchema.$defs.VerificationReceipt);
  assert.ok(frozenSchema.$defs.EgoPackageSignatureEnvelope);
  assert.equal(canonicalizeJcs({ b: 2, a: 1 }), '{"a":1,"b":2}');
});

test("Deterministic crypto-and-revocation-vectors.json covers subkeys, dyn_, grt_/vrf_, cascading revocation, and gmcref_", () => {
  const bundle = JSON.parse(readFileSync(resolve(ROOT, "vectors/crypto-and-revocation-vectors.json"), "utf8"));
  assert.equal(bundle.version, "1.0");
  assert.ok(Array.isArray(bundle.subkeyDerivation) && bundle.subkeyDerivation.length >= 2);
  assert.ok(Array.isArray(bundle.dynamicCodes) && bundle.dynamicCodes.length >= 4);
  assert.ok(Array.isArray(bundle.authExchangeAndReceipts) && bundle.authExchangeAndReceipts.length >= 2);
  assert.ok(Array.isArray(bundle.cascadingRevocation) && bundle.cascadingRevocation.length >= 4);
  assert.ok(Array.isArray(bundle.blindGmcRef) && bundle.blindGmcRef.length >= 2);

  for (const vec of bundle.subkeyDerivation) {
    if (vec.domain === "ifay.ego.package-signing.v1") {
      const key = deriveEgoPackageSigningKey(
        Buffer.from(vec.masterSeedHex, "hex"),
        vec.signerFayId,
        vec.keyIndex,
      );
      assert.equal(key.ok, true);
      assert.equal(key.value.publicKeyHex, vec.expectedPublicKeyHex);
      assert.equal(verifyEgoPackageEnvelope(vec.expectedEnvelope, vec.manifest), true);
    } else {
      const sub = derivePurposeSubkey(Buffer.from(vec.masterSeedHex, "hex"), vec.domain, vec.context);
      assert.equal(sub.ok, true);
      assert.equal(sub.value.publicKeyHex, vec.expectedPublicKeyHex);
    }
  }

  for (const vec of bundle.blindGmcRef) {
    const res = deriveBlindGmcRef(vec.humanId, Buffer.from(vec.userBlindSaltHex, "hex"), vec.namespace);
    assert.equal(res.ok, true);
    assert.equal(res.value, vec.expectedGmcRef);
  }
});
