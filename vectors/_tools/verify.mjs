import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  AccountDirectory,
  deriveBlindGmcRef,
  deriveEgoPackageSigningKey,
  deriveEntityKeypair,
  deriveHumanIdentityFromSeed,
  deriveOpaqueRef,
  derivePurposeSubkey,
  verifyAuthReceipt,
  verifyEd25519Signature,
  verifyEgoPackageEnvelope,
} from "../../src/fayid-toolkit.mjs";

const VECTORS_ROOT = resolve(import.meta.dirname, "..");
const FAMILIES = ["ownership", "hierarchy", "authority", "self-sovereign"];

function evaluateScenario(ctx) {
  const dir = new AccountDirectory();
  if (ctx.action === "register_cofay") {
    dir.registerHuman(`hid_${"a".repeat(32)}`);
    if (ctx.org) dir.registerOrganization(ctx.org, ctx.steward);
    if (ctx.ifay) dir.registerIFay(ctx.ifay, ctx.ifayHuman);
    const res = dir.registerCoFay(ctx.cofay, ctx.owner, ctx.signer);
    return res.ok
      ? { outcome: "accepted", owner: res.value.owner, ownerKind: res.value.ownerKind }
      : { outcome: "rejected", error: res.error };
  }

  if (ctx.action === "register_nested_cofay") {
    dir.registerHuman(ctx.primaryOwner);
    dir.registerCoFay(ctx.primaryCofay, ctx.primaryOwner, ctx.primaryOwner);
    const res = dir.registerCoFay(ctx.cofay, ctx.owner, ctx.signer);
    return res.ok
      ? { outcome: "accepted", owner: res.value.owner, ownerKind: res.value.ownerKind }
      : { outcome: "rejected", error: res.error };
  }

  if (ctx.action === "link_hierarchy") {
    dir.registerHuman(ctx.steward);
    for (const o of ctx.orgs) dir.registerOrganization(o, ctx.steward);
    for (const link of ctx.links) {
      const res = dir.setOrganizationParent(link);
      if (!res.ok) return { outcome: "rejected", error: res.error };
    }
    return { outcome: "accepted", ancestorChain: dir.getAncestorChain(ctx.queryOrg) };
  }

  if (ctx.action === "verify_no_rollup") {
    dir.registerHuman(ctx.steward);
    dir.registerOrganization(ctx.parentOrg, ctx.steward);
    dir.registerOrganization(ctx.childOrg, ctx.steward);
    dir.setOrganizationParent({
      org: ctx.childOrg,
      parent: ctx.parentOrg,
      childSigned: true,
      parentSigned: true,
    });
    dir.registerCoFay(ctx.cofay, ctx.childOrg, ctx.steward);
    return {
      outcome: "accepted",
      cofayOwner: dir.getCoFay(ctx.cofay).owner,
      ancestorChain: dir.getAncestorChain(ctx.childOrg),
    };
  }

  if (ctx.action === "grant_manager") {
    dir.registerHuman(ctx.owner);
    dir.registerIFay(ctx.manager, ctx.owner);
    dir.registerCoFay(ctx.cofay, ctx.owner, ctx.owner);
    const res = dir.grantCoFayManager(ctx.cofay, ctx.manager, ctx.signer);
    return res.ok
      ? { outcome: "accepted", owner: res.value.owner, managers: res.value.managers }
      : { outcome: "rejected", error: res.error };
  }

  if (ctx.action === "register_org") {
    const res = dir.registerOrganization(ctx.org, ctx.steward);
    return res.ok ? { outcome: "accepted" } : { outcome: "rejected", error: res.error };
  }

  if (ctx.action === "verify_self_sovereign") {
    const seed = Buffer.from(ctx.seedHex, "hex");
    const gmcSecret = Buffer.from(ctx.exampleNamespaceSaltHex, "hex");
    const derived = deriveHumanIdentityFromSeed(seed);
    const opaqueRef = deriveOpaqueRef(derived.idBytes, gmcSecret);
    const signatureValid = verifyEd25519Signature(
      derived.publicKeyRaw,
      Buffer.from(ctx.challengeUtf8, "utf8"),
      Buffer.from(ctx.signatureHex, "hex"),
    );
    return {
      outcome: "accepted",
      humanId: derived.humanId,
      publicKeyHex: derived.publicKeyRaw.toString("hex"),
      opaqueRef,
      signatureValid,
    };
  }

  throw new Error(`Unknown vector action: ${ctx.action}`);
}

let total = 0;
let failed = 0;

function check(label, condition, detail = "") {
  total++;
  if (!condition) {
    failed++;
    console.error(`FAIL ${label}${detail ? `: ${detail}` : ""}`);
  }
}

for (const family of FAMILIES) {
  const familyDir = join(VECTORS_ROOT, family);
  for (const entry of readdirSync(familyDir).sort()) {
    const scenarioDir = join(familyDir, entry);
    if (!statSync(scenarioDir).isDirectory()) continue;
    const ctx = JSON.parse(readFileSync(join(scenarioDir, "context.json"), "utf8"));
    const expected = JSON.parse(readFileSync(join(scenarioDir, "expected.json"), "utf8"));
    const actual = evaluateScenario(ctx);
    check(
      `${family}/${entry}`,
      JSON.stringify(actual) === JSON.stringify(expected),
      `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`,
    );
  }
}

const bundle = JSON.parse(readFileSync(join(VECTORS_ROOT, "crypto-and-revocation-vectors.json"), "utf8"));

for (const vec of bundle.subkeyDerivation) {
  if (vec.domain === "ifay.ego.package-signing.v1") {
    const key = deriveEgoPackageSigningKey(
      Buffer.from(vec.masterSeedHex, "hex"),
      vec.signerFayId,
      vec.keyIndex,
    );
    check(
      `crypto/${vec.id}`,
      key.ok &&
        key.value.publicKeyHex === vec.expectedPublicKeyHex &&
        verifyEgoPackageEnvelope(vec.expectedEnvelope, vec.manifest) &&
        !JSON.stringify(vec.expectedEnvelope).includes(vec.masterSeedHex),
    );
  } else {
    const sub = derivePurposeSubkey(Buffer.from(vec.masterSeedHex, "hex"), vec.domain, vec.context);
    check(`crypto/${vec.id}`, sub.ok && sub.value.publicKeyHex === vec.expectedPublicKeyHex);
  }
}

for (const vec of bundle.dynamicCodes) {
  const dir = new AccountDirectory({ authoritySecret: Buffer.from(vec.exampleAuthorityEntropyHex, "hex") });
  const seedBuf = Buffer.alloc(32, 0x24);
  const hid = deriveEntityKeypair(seedBuf, "hid", 0).value.entityId;
  const ifay = deriveEntityKeypair(seedBuf, "ifay", 0).value.entityId;
  const cofay = deriveEntityKeypair(seedBuf, "cofay", 0).value.entityId;
  dir.registerHuman(hid);
  dir.registerIFay(ifay, hid);
  dir.registerCoFay(cofay, hid, hid);
  dir.registerOrganization("org_vector-corp", hid);

  const issued = dir.issueDynamicCode({
    subjectId: vec.subjectId,
    holderSecret: Buffer.from(vec.exampleHolderEntropyHex, "hex"),
    nonce: Buffer.from(vec.nonceHex, "hex"),
    issuedAtSec: vec.issuedAtSec,
    expiresAtSec: vec.expiresAtSec,
  });

  if (!issued.ok) {
    check(`crypto/${vec.id}`, vec.expectedOutcome === "rejected" && issued.error === vec.expectedError);
  } else {
    const first = dir.verifyDynamicCode(issued.value.code, vec.verifyAtSec);
    if (vec.replaySecondPresentation) {
      const second = dir.verifyDynamicCode(issued.value.code, vec.verifyAtSec + 1);
      check(`crypto/${vec.id}`, first.ok && !second.ok && second.error === vec.expectedError);
    } else if (vec.expectedOutcome === "accepted") {
      check(
        `crypto/${vec.id}`,
        issued.value.code === vec.expectedCode &&
          first.ok &&
          first.value.resolvedRef === vec.expectedResolvedRef,
      );
    } else {
      check(`crypto/${vec.id}`, !first.ok && first.error === vec.expectedError);
    }
  }
}

for (const vec of bundle.authExchangeAndReceipts) {
  const dir = new AccountDirectory({ authoritySecret: Buffer.from(vec.exampleAuthorityEntropyHex, "hex") });
  dir.registerHuman(vec.humanId);
  dir.registerIFay(vec.targetId, vec.humanId);
  const issued = dir.issueAuthGrant({
    targetId: vec.targetId,
    actorId: vec.targetId,
    resourceRef: vec.resourceRef,
    scopeMode: vec.scopeMode,
    legacySourceKind: "ACCESS_TOKEN",
    legacyIssuer: "idp.ifay.example",
    legacySubject: "subject-vec-01",
    issuedAtSec: vec.issuedAtSec,
    expiresAtSec: vec.expiresAtSec,
  });
  const verified = dir.verifyAuthGrant({
    grantId: issued.value.grantId,
    requestedResourceRef: vec.requestedResourceRef,
    nowSec: vec.verifyAtSec,
  });
  if (vec.expectedOutcome === "accepted") {
    check(
      `crypto/${vec.id}`,
      issued.value.grantId === vec.expectedGrantId &&
        verified.ok &&
        verified.value.receipt.receiptId === vec.expectedReceiptId &&
        verifyAuthReceipt(verified.value.receipt),
    );
  } else {
    check(`crypto/${vec.id}`, !verified.ok && verified.error === vec.expectedError);
  }
}

for (const vec of bundle.cascadingRevocation) {
  const dir = new AccountDirectory({ authoritySecret: Buffer.alloc(32, 0x55) });
  const seedBuf = Buffer.alloc(32, 0x44);
  const hid = deriveEntityKeypair(seedBuf, "hid", 0).value.entityId;
  const ifay = deriveEntityKeypair(seedBuf, "ifay", 0).value.entityId;
  const cofayH = deriveEntityKeypair(seedBuf, "cofay", 0).value.entityId;
  const cofayO = deriveEntityKeypair(seedBuf, "cofay", 1).value.entityId;

  dir.registerHuman(hid);
  dir.registerIFay(ifay, hid);
  dir.registerOrganization("org_root", hid);
  dir.registerOrganization("org_sub", hid);
  dir.setOrganizationParent({ org: "org_sub", parent: "org_root", childSigned: true, parentSigned: true });
  dir.registerCoFay(cofayH, hid, hid);
  dir.registerCoFay(cofayO, "org_sub", hid);
  dir.grantCoFayManager(cofayH, ifay, hid);

  const targetForGrant =
    vec.targetKind === "ORGANIZATION_ID"
      ? cofayO
      : vec.targetKind === "COFAY_ID"
        ? cofayH
        : ifay;
  const grt = dir.issueAuthGrant({
    targetId: targetForGrant,
    actorId: vec.targetKind === "ORGANIZATION_ID" ? hid : targetForGrant,
    resourceRef: "https://svc.example.com/resource",
    issuedAtSec: 1000,
    expiresAtSec: 2000,
  });
  const entityToRevoke =
    vec.targetKind === "HUMAN_ID"
      ? hid
      : vec.targetKind === "ORGANIZATION_ID"
        ? "org_root"
        : vec.targetKind === "IFAY_ID"
          ? ifay
          : cofayH;

  const rev = dir.revokeEntity(entityToRevoke, hid);
  const afterVerify = dir.verifyAuthGrant({
    grantId: grt.value.grantId,
    requestedResourceRef: "https://svc.example.com/resource",
    nowSec: 1100,
  });
  const afterReissue = dir.issueAuthGrant({
    targetId: targetForGrant,
    actorId: hid,
    resourceRef: "https://svc.example.com/resource",
    issuedAtSec: 1100,
    expiresAtSec: 2000,
  });
  const humanPreservedWhenIfayRevoked = vec.targetKind === "IFAY_ID" ? !dir.isEntityRevoked(hid) : true;
  check(
    `crypto/${vec.id}`,
    rev.ok &&
      !afterVerify.ok &&
      afterVerify.error === vec.expectedGrantVerifyError &&
      !afterReissue.ok &&
      afterReissue.error === vec.expectedEntityReissueError &&
      humanPreservedWhenIfayRevoked,
  );
}

for (const vec of bundle.blindGmcRef) {
  const res = deriveBlindGmcRef(vec.humanId, Buffer.from(vec.userBlindSaltHex, "hex"), vec.namespace);
  check(`crypto/${vec.id}`, res.ok && res.value === vec.expectedGmcRef);
}

console.log(`Verified ${total} FayID vector scenarios: ${failed} failed.`);
if (failed > 0) {
  process.exit(1);
}
