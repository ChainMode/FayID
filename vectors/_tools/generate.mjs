import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  AccountDirectory,
  deriveBlindGmcRef,
  deriveEgoPackageSigningKey,
  deriveEntityKeypair,
  deriveHumanIdentityFromSeed,
  deriveOpaqueRef,
  derivePurposeSubkey,
  subkeyDomains,
} from "../../src/fayid-toolkit.mjs";

const VECTORS_ROOT = resolve(import.meta.dirname, "..");

const HID_ALICE = `hid_${"a".repeat(32)}`;
const IFAY_ALICE = `ifay_${"b".repeat(32)}`;
const COFAY_PRIMARY = `cofay_${"c".repeat(32)}`;
const COFAY_SECOND = `cofay_${"d".repeat(32)}`;

const seed = Buffer.alloc(32, 0x33);
const gmcSecret = Buffer.alloc(32, 0x77);
const derived = deriveHumanIdentityFromSeed(seed);
const expectedOpaque = deriveOpaqueRef(derived.idBytes, gmcSecret);
const sampleMsg = Buffer.from("fayid-holder-of-key-challenge-v1", "utf8");
const sampleSigHex = derived.signPayload(sampleMsg).toString("hex");

const scenarios = [
  {
    dir: "ownership/01-owner-is-human-accepted",
    context: { action: "register_cofay", cofay: COFAY_PRIMARY, owner: HID_ALICE, signer: HID_ALICE },
    expected: { outcome: "accepted", owner: HID_ALICE, ownerKind: "human" },
  },
  {
    dir: "ownership/02-owner-is-organization-accepted",
    context: { action: "register_cofay", org: "org_acme", steward: HID_ALICE, cofay: COFAY_PRIMARY, owner: "org_acme", signer: HID_ALICE },
    expected: { outcome: "accepted", owner: "org_acme", ownerKind: "organization" },
  },
  {
    dir: "ownership/03-owner-is-cofay-rejected",
    context: { action: "register_nested_cofay", primaryCofay: COFAY_PRIMARY, primaryOwner: HID_ALICE, cofay: COFAY_SECOND, owner: COFAY_PRIMARY, signer: COFAY_PRIMARY },
    expected: { outcome: "rejected", error: "OWNER_TYPE_NOT_ALLOWED" },
  },
  {
    dir: "ownership/04-owner-is-ifay-rejected",
    context: { action: "register_cofay", ifay: IFAY_ALICE, ifayHuman: HID_ALICE, cofay: COFAY_SECOND, owner: IFAY_ALICE, signer: IFAY_ALICE },
    expected: { outcome: "rejected", error: "OWNER_TYPE_NOT_ALLOWED" },
  },
  {
    dir: "hierarchy/01-two-party-signed-accepted",
    context: { action: "link_hierarchy", steward: HID_ALICE, orgs: ["org_parent", "org_child"], links: [{ org: "org_child", parent: "org_parent", childSigned: true, parentSigned: true }], queryOrg: "org_child" },
    expected: { outcome: "accepted", ancestorChain: ["org_parent", "org_child"] },
  },
  {
    dir: "hierarchy/02-single-party-rejected",
    context: { action: "link_hierarchy", steward: HID_ALICE, orgs: ["org_parent", "org_child"], links: [{ org: "org_child", parent: "org_parent", childSigned: true, parentSigned: false }], queryOrg: "org_child" },
    expected: { outcome: "rejected", error: "HIERARCHY_CONSENT_MISSING" },
  },
  {
    dir: "hierarchy/03-direct-cycle-rejected",
    context: { action: "link_hierarchy", steward: HID_ALICE, orgs: ["org_self"], links: [{ org: "org_self", parent: "org_self", childSigned: true, parentSigned: true }], queryOrg: "org_self" },
    expected: { outcome: "rejected", error: "HIERARCHY_CYCLE_CONFLICT" },
  },
  {
    dir: "hierarchy/04-indirect-cycle-rejected",
    context: {
      action: "link_hierarchy",
      steward: HID_ALICE,
      orgs: ["org_a", "org_b", "org_c"],
      links: [
        { org: "org_b", parent: "org_a", childSigned: true, parentSigned: true },
        { org: "org_c", parent: "org_b", childSigned: true, parentSigned: true },
        { org: "org_a", parent: "org_c", childSigned: true, parentSigned: true },
      ],
      queryOrg: "org_c",
    },
    expected: { outcome: "rejected", error: "HIERARCHY_CYCLE_CONFLICT" },
  },
  {
    dir: "hierarchy/05-cofay-owner-not-rolled-up-to-parent",
    context: {
      action: "verify_no_rollup",
      steward: HID_ALICE,
      parentOrg: "org_holding",
      childOrg: "org_subsidiary",
      cofay: COFAY_PRIMARY,
    },
    expected: { outcome: "accepted", cofayOwner: "org_subsidiary", ancestorChain: ["org_holding", "org_subsidiary"] },
  },
  {
    dir: "authority/01-grant-manager-owner-unchanged",
    context: { action: "grant_manager", owner: HID_ALICE, cofay: COFAY_PRIMARY, manager: IFAY_ALICE, signer: HID_ALICE },
    expected: { outcome: "accepted", owner: HID_ALICE, managers: [IFAY_ALICE] },
  },
  {
    dir: "authority/02-grant-by-non-owner-rejected",
    context: { action: "grant_manager", owner: HID_ALICE, cofay: COFAY_PRIMARY, manager: IFAY_ALICE, signer: IFAY_ALICE },
    expected: { outcome: "rejected", error: "AUTHORITY_GRANT_UNAUTHORIZED" },
  },
  {
    dir: "authority/03-org-steward-is-ifay-rejected",
    context: { action: "register_org", org: "org_invalid-steward", steward: IFAY_ALICE },
    expected: { outcome: "rejected", error: "STEWARD_TYPE_NOT_ALLOWED" },
  },
  {
    dir: "self-sovereign/01-holder-of-key-and-opaqueref",
    context: {
      action: "verify_self_sovereign",
      seedHex: seed.toString("hex"),
      exampleNamespaceSaltHex: gmcSecret.toString("hex"),
      challengeUtf8: "fayid-holder-of-key-challenge-v1",
      signatureHex: sampleSigHex,
    },
    expected: {
      outcome: "accepted",
      humanId: derived.humanId,
      publicKeyHex: derived.publicKeyRaw.toString("hex"),
      opaqueRef: expectedOpaque,
      signatureValid: true,
    },
  },
];

for (const sc of scenarios) {
  const targetDir = resolve(VECTORS_ROOT, sc.dir);
  mkdirSync(targetDir, { recursive: true });
  writeFileSync(resolve(targetDir, "context.json"), JSON.stringify(sc.context, null, 2) + "\n");
  writeFileSync(resolve(targetDir, "expected.json"), JSON.stringify(sc.expected, null, 2) + "\n");
}

// Generate deterministic FayID 1.0 crypto & cascading revocation vectors
const vecMasterSeed = Buffer.alloc(32, 0x24);
const vecAuthorityEntropy = Buffer.alloc(32, 0x68);
const vecHolderEntropy = Buffer.alloc(32, 0x9c);
const vecBlindSalt1 = Buffer.alloc(32, 0xb1);
const vecBlindSalt2 = Buffer.alloc(32, 0xd2);

const vecHid = deriveEntityKeypair(vecMasterSeed, "hid", 0).value;
const vecIfay = deriveEntityKeypair(vecMasterSeed, "ifay", 0).value;
const vecCofay = deriveEntityKeypair(vecMasterSeed, "cofay", 0).value;
const vecEntitySub = derivePurposeSubkey(vecMasterSeed, subkeyDomains.ENTITY, "ifay:0").value;
const vecEgoKey = deriveEgoPackageSigningKey(vecMasterSeed, vecIfay.entityId, 0).value;
const vecManifest = { egoSchema: "1.0", personaName: "Aria", weightsSha256: "0011223344556677" };
const vecEnvelope = vecEgoKey.signEgoPackageManifest(vecManifest);

const dynDir = new AccountDirectory({ authoritySecret: vecAuthorityEntropy });
dynDir.registerHuman(vecHid.entityId);
dynDir.registerIFay(vecIfay.entityId, vecHid.entityId);
dynDir.registerCoFay(vecCofay.entityId, vecHid.entityId, vecHid.entityId);
dynDir.registerOrganization("org_vector-corp", vecHid.entityId);

const dynHid = dynDir.issueDynamicCode({
  subjectId: vecHid.entityId,
  holderSecret: vecHolderEntropy,
  nonce: Buffer.alloc(16, 0x10),
  issuedAtSec: 5000,
  expiresAtSec: 5300,
});
const dynHidResolved = dynDir.verifyDynamicCode(dynHid.value.code, 5100);

const grantDir = new AccountDirectory({ authoritySecret: vecAuthorityEntropy });
grantDir.registerHuman(vecHid.entityId);
grantDir.registerIFay(vecIfay.entityId, vecHid.entityId);
const issuedGrant = grantDir.issueAuthGrant({
  targetId: vecIfay.entityId,
  actorId: vecIfay.entityId,
  resourceRef: "https://api.ifay.example/v1/tasks",
  scopeMode: "PREFIX",
  legacySourceKind: "ACCESS_TOKEN",
  legacyIssuer: "idp.ifay.example",
  legacySubject: "subject-vec-01",
  issuedAtSec: 6000,
  expiresAtSec: 7200,
});
const verifiedGrant = grantDir.verifyAuthGrant({
  grantId: issuedGrant.value.grantId,
  requestedResourceRef: "https://api.ifay.example/v1/tasks/active",
  nowSec: 6100,
});

const blind1 = deriveBlindGmcRef(vecHid.entityId, vecBlindSalt1, subkeyDomains.GMC_NATURAL_PERSON);
const blind2 = deriveBlindGmcRef(vecHid.entityId, vecBlindSalt2, subkeyDomains.GMC_NATURAL_PERSON);

const cryptoBundle = {
  version: "1.0",
  edition: "2025-10-25",
  subkeyDerivation: [
    {
      id: "subkey-01-entity-ed25519",
      masterSeedHex: vecMasterSeed.toString("hex"),
      domain: subkeyDomains.ENTITY,
      context: "ifay:0",
      expectedEntityId: vecIfay.entityId,
      expectedPublicKeyHex: vecEntitySub.publicKeyHex,
    },
    {
      id: "subkey-02-ego-package-signing-isolated",
      masterSeedHex: vecMasterSeed.toString("hex"),
      domain: subkeyDomains.EGO_PACKAGE_SIGNING,
      signerFayId: vecIfay.entityId,
      keyIndex: 0,
      manifest: vecManifest,
      expectedPublicKeyHex: vecEgoKey.publicKeyHex,
      expectedEnvelope: vecEnvelope,
    },
  ],
  dynamicCodes: [
    {
      id: "dyn-01-human-valid-blind-resolution",
      exampleAuthorityEntropyHex: vecAuthorityEntropy.toString("hex"),
      exampleHolderEntropyHex: vecHolderEntropy.toString("hex"),
      subjectId: vecHid.entityId,
      nonceHex: Buffer.alloc(16, 0x10).toString("hex"),
      issuedAtSec: 5000,
      expiresAtSec: 5300,
      verifyAtSec: 5100,
      expectedCode: dynHid.value.code,
      expectedOutcome: "accepted",
      expectedResolvedRef: dynHidResolved.value.resolvedRef,
    },
    {
      id: "dyn-02-expired-rejected",
      exampleAuthorityEntropyHex: vecAuthorityEntropy.toString("hex"),
      exampleHolderEntropyHex: vecHolderEntropy.toString("hex"),
      subjectId: vecIfay.entityId,
      nonceHex: Buffer.alloc(16, 0x20).toString("hex"),
      issuedAtSec: 5000,
      expiresAtSec: 5300,
      verifyAtSec: 5301,
      expectedOutcome: "rejected",
      expectedError: "DYNAMIC_CODE_EXPIRED",
    },
    {
      id: "dyn-03-replay-rejected",
      exampleAuthorityEntropyHex: vecAuthorityEntropy.toString("hex"),
      exampleHolderEntropyHex: vecHolderEntropy.toString("hex"),
      subjectId: vecCofay.entityId,
      nonceHex: Buffer.alloc(16, 0x30).toString("hex"),
      issuedAtSec: 5000,
      expiresAtSec: 5300,
      verifyAtSec: 5100,
      replaySecondPresentation: true,
      expectedOutcome: "rejected",
      expectedError: "DYNAMIC_CODE_REPLAYED",
    },
    {
      id: "dyn-04-organization-target-rejected",
      exampleAuthorityEntropyHex: vecAuthorityEntropy.toString("hex"),
      exampleHolderEntropyHex: vecHolderEntropy.toString("hex"),
      subjectId: "org_vector-corp",
      nonceHex: Buffer.alloc(16, 0x40).toString("hex"),
      issuedAtSec: 5000,
      expiresAtSec: 5300,
      expectedOutcome: "rejected",
      expectedError: "DYNAMIC_CODE_TARGET_NOT_ALLOWED",
    },
  ],
  authExchangeAndReceipts: [
    {
      id: "auth-01-prefix-grant-and-receipt",
      exampleAuthorityEntropyHex: vecAuthorityEntropy.toString("hex"),
      humanId: vecHid.entityId,
      targetId: vecIfay.entityId,
      resourceRef: "https://api.ifay.example/v1/tasks",
      requestedResourceRef: "https://api.ifay.example/v1/tasks/active",
      scopeMode: "PREFIX",
      issuedAtSec: 6000,
      expiresAtSec: 7200,
      verifyAtSec: 6100,
      expectedGrantId: issuedGrant.value.grantId,
      expectedReceiptId: verifiedGrant.value.receipt.receiptId,
      expectedOutcome: "accepted",
    },
    {
      id: "auth-02-out-of-scope-rejected",
      exampleAuthorityEntropyHex: vecAuthorityEntropy.toString("hex"),
      humanId: vecHid.entityId,
      targetId: vecIfay.entityId,
      resourceRef: "https://api.ifay.example/v1/tasks",
      requestedResourceRef: "https://api.ifay.example/v1/tasks-admin",
      scopeMode: "PREFIX",
      issuedAtSec: 6000,
      expiresAtSec: 7200,
      verifyAtSec: 6100,
      expectedOutcome: "rejected",
      expectedError: "GRANT_INVALID",
    },
  ],
  cascadingRevocation: [
    {
      id: "cascade-01-revoke-human-invalidates-ifay-cofay-org-and-grants",
      targetKind: "HUMAN_ID",
      expectedGrantVerifyError: "GRANT_REVOKED",
      expectedEntityReissueError: "ENTITY_REVOKED",
    },
    {
      id: "cascade-02-revoke-parent-org-invalidates-descendant-orgs-cofays-and-grants",
      targetKind: "ORGANIZATION_ID",
      expectedGrantVerifyError: "GRANT_REVOKED",
      expectedEntityReissueError: "ENTITY_REVOKED",
    },
    {
      id: "cascade-03-revoke-ifay-strips-manager-and-revokes-ifay-grants-preserving-human",
      targetKind: "IFAY_ID",
      expectedGrantVerifyError: "GRANT_REVOKED",
      expectedEntityReissueError: "ENTITY_REVOKED",
    },
    {
      id: "cascade-04-revoke-cofay-invalidates-cofay-and-its-grants",
      targetKind: "COFAY_ID",
      expectedGrantVerifyError: "GRANT_REVOKED",
      expectedEntityReissueError: "ENTITY_REVOKED",
    },
  ],
  blindGmcRef: [
    {
      id: "gmcref-01-primary-blind-salt",
      humanId: vecHid.entityId,
      userBlindSaltHex: vecBlindSalt1.toString("hex"),
      namespace: subkeyDomains.GMC_NATURAL_PERSON,
      expectedGmcRef: blind1.value,
    },
    {
      id: "gmcref-02-rotated-blind-salt-unlinkable",
      humanId: vecHid.entityId,
      userBlindSaltHex: vecBlindSalt2.toString("hex"),
      namespace: subkeyDomains.GMC_NATURAL_PERSON,
      expectedGmcRef: blind2.value,
    },
  ],
};

writeFileSync(
  resolve(VECTORS_ROOT, "crypto-and-revocation-vectors.json"),
  JSON.stringify(cryptoBundle, null, 2) + "\n",
);

console.log(`Generated ${scenarios.length} directory scenarios and crypto-and-revocation-vectors.json.`);
