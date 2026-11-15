import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { deriveHumanIdentityFromSeed, deriveOpaqueRef } from "../../src/fayid-toolkit.mjs";

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

console.log(`Generated ${scenarios.length} FayID vector scenarios.`);
