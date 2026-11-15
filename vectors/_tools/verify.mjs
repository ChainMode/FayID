import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  AccountDirectory,
  deriveHumanIdentityFromSeed,
  deriveOpaqueRef,
  verifyEd25519Signature,
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

for (const family of FAMILIES) {
  const familyDir = join(VECTORS_ROOT, family);
  for (const entry of readdirSync(familyDir).sort()) {
    const scenarioDir = join(familyDir, entry);
    if (!statSync(scenarioDir).isDirectory()) continue;
    total++;
    const ctx = JSON.parse(readFileSync(join(scenarioDir, "context.json"), "utf8"));
    const expected = JSON.parse(readFileSync(join(scenarioDir, "expected.json"), "utf8"));
    const actual = evaluateScenario(ctx);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      failed++;
      console.error(`FAIL ${family}/${entry}:\n  expected=${JSON.stringify(expected)}\n  actual=${JSON.stringify(actual)}`);
    }
  }
}

console.log(`Verified ${total} FayID vector scenarios: ${failed} failed.`);
if (failed > 0) {
  process.exit(1);
}
