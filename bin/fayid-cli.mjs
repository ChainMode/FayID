#!/usr/bin/env node
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  PLATFORM_CATEGORIES,
  createFayIdVerifier,
  deriveEntityKeypair,
  issueDynamicPresentation,
  issuePlatformRegistration,
  revokePlatformRegistration,
  signFayIdRequest,
  verifyPlatformRegistration,
} from "../src/index.mjs";

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const eqIdx = arg.indexOf("=");
      if (eqIdx !== -1) {
        flags[arg.slice(2, eqIdx)] = arg.slice(eqIdx + 1);
      } else {
        const next = argv[i + 1];
        if (next && !next.startsWith("--")) {
          flags[arg.slice(2)] = next;
          i += 1;
        } else {
          flags[arg.slice(2)] = true;
        }
      }
    } else {
      positional.push(arg);
    }
  }
  return { cmd: positional[0] ?? "help", positional: positional.slice(1), flags };
}

function seedFromFlag(seedFlag) {
  if (!seedFlag) return randomBytes(32);
  const str = String(seedFlag);
  if (/^[0-9a-fA-F]{64}$/.test(str)) return Buffer.from(str, "hex");
  return createHash("sha256").update(str, "utf8").digest();
}

function printUsage() {
  console.log(`FayID CLI — Self-Sovereign Identity, Dynamic Code & Opt-In Platform Registration

Usage:
  fayid-cli keygen [--prefix hid|ifay|cofay|org] [--slot 0] [--seed <hex64|passphrase>]
  fayid-cli dynamic-code --seed <hex64|passphrase> [--prefix hid|ifay|cofay] [--slot 0] [--ttl 300] [--dync]
  fayid-cli register-platform --seed <hex64|passphrase> --platform-seed <hex64|passphrase> --platform <org_slug> --category <REAL_NAME|EXPERT|COMMERCE|SERVICE> [--handle <name>]
  fayid-cli verify-registration --file <attestation.json>
  fayid-cli sign-request --seed <hex64|passphrase> [--prefix ifay|cofay] [--method POST] [--url /api/action] [--body '{"ping":1}']
`);
}

async function main() {
  const { cmd, flags } = parseArgs(process.argv.slice(2));

  if (cmd === "help" || flags.help) {
    printUsage();
    return;
  }

  if (cmd === "keygen") {
    const prefix = String(flags.prefix ?? "ifay");
    const slot = flags.slot !== undefined ? (Number.isNaN(Number(flags.slot)) ? flags.slot : Number(flags.slot)) : 0;
    const seed = seedFromFlag(flags.seed);
    const kp = deriveEntityKeypair(seed, prefix, slot);
    if (!kp.ok) {
      console.error(JSON.stringify(kp));
      process.exitCode = 1;
      return;
    }
    console.log(
      JSON.stringify(
        {
          ok: true,
          entityId: kp.value.entityId,
          kind: kp.value.kind,
          publicKeyHex: kp.value.publicKeyHex,
          seedHex: flags.seed ? undefined : seed.toString("hex"),
        },
        null,
        2,
      ),
    );
    return;
  }

  if (cmd === "dynamic-code") {
    const seed = seedFromFlag(flags.seed);
    const prefix = String(flags.prefix ?? "hid");
    const slot = Number(flags.slot ?? 0);
    const kp = deriveEntityKeypair(seed, prefix, slot);
    if (!kp.ok) {
      console.error(JSON.stringify(kp));
      process.exitCode = 1;
      return;
    }
    const dyn = issueDynamicPresentation({
      masterSeed: seed,
      subjectId: kp.value.entityId,
      ttlSec: Number(flags.ttl ?? 300),
      useDyncAlias: Boolean(flags.dync),
    });
    if (!dyn.ok) {
      console.error(JSON.stringify(dyn));
      process.exitCode = 1;
      return;
    }
    console.log(
      JSON.stringify(
        {
          ok: true,
          dynamicCode: dyn.value.dynamicCode,
          canonicalCode: dyn.value.canonicalCode,
          ticket: dyn.value.ticket,
        },
        null,
        2,
      ),
    );
    return;
  }

  if (cmd === "register-platform") {
    const seed = seedFromFlag(flags.seed);
    const platformSeed = seedFromFlag(flags["platform-seed"] ?? "platform-registry-example-seed");
    const platformSlug = String(flags.platform ?? "org_expert-hub").replace(/^org_/, "");
    const category = String(flags.category ?? PLATFORM_CATEGORIES.EXPERT).toUpperCase();
    const subjectKp = deriveEntityKeypair(seed, "ifay", Number(flags.slot ?? 0));
    const platformKp = deriveEntityKeypair(platformSeed, "org", platformSlug);
    if (!subjectKp.ok || !platformKp.ok) {
      console.error(JSON.stringify({ ok: false, error: "KEY_DERIVATION_FAILED" }));
      process.exitCode = 1;
      return;
    }
    const res = issuePlatformRegistration({
      subjectId: subjectKp.value.entityId,
      subjectSigner: subjectKp.value,
      platformId: platformKp.value.entityId,
      platformCategory: category,
      platformSigner: platformKp.value,
      handle: String(flags.handle ?? `@${subjectKp.value.entityId.slice(0, 14)}`),
      scopes: flags.scopes ? String(flags.scopes).split(",") : ["verified-member"],
    });
    if (!res.ok) {
      console.error(JSON.stringify(res));
      process.exitCode = 1;
      return;
    }
    console.log(JSON.stringify(res.value, null, 2));
    return;
  }

  if (cmd === "verify-registration") {
    const raw = flags.file
      ? readFileSync(String(flags.file), "utf8")
      : String(flags.json ?? "{}");
    const att = JSON.parse(raw);
    const res = verifyPlatformRegistration(att);
    if (!res.ok) {
      console.error(JSON.stringify(res));
      process.exitCode = 1;
      return;
    }
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  if (cmd === "revoke-registration") {
    const raw = flags.file
      ? JSON.parse(readFileSync(String(flags.file), "utf8"))
      : String(flags.id ?? "");
    const res = revokePlatformRegistration(raw, String(flags.actor ?? ""));
    if (!res.ok) {
      console.error(JSON.stringify(res));
      process.exitCode = 1;
      return;
    }
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  if (cmd === "sign-request") {
    const seed = seedFromFlag(flags.seed);
    const prefix = String(flags.prefix ?? "ifay");
    const kp = deriveEntityKeypair(seed, prefix, Number(flags.slot ?? 0));
    if (!kp.ok) {
      console.error(JSON.stringify(kp));
      process.exitCode = 1;
      return;
    }
    const method = String(flags.method ?? "POST");
    const url = String(flags.url ?? "/api/action");
    const body = String(flags.body ?? "");
    const headers = signFayIdRequest({
      method,
      url,
      body,
      presenterId: kp.value.entityId,
      signer: kp.value,
    });
    const verifier = createFayIdVerifier();
    const selfCheck = verifier.verifyRequest({ method, url, headers, body });
    console.log(JSON.stringify({ ok: selfCheck.ok, presenterId: kp.value.entityId, headers }, null, 2));
    return;
  }

  printUsage();
  process.exitCode = 1;
}

main();
