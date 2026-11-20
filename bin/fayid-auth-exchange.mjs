#!/usr/bin/env node
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import {
  AuthExchangeVault,
  CREDENTIAL_KINDS,
  createAuthExchangeProxyServer,
  deriveEntityKeypair,
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
  return { cmd: positional[0] ?? "help", flags };
}

function getVaultKey(flags) {
  return String(
    flags["vault-key"] ??
      process.env.FAYID_VAULT_KEY ??
      "fayid-local-vault-example-passphrase",
  );
}

function getVaultPath(flags) {
  return resolve(
    String(flags.vault ?? process.env.FAYID_VAULT_FILE ?? ".fayid-vault.enc.json"),
  );
}

function printUsage() {
  console.log(`fayid-auth-exchange — Local AES-256-GCM Credential Vault & Zero-Leakage HTTP Bridge Proxy

Usage:
  fayid-auth-exchange seal --vault <path> --kind <PASSWORD|OAUTH_TOKEN|API_KEY|CERTIFICATE|SMART_CONTRACT> --resource <https://api.example.com/v1> --secret <value-or-json> [--owner-seed <seed>] [--label <name>]
  fayid-auth-exchange list --vault <path>
  fayid-auth-exchange exchange --vault <path> --credential <cred_...> --target <ifay_...|cofay_...> [--ttl 600] [--scope EXACT|PREFIX]
  fayid-auth-exchange revoke --vault <path> --grant <ag_...|grt_...> [--proxy-url http://127.0.0.1:4770 --admin-token <token>]
  fayid-auth-exchange proxy --vault <path> [--host 127.0.0.1] [--port 4770] [--admin-token <token>]
`);
}

async function main() {
  const { cmd, flags } = parseArgs(process.argv.slice(2));
  if (cmd === "help" || flags.help) {
    printUsage();
    return;
  }

  const vaultPath = getVaultPath(flags);
  const vaultKey = getVaultKey(flags);

  if (cmd === "seal") {
    const vault = AuthExchangeVault.openFile(vaultPath, vaultKey);
    const kind = String(flags.kind ?? CREDENTIAL_KINDS.API_KEY).toUpperCase();
    const ownerSeed = createHash("sha256")
      .update(String(flags["owner-seed"] ?? vaultKey), "utf8")
      .digest();
    const ownerHid = String(
      flags.owner ?? deriveEntityKeypair(ownerSeed, "hid", 0).value.entityId,
    );
    const rawSecret = String(flags.secret ?? "");
    let secretMaterial = rawSecret;
    if (rawSecret.trim().startsWith("{")) {
      try {
        secretMaterial = JSON.parse(rawSecret);
      } catch {
        secretMaterial = rawSecret;
      }
    }

    const res = vault.sealCredential({
      credentialKind: kind,
      label: String(flags.label ?? `${kind.toLowerCase()}-credential`),
      resourceRef: String(flags.resource ?? "https://api.example.com/v1"),
      ownerHumanId: ownerHid,
      secretMaterial,
      injectionPolicy: {
        headerName: flags["header-name"] ? String(flags["header-name"]) : undefined,
        headerScheme: flags["header-scheme"] ? String(flags["header-scheme"]) : undefined,
      },
    });
    if (!res.ok) {
      console.error(JSON.stringify(res));
      process.exitCode = 1;
      return;
    }
    vault.saveToFile(vaultPath);
    console.log(JSON.stringify({ ok: true, vaultPath, credential: res.value }, null, 2));
    return;
  }

  if (cmd === "list") {
    const vault = AuthExchangeVault.openFile(vaultPath, vaultKey);
    console.log(JSON.stringify({ ok: true, credentials: vault.listCredentials() }, null, 2));
    return;
  }

  if (cmd === "exchange") {
    const vault = AuthExchangeVault.openFile(vaultPath, vaultKey);
    const res = vault.exchangeGrant({
      credentialId: String(flags.credential ?? ""),
      targetFayId: String(flags.target ?? ""),
      resourceRef: flags.resource ? String(flags.resource) : undefined,
      scopeMode: String(flags.scope ?? "PREFIX").toUpperCase(),
      ttlSec: flags.ttl ? Number(flags.ttl) : undefined,
    });
    if (!res.ok) {
      console.error(JSON.stringify(res));
      process.exitCode = 1;
      return;
    }
    vault.saveToFile(vaultPath);
    console.log(JSON.stringify({ ok: true, grant: res.value }, null, 2));
    return;
  }

  if (cmd === "revoke") {
    const grantRef = String(flags.grant ?? "");
    if (flags["proxy-url"]) {
      const proxyUrl = String(flags["proxy-url"]).replace(/\/+$/, "");
      const res = await fetch(`${proxyUrl}/grants/revoke`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-fayid-admin-token": String(flags["admin-token"] ?? ""),
        },
        body: JSON.stringify({ grantTicket: grantRef }),
      });
      const json = await res.json();
      console.log(JSON.stringify(json, null, 2));
      if (!res.ok || !json.ok) process.exitCode = 1;
      return;
    }
    const vault = AuthExchangeVault.openFile(vaultPath, vaultKey);
    const res = vault.revokeGrant(grantRef, flags.signer ? String(flags.signer) : undefined);
    if (!res.ok) {
      console.error(JSON.stringify(res));
      process.exitCode = 1;
      return;
    }
    vault.saveToFile(vaultPath);
    console.log(JSON.stringify({ ok: true, revoked: res.value }, null, 2));
    return;
  }

  if (cmd === "proxy") {
    const vault = AuthExchangeVault.openFile(vaultPath, vaultKey);
    const proxy = createAuthExchangeProxyServer({
      vault,
      host: String(flags.host ?? "127.0.0.1"),
      port: Number(flags.port ?? 4770),
      adminToken: flags["admin-token"] ? String(flags["admin-token"]) : undefined,
      requireHolderSignature: Boolean(flags["require-signature"]),
      vaultFilePath: vaultPath,
    });
    const info = await proxy.listen();
    console.log(
      JSON.stringify(
        {
          ok: true,
          service: "fayid-auth-exchange-proxy",
          url: info.url,
          proxyEndpoint: `${info.url}/proxy`,
          sealedCredentials: vault.listCredentials().length,
        },
        null,
        2,
      ),
    );
    const shutdown = async () => {
      await proxy.close();
      process.exit(0);
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
    return;
  }

  printUsage();
  process.exitCode = 1;
}

main();
