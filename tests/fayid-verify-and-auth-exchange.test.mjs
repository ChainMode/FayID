import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  AccountDirectory,
  AuthExchangeVault,
  CREDENTIAL_KINDS,
  MonotonicRevocationList,
  PLATFORM_CATEGORIES,
  PlatformRegistry,
  createAuthExchangeProxyServer,
  createFayIdVerifier,
  deriveBlindGmcRef,
  deriveEntityKeypair,
  issueDynamicPresentation,
  issuePlatformRegistration,
  registrationErrorCodes,
  revokePlatformRegistration,
  signFayIdRequest,
  verifyAuthReceipt,
  verifyErrorCodes,
  verifyPlatformRegistration,
} from "../src/index.mjs";

const ROOT = resolve(import.meta.dirname, "..");

test("Opt-In Platform Registration: stealth by default, dual-signed registration across all 4 categories, plaintext hid_ rejection, and symmetric opt-out", () => {
  const humanSeed = Buffer.alloc(32, 0x31);
  const platformSeed = Buffer.alloc(32, 0x32);

  const human = deriveEntityKeypair(humanSeed, "hid", 0).value;
  const ifay = deriveEntityKeypair(humanSeed, "ifay", 0).value;
  const cofay = deriveEntityKeypair(humanSeed, "cofay", 0).value;

  const registry = new PlatformRegistry();

  // Stealth by default: un-registered iFay and coFay cannot be discovered publicly
  const stealthIfay = registry.resolveDiscoverableSubject(ifay.entityId, { nowSec: 1000 });
  assert.equal(stealthIfay.ok, false);
  assert.equal(stealthIfay.error, registrationErrorCodes.STEALTH_UNREGISTERED);

  // Plaintext hid_ rejected both as subject and inside claims/lookup
  assert.equal(
    registry.resolveDiscoverableSubject(human.entityId).error,
    registrationErrorCodes.HUMAN_ID_PLAINTEXT_FORBIDDEN,
  );

  const realNameOrg = deriveEntityKeypair(platformSeed, "org", "civic-realname").value;
  const expertOrg = deriveEntityKeypair(platformSeed, "org", "expert-guild").value;
  const commerceOrg = deriveEntityKeypair(platformSeed, "org", "artisan-market").value;
  const serviceOrg = deriveEntityKeypair(platformSeed, "org", "cloud-dispatch").value;

  const leakAttempt = issuePlatformRegistration({
    subjectId: human.entityId,
    subjectSigner: human,
    platformId: realNameOrg.entityId,
    platformCategory: PLATFORM_CATEGORIES.REAL_NAME,
    platformSigner: realNameOrg,
  });
  assert.equal(leakAttempt.ok, false);
  assert.equal(leakAttempt.error, registrationErrorCodes.HUMAN_ID_PLAINTEXT_FORBIDDEN);

  const claimLeakAttempt = issuePlatformRegistration({
    subjectId: ifay.entityId,
    subjectSigner: ifay,
    platformId: realNameOrg.entityId,
    platformCategory: PLATFORM_CATEGORIES.REAL_NAME,
    platformSigner: realNameOrg,
    claims: { leakedOwner: human.entityId },
  });
  assert.equal(claimLeakAttempt.ok, false);
  assert.equal(claimLeakAttempt.error, registrationErrorCodes.HUMAN_ID_PLAINTEXT_FORBIDDEN);

  // Issue across REAL_NAME, EXPERT, COMMERCE, SERVICE with blind gmcref_ anchor
  const blindAnchor = deriveBlindGmcRef(human.entityId, Buffer.alloc(16, 0x77)).value;
  const categoriesAndOrgs = [
    [PLATFORM_CATEGORIES.REAL_NAME, realNameOrg, ifay],
    [PLATFORM_CATEGORIES.EXPERT, expertOrg, ifay],
    [PLATFORM_CATEGORIES.COMMERCE, commerceOrg, cofay],
    [PLATFORM_CATEGORIES.SERVICE, serviceOrg, cofay],
  ];

  const issued = [];
  for (const [category, orgSigner, subjSigner] of categoriesAndOrgs) {
    const res = issuePlatformRegistration({
      subjectId: subjSigner.entityId,
      subjectSigner: subjSigner,
      platformId: orgSigner.entityId,
      platformCategory: category,
      platformSigner: orgSigner,
      handle: `@${category.toLowerCase()}-node`,
      scopes: [`scope:${category.toLowerCase()}`],
      claims: { verifiedTier: "tier-1" },
      blindHumanAnchor: blindAnchor,
      issuedAtSec: 1000,
      expiresAtSec: 5000,
      registry,
    });
    assert.equal(res.ok, true);
    assert.ok(!JSON.stringify(res.value).includes(human.entityId));
    issued.push(res.value);

    const ver = verifyPlatformRegistration(res.value, {
      registry,
      requiredCategory: category,
      requiredPlatformId: orgSigner.entityId,
      requiredScopes: [`scope:${category.toLowerCase()}`],
      trustedPlatformKeys: { [orgSigner.entityId]: orgSigner.publicKeyHex },
      nowSec: 2000,
    });
    assert.equal(ver.ok, true);
  }

  // Discoverable after opt-in
  const foundIfay = registry.resolveDiscoverableSubject(ifay.entityId, { nowSec: 2000 });
  assert.equal(foundIfay.ok, true);
  assert.equal(foundIfay.value.registrations.length, 2);

  // Expired check
  const expiredVer = verifyPlatformRegistration(issued[0], { nowSec: 6000 });
  assert.equal(expiredVer.ok, false);
  assert.equal(expiredVer.error, registrationErrorCodes.REGISTRATION_EXPIRED);

  // Symmetric opt-out by iFay & revocation by platform returns subject to stealth
  assert.equal(
    revokePlatformRegistration(issued[0], "ifay_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", { registry }).ok,
    false,
  );
  assert.equal(revokePlatformRegistration(issued[0], ifay.entityId, { registry, nowSec: 2500 }).ok, true);
  assert.equal(revokePlatformRegistration(issued[1], expertOrg.entityId, { registry, nowSec: 2500 }).ok, true);

  const backToStealth = registry.resolveDiscoverableSubject(ifay.entityId, { nowSec: 2600 });
  assert.equal(backToStealth.ok, false);
  assert.equal(backToStealth.error, registrationErrorCodes.STEALTH_UNREGISTERED);

  const afterRevokeVer = verifyPlatformRegistration(issued[0], { registry, nowSec: 2600 });
  assert.equal(afterRevokeVer.ok, false);
  assert.equal(afterRevokeVer.error, registrationErrorCodes.REGISTRATION_REVOKED);
});

test("MonotonicRevocationList: federated signed sync, blind hid_ revocation, and rollback attack rejection", () => {
  const authoritySeed = Buffer.alloc(32, 0x44);
  const authority = deriveEntityKeypair(authoritySeed, "org", "federation-root").value;
  const human = deriveEntityKeypair(Buffer.alloc(32, 0x45), "hid", 0).value;
  const ifay = deriveEntityKeypair(Buffer.alloc(32, 0x45), "ifay", 0).value;

  const sourceList = new MonotonicRevocationList({ initialNowSec: 1000 });
  sourceList.revoke(human.entityId, { reason: "compromised-seed", revokedAtSec: 1010 });
  sourceList.revoke(ifay.entityId, { reason: "cascade", revokedAtSec: 1015 });

  const bundleV2 = sourceList.exportSignedBundle(authority, authority.entityId);
  // Plaintext hid_ never appears in signed revocation bundle!
  assert.ok(!JSON.stringify(bundleV2).includes(human.entityId));
  assert.equal(bundleV2.sequence, 2);

  const replica = new MonotonicRevocationList({ initialNowSec: 1000 });
  const importRes = replica.importBundle(bundleV2, { expectedPublicKeyHex: authority.publicKeyHex });
  assert.equal(importRes.ok, true);
  assert.equal(replica.isRevoked(human.entityId), true);
  assert.equal(replica.isRevoked(ifay.entityId), true);

  // Stale sequence rollback rejected
  const staleBundle = { ...bundleV2, sequence: 1 };
  const tamperedRes = replica.importBundle(staleBundle);
  assert.equal(tamperedRes.ok, false);

  // Omitting an already-revoked entry at higher sequence is rejected
  const maliciousList = new MonotonicRevocationList({ initialNowSec: 2000 });
  maliciousList.revoke(ifay.entityId);
  maliciousList.sequence = 5;
  const maliciousBundle = maliciousList.exportSignedBundle(authority, authority.entityId);
  const rollbackDropRes = replica.importBundle(maliciousBundle, {
    expectedPublicKeyHex: authority.publicKeyHex,
  });
  assert.equal(rollbackDropRes.ok, false);
  assert.equal(rollbackDropRes.error, registrationErrorCodes.REVOCATION_ROLLBACK_REJECTED);
});

test("Verify with FayID middleware: Node HTTP, Express-style next(), Fetch protectFetch, Dynamic Code (dyn_ & dync_), challenge-response, anti-replay, and IDENTITY_REVOKED", async () => {
  const seed = Buffer.alloc(32, 0x61);
  const orgSeed = Buffer.alloc(32, 0x62);
  const human = deriveEntityKeypair(seed, "hid", 0).value;
  const ifay = deriveEntityKeypair(seed, "ifay", 0).value;
  const cofay = deriveEntityKeypair(seed, "cofay", 0).value;
  const commercePlatform = deriveEntityKeypair(orgSeed, "org", "global-bazaar").value;

  const directory = new AccountDirectory({ authoritySecret: Buffer.alloc(32, 0x63) });
  directory.registerHuman(human.entityId);
  directory.registerIFay(ifay.entityId, human.entityId);
  directory.registerCoFay(cofay.entityId, human.entityId, human.entityId);

  const commerceAtt = issuePlatformRegistration({
    subjectId: cofay.entityId,
    subjectSigner: cofay,
    platformId: commercePlatform.entityId,
    platformCategory: PLATFORM_CATEGORIES.COMMERCE,
    platformSigner: commercePlatform,
    handle: "@cofay-merchant",
    scopes: ["merchant:checkout"],
  }).value;

  const verifier = createFayIdVerifier({
    directory,
    trustedPlatformKeys: { [commercePlatform.entityId]: commercePlatform.publicKeyHex },
  });

  // 1. Express-style (req, res, next) HTTP server
  const server = http.createServer((req, res) => {
    verifier(req, res, () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, fayid: req.fayid }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  try {
    // Plaintext hid_ rejected on both client helper and server verifier
    assert.throws(() =>
      signFayIdRequest({
        method: "GET",
        url: "/v1/orders",
        presenterId: human.entityId,
        signer: human,
      }),
    );

    const forgedPlainHid = verifier.verifyRequest({
      method: "GET",
      url: "/v1/orders",
      headers: {
        "x-fayid-presenter": human.entityId,
        "x-fayid-pubkey": human.publicKeyHex,
        "x-fayid-timestamp": String(Math.floor(Date.now() / 1000)),
        "x-fayid-nonce": "nonce-plain-hid",
        "x-fayid-signature": "00".repeat(64),
      },
    });
    assert.equal(forgedPlainHid.ok, false);
    assert.equal(forgedPlainHid.error, verifyErrorCodes.HUMAN_ID_PLAINTEXT_FORBIDDEN);

    // Valid coFay request with COMMERCE platform registration + challenge
    const { challenge } = verifier.createChallenge();
    const payload = JSON.stringify({ orderId: "ord-101" });
    const cofayHeaders = signFayIdRequest({
      method: "POST",
      url: "/v1/orders?fast=1",
      body: payload,
      presenterId: cofay.entityId,
      signer: cofay,
      challenge,
      registrations: [commerceAtt],
    });

    const resp1 = await fetch(`${baseUrl}/v1/orders?fast=1`, {
      method: "POST",
      headers: { "content-type": "application/json", ...cofayHeaders },
      body: payload,
    });
    assert.equal(resp1.status, 200);
    const data1 = await resp1.json();
    assert.equal(data1.fayid.subjectRef, cofay.entityId);
    assert.equal(data1.fayid.registrations[0].platformCategory, "COMMERCE");

    // Replaying exact same signed headers fails closed (challenge/nonce consumed)
    const replayResp = await fetch(`${baseUrl}/v1/orders?fast=1`, {
      method: "POST",
      headers: { "content-type": "application/json", ...cofayHeaders },
      body: payload,
    });
    assert.equal(replayResp.status, 401);

    // Privacy-preserving Dynamic Code (`dync_...`) on Fetch Standard handler (`protectFetch`)
    const fetchProtected = verifier.protectFetch(async (_req, fayidCtx) => {
      return new Response(JSON.stringify({ ok: true, fayidCtx }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    const dynPres = issueDynamicPresentation({
      masterSeed: seed,
      subjectId: human.entityId,
      ttlSec: 120,
      useDyncAlias: true,
      directory,
    }).value;
    assert.match(dynPres.dynamicCode, /^dync_[a-z2-7]+$/);

    const dynHeaders = signFayIdRequest({
      method: "POST",
      url: "https://service.example/api/verify",
      body: '{"check":true}',
      dynamicPresentation: dynPres,
    });
    const fetchRes = await fetchProtected(
      new Request("https://service.example/api/verify", {
        method: "POST",
        headers: dynHeaders,
        body: '{"check":true}',
      }),
    );
    assert.equal(fetchRes.status, 200);
    const fetchJson = await fetchRes.json();
    assert.equal(fetchJson.fayidCtx.presenterKind, "DYNAMIC_CODE");
    assert.match(fetchJson.fayidCtx.subjectRef, /^gmcref_[a-z2-7]+$/);

    // Replaying single-use Dynamic Code with a fresh request signature MUST fail with DYNAMIC_CODE_REPLAYED
    const dynReplayHeaders = signFayIdRequest({
      method: "POST",
      url: "https://service.example/api/verify",
      body: '{"check":true}',
      dynamicPresentation: dynPres,
    });
    const fetchReplayRes = await fetchProtected(
      new Request("https://service.example/api/verify", {
        method: "POST",
        headers: dynReplayHeaders,
        body: '{"check":true}',
      }),
    );
    assert.equal(fetchReplayRes.status, 401);
    const fetchReplayJson = await fetchReplayRes.json();
    assert.equal(fetchReplayJson.error, "DYNAMIC_CODE_REPLAYED");

    // Revoking Human Prime cascades to iFay & coFay -> returns HTTP 403 IDENTITY_REVOKED
    directory.revokeEntity(human.entityId, human.entityId);
    const afterRevokeHeaders = signFayIdRequest({
      method: "GET",
      url: "/v1/orders",
      presenterId: ifay.entityId,
      signer: ifay,
    });
    const revHttpRes = await fetch(`${baseUrl}/v1/orders`, { headers: afterRevokeHeaders });
    assert.equal(revHttpRes.status, 403);
    const revHttpJson = await revHttpRes.json();
    assert.equal(revHttpJson.error, "IDENTITY_REVOKED");
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test("Auth Exchange Local AES-256-GCM Vault & HTTP Credential Bridge Proxy: all 5 credential types, zero raw secret leakage, encrypted disk persistence, and instant revokeGrant", async () => {
  const tempDir = mkdtempSync(join(tmpdir(), "fayid-vault-test-"));
  const vaultFile = join(tempDir, "vault.enc.json");

  const seed = Buffer.alloc(32, 0x71);
  const human = deriveEntityKeypair(seed, "hid", 0).value;
  const ifay = deriveEntityKeypair(seed, "ifay", 0).value;

  const receivedUpstreamHeaders = [];
  const upstreamServer = http.createServer(async (req, res) => {
    receivedUpstreamHeaders.push({ url: req.url, headers: { ...req.headers } });
    res.writeHead(200, {
      "content-type": "application/json",
      "x-api-key": "should-be-stripped-by-proxy-example",
    });
    res.end(JSON.stringify({ ok: true, path: req.url }));
  });
  await new Promise((r) => upstreamServer.listen(0, "127.0.0.1", r));
  const upstreamOrigin = `http://127.0.0.1:${upstreamServer.address().port}`;

  let bridge = null;
  try {
    const vault = new AuthExchangeVault({ vaultMasterKey: "unit-test-vault-key-example" });

    const sentinelApiKey = "sentinel-api-secret-example-value-991";
    const sentinelPassword = "sentinel-basic-password-example-992";
    const sentinelOauth = "sentinel-oauth-token-example-993";
    const sentinelCert = "CERT-BODY-EXAMPLE-994";
    const sentinelContract = "contract-signing-seed-example-995";

    const cApi = vault.sealCredential({
      credentialKind: CREDENTIAL_KINDS.API_KEY,
      resourceRef: `${upstreamOrigin}/api`,
      ownerHumanId: human.entityId,
      secretMaterial: { apiKey: sentinelApiKey },
    }).value;
    const cPass = vault.sealCredential({
      credentialKind: CREDENTIAL_KINDS.PASSWORD,
      resourceRef: `${upstreamOrigin}/legacy-basic`,
      ownerHumanId: human.entityId,
      secretMaterial: { username: "alice", password: sentinelPassword },
    }).value;
    const cOauth = vault.sealCredential({
      credentialKind: CREDENTIAL_KINDS.OAUTH_TOKEN,
      resourceRef: `${upstreamOrigin}/oauth`,
      ownerHumanId: human.entityId,
      secretMaterial: { accessToken: sentinelOauth },
    }).value;
    const cCert = vault.sealCredential({
      credentialKind: CREDENTIAL_KINDS.CERTIFICATE,
      resourceRef: `${upstreamOrigin}/mtls`,
      ownerHumanId: human.entityId,
      secretMaterial: { certPem: sentinelCert },
    }).value;
    const cWeb3 = vault.sealCredential({
      credentialKind: CREDENTIAL_KINDS.SMART_CONTRACT,
      resourceRef: `${upstreamOrigin}/rpc`,
      ownerHumanId: human.entityId,
      secretMaterial: { chainId: "8453", contractAddress: "0xabc123", sessionPrivateKey: sentinelContract },
    }).value;

    // Persist encrypted vault to disk and confirm ZERO plaintext secrets or hid_ in ciphertext file!
    vault.saveToFile(vaultFile);
    const rawDiskText = readFileSync(vaultFile, "utf8");
    for (const secretStr of [
      sentinelApiKey,
      sentinelPassword,
      sentinelOauth,
      sentinelCert,
      sentinelContract,
      human.entityId,
    ]) {
      assert.ok(!rawDiskText.includes(secretStr), `Vault file leaked ${secretStr}`);
    }

    // Wrong passphrase fails AES-256-GCM authentication tag verification
    assert.throws(() => AuthExchangeVault.openFile(vaultFile, "wrong-passphrase-example"));

    // Reopen from disk and issue grants for all 5 credential types
    const reopenedVault = AuthExchangeVault.openFile(vaultFile, "unit-test-vault-key-example");
    assert.equal(reopenedVault.listCredentials().length, 5);

    const gApi = reopenedVault.exchangeGrant({
      credentialId: cApi.credentialId,
      targetFayId: ifay.entityId,
      scopeMode: "PREFIX",
      ttlSec: 300,
    }).value;
    const gPass = reopenedVault.exchangeGrant({
      credentialId: cPass.credentialId,
      targetFayId: ifay.entityId,
      scopeMode: "PREFIX",
      ttlSec: 300,
    }).value;
    const gOauth = reopenedVault.exchangeGrant({
      credentialId: cOauth.credentialId,
      targetFayId: ifay.entityId,
      scopeMode: "PREFIX",
      ttlSec: 300,
    }).value;
    const gCert = reopenedVault.exchangeGrant({
      credentialId: cCert.credentialId,
      targetFayId: ifay.entityId,
      scopeMode: "PREFIX",
      ttlSec: 300,
    }).value;
    const gWeb3 = reopenedVault.exchangeGrant({
      credentialId: cWeb3.credentialId,
      targetFayId: ifay.entityId,
      scopeMode: "PREFIX",
      ttlSec: 300,
    }).value;

    assert.match(gApi.grantTicket, /^ag_[a-z2-7]+$/);
    assert.match(gApi.grantId, /^grt_[a-z2-7]+$/);

    // Low-trust PASSWORD > 900s rejected
    assert.equal(
      reopenedVault.exchangeGrant({
        credentialId: cPass.credentialId,
        targetFayId: ifay.entityId,
        ttlSec: 1800,
      }).ok,
      false,
    );

    bridge = createAuthExchangeProxyServer({
      vault: reopenedVault,
      requireHolderSignature: true,
    });
    const bridgeInfo = await bridge.listen();

    async function callViaProxy(grantTicketOrId, targetPath, method = "GET", body = "") {
      const signedHeaders = signFayIdRequest({
        method,
        url: "/proxy",
        body,
        presenterId: ifay.entityId,
        signer: ifay,
      });
      return fetch(`${bridgeInfo.url}/proxy`, {
        method,
        headers: {
          authorization: `Bearer ${grantTicketOrId}`,
          "x-fayid-target-url": `${upstreamOrigin}${targetPath}`,
          ...signedHeaders,
        },
        body: method === "GET" ? undefined : body,
      });
    }

    const r1 = await callViaProxy(gApi.grantTicket, "/api/items");
    assert.equal(r1.status, 200);
    // Proxy strips upstream reflected sensitive headers and attaches valid vrf_ receipt
    assert.equal(r1.headers.get("x-api-key"), null);
    const receipt1 = JSON.parse(
      Buffer.from(r1.headers.get("x-fayid-verification-receipt"), "base64url").toString("utf8"),
    );
    assert.equal(verifyAuthReceipt(receipt1), true);
    assert.equal(receivedUpstreamHeaders[0].headers["x-api-key"], sentinelApiKey);
    assert.equal(receivedUpstreamHeaders[0].headers["authorization"], undefined);

    const r2 = await callViaProxy(gPass.grantId, "/legacy-basic/login");
    assert.equal(r2.status, 200);
    assert.equal(
      receivedUpstreamHeaders[1].headers["authorization"],
      `Basic ${Buffer.from(`alice:${sentinelPassword}`).toString("base64")}`,
    );

    const r3 = await callViaProxy(gOauth.grantTicket, "/oauth/userinfo");
    assert.equal(r3.status, 200);
    assert.equal(receivedUpstreamHeaders[2].headers["authorization"], `Bearer ${sentinelOauth}`);

    const r4 = await callViaProxy(gCert.grantTicket, "/mtls/enroll");
    assert.equal(r4.status, 200);
    assert.equal(receivedUpstreamHeaders[3].headers["x-client-cert-bound"], "mtls-vault-sealed");

    const r5 = await callViaProxy(gWeb3.grantTicket, "/rpc/call", "POST", '{"method":"eth_call"}');
    assert.equal(r5.status, 200);
    assert.equal(receivedUpstreamHeaders[4].headers["x-web3-chain-id"], "8453");
    assert.match(receivedUpstreamHeaders[4].headers["x-web3-call-intent-sig"], /^0x[0-9a-f]{64}$/);

    // Out-of-scope target URL rejected with 401 GRANT_INVALID
    const outScope = await callViaProxy(gApi.grantTicket, "/oauth/userinfo");
    assert.equal(outScope.status, 401);

    // Instant revokeGrant via live proxy admin endpoint -> immediately blocks with 403 GRANT_REVOKED
    const revHttp = await fetch(`${bridgeInfo.url}/grants/revoke`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-fayid-admin-token": bridgeInfo.adminToken,
      },
      body: JSON.stringify({ grantTicket: gApi.grantTicket }),
    });
    assert.equal(revHttp.status, 200);

    const afterRevoke = await callViaProxy(gApi.grantTicket, "/api/items");
    assert.equal(afterRevoke.status, 403);
    const afterRevokeJson = await afterRevoke.json();
    assert.equal(afterRevokeJson.error, "GRANT_REVOKED");
  } finally {
    if (bridge) await bridge.close();
    await new Promise((r) => upstreamServer.close(r));
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test("CLI binaries (fayid-cli.mjs & fayid-auth-exchange.mjs): end-to-end execution", () => {
  const tempDir = mkdtempSync(join(tmpdir(), "fayid-cli-test-"));
  const vaultFile = join(tempDir, "cli-vault.enc.json");
  try {
    const keygenOut = JSON.parse(
      execFileSync(
        process.execPath,
        [join(ROOT, "bin/fayid-cli.mjs"), "keygen", "--prefix", "ifay", "--seed", "cli-example-seed"],
        { encoding: "utf8" },
      ),
    );
    assert.equal(keygenOut.ok, true);
    assert.match(keygenOut.entityId, /^ifay_[a-z2-7]+$/);

    const dynOut = JSON.parse(
      execFileSync(
        process.execPath,
        [join(ROOT, "bin/fayid-cli.mjs"), "dynamic-code", "--seed", "cli-example-seed", "--dync"],
        { encoding: "utf8" },
      ),
    );
    assert.equal(dynOut.ok, true);
    assert.match(dynOut.dynamicCode, /^dync_[a-z2-7]+$/);

    const sealOut = JSON.parse(
      execFileSync(
        process.execPath,
        [
          join(ROOT, "bin/fayid-auth-exchange.mjs"),
          "seal",
          "--vault",
          vaultFile,
          "--kind",
          "OAUTH_TOKEN",
          "--resource",
          "https://api.example.com/v1",
          "--secret",
          "cli-oauth-example-token",
        ],
        { encoding: "utf8" },
      ),
    );
    assert.equal(sealOut.ok, true);

    const exchOut = JSON.parse(
      execFileSync(
        process.execPath,
        [
          join(ROOT, "bin/fayid-auth-exchange.mjs"),
          "exchange",
          "--vault",
          vaultFile,
          "--credential",
          sealOut.credential.credentialId,
          "--target",
          keygenOut.entityId,
        ],
        { encoding: "utf8" },
      ),
    );
    assert.equal(exchOut.ok, true);
    assert.match(exchOut.grant.grantTicket, /^ag_[a-z2-7]+$/);

    const revOut = JSON.parse(
      execFileSync(
        process.execPath,
        [
          join(ROOT, "bin/fayid-auth-exchange.mjs"),
          "revoke",
          "--vault",
          vaultFile,
          "--grant",
          exchOut.grant.grantTicket,
        ],
        { encoding: "utf8" },
      ),
    );
    assert.equal(revOut.ok, true);
    assert.equal(revOut.revoked.state, "REVOKED");
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});
