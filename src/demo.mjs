import http from "node:http";
import {
  AuthExchangeVault,
  CREDENTIAL_KINDS,
  PLATFORM_CATEGORIES,
  PlatformRegistry,
  createAuthExchangeProxyServer,
  createFayIdVerifier,
  deriveBlindGmcRef,
  deriveEntityKeypair,
  issueDynamicPresentation,
  issuePlatformRegistration,
  revokePlatformRegistration,
  signFayIdRequest,
  verifyAuthReceipt,
} from "./index.mjs";

async function main() {
  console.log("=== FayID Developer Integration Kit & Auth Exchange Live Demo ===\n");

  const humanSeed = Buffer.alloc(32, 0x17);
  const platformSeed = Buffer.alloc(32, 0x28);

  const human = deriveEntityKeypair(humanSeed, "hid", 0).value;
  const ifay = deriveEntityKeypair(humanSeed, "ifay", 0).value;
  const expertPlatform = deriveEntityKeypair(platformSeed, "org", "medical-expert-board").value;

  // 1. Stealth-by-default & Opt-In Platform Registration
  const registry = new PlatformRegistry();
  const stealthBefore = registry.resolveDiscoverableSubject(ifay.entityId);
  console.log(`[1] Stealth by default before opt-in: ${stealthBefore.error}`);

  const blindAnchor = deriveBlindGmcRef(human.entityId, Buffer.alloc(16, 0x55)).value;
  const regAttestation = issuePlatformRegistration({
    subjectId: ifay.entityId,
    subjectSigner: ifay,
    platformId: expertPlatform.entityId,
    platformCategory: PLATFORM_CATEGORIES.EXPERT,
    platformSigner: expertPlatform,
    handle: "@dr-ifay-cardio",
    scopes: ["consult:cardiology"],
    blindHumanAnchor: blindAnchor,
    registry,
  }).value;
  console.log(
    `[2] Opt-In Platform Registration issued: ${regAttestation.registrationId} on ${regAttestation.platformId} (${regAttestation.platformCategory})`,
  );

  // 2. Verify with FayID (5-line drop-in HTTP middleware)
  const verifyFayId = createFayIdVerifier({
    platformRegistry: registry,
    trustedPlatformKeys: { [expertPlatform.entityId]: expertPlatform.publicKeyHex },
  });

  const appServer = http.createServer(async (req, res) => {
    const auth = await verifyFayId(req, res);
    if (!auth.ok) return;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, caller: req.fayid }));
  });
  await new Promise((r) => appServer.listen(0, "127.0.0.1", r));
  const appPort = appServer.address().port;
  const appBase = `http://127.0.0.1:${appPort}`;

  // 2a. iFay Holder-of-Key + Platform Registration verification
  const bodyStr = JSON.stringify({ query: "second-opinion" });
  const ifayHeaders = signFayIdRequest({
    method: "POST",
    url: "/api/consult",
    body: bodyStr,
    presenterId: ifay.entityId,
    signer: ifay,
    registrations: [regAttestation],
  });
  const resIfay = await fetch(`${appBase}/api/consult`, {
    method: "POST",
    headers: { "content-type": "application/json", ...ifayHeaders },
    body: bodyStr,
  });
  const jsonIfay = await resIfay.json();
  console.log(
    `[3] Verify with FayID (iFay + EXPERT attestation): HTTP ${resIfay.status} presenter=${jsonIfay.caller.subjectRef}`,
  );

  // 2b. Human Prime privacy-preserving Dynamic Code (`dync_...`) without exposing plaintext hid_
  const dynPres = issueDynamicPresentation({
    masterSeed: humanSeed,
    subjectId: human.entityId,
    ttlSec: 180,
    useDyncAlias: true,
  }).value;
  const dynHeaders = signFayIdRequest({
    method: "GET",
    url: "/api/me",
    dynamicPresentation: dynPres,
  });
  const resDyn = await fetch(`${appBase}/api/me`, { headers: dynHeaders });
  const jsonDyn = await resDyn.json();
  console.log(
    `[4] Verify with FayID (Privacy Dynamic Code ${dynPres.dynamicCode}): HTTP ${resDyn.status} blindRef=${jsonDyn.caller.subjectRef.slice(0, 22)}... (hid_ hidden!)`,
  );

  // 2c. Opt-out registration & monotonic entity revocation
  revokePlatformRegistration(regAttestation, ifay.entityId, { registry });
  console.log(
    `[5] Opt-Out back to stealth: discoverable=${registry.resolveDiscoverableSubject(ifay.entityId).error}`,
  );
  verifyFayId.revocationList.revoke(ifay.entityId, { reason: "demo-revocation" });
  const revokedHeaders = signFayIdRequest({
    method: "GET",
    url: "/api/consult",
    presenterId: ifay.entityId,
    signer: ifay,
  });
  const resRevoked = await fetch(`${appBase}/api/consult`, { headers: revokedHeaders });
  const jsonRevoked = await resRevoked.json();
  console.log(
    `[6] Monotonic revocation enforced: HTTP ${resRevoked.status} error=${jsonRevoked.error}`,
  );

  // 3. Auth Exchange Local AES-256-GCM Credential Vault & HTTP Bridge Proxy
  let upstreamObservedApiKey = null;
  const upstreamServer = http.createServer((req, res) => {
    upstreamObservedApiKey = req.headers["x-api-key"] ?? null;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        ok: true,
        upstreamAuthenticated: Boolean(upstreamObservedApiKey),
        data: "confidential-portfolio-summary",
      }),
    );
  });
  await new Promise((r) => upstreamServer.listen(0, "127.0.0.1", r));
  const upstreamUrl = `http://127.0.0.1:${upstreamServer.address().port}/v1/portfolio`;

  const vault = new AuthExchangeVault({ vaultMasterKey: "demo-vault-passphrase-example" });
  const activeIfay = deriveEntityKeypair(humanSeed, "ifay", 1).value;
  const sealed = vault.sealCredential({
    credentialKind: CREDENTIAL_KINDS.API_KEY,
    label: "upstream-broker-key",
    resourceRef: upstreamUrl,
    ownerHumanId: human.entityId,
    secretMaterial: { apiKey: "example-upstream-secret-token-never-seen-by-ifay" },
  }).value;

  const grant = vault.exchangeGrant({
    credentialId: sealed.credentialId,
    targetFayId: activeIfay.entityId,
    scopeMode: "EXACT",
    ttlSec: 300,
  }).value;

  const bridge = createAuthExchangeProxyServer({ vault });
  const bridgeInfo = await bridge.listen();

  const proxyRes = await fetch(`${bridgeInfo.url}/proxy`, {
    method: "GET",
    headers: {
      authorization: `Bearer ${grant.grantTicket}`,
      "x-fayid-target-url": upstreamUrl,
    },
  });
  const proxyJson = await proxyRes.json();
  const receiptJson = JSON.parse(
    Buffer.from(proxyRes.headers.get("x-fayid-verification-receipt"), "base64url").toString("utf8"),
  );
  console.log(
    `[7] Auth Exchange Bridge Proxy (${grant.grantTicket}): HTTP ${proxyRes.status} upstreamAuthenticated=${proxyJson.upstreamAuthenticated} receiptValid=${verifyAuthReceipt(receiptJson)}`,
  );

  // Instant grant revocation
  vault.revokeGrant(grant.grantTicket);
  const afterRevokeRes = await fetch(`${bridgeInfo.url}/proxy`, {
    method: "GET",
    headers: {
      authorization: `Bearer ${grant.grantTicket}`,
      "x-fayid-target-url": upstreamUrl,
    },
  });
  const afterRevokeJson = await afterRevokeRes.json();
  console.log(
    `[8] Instant revokeGrant enforced: HTTP ${afterRevokeRes.status} error=${afterRevokeJson.error}\n`,
  );

  await bridge.close();
  await new Promise((r) => upstreamServer.close(r));
  await new Promise((r) => appServer.close(r));
  console.log("All FayID demo steps completed cleanly.");
}

main();
