import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import { dirname } from "node:path";
import {
  baselineLimits,
  err,
  errorCodes,
  matchesResourceRef,
  normalizeResourceRef,
  ok,
} from "../schema/draft/testkit/reference/fayid.js";
import {
  AccountDirectory,
  accountErrorCodes,
  base32EncodeNoPad,
  canonicalizeJcs,
  parseCanonicalFayID,
} from "./fayid-toolkit.mjs";
import { matchesSelfCertifyingPublicKey } from "./platform-registration.mjs";
import { HTTP_AUTH_DOMAIN } from "./verify-with-fayid.mjs";

export const CREDENTIAL_KINDS = Object.freeze({
  PASSWORD: "PASSWORD",
  OAUTH_TOKEN: "OAUTH_TOKEN",
  API_KEY: "API_KEY",
  CERTIFICATE: "CERTIFICATE",
  SMART_CONTRACT: "SMART_CONTRACT",
});

const KIND_TO_LEGACY_SOURCE = Object.freeze({
  PASSWORD: "PASSWORD",
  OAUTH_TOKEN: "ACCESS_TOKEN",
  API_KEY: "AUTHORIZATION",
  CERTIFICATE: "CERTIFICATE",
  SMART_CONTRACT: "SMART_CONTRACT",
});

const KIND_TRUST_LEVEL = Object.freeze({
  PASSWORD: "LOW",
  OAUTH_TOKEN: "MEDIUM",
  API_KEY: "MEDIUM",
  CERTIFICATE: "HIGH",
  SMART_CONTRACT: "HIGH",
});

function deriveAes256Key(masterSecret, saltBuf) {
  if (Buffer.isBuffer(masterSecret) || masterSecret instanceof Uint8Array) {
    const raw = Buffer.from(masterSecret);
    if (raw.length === 32 && saltBuf.length === 0) return Buffer.from(raw);
    return Buffer.from(
      hkdfSync("sha256", raw, saltBuf, Buffer.from("ifay.fayid.vault-aes256gcm.v1", "utf8"), 32),
    );
  }
  return scryptSync(String(masterSecret), saltBuf, 32);
}

/**
 * Normalizes either an `ag_<base32>` Authorization Grant ticket or canonical `grt_<base32>` grant ID
 * into canonical `grt_<base32>` + `ag_<base32>` pair.
 * @param {string} grantOrTicket
 */
export function normalizeGrantIdentifier(grantOrTicket) {
  if (typeof grantOrTicket !== "string" || grantOrTicket.trim().length === 0) {
    return err(errorCodes.GRANT_INVALID);
  }
  const lower = grantOrTicket.trim().toLowerCase();
  if (lower.startsWith("ag_")) {
    const body = lower.slice("ag_".length);
    if (!/^[a-z2-7]{16,64}$/.test(body)) {
      return err(errorCodes.GRANT_INVALID);
    }
    return ok({ grantId: `grt_${body}`, grantTicket: `ag_${body}`, body });
  }
  const parsed = parseCanonicalFayID(lower);
  if (!parsed.ok || parsed.value.kind !== "AUTHORIZATION_GRANT") {
    return err(errorCodes.GRANT_INVALID);
  }
  const body = parsed.value.value.slice("grt_".length);
  return ok({ grantId: parsed.value.value, grantTicket: `ag_${body}`, body });
}

/**
 * Local Encrypted `Auth Exchange` Credential Vault (`AES-256-GCM`).
 *
 * Seals legacy credentials (`PASSWORD`, `OAUTH_TOKEN`, `API_KEY`, `CERTIFICATE`, `SMART_CONTRACT`)
 * so an `iFay` or `coFay` NEVER sees raw passwords, OAuth tokens, or API keys — receiving only
 * time-bounded, scoped, instantly revocable `Authorization Grant` tickets (`ag_...` / `grt_...`).
 */
export class AuthExchangeVault {
  constructor(options = {}) {
    const rawSecret = options.vaultMasterKey ?? randomBytes(32);
    this._vaultSalt = options.vaultSalt
      ? Buffer.from(options.vaultSalt)
      : randomBytes(16);
    this._aesKey = deriveAes256Key(rawSecret, this._vaultSalt);
    this._authoritySecret = Buffer.from(
      hkdfSync(
        "sha256",
        this._aesKey,
        this._vaultSalt,
        Buffer.from("ifay.fayid.vault-authority.v1", "utf8"),
        32,
      ),
    );
    this.directory =
      options.directory ?? new AccountDirectory({ authoritySecret: this._authoritySecret });

    this._sealedCredentials = new Map();
    this._grantBindings = new Map();
  }

  _encryptRecord(aadStr, secretObject) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this._aesKey, iv);
    cipher.setAAD(Buffer.from(aadStr, "utf8"));
    const plaintextBuf = Buffer.from(JSON.stringify(secretObject), "utf8");
    const ciphertext = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
    plaintextBuf.fill(0);
    const authTag = cipher.getAuthTag();
    return {
      cipherAlg: "AES-256-GCM",
      ivHex: iv.toString("hex"),
      authTagHex: authTag.toString("hex"),
      ciphertextHex: ciphertext.toString("hex"),
    };
  }

  _decryptRecord(aadStr, encryptedEnvelope) {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this._aesKey,
      Buffer.from(encryptedEnvelope.ivHex, "hex"),
    );
    decipher.setAAD(Buffer.from(aadStr, "utf8"));
    decipher.setAuthTag(Buffer.from(encryptedEnvelope.authTagHex, "hex"));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedEnvelope.ciphertextHex, "hex")),
      decipher.final(),
    ]);
    try {
      return JSON.parse(decrypted.toString("utf8"));
    } finally {
      decrypted.fill(0);
    }
  }

  _ensureEntitiesRegistered(ownerHumanId, targetFayId) {
    if (ownerHumanId) {
      const pOwner = parseCanonicalFayID(ownerHumanId);
      if (pOwner.ok && pOwner.value.kind === "HUMAN_ID" && !this.directory.humans.has(pOwner.value.value)) {
        this.directory.registerHuman(pOwner.value.value);
      }
    }
    if (targetFayId && ownerHumanId) {
      const pTarget = parseCanonicalFayID(targetFayId);
      if (pTarget.ok && pTarget.value.kind === "IFAY_ID" && !this.directory.ifays.has(pTarget.value.value)) {
        this.directory.registerIFay(pTarget.value.value, ownerHumanId);
      } else if (
        pTarget.ok &&
        pTarget.value.kind === "COFAY_ID" &&
        !this.directory.cofays.has(pTarget.value.value)
      ) {
        this.directory.registerCoFay(pTarget.value.value, ownerHumanId, ownerHumanId);
      }
    }
  }

  /**
   * Seals a legacy credential inside the `AES-256-GCM` vault.
   * Returns safe metadata ONLY (never returns `secretMaterial`).
   */
  sealCredential({
    credentialKind,
    label = "sealed-credential",
    resourceRef,
    issuer = "upstream",
    subject = "holder",
    ownerHumanId,
    secretMaterial,
    injectionPolicy = {},
    createdAtSec = Math.floor(Date.now() / 1000),
  }) {
    if (!KIND_TO_LEGACY_SOURCE[credentialKind]) {
      return err(errorCodes.LEGACY_AUTH_FAILED);
    }
    const normRes = normalizeResourceRef(resourceRef);
    if (!normRes.ok) return normRes;

    const pOwner = parseCanonicalFayID(ownerHumanId);
    if (!pOwner.ok || pOwner.value.kind !== "HUMAN_ID") {
      return err(errorCodes.HUMAN_ID_OWNERSHIP_NOT_PROVEN);
    }
    if (!secretMaterial || (typeof secretMaterial !== "object" && typeof secretMaterial !== "string")) {
      return err(errorCodes.LEGACY_AUTH_FAILED);
    }

    this._ensureEntitiesRegistered(pOwner.value.value, null);

    const normalizedSecret =
      typeof secretMaterial === "string" ? { value: secretMaterial } : { ...secretMaterial };

    const credIdBytes = createHash("sha256")
      .update(`cred:${credentialKind}:${normRes.value}:${randomBytes(16).toString("hex")}`, "utf8")
      .digest();
    const credentialId = `cred_${base32EncodeNoPad(credIdBytes.subarray(0, 16))}`;
    const aad = `${credentialId}|${credentialKind}|${normRes.value}|${pOwner.value.value}`;
    const encrypted = this._encryptRecord(aad, normalizedSecret);

    const record = {
      credentialId,
      credentialKind,
      trustLevel: KIND_TRUST_LEVEL[credentialKind],
      label: String(label),
      resourceRef: normRes.value,
      issuer: String(issuer).replace(/:/g, "-"),
      subject: String(subject),
      ownerHumanId: pOwner.value.value,
      injectionPolicy: {
        headerName: injectionPolicy.headerName ?? null,
        headerScheme: injectionPolicy.headerScheme ?? null,
      },
      createdAtSec,
      encrypted,
    };

    this._sealedCredentials.set(credentialId, record);

    return ok({
      credentialId,
      credentialKind,
      trustLevel: record.trustLevel,
      label: record.label,
      resourceRef: record.resourceRef,
      cipherAlg: "AES-256-GCM",
      createdAtSec,
    });
  }

  /**
   * Lists sealed credentials without ever exposing plaintext secret material or owner plaintext `hid_`.
   */
  listCredentials() {
    const out = [];
    for (const rec of this._sealedCredentials.values()) {
      out.push({
        credentialId: rec.credentialId,
        credentialKind: rec.credentialKind,
        trustLevel: rec.trustLevel,
        label: rec.label,
        resourceRef: rec.resourceRef,
        cipherAlg: rec.encrypted.cipherAlg,
        createdAtSec: rec.createdAtSec,
      });
    }
    return out;
  }

  /**
   * Exchanges a sealed credential for a time-bounded, scoped `Authorization Grant` ticket (`ag_...` & `grt_...`).
   */
  exchangeGrant({
    credentialId,
    targetFayId,
    actorId = null,
    resourceRef = null,
    scopeMode = "PREFIX",
    ttlSec = null,
    issuedAtSec = Math.floor(Date.now() / 1000),
  }) {
    const cred = this._sealedCredentials.get(credentialId);
    if (!cred) {
      return err(errorCodes.GRANT_INVALID);
    }

    const pTarget = parseCanonicalFayID(targetFayId);
    if (
      !pTarget.ok ||
      (pTarget.value.kind !== "IFAY_ID" && pTarget.value.kind !== "COFAY_ID")
    ) {
      return err(errorCodes.MALFORMED_FAYID_STRING);
    }

    this._ensureEntitiesRegistered(cred.ownerHumanId, pTarget.value.value);

    const maxAllowedTtl =
      cred.trustLevel === "LOW"
        ? baselineLimits.LOW_TRUST_GRANT_MAX_TTL_SECONDS
        : baselineLimits.GRANT_MAX_TTL_SECONDS;
    const effectiveTtl = ttlSec ?? Math.min(600, maxAllowedTtl);

    const effectiveResource = resourceRef ?? cred.resourceRef;
    if (!matchesResourceRef(cred.resourceRef, effectiveResource, "PREFIX")) {
      return err(errorCodes.GRANT_INVALID);
    }

    const grantRes = this.directory.issueAuthGrant({
      targetId: pTarget.value.value,
      actorId: actorId ?? cred.ownerHumanId,
      resourceRef: effectiveResource,
      scopeMode,
      legacySourceKind: KIND_TO_LEGACY_SOURCE[cred.credentialKind],
      legacyIssuer: cred.issuer,
      legacySubject: cred.subject,
      issuedAtSec,
      expiresAtSec: issuedAtSec + effectiveTtl,
    });
    if (!grantRes.ok) return grantRes;

    const grantId = grantRes.value.grantId;
    const grantTicket = `ag_${grantId.slice("grt_".length)}`;

    this._grantBindings.set(grantId, {
      credentialId: cred.credentialId,
      targetFayId: pTarget.value.value,
      grantTicket,
    });

    return ok({
      grantTicket,
      grantId,
      targetFayId: pTarget.value.value,
      credentialId: cred.credentialId,
      credentialKind: cred.credentialKind,
      trustLevel: cred.trustLevel,
      resourceRef: grantRes.value.resourceRef,
      scopeMode: grantRes.value.scopeMode,
      issuedAtSec: grantRes.value.issuedAtSec,
      expiresAtSec: grantRes.value.expiresAtSec,
      signatureHex: grantRes.value.signatureHex,
      issuerPublicKeyHex: grantRes.value.issuerPublicKeyHex,
    });
  }

  /**
   * Instantly revokes an `ag_...` or `grt_...` Authorization Grant.
   */
  revokeGrant(grantOrTicket, signerId = null) {
    const norm = normalizeGrantIdentifier(grantOrTicket);
    if (!norm.ok) return norm;
    const binding = this._grantBindings.get(norm.value.grantId);
    const cred = binding ? this._sealedCredentials.get(binding.credentialId) : null;
    const effectiveSigner = signerId ?? cred?.ownerHumanId ?? binding?.targetFayId ?? "";
    const res = this.directory.revokeGrant(norm.value.grantId, effectiveSigner);
    if (!res.ok) return res;
    return ok({
      grantTicket: norm.value.grantTicket,
      grantId: norm.value.grantId,
      state: res.value.state,
      statusVersion: res.value.statusVersion,
    });
  }

  /**
   * Internal proxy-only operation: verifies the `ag_...` / `grt_...` grant for `requestedResourceRef`
   * and produces the injected upstream HTTP headers + signed `vrf_...` receipt without ever returning
   * raw secret material to the calling `iFay`.
   */
  resolveUpstreamAuthForProxy({
    grantOrTicket,
    requestedResourceRef,
    method = "GET",
    bodyBytes = Buffer.alloc(0),
    nowSec = Math.floor(Date.now() / 1000),
  }) {
    const norm = normalizeGrantIdentifier(grantOrTicket);
    if (!norm.ok) return norm;

    const binding = this._grantBindings.get(norm.value.grantId);
    if (!binding) {
      return err(errorCodes.GRANT_INVALID);
    }

    const verifyRes = this.directory.verifyAuthGrant({
      grantId: norm.value.grantId,
      requestedResourceRef,
      nowSec,
    });
    if (!verifyRes.ok) return verifyRes;

    const cred = this._sealedCredentials.get(binding.credentialId);
    if (!cred) {
      return err(errorCodes.GRANT_INVALID);
    }

    const aad = `${cred.credentialId}|${cred.credentialKind}|${cred.resourceRef}|${cred.ownerHumanId}`;
    let secret;
    try {
      secret = this._decryptRecord(aad, cred.encrypted);
    } catch {
      return err(errorCodes.LEGACY_AUTH_FAILED);
    }

    const injectedHeaders = {};
    try {
      switch (cred.credentialKind) {
        case CREDENTIAL_KINDS.API_KEY: {
          const apiKeyVal = String(secret.apiKey ?? secret.value ?? "");
          const headerName = (cred.injectionPolicy.headerName ?? "x-api-key").toLowerCase();
          const scheme = cred.injectionPolicy.headerScheme;
          injectedHeaders[headerName] = scheme ? `${scheme} ${apiKeyVal}` : apiKeyVal;
          break;
        }
        case CREDENTIAL_KINDS.OAUTH_TOKEN: {
          const tokenVal = String(secret.accessToken ?? secret.oauthToken ?? secret.value ?? "");
          const headerName = (cred.injectionPolicy.headerName ?? "authorization").toLowerCase();
          const scheme = cred.injectionPolicy.headerScheme ?? "Bearer";
          injectedHeaders[headerName] = `${scheme} ${tokenVal}`;
          break;
        }
        case CREDENTIAL_KINDS.PASSWORD: {
          const username = String(secret.username ?? cred.subject ?? "user");
          const password = String(secret.password ?? secret.value ?? "");
          const basic = Buffer.from(`${username}:${password}`, "utf8").toString("base64");
          injectedHeaders["authorization"] = `Basic ${basic}`;
          break;
        }
        case CREDENTIAL_KINDS.CERTIFICATE: {
          const certPem = String(secret.certPem ?? secret.certificate ?? secret.value ?? "");
          const thumbprint = createHash("sha256").update(certPem, "utf8").digest("hex");
          injectedHeaders["x-client-cert-sha256"] = thumbprint;
          injectedHeaders["x-client-cert-bound"] = "mtls-vault-sealed";
          break;
        }
        case CREDENTIAL_KINDS.SMART_CONTRACT: {
          const sessionKey = String(secret.sessionPrivateKey ?? secret.signingSecret ?? secret.value ?? "");
          const chainId = String(secret.chainId ?? "1");
          const contractAddress = String(secret.contractAddress ?? "0x0");
          const bodyDigest = createHash("sha256").update(Buffer.from(bodyBytes)).digest("hex");
          const callMac = createHmac("sha256", Buffer.from(sessionKey, "utf8"))
            .update(`${chainId}:${contractAddress}:${method}:${requestedResourceRef}:${bodyDigest}:${nowSec}`, "utf8")
            .digest("hex");
          injectedHeaders["x-web3-chain-id"] = chainId;
          injectedHeaders["x-web3-contract"] = contractAddress;
          injectedHeaders["x-web3-call-intent-sig"] = `0x${callMac}`;
          break;
        }
        default:
          return err(errorCodes.LEGACY_AUTH_FAILED);
      }
    } finally {
      for (const k of Object.keys(secret)) {
        secret[k] = "";
      }
    }

    return ok({
      grantId: norm.value.grantId,
      grantTicket: norm.value.grantTicket,
      targetFayId: binding.targetFayId,
      credentialKind: cred.credentialKind,
      injectedHeaders,
      receipt: verifyRes.value.receipt,
    });
  }

  /**
   * Persists the encrypted vault state to disk (`AES-256-GCM` outer + inner envelopes).
   */
  saveToFile(filePath) {
    mkdirSync(dirname(filePath), { recursive: true });
    const grantsSnapshot = [];
    for (const [grantId, grantRec] of this.directory.grants.entries()) {
      grantsSnapshot.push([grantId, grantRec]);
    }
    const innerState = {
      humans: Array.from(this.directory.humans),
      ifays: Array.from(this.directory.ifays.entries()),
      cofays: Array.from(this.directory.cofays.entries()).map(([k, v]) => [
        k,
        { ...v, managers: Array.from(v.managers) },
      ]),
      revokedEntities: Array.from(this.directory.revokedEntities),
      grantCounter: this.directory._grantCounter,
      receiptCounter: this.directory._receiptCounter,
      grants: grantsSnapshot,
      sealedCredentials: Array.from(this._sealedCredentials.entries()),
      grantBindings: Array.from(this._grantBindings.entries()),
    };

    const outerEnvelope = this._encryptRecord("ifay.fayid.vault-file.v1", innerState);
    const diskDoc = {
      format: "ifay.fayid.auth-exchange-vault",
      version: "1.0",
      vaultSaltHex: this._vaultSalt.toString("hex"),
      envelope: outerEnvelope,
    };
    writeFileSync(filePath, `${JSON.stringify(diskDoc, null, 2)}\n`, { mode: 0o600 });
  }

  /**
   * Opens an encrypted vault file from disk using `vaultMasterKey`.
   */
  static openFile(filePath, vaultMasterKey) {
    if (!existsSync(filePath)) {
      return new AuthExchangeVault({ vaultMasterKey });
    }
    const rawDoc = JSON.parse(readFileSync(filePath, "utf8"));
    const vaultSalt = Buffer.from(rawDoc.vaultSaltHex, "hex");
    const vault = new AuthExchangeVault({ vaultMasterKey, vaultSalt });
    const inner = vault._decryptRecord("ifay.fayid.vault-file.v1", rawDoc.envelope);

    vault.directory.humans = new Set(inner.humans ?? []);
    vault.directory.ifays = new Map(inner.ifays ?? []);
    vault.directory.cofays = new Map(
      (inner.cofays ?? []).map(([k, v]) => [k, { ...v, managers: new Set(v.managers ?? []) }]),
    );
    vault.directory.revokedEntities = new Set(inner.revokedEntities ?? []);
    vault.directory._grantCounter = inner.grantCounter ?? 0;
    vault.directory._receiptCounter = inner.receiptCounter ?? 0;
    vault.directory.grants = new Map(inner.grants ?? []);
    vault._sealedCredentials = new Map(inner.sealedCredentials ?? []);
    vault._grantBindings = new Map(inner.grantBindings ?? []);
    return vault;
  }
}

function readBearerOrGrantHeader(headers) {
  const explicit = headers["x-fayid-grant"];
  if (explicit) return Array.isArray(explicit) ? explicit[0] : explicit;
  const auth = headers["authorization"];
  const rawAuth = Array.isArray(auth) ? auth[0] : auth;
  if (typeof rawAuth === "string" && /^bearer\s+/i.test(rawAuth)) {
    return rawAuth.replace(/^bearer\s+/i, "").trim();
  }
  return null;
}

const SENSITIVE_RESPONSE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "x-api-key",
  "set-cookie",
  "x-web3-call-intent-sig",
  "x-client-cert-sha256",
]);

/**
 * Starts a local `127.0.0.1` HTTP Credential Bridge Proxy where an `iFay` presents ONLY a scoped
 * `Authorization Grant` (`ag_...` or `grt_...`) and NEVER sees the raw upstream credential.
 */
export function createAuthExchangeProxyServer({
  vault,
  host = "127.0.0.1",
  port = 0,
  adminToken = randomBytes(24).toString("hex"),
  requireHolderSignature = false,
  fetchImpl = globalThis.fetch,
  vaultFilePath = null,
}) {
  if (!(vault instanceof AuthExchangeVault)) {
    throw new TypeError("createAuthExchangeProxyServer requires an AuthExchangeVault instance");
  }

  function checkAdminToken(req) {
    const supplied = String(req.headers["x-fayid-admin-token"] ?? "");
    const a = Buffer.from(supplied, "utf8");
    const b = Buffer.from(adminToken, "utf8");
    return a.length === b.length && timingSafeEqual(a, b);
  }

  async function readBodyBuffer(req) {
    const chunks = [];
    for await (const c of req) {
      chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    }
    return Buffer.concat(chunks);
  }

  function sendJson(res, status, obj, extraHeaders = {}) {
    res.writeHead(status, {
      "content-type": "application/json; charset=utf-8",
      ...extraHeaders,
    });
    res.end(JSON.stringify(obj));
  }

  const server = http.createServer(async (req, res) => {
    try {
      const reqUrl = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);

      if (req.method === "GET" && reqUrl.pathname === "/health") {
        return sendJson(res, 200, {
          ok: true,
          service: "fayid-auth-exchange-proxy",
          sealedCredentials: vault.listCredentials().length,
        });
      }

      // Local instant grant revocation endpoint (admin-authenticated)
      if (req.method === "POST" && reqUrl.pathname === "/grants/revoke") {
        if (!checkAdminToken(req)) {
          return sendJson(res, 401, { ok: false, error: accountErrorCodes.OWNERSHIP_NOT_PROVEN });
        }
        const raw = await readBodyBuffer(req);
        const payload = JSON.parse(raw.toString("utf8") || "{}");
        const revRes = vault.revokeGrant(payload.grantId ?? payload.grantTicket, payload.signerId);
        if (!revRes.ok) {
          return sendJson(res, 400, { ok: false, error: revRes.error });
        }
        if (vaultFilePath) vault.saveToFile(vaultFilePath);
        return sendJson(res, 200, { ok: true, value: revRes.value });
      }

      // Credential Bridge Proxy endpoint (`ANY /proxy`)
      if (reqUrl.pathname === "/proxy" || reqUrl.pathname.startsWith("/proxy/")) {
        const grantToken = readBearerOrGrantHeader(req.headers);
        if (!grantToken) {
          return sendJson(res, 401, { ok: false, error: errorCodes.GRANT_INVALID });
        }

        const targetUrl = String(
          req.headers["x-fayid-target-url"] ?? reqUrl.searchParams.get("target") ?? "",
        ).trim();
        if (!targetUrl) {
          return sendJson(res, 400, { ok: false, error: errorCodes.MALFORMED_FAYID_STRING });
        }

        const bodyBuf = await readBodyBuffer(req);

        const resolved = vault.resolveUpstreamAuthForProxy({
          grantOrTicket: grantToken,
          requestedResourceRef: targetUrl,
          method: req.method ?? "GET",
          bodyBytes: bodyBuf,
        });

        if (!resolved.ok) {
          const status =
            resolved.error === errorCodes.GRANT_REVOKED ||
            resolved.error === errorCodes.IDENTITY_REVOKED
              ? 403
              : 401;
          return sendJson(res, status, { ok: false, error: resolved.error });
        }

        // Optional Holder-of-Key verification ensuring caller possesses targetFayId's Ed25519 key
        const presenterHeader = req.headers["x-fayid-presenter"];
        if (requireHolderSignature || presenterHeader) {
          const presenter = String(presenterHeader ?? "").trim().toLowerCase();
          const pubKeyHex = String(req.headers["x-fayid-pubkey"] ?? "").trim().toLowerCase();
          const sigHex = String(req.headers["x-fayid-signature"] ?? "").trim().toLowerCase();
          const tsSec = Number(req.headers["x-fayid-timestamp"]);
          const nonce = String(req.headers["x-fayid-nonce"] ?? "");
          if (
            presenter !== resolved.value.targetFayId ||
            !matchesSelfCertifyingPublicKey(presenter, pubKeyHex)
          ) {
            return sendJson(res, 403, {
              ok: false,
              error: errorCodes.TARGET_OWNERSHIP_NOT_PROVEN,
            });
          }
          const bodySha256 = createHash("sha256").update(bodyBuf).digest("hex");
          const signingPayload = {
            domain: HTTP_AUTH_DOMAIN,
            method: String(req.method ?? "GET").toUpperCase(),
            path: `${reqUrl.pathname}${reqUrl.search}`,
            presenter,
            publicKeyHex: pubKeyHex,
            timestampSec: tsSec,
            nonce,
            bodySha256,
          };
          const { verifyEd25519Signature } = await import("./fayid-toolkit.mjs");
          const sigValid = verifyEd25519Signature(
            Buffer.from(pubKeyHex, "hex"),
            Buffer.from(canonicalizeJcs(signingPayload), "utf8"),
            Buffer.from(sigHex, "hex"),
          );
          if (!sigValid) {
            return sendJson(res, 403, {
              ok: false,
              error: errorCodes.TARGET_OWNERSHIP_NOT_PROVEN,
            });
          }
        }

        // Build clean upstream headers (strip grant & x-fayid-* headers, inject upstream secret!)
        const forwardHeaders = {};
        for (const [hk, hv] of Object.entries(req.headers)) {
          const lk = hk.toLowerCase();
          if (
            lk === "host" ||
            lk === "connection" ||
            lk === "content-length" ||
            lk === "authorization" ||
            lk.startsWith("x-fayid-")
          ) {
            continue;
          }
          if (hv !== undefined) {
            forwardHeaders[lk] = Array.isArray(hv) ? hv.join(", ") : hv;
          }
        }
        Object.assign(forwardHeaders, resolved.value.injectedHeaders);

        const method = String(req.method ?? "GET").toUpperCase();
        const upstreamRes = await fetchImpl(targetUrl, {
          method,
          headers: forwardHeaders,
          body: method === "GET" || method === "HEAD" ? undefined : bodyBuf,
        });

        // Clear injected header values in local object immediately after dispatch
        for (const ik of Object.keys(resolved.value.injectedHeaders)) {
          resolved.value.injectedHeaders[ik] = "";
        }

        const outHeaders = {
          "x-fayid-verification-receipt": Buffer.from(
            JSON.stringify(resolved.value.receipt),
            "utf8",
          ).toString("base64url"),
          "x-fayid-grant-id": resolved.value.grantId,
        };
        upstreamRes.headers.forEach((val, key) => {
          const lk = key.toLowerCase();
          if (!SENSITIVE_RESPONSE_HEADERS.has(lk) && lk !== "transfer-encoding" && lk !== "content-encoding") {
            outHeaders[lk] = val;
          }
        });

        const upstreamBytes = Buffer.from(await upstreamRes.arrayBuffer());
        res.writeHead(upstreamRes.status, outHeaders);
        res.end(upstreamBytes);
        return;
      }

      return sendJson(res, 404, { ok: false, error: "NOT_FOUND" });
    } catch (e) {
      return sendJson(res, 502, {
        ok: false,
        error: "UPSTREAM_BRIDGE_ERROR",
        detail: e instanceof Error ? e.message : String(e),
      });
    }
  });

  return {
    server,
    adminToken,
    async listen() {
      await new Promise((resolvePromise, rejectPromise) => {
        server.once("error", rejectPromise);
        server.listen(port, host, () => resolvePromise());
      });
      const addr = server.address();
      const boundPort = typeof addr === "object" && addr ? addr.port : port;
      return {
        host,
        port: boundPort,
        url: `http://${host}:${boundPort}`,
        adminToken,
      };
    },
    async close() {
      if (!server.listening) return;
      await new Promise((resolvePromise) => server.close(() => resolvePromise()));
    },
  };
}
