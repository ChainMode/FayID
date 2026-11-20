import { createHash, hkdfSync, randomBytes } from "node:crypto";
import { baselineLimits, err, errorCodes, ok } from "../schema/draft/testkit/reference/fayid.js";
import {
  accountErrorCodes,
  base32EncodeNoPad,
  canonicalizeJcs,
  deriveBlindGmcRef,
  derivePurposeSubkey,
  parseCanonicalFayID,
  subkeyDomains,
  verifyEd25519Signature,
} from "./fayid-toolkit.mjs";
import {
  MonotonicRevocationList,
  computeBlindRevocationTag,
  containsPlaintextHumanId,
  matchesSelfCertifyingPublicKey,
  registrationErrorCodes,
  verifyPlatformRegistration,
} from "./platform-registration.mjs";

export const HTTP_AUTH_DOMAIN = "ifay.fayid.http-auth.v1";
export const DYNAMIC_PRESENTATION_DOMAIN = "ifay.fayid.dynamic-presentation.v1";

export const verifyErrorCodes = Object.freeze({
  ...registrationErrorCodes,
  CHALLENGE_EXPIRED: "CHALLENGE_EXPIRED",
  CHALLENGE_MISMATCH: "CHALLENGE_MISMATCH",
  REQUEST_SIGNATURE_INVALID: "REQUEST_SIGNATURE_INVALID",
  REQUEST_TIMESTAMP_STALE: "REQUEST_TIMESTAMP_STALE",
  REQUEST_NONCE_REPLAYED: "REQUEST_NONCE_REPLAYED",
  BODY_DIGEST_MISMATCH: "BODY_DIGEST_MISMATCH",
  PLATFORM_REGISTRATION_REQUIRED: "PLATFORM_REGISTRATION_REQUIRED",
});

/**
 * Normalizes canonical `dyn_<base32>` or alias `dync_<base32>` Dynamic Code tokens.
 * @param {string} code
 */
export function normalizeDynamicCodeToken(code) {
  if (typeof code !== "string" || code.trim().length === 0) {
    return err(errorCodes.MALFORMED_FAYID_STRING);
  }
  const lower = code.trim().toLowerCase();
  if (lower.startsWith("dync_")) {
    const body = lower.slice("dync_".length);
    if (!/^[a-z2-7]{16,64}$/.test(body)) {
      return err(errorCodes.MALFORMED_FAYID_STRING);
    }
    return ok({ raw: lower, canonical: `dyn_${body}`, body });
  }
  const parsed = parseCanonicalFayID(lower);
  if (!parsed.ok || parsed.value.kind !== "DYNAMIC_CODE") {
    return err(errorCodes.MALFORMED_FAYID_STRING);
  }
  return ok({
    raw: parsed.value.value,
    canonical: parsed.value.value,
    body: parsed.value.value.slice("dyn_".length),
  });
}

function sha256Hex(input) {
  if (input === undefined || input === null || input === "") {
    return createHash("sha256").update("", "utf8").digest("hex");
  }
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    return createHash("sha256").update(Buffer.from(input)).digest("hex");
  }
  if (typeof input === "string") {
    return createHash("sha256").update(input, "utf8").digest("hex");
  }
  return createHash("sha256").update(canonicalizeJcs(input), "utf8").digest("hex");
}

function extractHeader(headers, key) {
  if (!headers) return undefined;
  const lower = key.toLowerCase();
  if (typeof headers.get === "function") {
    const v = headers.get(lower) ?? headers.get(key);
    return v === null ? undefined : v;
  }
  const direct = headers[lower] ?? headers[key];
  if (Array.isArray(direct)) return direct[0];
  return direct;
}

function normalizePathAndQuery(urlOrPath) {
  if (!urlOrPath) return "/";
  const str = String(urlOrPath);
  if (str.startsWith("http://") || str.startsWith("https://")) {
    const u = new URL(str);
    return `${u.pathname}${u.search}`;
  }
  return str.startsWith("/") ? str : `/${str}`;
}

/**
 * Issues a privacy-preserving Holder-of-Key Dynamic Code presentation bundle (`dyn_...` / `dync_...`)
 * for a `Human Prime` (`hid_`), `iFay` (`ifay_`), or `coFay` (`cofay_`) WITHOUT ever embedding
 * plaintext `hid_` in the outbound ticket or HTTP headers!
 */
export function issueDynamicPresentation({
  masterSeed,
  subjectId,
  ttlSec = 300,
  issuedAtSec = Math.floor(Date.now() / 1000),
  nonce = randomBytes(16),
  useDyncAlias = false,
  blindSalt = Buffer.from("ifay.fayid.default-blind-salt.v1", "utf8"),
  federationSalt = "ifay.fayid.default-revocation-salt.v1",
  directory = null,
}) {
  const parsed = parseCanonicalFayID(subjectId);
  if (
    !parsed.ok ||
    (parsed.value.kind !== "HUMAN_ID" &&
      parsed.value.kind !== "IFAY_ID" &&
      parsed.value.kind !== "COFAY_ID")
  ) {
    return err(accountErrorCodes.DYNAMIC_CODE_TARGET_NOT_ALLOWED);
  }
  if (!masterSeed || Buffer.from(masterSeed).length < 32) {
    return err(errorCodes.INSUFFICIENT_ENTROPY);
  }
  if (ttlSec <= 0 || ttlSec > baselineLimits.DYNAMIC_CODE_MAX_TTL_SECONDS) {
    return err(errorCodes.DYNAMIC_CODE_INVALID);
  }

  const expiresAtSec = issuedAtSec + ttlSec;
  const nonceBuf = Buffer.from(nonce);
  const nonceHex = nonceBuf.toString("hex");

  let canonicalCode;
  if (directory) {
    const dirRes = directory.issueDynamicCode({
      subjectId: parsed.value.value,
      holderSecret: masterSeed,
      nonce: nonceBuf,
      issuedAtSec,
      expiresAtSec,
    });
    if (!dirRes.ok) return dirRes;
    canonicalCode = dirRes.value.code;
  } else {
    const payload = Buffer.from(
      hkdfSync(
        "sha256",
        Buffer.from(masterSeed),
        nonceBuf,
        Buffer.from(`${subkeyDomains.DYNAMIC_CODE}:${parsed.value.value}:${issuedAtSec}:${expiresAtSec}`, "utf8"),
        16,
      ),
    );
    canonicalCode = `dyn_${base32EncodeNoPad(payload)}`;
  }

  const codeBody = canonicalCode.slice("dyn_".length);
  const dynamicCode = useDyncAlias ? `dync_${codeBody}` : canonicalCode;

  // Derive a single-use unlinkable Ed25519 session signer bound to this Dynamic Code
  const ephemeralRes = derivePurposeSubkey(
    masterSeed,
    subkeyDomains.DYNAMIC_CODE,
    `ephemeral:${canonicalCode}:${nonceHex}`,
  );
  if (!ephemeralRes.ok) return ephemeralRes;
  const sessionSigner = ephemeralRes.value;

  let blindSubjectRef = parsed.value.value;
  if (parsed.value.kind === "HUMAN_ID") {
    const blindRes = deriveBlindGmcRef(parsed.value.value, blindSalt, "ifay.fayid.verify-blind.v1");
    if (!blindRes.ok) return blindRes;
    blindSubjectRef = blindRes.value;
  }

  const blindRevocationTag = computeBlindRevocationTag(parsed.value.value, federationSalt);

  const ticketCore = {
    version: "1.0",
    domain: DYNAMIC_PRESENTATION_DOMAIN,
    dynamicCode,
    subjectKind: parsed.value.kind,
    blindSubjectRef,
    blindRevocationTag,
    sessionPublicKeyHex: sessionSigner.publicKeyHex,
    issuedAtSec,
    expiresAtSec,
  };
  const ticketSignatureHex = Buffer.from(
    sessionSigner.signPayload(Buffer.from(canonicalizeJcs(ticketCore), "utf8")),
  ).toString("hex");

  return ok({
    dynamicCode,
    canonicalCode,
    ticket: Object.freeze({
      ...ticketCore,
      ticketSignatureHex,
    }),
    sessionSigner,
  });
}

/**
 * Signs an outgoing HTTP / Fetch request with Holder-of-Key Ed25519 headers for `Verify with FayID`.
 * Supports `iFay` (`ifay_`), `coFay` (`cofay_`), and privacy-preserving `Dynamic Code` (`dyn_` / `dync_`).
 */
export function signFayIdRequest({
  method = "GET",
  url = "/",
  body = "",
  presenterId,
  signer,
  dynamicPresentation = null,
  challenge = null,
  registrations = [],
  nowSec = Math.floor(Date.now() / 1000),
  nonce = randomBytes(16).toString("hex"),
}) {
  const effectivePresenter = dynamicPresentation
    ? dynamicPresentation.dynamicCode
    : String(presenterId ?? "").trim().toLowerCase();
  const effectiveSigner = dynamicPresentation ? dynamicPresentation.sessionSigner : signer;

  if (containsPlaintextHumanId(effectivePresenter)) {
    throw new Error(
      "HUMAN_ID_PLAINTEXT_FORBIDDEN: Plaintext hid_ must never be transmitted outbound; use issueDynamicPresentation() instead.",
    );
  }
  if (!effectiveSigner || typeof effectiveSigner.signPayload !== "function") {
    throw new Error("Missing Holder-of-Key Ed25519 signer");
  }

  const upperMethod = String(method).toUpperCase();
  const pathAndQuery = normalizePathAndQuery(url);
  const bodySha256 = sha256Hex(body);

  const signingPayload = {
    domain: HTTP_AUTH_DOMAIN,
    method: upperMethod,
    path: pathAndQuery,
    presenter: effectivePresenter,
    publicKeyHex: effectiveSigner.publicKeyHex.toLowerCase(),
    timestampSec: nowSec,
    nonce,
    bodySha256,
    ...(challenge ? { challenge } : {}),
  };

  const signatureHex = Buffer.from(
    effectiveSigner.signPayload(Buffer.from(canonicalizeJcs(signingPayload), "utf8")),
  ).toString("hex");

  const headers = {
    "x-fayid-presenter": effectivePresenter,
    "x-fayid-pubkey": effectiveSigner.publicKeyHex.toLowerCase(),
    "x-fayid-timestamp": String(nowSec),
    "x-fayid-nonce": nonce,
    "x-fayid-body-sha256": bodySha256,
    "x-fayid-signature": signatureHex,
  };

  if (challenge) {
    headers["x-fayid-challenge"] = challenge;
  }
  if (dynamicPresentation?.ticket) {
    headers["x-fayid-dynamic-ticket"] = Buffer.from(
      JSON.stringify(dynamicPresentation.ticket),
      "utf8",
    ).toString("base64url");
  }
  if (Array.isArray(registrations) && registrations.length > 0) {
    headers["x-fayid-registrations"] = Buffer.from(
      JSON.stringify(registrations),
      "utf8",
    ).toString("base64url");
  }

  return headers;
}

async function readNodeIncomingBody(req) {
  if (req.body !== undefined) {
    if (typeof req.body === "string" || Buffer.isBuffer(req.body) || req.body instanceof Uint8Array) {
      return req.body;
    }
    return JSON.stringify(req.body);
  }
  if (!req || typeof req[Symbol.asyncIterator] !== "function") {
    return "";
  }
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks);
  req.rawBody = raw;
  if (raw.length > 0) {
    const ct = String(extractHeader(req.headers, "content-type") ?? "");
    if (ct.includes("application/json")) {
      try {
        req.body = JSON.parse(raw.toString("utf8"));
      } catch {
        req.body = raw.toString("utf8");
      }
    } else {
      req.body = raw.toString("utf8");
    }
  }
  return raw;
}

/**
 * Drop-in `Verify with FayID` Zero-Dependency Web/API Integration Middleware & Verifier.
 *
 * Directly callable as Express / Connect / Node `http` middleware `(req, res, next)` AND
 * exposes `.verifyRequest(...)`, `.verifyFetch(...)`, `.protectFetch(...)`, and `.createChallenge(...)`.
 */
export function createFayIdVerifier(options = {}) {
  const maxSkewSec = options.maxClockSkewSec ?? baselineLimits.PROOF_CHALLENGE_MAX_TTL_SECONDS;
  const revocationList = options.revocationList ?? new MonotonicRevocationList(options);
  const directory = options.directory ?? null;
  const platformRegistry = options.platformRegistry ?? null;
  const trustedPlatformKeys = options.trustedPlatformKeys ?? null;
  const requiredPlatformCategory = options.requiredPlatformCategory ?? null;
  const requiredPlatformId = options.requiredPlatformId ?? null;
  const requiredScopes = options.requiredScopes ?? null;
  const requireChallenge = Boolean(options.requireChallenge);

  const seenNonces = new Map();
  const consumedDynamicCodes = new Set();
  const activeChallenges = new Map();

  function pruneCaches(nowSec) {
    for (const [k, exp] of seenNonces.entries()) {
      if (nowSec > exp) seenNonces.delete(k);
    }
    for (const [ch, exp] of activeChallenges.entries()) {
      if (nowSec > exp) activeChallenges.delete(ch);
    }
  }

  function createChallenge(nowSec = Math.floor(Date.now() / 1000), ttlSec = 120) {
    const clampedTtl = Math.min(Math.max(1, ttlSec), baselineLimits.PROOF_CHALLENGE_MAX_TTL_SECONDS);
    const challenge = `chl_${base32EncodeNoPad(randomBytes(16))}`;
    const expiresAtSec = nowSec + clampedTtl;
    activeChallenges.set(challenge, expiresAtSec);
    return { challenge, issuedAtSec: nowSec, expiresAtSec };
  }

  function verifyRequest({
    method = "GET",
    url = "/",
    headers = {},
    body = undefined,
    nowSec = Math.floor(Date.now() / 1000),
  }) {
    pruneCaches(nowSec);

    const presenterRaw = extractHeader(headers, "x-fayid-presenter");
    const pubKeyHex = extractHeader(headers, "x-fayid-pubkey");
    const tsRaw = extractHeader(headers, "x-fayid-timestamp");
    const nonce = extractHeader(headers, "x-fayid-nonce");
    const bodyShaHeader = extractHeader(headers, "x-fayid-body-sha256");
    const sigHex = extractHeader(headers, "x-fayid-signature");
    const challenge = extractHeader(headers, "x-fayid-challenge");

    if (!presenterRaw || !pubKeyHex || !tsRaw || !nonce || !sigHex) {
      return err(verifyErrorCodes.REQUEST_SIGNATURE_INVALID);
    }

    // Never allow plaintext HumanID (`hid_...`) over the wire!
    if (containsPlaintextHumanId(presenterRaw)) {
      return err(verifyErrorCodes.HUMAN_ID_PLAINTEXT_FORBIDDEN);
    }

    const timestampSec = Number(tsRaw);
    if (!Number.isFinite(timestampSec) || Math.abs(nowSec - timestampSec) > maxSkewSec) {
      return err(verifyErrorCodes.REQUEST_TIMESTAMP_STALE);
    }

    if (requireChallenge || challenge) {
      if (!challenge || !activeChallenges.has(challenge)) {
        return err(verifyErrorCodes.CHALLENGE_MISMATCH);
      }
      const chExp = activeChallenges.get(challenge);
      activeChallenges.delete(challenge);
      if (nowSec > chExp) {
        return err(verifyErrorCodes.CHALLENGE_EXPIRED);
      }
    }

    const nonceKey = `${presenterRaw.toLowerCase()}:${nonce}`;
    if (seenNonces.has(nonceKey)) {
      return err(verifyErrorCodes.REQUEST_NONCE_REPLAYED);
    }

    const computedBodySha = body !== undefined ? sha256Hex(body) : (bodyShaHeader ?? sha256Hex(""));
    if (bodyShaHeader && body !== undefined && bodyShaHeader.toLowerCase() !== computedBodySha) {
      return err(verifyErrorCodes.BODY_DIGEST_MISMATCH);
    }

    const normPresenter = String(presenterRaw).trim().toLowerCase();
    const normPubKeyHex = String(pubKeyHex).trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(normPubKeyHex) || !/^[0-9a-f]{128}$/i.test(sigHex)) {
      return err(verifyErrorCodes.REQUEST_SIGNATURE_INVALID);
    }

    const signingPayload = {
      domain: HTTP_AUTH_DOMAIN,
      method: String(method).toUpperCase(),
      path: normalizePathAndQuery(url),
      presenter: normPresenter,
      publicKeyHex: normPubKeyHex,
      timestampSec,
      nonce,
      bodySha256: bodyShaHeader ? bodyShaHeader.toLowerCase() : computedBodySha,
      ...(challenge ? { challenge } : {}),
    };

    const httpSigValid = verifyEd25519Signature(
      Buffer.from(normPubKeyHex, "hex"),
      Buffer.from(canonicalizeJcs(signingPayload), "utf8"),
      Buffer.from(sigHex, "hex"),
    );
    if (!httpSigValid) {
      return err(verifyErrorCodes.REQUEST_SIGNATURE_INVALID);
    }

    // Branch 1: Privacy-preserving Dynamic Code (`dyn_...` or `dync_...`)
    let subjectKind;
    let subjectRef;
    let dynamicCodeUsed = null;

    if (normPresenter.startsWith("dyn_") || normPresenter.startsWith("dync_")) {
      const normDyn = normalizeDynamicCodeToken(normPresenter);
      if (!normDyn.ok) return normDyn;

      if (consumedDynamicCodes.has(normDyn.value.canonical)) {
        return err(accountErrorCodes.DYNAMIC_CODE_REPLAYED);
      }

      const rawTicketB64 = extractHeader(headers, "x-fayid-dynamic-ticket");
      let ticket = null;
      if (rawTicketB64) {
        try {
          ticket = JSON.parse(Buffer.from(rawTicketB64, "base64url").toString("utf8"));
        } catch {
          return err(errorCodes.DYNAMIC_CODE_INVALID);
        }
        if (containsPlaintextHumanId(ticket)) {
          return err(verifyErrorCodes.HUMAN_ID_PLAINTEXT_FORBIDDEN);
        }
      }

      if (ticket) {
        if (
          ticket.domain !== DYNAMIC_PRESENTATION_DOMAIN ||
          String(ticket.dynamicCode).toLowerCase() !== normPresenter ||
          String(ticket.sessionPublicKeyHex).toLowerCase() !== normPubKeyHex
        ) {
          return err(errorCodes.DYNAMIC_CODE_INVALID);
        }
        if (
          typeof ticket.expiresAtSec !== "number" ||
          typeof ticket.issuedAtSec !== "number" ||
          ticket.expiresAtSec - ticket.issuedAtSec > baselineLimits.DYNAMIC_CODE_MAX_TTL_SECONDS
        ) {
          return err(errorCodes.DYNAMIC_CODE_INVALID);
        }
        if (nowSec > ticket.expiresAtSec) {
          return err(errorCodes.DYNAMIC_CODE_EXPIRED);
        }
        if (
          revocationList.isRevoked(ticket.blindRevocationTag) ||
          revocationList.isRevoked(ticket.blindSubjectRef)
        ) {
          return err(errorCodes.IDENTITY_REVOKED);
        }
        const { ticketSignatureHex, ...ticketCore } = ticket;
        const ticketOk = verifyEd25519Signature(
          Buffer.from(normPubKeyHex, "hex"),
          Buffer.from(canonicalizeJcs(ticketCore), "utf8"),
          Buffer.from(ticketSignatureHex, "hex"),
        );
        if (!ticketOk) {
          return err(errorCodes.DYNAMIC_CODE_INVALID);
        }
        subjectKind = ticket.subjectKind;
        subjectRef = ticket.blindSubjectRef;
      }

      if (directory) {
        const dirRes = directory.verifyDynamicCode(normDyn.value.canonical, nowSec);
        if (!dirRes.ok) {
          if (dirRes.error === accountErrorCodes.ENTITY_REVOKED) {
            return err(errorCodes.IDENTITY_REVOKED);
          }
          return dirRes;
        }
        subjectKind = dirRes.value.subjectKind;
        subjectRef = dirRes.value.resolvedRef;
      } else if (!ticket) {
        return err(errorCodes.DYNAMIC_CODE_INVALID);
      }

      consumedDynamicCodes.add(normDyn.value.canonical);
      dynamicCodeUsed = normDyn.value.raw;
    } else {
      // Branch 2: Direct Holder-of-Key `ifay_...` or `cofay_...`
      const parsed = parseCanonicalFayID(normPresenter);
      if (
        !parsed.ok ||
        (parsed.value.kind !== "IFAY_ID" && parsed.value.kind !== "COFAY_ID")
      ) {
        return err(errorCodes.MALFORMED_FAYID_STRING);
      }
      if (
        revocationList.isRevoked(parsed.value.value) ||
        directory?.isEntityRevoked(parsed.value.value)
      ) {
        return err(errorCodes.IDENTITY_REVOKED);
      }
      if (!matchesSelfCertifyingPublicKey(parsed.value.value, normPubKeyHex)) {
        return err(errorCodes.OWNERSHIP_NOT_PROVEN);
      }
      subjectKind = parsed.value.kind;
      subjectRef = parsed.value.value;
    }

    // Verify Opt-In Platform Registration Attestations if supplied or required
    const verifiedRegistrations = [];
    const rawRegHeader = extractHeader(headers, "x-fayid-registrations");
    if (rawRegHeader) {
      let regList;
      try {
        regList = JSON.parse(Buffer.from(rawRegHeader, "base64url").toString("utf8"));
      } catch {
        return err(registrationErrorCodes.PLATFORM_ATTESTATION_INVALID);
      }
      const arr = Array.isArray(regList) ? regList : [regList];
      for (const att of arr) {
        const ver = verifyPlatformRegistration(att, {
          revocationList,
          directory,
          registry: platformRegistry,
          trustedPlatformKeys,
          expectedSubjectId: dynamicCodeUsed ? undefined : subjectRef,
          nowSec,
        });
        if (!ver.ok) return ver;
        verifiedRegistrations.push(ver.value);
      }
    }

    if (requiredPlatformCategory || requiredPlatformId || (requiredScopes && requiredScopes.length > 0)) {
      const matching = verifiedRegistrations.find((reg) => {
        if (requiredPlatformCategory && reg.platformCategory !== requiredPlatformCategory) {
          return false;
        }
        if (requiredPlatformId && reg.platformId !== requiredPlatformId.toLowerCase()) {
          return false;
        }
        if (requiredScopes && requiredScopes.length > 0) {
          const scopeSet = new Set(reg.scopes ?? []);
          if (!requiredScopes.every((s) => scopeSet.has(s))) return false;
        }
        return true;
      });
      if (!matching) {
        return err(verifyErrorCodes.PLATFORM_REGISTRATION_REQUIRED);
      }
    }

    seenNonces.set(nonceKey, nowSec + maxSkewSec + 60);

    return ok({
      verified: true,
      presenterKind: dynamicCodeUsed ? "DYNAMIC_CODE" : subjectKind,
      subjectKind,
      subjectRef,
      dynamicCode: dynamicCodeUsed,
      publicKeyHex: normPubKeyHex,
      registrations: verifiedRegistrations,
      verifiedAtSec: nowSec,
    });
  }

  async function middleware(req, res, next) {
    try {
      const rawBody = await readNodeIncomingBody(req);
      const outcome = verifyRequest({
        method: req.method,
        url: req.originalUrl ?? req.url ?? "/",
        headers: req.headers,
        body: rawBody,
      });

      if (!outcome.ok) {
        const status = outcome.error === errorCodes.IDENTITY_REVOKED ? 403 : 401;
        if (res && typeof res.writeHead === "function") {
          const payload = JSON.stringify({ ok: false, error: outcome.error });
          res.statusCode = status;
          res.setHeader?.("content-type", "application/json; charset=utf-8");
          res.end(payload);
        }
        return outcome;
      }

      req.fayid = outcome.value;
      if (typeof next === "function") {
        next();
      }
      return outcome;
    } catch {
      if (res && typeof res.writeHead === "function") {
        res.statusCode = 400;
        res.setHeader?.("content-type", "application/json; charset=utf-8");
        res.end(JSON.stringify({ ok: false, error: verifyErrorCodes.REQUEST_SIGNATURE_INVALID }));
      }
      return err(verifyErrorCodes.REQUEST_SIGNATURE_INVALID);
    }
  }

  async function verifyFetch(request, nowSec) {
    const cloned = request.clone();
    const rawBytes = new Uint8Array(await cloned.arrayBuffer());
    return verifyRequest({
      method: request.method,
      url: request.url,
      headers: request.headers,
      body: rawBytes,
      nowSec,
    });
  }

  function protectFetch(handler) {
    return async function guardedFetchHandler(request) {
      const outcome = await verifyFetch(request);
      if (!outcome.ok) {
        const status = outcome.error === errorCodes.IDENTITY_REVOKED ? 403 : 401;
        return new Response(JSON.stringify({ ok: false, error: outcome.error }), {
          status,
          headers: { "content-type": "application/json; charset=utf-8" },
        });
      }
      return handler(request, outcome.value);
    };
  }

  middleware.middleware = middleware;
  middleware.verifyRequest = verifyRequest;
  middleware.verifyFetch = verifyFetch;
  middleware.protectFetch = protectFetch;
  middleware.createChallenge = createChallenge;
  middleware.revocationList = revocationList;

  return middleware;
}
