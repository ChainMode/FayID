import { createHash, createHmac, randomBytes } from "node:crypto";
import { err, errorCodes, ok } from "../schema/draft/testkit/reference/fayid.js";
import {
  accountErrorCodes,
  base32DecodeNoPad,
  base32EncodeNoPad,
  canonicalizeJcs,
  parseCanonicalFayID,
  verifyEd25519Signature,
} from "./fayid-toolkit.mjs";

export const PLATFORM_CATEGORIES = Object.freeze({
  REAL_NAME: "REAL_NAME",
  EXPERT: "EXPERT",
  COMMERCE: "COMMERCE",
  SERVICE: "SERVICE",
});

export const registrationDomains = Object.freeze({
  PLATFORM_OPT_IN: "ifay.fayid.platform-optin.v1",
  PLATFORM_ATTESTATION: "ifay.fayid.platform-attestation.v1",
  FEDERATED_REVOCATION: "ifay.fayid.revocation-bundle.v1",
});

export const registrationErrorCodes = Object.freeze({
  ...accountErrorCodes,
  HUMAN_ID_PLAINTEXT_FORBIDDEN: "HUMAN_ID_PLAINTEXT_FORBIDDEN",
  STEALTH_UNREGISTERED: "STEALTH_UNREGISTERED",
  PLATFORM_CATEGORY_INVALID: "PLATFORM_CATEGORY_INVALID",
  PLATFORM_OPT_IN_INVALID: "PLATFORM_OPT_IN_INVALID",
  PLATFORM_ATTESTATION_INVALID: "PLATFORM_ATTESTATION_INVALID",
  PLATFORM_UNTRUSTED: "PLATFORM_UNTRUSTED",
  REGISTRATION_EXPIRED: "REGISTRATION_EXPIRED",
  REGISTRATION_REVOKED: "REGISTRATION_REVOKED",
  REGISTRATION_SCOPE_MISSING: "REGISTRATION_SCOPE_MISSING",
  REVOCATION_ROLLBACK_REJECTED: "REVOCATION_ROLLBACK_REJECTED",
  REVOCATION_SIGNATURE_INVALID: "REVOCATION_SIGNATURE_INVALID",
});

const ALLOWED_CATEGORIES = new Set(Object.values(PLATFORM_CATEGORIES));
const REG_ID_RE = /^reg_[a-z2-7]{16,64}$/;

/**
 * Checks that an object contains zero plaintext `hid_<base32>` strings anywhere in its values.
 * Enforces the FayID invariant that Human Prime root identifiers never leave local boundaries.
 * @param {unknown} value
 * @returns {boolean}
 */
export function containsPlaintextHumanId(value) {
  if (typeof value === "string") {
    return /\bhid_[a-z2-7]{16,}\b/i.test(value);
  }
  if (Array.isArray(value)) {
    return value.some((item) => containsPlaintextHumanId(item));
  }
  if (value && typeof value === "object") {
    return Object.values(value).some((v) => containsPlaintextHumanId(v));
  }
  return false;
}

/**
 * Verifies that a raw 32-byte Ed25519 public key cryptographically hashes to the self-certifying
 * `<ifay|cofay|hid>_<base32>` identifier (`SHA-256(publicKeyRaw)`).
 * @param {string} entityId
 * @param {Uint8Array | string} publicKeyRawOrHex
 * @returns {boolean}
 */
export function matchesSelfCertifyingPublicKey(entityId, publicKeyRawOrHex) {
  const parsed = parseCanonicalFayID(entityId);
  if (!parsed.ok) return false;
  if (
    parsed.value.kind !== "IFAY_ID" &&
    parsed.value.kind !== "COFAY_ID" &&
    parsed.value.kind !== "HUMAN_ID"
  ) {
    return false;
  }
  const pubRaw =
    typeof publicKeyRawOrHex === "string"
      ? Buffer.from(publicKeyRawOrHex, "hex")
      : Buffer.from(publicKeyRawOrHex);
  if (pubRaw.length !== 32) return false;
  const digest = createHash("sha256").update(pubRaw).digest();
  const prefix = parsed.value.value.split("_")[0];
  const expected = `${prefix}_${base32EncodeNoPad(digest)}`;
  return expected === parsed.value.value;
}

/**
 * Computes a privacy-preserving blind revocation tag (`revtag_<base32>`) for an entity so
 * federated revocation lists can revoke a Human Prime or Fay without exposing plaintext `hid_`.
 * @param {string} entityId
 * @param {Uint8Array | string} [federationSalt="ifay.fayid.default-revocation-salt.v1"]
 */
export function computeBlindRevocationTag(
  entityId,
  federationSalt = "ifay.fayid.default-revocation-salt.v1",
) {
  const parsed = parseCanonicalFayID(entityId);
  const norm = parsed.ok ? parsed.value.value : String(entityId).trim().toLowerCase();
  const saltBuf = Buffer.isBuffer(federationSalt) || federationSalt instanceof Uint8Array
    ? Buffer.from(federationSalt)
    : Buffer.from(String(federationSalt), "utf8");
  const digest = createHmac("sha256", saltBuf).update(`revtag:${norm}`, "utf8").digest();
  return `revtag_${base32EncodeNoPad(digest.subarray(0, 20))}`;
}

/**
 * Monotonic Local & Federated Revocation List.
 * Guarantees revocations only grow monotonically (`sequence` strictly non-decreasing, no un-revoking)
 * and supports Ed25519-signed federated revocation bundles.
 */
export class MonotonicRevocationList {
  constructor(options = {}) {
    this.sequence = 0;
    this.updatedAtSec = options.initialNowSec ?? Math.floor(Date.now() / 1000);
    this._federationSalt = options.federationSalt ?? "ifay.fayid.default-revocation-salt.v1";
    this._revokedIds = new Map();
    this._revokedBlindTags = new Map();
  }

  /**
   * Monotonically revokes an entity ID (`ifay_`, `cofay_`, `org_`, `reg_`) or `hid_` (stored only as blind tag!).
   * @param {string} targetId
   * @param {{ reason?: string; revokedAtSec?: number }} [meta]
   */
  revoke(targetId, meta = {}) {
    if (typeof targetId !== "string" || targetId.trim().length === 0) {
      return err(errorCodes.MALFORMED_FAYID_STRING);
    }
    const norm = targetId.trim().toLowerCase();
    const nowSec = meta.revokedAtSec ?? Math.floor(Date.now() / 1000);
    const reason = meta.reason ?? "explicit-revocation";

    const blindTag = norm.startsWith("revtag_")
      ? norm
      : computeBlindRevocationTag(norm, this._federationSalt);

    const isHumanPlaintext = norm.startsWith("hid_");
    let changed = false;

    if (!this._revokedBlindTags.has(blindTag)) {
      this._revokedBlindTags.set(blindTag, { reason, revokedAtSec: nowSec });
      changed = true;
    }
    if (!isHumanPlaintext && !this._revokedIds.has(norm)) {
      this._revokedIds.set(norm, { reason, revokedAtSec: nowSec });
      changed = true;
    }

    if (changed) {
      this.sequence += 1;
      this.updatedAtSec = Math.max(this.updatedAtSec, nowSec);
    }

    return ok({
      sequence: this.sequence,
      revokedRef: isHumanPlaintext ? blindTag : norm,
      blindTag,
    });
  }

  /**
   * Checks whether an entity, registration ID, or blind revocation tag is revoked.
   * @param {string | null | undefined} idOrTag
   * @returns {boolean}
   */
  isRevoked(idOrTag) {
    if (typeof idOrTag !== "string" || idOrTag.length === 0) return false;
    const norm = idOrTag.trim().toLowerCase();
    if (this._revokedIds.has(norm) || this._revokedBlindTags.has(norm)) {
      return true;
    }
    const blindTag = computeBlindRevocationTag(norm, this._federationSalt);
    return this._revokedBlindTags.has(blindTag);
  }

  exportSnapshot() {
    return {
      version: "1.0",
      sequence: this.sequence,
      updatedAtSec: this.updatedAtSec,
      revokedIds: Array.from(this._revokedIds.keys()).sort(),
      revokedBlindTags: Array.from(this._revokedBlindTags.keys()).sort(),
    };
  }

  /**
   * Signs a federated revocation bundle with an authority/platform Ed25519 signer.
   * @param {{ publicKeyHex: string; signPayload(bytes: Uint8Array): Uint8Array }} signer
   * @param {string} issuerId
   */
  exportSignedBundle(signer, issuerId) {
    const snapshot = this.exportSnapshot();
    const core = {
      domain: registrationDomains.FEDERATED_REVOCATION,
      issuerId: String(issuerId).toLowerCase(),
      publicKeyHex: signer.publicKeyHex,
      ...snapshot,
    };
    const sig = Buffer.from(signer.signPayload(Buffer.from(canonicalizeJcs(core), "utf8"))).toString("hex");
    return { ...core, signatureHex: sig };
  }

  /**
   * Applies an incoming federated snapshot or signed bundle monotonically.
   * Rejects rollback attempts (`incoming.sequence < this.sequence` or missing previously-revoked entries).
   * @param {object} bundle
   * @param {{ expectedPublicKeyHex?: string }} [options]
   */
  importBundle(bundle, options = {}) {
    if (!bundle || typeof bundle !== "object" || typeof bundle.sequence !== "number") {
      return err(registrationErrorCodes.REVOCATION_SIGNATURE_INVALID);
    }
    if (bundle.signatureHex) {
      if (
        options.expectedPublicKeyHex &&
        bundle.publicKeyHex !== options.expectedPublicKeyHex
      ) {
        return err(registrationErrorCodes.REVOCATION_SIGNATURE_INVALID);
      }
      const { signatureHex, ...core } = bundle;
      const valid = verifyEd25519Signature(
        Buffer.from(bundle.publicKeyHex, "hex"),
        Buffer.from(canonicalizeJcs(core), "utf8"),
        Buffer.from(signatureHex, "hex"),
      );
      if (!valid) {
        return err(registrationErrorCodes.REVOCATION_SIGNATURE_INVALID);
      }
    }

    if (bundle.sequence < this.sequence) {
      return err(registrationErrorCodes.REVOCATION_ROLLBACK_REJECTED);
    }

    const incomingIds = new Set((bundle.revokedIds ?? []).map((x) => String(x).toLowerCase()));
    const incomingTags = new Set((bundle.revokedBlindTags ?? []).map((x) => String(x).toLowerCase()));

    // Strict monotonicity: incoming snapshot at >= sequence cannot drop any existing revocation
    for (const existingId of this._revokedIds.keys()) {
      if (!incomingIds.has(existingId)) {
        return err(registrationErrorCodes.REVOCATION_ROLLBACK_REJECTED);
      }
    }
    for (const existingTag of this._revokedBlindTags.keys()) {
      if (!incomingTags.has(existingTag)) {
        return err(registrationErrorCodes.REVOCATION_ROLLBACK_REJECTED);
      }
    }

    for (const id of incomingIds) {
      if (id.startsWith("hid_")) {
        return err(registrationErrorCodes.HUMAN_ID_PLAINTEXT_FORBIDDEN);
      }
      if (!this._revokedIds.has(id)) {
        this._revokedIds.set(id, { reason: "federated-sync", revokedAtSec: bundle.updatedAtSec ?? 0 });
      }
    }
    for (const tag of incomingTags) {
      if (!this._revokedBlindTags.has(tag)) {
        this._revokedBlindTags.set(tag, { reason: "federated-sync", revokedAtSec: bundle.updatedAtSec ?? 0 });
      }
    }

    this.sequence = bundle.sequence;
    this.updatedAtSec = Math.max(this.updatedAtSec, bundle.updatedAtSec ?? 0);
    return ok({ sequence: this.sequence, totalRevoked: this._revokedBlindTags.size + this._revokedIds.size });
  }
}

/**
 * Issues a dual-signed Opt-In Platform Registration Attestation (`reg_<base32>`).
 *
 * Implements the "Stealth by default, opt-in register like a phone number" model:
 * - An `iFay` or `coFay` explicitly signs an opt-in request (`ifay.fayid.platform-optin.v1`);
 * - The target platform (`org_<slug>`) countersigns the attestation (`ifay.fayid.platform-attestation.v1`);
 * - Plaintext `hid_` is strictly forbidden anywhere in the attestation (uses optional blind `gmcref_` anchor).
 */
export function issuePlatformRegistration({
  subjectId,
  subjectSigner,
  platformId,
  platformCategory,
  platformSigner,
  handle,
  scopes = [],
  claims = {},
  discoverable = true,
  blindHumanAnchor = null,
  issuedAtSec = Math.floor(Date.now() / 1000),
  expiresAtSec = issuedAtSec + 86400 * 30,
  registry = null,
}) {
  const parsedSubject = parseCanonicalFayID(subjectId);
  if (
    !parsedSubject.ok ||
    (parsedSubject.value.kind !== "IFAY_ID" && parsedSubject.value.kind !== "COFAY_ID")
  ) {
    if (parsedSubject.ok && parsedSubject.value.kind === "HUMAN_ID") {
      return err(registrationErrorCodes.HUMAN_ID_PLAINTEXT_FORBIDDEN);
    }
    return err(errorCodes.MALFORMED_FAYID_STRING);
  }

  const parsedPlatform = parseCanonicalFayID(platformId);
  if (!parsedPlatform.ok || parsedPlatform.value.kind !== "ORGANIZATION_ID") {
    return err(errorCodes.MALFORMED_FAYID_STRING);
  }

  if (!ALLOWED_CATEGORIES.has(platformCategory)) {
    return err(registrationErrorCodes.PLATFORM_CATEGORY_INVALID);
  }

  if (
    containsPlaintextHumanId(handle) ||
    containsPlaintextHumanId(scopes) ||
    containsPlaintextHumanId(claims) ||
    containsPlaintextHumanId(blindHumanAnchor)
  ) {
    return err(registrationErrorCodes.HUMAN_ID_PLAINTEXT_FORBIDDEN);
  }

  if (blindHumanAnchor !== null) {
    const parsedAnchor = parseCanonicalFayID(blindHumanAnchor);
    if (!parsedAnchor.ok || parsedAnchor.value.kind !== "OPAQUE_REF") {
      return err(errorCodes.MALFORMED_FAYID_STRING);
    }
  }

  if (
    !subjectSigner ||
    typeof subjectSigner.signPayload !== "function" ||
    !subjectSigner.publicKeyHex ||
    !matchesSelfCertifyingPublicKey(parsedSubject.value.value, subjectSigner.publicKeyHex)
  ) {
    return err(errorCodes.OWNERSHIP_NOT_PROVEN);
  }

  if (
    !platformSigner ||
    typeof platformSigner.signPayload !== "function" ||
    !platformSigner.publicKeyHex
  ) {
    return err(registrationErrorCodes.PLATFORM_ATTESTATION_INVALID);
  }

  if (
    typeof issuedAtSec !== "number" ||
    typeof expiresAtSec !== "number" ||
    expiresAtSec <= issuedAtSec
  ) {
    return err(registrationErrorCodes.PLATFORM_ATTESTATION_INVALID);
  }

  const normSubject = parsedSubject.value.value;
  const normPlatform = parsedPlatform.value.value;
  const cleanScopes = Array.from(new Set((scopes ?? []).map((s) => String(s).trim()).filter(Boolean))).sort();
  const cleanHandle = String(handle ?? normSubject).trim();

  const nonceHex = randomBytes(12).toString("hex");
  const regSeed = createHash("sha256")
    .update(
      `reg:${normSubject}:${normPlatform}:${platformCategory}:${issuedAtSec}:${nonceHex}`,
      "utf8",
    )
    .digest();
  const registrationId = `reg_${base32EncodeNoPad(regSeed.subarray(0, 16))}`;

  const optInCore = {
    version: "1.0",
    domain: registrationDomains.PLATFORM_OPT_IN,
    registrationId,
    subjectId: normSubject,
    subjectKind: parsedSubject.value.kind,
    subjectPublicKeyHex: subjectSigner.publicKeyHex.toLowerCase(),
    platformId: normPlatform,
    platformCategory,
    handle: cleanHandle,
    scopes: cleanScopes,
    discoverable: Boolean(discoverable),
    ...(blindHumanAnchor ? { blindHumanAnchor: blindHumanAnchor.toLowerCase() } : {}),
    issuedAtSec,
    expiresAtSec,
  };

  const optInSignatureHex = Buffer.from(
    subjectSigner.signPayload(Buffer.from(canonicalizeJcs(optInCore), "utf8")),
  ).toString("hex");

  const attestationCore = {
    version: "1.0",
    domain: registrationDomains.PLATFORM_ATTESTATION,
    registrationId,
    subjectId: normSubject,
    subjectKind: parsedSubject.value.kind,
    subjectPublicKeyHex: optInCore.subjectPublicKeyHex,
    platformId: normPlatform,
    platformCategory,
    platformPublicKeyHex: platformSigner.publicKeyHex.toLowerCase(),
    handle: cleanHandle,
    scopes: cleanScopes,
    claims: claims ?? {},
    discoverable: Boolean(discoverable),
    ...(blindHumanAnchor ? { blindHumanAnchor: blindHumanAnchor.toLowerCase() } : {}),
    issuedAtSec,
    expiresAtSec,
    optInSignatureHex,
  };

  const platformSignatureHex = Buffer.from(
    platformSigner.signPayload(Buffer.from(canonicalizeJcs(attestationCore), "utf8")),
  ).toString("hex");

  const attestation = Object.freeze({
    ...attestationCore,
    platformSignatureHex,
  });

  if (registry && typeof registry.recordRegistration === "function") {
    const regRes = registry.recordRegistration(attestation);
    if (!regRes.ok) return regRes;
  }

  return ok(attestation);
}

/**
 * Cryptographically verifies an Opt-In Platform Registration Attestation offline or against
 * a `PlatformRegistry` / `MonotonicRevocationList` / `AccountDirectory`.
 */
export function verifyPlatformRegistration(attestation, options = {}) {
  try {
    if (!attestation || typeof attestation !== "object" || attestation.version !== "1.0") {
      return err(registrationErrorCodes.PLATFORM_ATTESTATION_INVALID);
    }
    if (
      attestation.domain !== registrationDomains.PLATFORM_ATTESTATION ||
      typeof attestation.registrationId !== "string" ||
      !REG_ID_RE.test(attestation.registrationId)
    ) {
      return err(registrationErrorCodes.PLATFORM_ATTESTATION_INVALID);
    }

    if (containsPlaintextHumanId(attestation)) {
      return err(registrationErrorCodes.HUMAN_ID_PLAINTEXT_FORBIDDEN);
    }

    const parsedSubject = parseCanonicalFayID(attestation.subjectId);
    const parsedPlatform = parseCanonicalFayID(attestation.platformId);
    if (
      !parsedSubject.ok ||
      (parsedSubject.value.kind !== "IFAY_ID" && parsedSubject.value.kind !== "COFAY_ID") ||
      !parsedPlatform.ok ||
      parsedPlatform.value.kind !== "ORGANIZATION_ID"
    ) {
      return err(registrationErrorCodes.PLATFORM_ATTESTATION_INVALID);
    }

    if (!ALLOWED_CATEGORIES.has(attestation.platformCategory)) {
      return err(registrationErrorCodes.PLATFORM_CATEGORY_INVALID);
    }

    // Revocation checks first (fail closed with IDENTITY_REVOKED / REGISTRATION_REVOKED)
    const revList = options.revocationList ?? options.registry?.revocationList ?? null;
    const directory = options.directory ?? null;

    if (
      revList?.isRevoked(parsedSubject.value.value) ||
      revList?.isRevoked(parsedPlatform.value.value) ||
      (attestation.blindHumanAnchor && revList?.isRevoked(attestation.blindHumanAnchor)) ||
      directory?.isEntityRevoked(parsedSubject.value.value) ||
      directory?.isEntityRevoked(parsedPlatform.value.value)
    ) {
      return err(errorCodes.IDENTITY_REVOKED);
    }

    if (
      revList?.isRevoked(attestation.registrationId) ||
      options.registry?.isRegistrationRevoked(attestation.registrationId)
    ) {
      return err(registrationErrorCodes.REGISTRATION_REVOKED);
    }

    const nowSec = options.nowSec ?? Math.floor(Date.now() / 1000);
    if (typeof attestation.expiresAtSec !== "number" || nowSec > attestation.expiresAtSec) {
      return err(registrationErrorCodes.REGISTRATION_EXPIRED);
    }

    if (
      options.expectedSubjectId &&
      parsedSubject.value.value !== String(options.expectedSubjectId).toLowerCase()
    ) {
      return err(errorCodes.OWNERSHIP_NOT_PROVEN);
    }

    if (
      options.requiredCategory &&
      attestation.platformCategory !== options.requiredCategory
    ) {
      return err(registrationErrorCodes.PLATFORM_CATEGORY_INVALID);
    }

    if (
      options.requiredPlatformId &&
      parsedPlatform.value.value !== String(options.requiredPlatformId).toLowerCase()
    ) {
      return err(registrationErrorCodes.PLATFORM_UNTRUSTED);
    }

    if (Array.isArray(options.requiredScopes) && options.requiredScopes.length > 0) {
      const granted = new Set(attestation.scopes ?? []);
      for (const reqScope of options.requiredScopes) {
        if (!granted.has(reqScope)) {
          return err(registrationErrorCodes.REGISTRATION_SCOPE_MISSING);
        }
      }
    }

    // Trusted platform public key pinning if configured
    if (options.trustedPlatformKeys) {
      const expectedKey =
        options.trustedPlatformKeys instanceof Map
          ? options.trustedPlatformKeys.get(parsedPlatform.value.value)
          : options.trustedPlatformKeys[parsedPlatform.value.value];
      if (!expectedKey || expectedKey.toLowerCase() !== attestation.platformPublicKeyHex.toLowerCase()) {
        return err(registrationErrorCodes.PLATFORM_UNTRUSTED);
      }
    }

    // Holder-of-Key self-certifying subject check + opt-in signature check
    if (!matchesSelfCertifyingPublicKey(parsedSubject.value.value, attestation.subjectPublicKeyHex)) {
      return err(registrationErrorCodes.PLATFORM_OPT_IN_INVALID);
    }

    const optInCore = {
      version: "1.0",
      domain: registrationDomains.PLATFORM_OPT_IN,
      registrationId: attestation.registrationId,
      subjectId: parsedSubject.value.value,
      subjectKind: attestation.subjectKind,
      subjectPublicKeyHex: attestation.subjectPublicKeyHex,
      platformId: parsedPlatform.value.value,
      platformCategory: attestation.platformCategory,
      handle: attestation.handle,
      scopes: attestation.scopes,
      discoverable: attestation.discoverable,
      ...(attestation.blindHumanAnchor ? { blindHumanAnchor: attestation.blindHumanAnchor } : {}),
      issuedAtSec: attestation.issuedAtSec,
      expiresAtSec: attestation.expiresAtSec,
    };

    const optInValid = verifyEd25519Signature(
      Buffer.from(attestation.subjectPublicKeyHex, "hex"),
      Buffer.from(canonicalizeJcs(optInCore), "utf8"),
      Buffer.from(attestation.optInSignatureHex, "hex"),
    );
    if (!optInValid) {
      return err(registrationErrorCodes.PLATFORM_OPT_IN_INVALID);
    }

    const { platformSignatureHex, ...attestationCore } = attestation;
    const platformValid = verifyEd25519Signature(
      Buffer.from(attestation.platformPublicKeyHex, "hex"),
      Buffer.from(canonicalizeJcs(attestationCore), "utf8"),
      Buffer.from(platformSignatureHex, "hex"),
    );
    if (!platformValid) {
      return err(registrationErrorCodes.PLATFORM_ATTESTATION_INVALID);
    }

    return ok({
      valid: true,
      registrationId: attestation.registrationId,
      subjectId: parsedSubject.value.value,
      platformId: parsedPlatform.value.value,
      platformCategory: attestation.platformCategory,
      handle: attestation.handle,
      scopes: attestation.scopes,
      claims: attestation.claims,
      discoverable: attestation.discoverable,
      blindHumanAnchor: attestation.blindHumanAnchor ?? null,
      expiresAtSec: attestation.expiresAtSec,
    });
  } catch {
    return err(registrationErrorCodes.PLATFORM_ATTESTATION_INVALID);
  }
}

/**
 * Symmetrically revokes an Opt-In Platform Registration (`reg_<base32>`):
 * Either the `iFay`/`coFay` holder (returning to stealth mode!) OR the issuing platform (`org_`)
 * can revoke the registration monotonically.
 */
export function revokePlatformRegistration(
  registrationOrId,
  actorId,
  options = {},
) {
  const regId =
    typeof registrationOrId === "string"
      ? registrationOrId.trim().toLowerCase()
      : registrationOrId?.registrationId?.toLowerCase();

  if (!regId || !REG_ID_RE.test(regId)) {
    return err(errorCodes.MALFORMED_FAYID_STRING);
  }

  const registry = options.registry ?? null;
  const revList = options.revocationList ?? registry?.revocationList ?? null;
  const record =
    typeof registrationOrId === "object" && registrationOrId !== null
      ? registrationOrId
      : registry?.getRegistration(regId) ?? null;

  const normActor = typeof actorId === "string" ? actorId.trim().toLowerCase() : "";
  if (!normActor) {
    return err(errorCodes.OWNERSHIP_NOT_PROVEN);
  }

  if (record) {
    if (normActor !== record.subjectId && normActor !== record.platformId) {
      return err(errorCodes.OWNERSHIP_NOT_PROVEN);
    }
  }

  const nowSec = options.nowSec ?? Math.floor(Date.now() / 1000);
  if (registry) {
    registry._markRevoked(regId);
  }
  if (revList) {
    revList.revoke(regId, { reason: options.reason ?? `revoked-by:${normActor}`, revokedAtSec: nowSec });
  }

  return ok({
    registrationId: regId,
    state: "REVOKED",
    revokedBy: normActor,
    discoverable: false,
  });
}

/**
 * Opt-In Platform Directory enforcing Stealth-by-Default:
 * An `iFay` or `coFay` is completely invisible (`STEALTH_UNREGISTERED`) unless it has an active,
 * non-expired, non-revoked opt-in registration with `discoverable: true`.
 */
export class PlatformRegistry {
  constructor(options = {}) {
    this.revocationList = options.revocationList ?? new MonotonicRevocationList(options);
    this._registrations = new Map();
    this._revokedRegistrations = new Set();
  }

  recordRegistration(attestation) {
    if (
      this.revocationList.isRevoked(attestation.subjectId) ||
      this.revocationList.isRevoked(attestation.platformId)
    ) {
      return err(errorCodes.IDENTITY_REVOKED);
    }
    this._registrations.set(attestation.registrationId, attestation);
    return ok(attestation.registrationId);
  }

  getRegistration(registrationId) {
    return this._registrations.get(String(registrationId).toLowerCase()) ?? null;
  }

  isRegistrationRevoked(registrationId) {
    const norm = String(registrationId).toLowerCase();
    return this._revokedRegistrations.has(norm) || this.revocationList.isRevoked(norm);
  }

  _markRevoked(registrationId) {
    this._revokedRegistrations.add(String(registrationId).toLowerCase());
  }

  /**
   * Public discovery lookup: returns `STEALTH_UNREGISTERED` unless the Fay explicitly opted in
   * with `discoverable: true` and the registration is currently valid & unrevoked.
   */
  resolveDiscoverableSubject(subjectId, options = {}) {
    const parsed = parseCanonicalFayID(subjectId);
    if (!parsed.ok) return err(errorCodes.MALFORMED_FAYID_STRING);
    if (parsed.value.kind === "HUMAN_ID") {
      return err(registrationErrorCodes.HUMAN_ID_PLAINTEXT_FORBIDDEN);
    }
    const normSubject = parsed.value.value;
    if (this.revocationList.isRevoked(normSubject)) {
      return err(errorCodes.IDENTITY_REVOKED);
    }

    const nowSec = options.nowSec ?? Math.floor(Date.now() / 1000);
    const active = [];
    for (const att of this._registrations.values()) {
      if (att.subjectId !== normSubject || !att.discoverable) continue;
      const ver = verifyPlatformRegistration(att, {
        registry: this,
        revocationList: this.revocationList,
        nowSec,
        requiredCategory: options.category,
        requiredPlatformId: options.platformId,
      });
      if (ver.ok) {
        active.push(ver.value);
      }
    }

    if (active.length === 0) {
      return err(registrationErrorCodes.STEALTH_UNREGISTERED);
    }
    return ok({
      subjectId: normSubject,
      discoverable: true,
      registrations: active,
    });
  }
}
