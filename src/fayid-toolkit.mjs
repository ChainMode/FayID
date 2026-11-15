import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  randomBytes,
  sign,
  verify,
} from "node:crypto";
import {
  baselineLimits,
  err,
  errorCodes,
  matchesResourceRef,
  normalizeFayID,
  normalizeResourceRef,
  ok,
  prefixes,
} from "../schema/draft/testkit/reference/fayid.js";

const RFC4648_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export const subkeyDomains = Object.freeze({
  ENTITY: "ifay.fayid.entity.v1",
  EGO_PACKAGE_SIGNING: "ifay.ego.package-signing.v1",
  DYNAMIC_CODE: "ifay.fayid.dynamic-code.v1",
  AUTH_EXCHANGE: "ifay.fayid.auth-exchange.v1",
  GMC_NATURAL_PERSON: "ifay.gmc.natural-person.v1",
});

export const accountErrorCodes = Object.freeze({
  ...errorCodes,
  OWNER_TYPE_NOT_ALLOWED: "OWNER_TYPE_NOT_ALLOWED",
  HIERARCHY_CONSENT_MISSING: "HIERARCHY_CONSENT_MISSING",
  HIERARCHY_CYCLE_CONFLICT: "HIERARCHY_CYCLE_CONFLICT",
  AUTHORITY_GRANT_UNAUTHORIZED: "AUTHORITY_GRANT_UNAUTHORIZED",
  STEWARD_TYPE_NOT_ALLOWED: "STEWARD_TYPE_NOT_ALLOWED",
  ENTITY_REVOKED: "ENTITY_REVOKED",
  DYNAMIC_CODE_REPLAYED: "DYNAMIC_CODE_REPLAYED",
  DYNAMIC_CODE_TARGET_NOT_ALLOWED: "DYNAMIC_CODE_TARGET_NOT_ALLOWED",
  DOMAIN_SEPARATION_REQUIRED: "DOMAIN_SEPARATION_REQUIRED",
  RECEIPT_INVALID: "RECEIPT_INVALID",
});

const LEGACY_TRUST_DEFAULTS = Object.freeze({
  PASSWORD: "LOW",
  ACCESS_TOKEN: "MEDIUM",
  AUTHORIZATION: "MEDIUM",
  CERTIFICATE: "HIGH",
  SMART_CONTRACT: "HIGH",
});

/**
 * Deterministic RFC 8785 JCS-compatible UTF-8 canonical JSON stringifier.
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalizeJcs(value) {
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("Non-finite numbers cannot be canonicalized in JCS");
    }
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJcs(item === undefined ? null : item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJcs(value[k])}`).join(",")}}`;
  }
  throw new TypeError(`Unsupported JCS value type: ${typeof value}`);
}

function ed25519FromSeed32(seed32Buf) {
  const privKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed32Buf.subarray(0, 32)]),
    format: "der",
    type: "pkcs8",
  });
  const pubKey = createPublicKey(privKey);
  const spki = pubKey.export({ format: "der", type: "spki" });
  const publicKeyRaw = Buffer.from(spki.subarray(spki.length - 32));
  return {
    publicKeyRaw,
    publicKeyHex: publicKeyRaw.toString("hex"),
    signBytes(payloadBytes) {
      return sign(null, Buffer.from(payloadBytes), privKey);
    },
  };
}

/**
 * Encodes bytes into lowercase RFC 4648 Base32 without `=` padding.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function base32EncodeNoPad(bytes) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += RFC4648_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += RFC4648_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

/**
 * Decodes lowercase/uppercase RFC 4648 Base32 without padding back to Buffer.
 * @param {string} input
 * @returns {Buffer | null}
 */
export function base32DecodeNoPad(input) {
  if (typeof input !== "string" || input.length === 0) return null;
  const lower = input.toLowerCase();
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of lower) {
    const idx = RFC4648_ALPHABET.indexOf(ch);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/**
 * Parses and normalizes any canonical `<prefix>_<base32|slug>` FayID string.
 * @param {string} input
 */
export function parseCanonicalFayID(input) {
  return normalizeFayID(input);
}

/**
 * Deterministic transition adapter converting legacy 64-hex digests (e.g. GMChain BLAKE3/SHA256)
 * into canonical `<prefix>_<base32-nopad>` FayID identifiers (ADR 0002).
 * @param {"hid" | "ifay" | "cofay" | "org" | "gmcref"} entityPrefix
 * @param {string} hex64
 */
export function fromLegacyHexIdentity(entityPrefix, hex64) {
  const allowed = new Set(["hid", "ifay", "cofay", "org", "gmcref"]);
  if (!allowed.has(entityPrefix) || typeof hex64 !== "string" || !/^[0-9a-fA-F]{64}$/.test(hex64)) {
    return err(accountErrorCodes.MALFORMED_FAYID_STRING);
  }
  const bytes = Buffer.from(hex64, "hex");
  return ok(`${entityPrefix}_${base32EncodeNoPad(bytes)}`);
}

/**
 * Self-Sovereign Holder-of-Key Ed25519 derivation from a 32-byte local root seed (ADR 0002).
 * Never requires or touches any centralized `issuer_master_secret`.
 * @param {Uint8Array} seed32
 */
export function deriveHumanIdentityFromSeed(seed32) {
  const buf = Buffer.from(seed32);
  if (buf.length < 32) {
    return err(accountErrorCodes.INSUFFICIENT_ENTROPY);
  }
  const kp = ed25519FromSeed32(buf);
  const idBytes = createHash("sha256").update(kp.publicKeyRaw).digest();
  const humanId = `${prefixes.HUMAN_ID}${base32EncodeNoPad(idBytes)}`;

  return {
    humanId,
    idBytes,
    publicKeyRaw: kp.publicKeyRaw,
    signPayload(payloadBytes) {
      return kp.signBytes(payloadBytes);
    },
    toPublicRecord() {
      return {
        kind: "HUMAN_PUBLIC_KEY_RECORD",
        publicKeyHex: kp.publicKeyHex,
      };
    },
    toJSON() {
      return {
        kind: "HUMAN_PUBLIC_KEY_RECORD",
        publicKeyHex: kp.publicKeyHex,
      };
    },
  };
}

/**
 * Derives a deterministic 32-byte Ed25519 purpose subkey from a master seed via HKDF-SHA256
 * with explicit domain separation (`ifay.fayid.entity.v1`, `ifay.ego.package-signing.v1`, etc.).
 * Root seed and subkey private material are isolated inside closure and NEVER serialized.
 *
 * @param {Uint8Array} masterSeed
 * @param {string} domain
 * @param {string} [context="default"]
 */
export function derivePurposeSubkey(masterSeed, domain, context = "default") {
  if (!masterSeed || Buffer.from(masterSeed).length < 32) {
    return err(accountErrorCodes.INSUFFICIENT_ENTROPY);
  }
  if (typeof domain !== "string" || !/^[a-z0-9._-]+$/i.test(domain.trim())) {
    return err(accountErrorCodes.DOMAIN_SEPARATION_REQUIRED);
  }
  const cleanDomain = domain.trim();
  const cleanContext = String(context ?? "default");
  const salt = createHash("sha256").update(`fayid/subkey-salt/v1:${cleanDomain}`, "utf8").digest();
  const subSeed32 = Buffer.from(
    hkdfSync("sha256", Buffer.from(masterSeed), salt, Buffer.from(`${cleanDomain}:${cleanContext}`, "utf8"), 32),
  );
  const kp = ed25519FromSeed32(subSeed32);
  subSeed32.fill(0);

  const publicRecord = Object.freeze({
    domain: cleanDomain,
    context: cleanContext,
    publicKeyHex: kp.publicKeyHex,
  });

  return ok({
    domain: cleanDomain,
    context: cleanContext,
    publicKeyRaw: kp.publicKeyRaw,
    publicKeyHex: kp.publicKeyHex,
    signPayload(payloadBytes) {
      return kp.signBytes(payloadBytes);
    },
    toPublicRecord() {
      return publicRecord;
    },
    toJSON() {
      return publicRecord;
    },
  });
}

/**
 * Derives a deterministic entity Ed25519 keypair and canonical FayID (`hid_`, `ifay_`, `cofay_`, `org_`)
 * under domain `ifay.fayid.entity.v1`.
 *
 * @param {Uint8Array} masterSeed
 * @param {"hid" | "ifay" | "cofay" | "org"} entityPrefix
 * @param {number | string} [slotOrSlug=0]
 */
export function deriveEntityKeypair(masterSeed, entityPrefix, slotOrSlug = 0) {
  const allowed = new Map([
    ["hid", "HUMAN_ID"],
    ["ifay", "IFAY_ID"],
    ["cofay", "COFAY_ID"],
    ["org", "ORGANIZATION_ID"],
  ]);
  if (!allowed.has(entityPrefix)) {
    return err(accountErrorCodes.MALFORMED_FAYID_STRING);
  }
  const subRes = derivePurposeSubkey(masterSeed, subkeyDomains.ENTITY, `${entityPrefix}:${slotOrSlug}`);
  if (!subRes.ok) return subRes;

  const sub = subRes.value;
  const idDigest = createHash("sha256").update(sub.publicKeyRaw).digest();
  let entityId;
  if (entityPrefix === "org" && typeof slotOrSlug === "string" && /^[a-z0-9-]+$/.test(slotOrSlug)) {
    entityId = `org_${slotOrSlug}`;
  } else {
    entityId = `${entityPrefix}_${base32EncodeNoPad(idDigest)}`;
  }

  const kind = allowed.get(entityPrefix);
  const publicRecord = Object.freeze({
    kind,
    ...(entityPrefix === "hid" ? {} : { entityId }),
    domain: subkeyDomains.ENTITY,
    publicKeyHex: sub.publicKeyHex,
  });

  return ok({
    entityId,
    kind,
    domain: subkeyDomains.ENTITY,
    publicKeyRaw: sub.publicKeyRaw,
    publicKeyHex: sub.publicKeyHex,
    signPayload: sub.signPayload,
    toPublicRecord() {
      return publicRecord;
    },
    toJSON() {
      return publicRecord;
    },
  });
}

/**
 * Derives a domain-separated Ego package signing key (`ifay.ego.package-signing.v1`) bound to an
 * `iFayID` or `coFayID` so root private keys NEVER enter Ego packaging or outbound payloads.
 *
 * @param {Uint8Array} masterSeed
 * @param {string} signerFayId
 * @param {number} [keyIndex=0]
 */
export function deriveEgoPackageSigningKey(masterSeed, signerFayId, keyIndex = 0) {
  const parsed = parseCanonicalFayID(signerFayId);
  if (!parsed.ok || (parsed.value.kind !== "IFAY_ID" && parsed.value.kind !== "COFAY_ID")) {
    return err(accountErrorCodes.MALFORMED_FAYID_STRING);
  }
  if (!Number.isInteger(keyIndex) || keyIndex < 0) {
    return err(accountErrorCodes.MALFORMED_FAYID_STRING);
  }
  const normId = parsed.value.value;
  const subRes = derivePurposeSubkey(masterSeed, subkeyDomains.EGO_PACKAGE_SIGNING, `${normId}#${keyIndex}`);
  if (!subRes.ok) return subRes;
  const sub = subRes.value;

  const publicRecord = Object.freeze({
    version: "1.0",
    domain: subkeyDomains.EGO_PACKAGE_SIGNING,
    signerFayId: normId,
    keyIndex,
    publicKeyHex: sub.publicKeyHex,
  });

  return ok({
    domain: subkeyDomains.EGO_PACKAGE_SIGNING,
    signerFayId: normId,
    keyIndex,
    publicKeyRaw: sub.publicKeyRaw,
    publicKeyHex: sub.publicKeyHex,
    signPayload: sub.signPayload,
    signEgoPackageManifest(manifestOrBytes) {
      const payloadBytes = Buffer.isBuffer(manifestOrBytes) || manifestOrBytes instanceof Uint8Array
        ? Buffer.from(manifestOrBytes)
        : Buffer.from(canonicalizeJcs(manifestOrBytes), "utf8");
      const payloadDigestHex = createHash("sha256").update(payloadBytes).digest("hex");
      const signingCore = {
        version: "1.0",
        domain: subkeyDomains.EGO_PACKAGE_SIGNING,
        signerFayId: normId,
        keyIndex,
        publicKeyHex: sub.publicKeyHex,
        payloadDigestHex,
      };
      const sig = sub.signPayload(Buffer.from(canonicalizeJcs(signingCore), "utf8"));
      return {
        ...signingCore,
        signatureHex: sig.toString("hex"),
      };
    },
    toPublicRecord() {
      return publicRecord;
    },
    toJSON() {
      return publicRecord;
    },
  });
}

/**
 * Verifies an Ego package signature envelope produced under `ifay.ego.package-signing.v1`.
 * @param {object} envelope
 * @param {unknown} manifestOrBytes
 */
export function verifyEgoPackageEnvelope(envelope, manifestOrBytes) {
  try {
    if (!envelope || envelope.version !== "1.0" || envelope.domain !== subkeyDomains.EGO_PACKAGE_SIGNING) {
      return false;
    }
    const parsed = parseCanonicalFayID(envelope.signerFayId);
    if (!parsed.ok || (parsed.value.kind !== "IFAY_ID" && parsed.value.kind !== "COFAY_ID")) {
      return false;
    }
    const payloadBytes = Buffer.isBuffer(manifestOrBytes) || manifestOrBytes instanceof Uint8Array
      ? Buffer.from(manifestOrBytes)
      : Buffer.from(canonicalizeJcs(manifestOrBytes), "utf8");
    const expectedDigest = createHash("sha256").update(payloadBytes).digest("hex");
    if (expectedDigest !== envelope.payloadDigestHex) {
      return false;
    }
    const signingCore = {
      version: "1.0",
      domain: envelope.domain,
      signerFayId: parsed.value.value,
      keyIndex: envelope.keyIndex,
      publicKeyHex: envelope.publicKeyHex,
      payloadDigestHex: envelope.payloadDigestHex,
    };
    return verifyEd25519Signature(
      Buffer.from(envelope.publicKeyHex, "hex"),
      Buffer.from(canonicalizeJcs(signingCore), "utf8"),
      Buffer.from(envelope.signatureHex, "hex"),
    );
  } catch {
    return false;
  }
}

/**
 * Verifies an Ed25519 Holder-of-Key signature given raw 32-byte public key.
 * @param {Uint8Array} publicKeyRaw
 * @param {Uint8Array} payloadBytes
 * @param {Uint8Array} signatureBytes
 */
export function verifyEd25519Signature(publicKeyRaw, payloadBytes, signatureBytes) {
  try {
    const raw = Buffer.from(publicKeyRaw);
    if (raw.length !== 32) return false;
    const pubKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      format: "der",
      type: "spki",
    });
    return verify(null, Buffer.from(payloadBytes), pubKey, Buffer.from(signatureBytes));
  } catch {
    return false;
  }
}

/**
 * Holder-of-Key Dynamic Code derivation (§6.3) using local root derive key (Wave 1 low-level primitive).
 */
export function deriveDynamicCode(localRootKey, humanIdStr, nonceBytes, issuedAtSec, expiresAtSec) {
  const deriveSecret = Buffer.from(
    hkdfSync("sha256", Buffer.from(localRootKey), Buffer.from(humanIdStr, "utf8"), Buffer.from("fayid/derive_secret/v1", "utf8"), 32),
  );
  const payload = Buffer.from(
    hkdfSync("sha256", deriveSecret, Buffer.from(nonceBytes), Buffer.from(`fayid/dyn/v1:${issuedAtSec}:${expiresAtSec}`, "utf8"), 16),
  );
  const code = `${prefixes.DYNAMIC_CODE}${base32EncodeNoPad(payload)}`;
  const lookupKeyHex = createHash("sha256").update(code, "utf8").digest("hex");
  return { code, lookupKeyHex, issuedAtSec, expiresAtSec };
}

/**
 * Blind OpaqueRef (`gmcref_`) derivation (§6.5) for GMChain natural-person voting normalization (Wave 1 primitive).
 */
export function deriveOpaqueRef(humanIdBytes, gmcNamespaceSecret) {
  const derived = Buffer.from(
    hkdfSync("sha256", Buffer.from(gmcNamespaceSecret), Buffer.from(humanIdBytes), Buffer.from("fayid/gmc/v1", "utf8"), 32),
  );
  return `${prefixes.OPAQUE_REF}${base32EncodeNoPad(derived)}`;
}

/**
 * Deterministic domain-separated blind natural-person anchor (`gmcref_<base32>`) from a canonical
 * `HumanID` (or 32-byte digest) + user blind salt so `GMChain` normalizes natural-person governance
 * weight across 1:N `iFay`s without linkable plaintext `hid_` exposure.
 *
 * @param {string | Uint8Array} humanIdOrBytes
 * @param {Uint8Array} userBlindSalt
 * @param {string} [namespace="ifay.gmc.natural-person.v1"]
 */
export function deriveBlindGmcRef(humanIdOrBytes, userBlindSalt, namespace = subkeyDomains.GMC_NATURAL_PERSON) {
  if (!userBlindSalt || Buffer.from(userBlindSalt).length < 16) {
    return err(accountErrorCodes.INSUFFICIENT_ENTROPY);
  }
  if (typeof namespace !== "string" || namespace.trim().length === 0) {
    return err(accountErrorCodes.DOMAIN_SEPARATION_REQUIRED);
  }

  let canonicalHumanBytes;
  if (typeof humanIdOrBytes === "string") {
    const parsed = parseCanonicalFayID(humanIdOrBytes);
    if (!parsed.ok || parsed.value.kind !== "HUMAN_ID") {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    const decoded = base32DecodeNoPad(parsed.value.value.slice(prefixes.HUMAN_ID.length));
    if (!decoded || decoded.length === 0) {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    canonicalHumanBytes = decoded;
  } else if (humanIdOrBytes instanceof Uint8Array || Buffer.isBuffer(humanIdOrBytes)) {
    const raw = Buffer.from(humanIdOrBytes);
    if (raw.length < 16) {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    canonicalHumanBytes = raw;
  } else {
    return err(accountErrorCodes.MALFORMED_FAYID_STRING);
  }

  const derived = Buffer.from(
    hkdfSync(
      "sha256",
      Buffer.from(userBlindSalt),
      canonicalHumanBytes,
      Buffer.from(namespace.trim(), "utf8"),
      32,
    ),
  );
  return ok(`${prefixes.OPAQUE_REF}${base32EncodeNoPad(derived)}`);
}

/**
 * Independently verifies a signed `vrf_<base32>` Auth Exchange Verification Receipt.
 * @param {object} receipt
 */
export function verifyAuthReceipt(receipt) {
  try {
    if (!receipt || typeof receipt !== "object" || receipt.version !== "1.0") return false;
    const parsedReceipt = parseCanonicalFayID(receipt.receiptId);
    const parsedGrant = parseCanonicalFayID(receipt.grantId);
    if (
      !parsedReceipt.ok ||
      parsedReceipt.value.kind !== "VERIFICATION_CODE" ||
      !parsedGrant.ok ||
      parsedGrant.value.kind !== "AUTHORIZATION_GRANT"
    ) {
      return false;
    }
    const signedCore = {
      version: receipt.version,
      receiptId: parsedReceipt.value.value,
      grantId: parsedGrant.value.value,
      requestedResourceRef: receipt.requestedResourceRef,
      scopeMode: receipt.scopeMode,
      verifiedAtSec: receipt.verifiedAtSec,
      statusVersion: receipt.statusVersion,
      verifierPublicKeyHex: receipt.verifierPublicKeyHex,
    };
    return verifyEd25519Signature(
      Buffer.from(receipt.verifierPublicKeyHex, "hex"),
      Buffer.from(canonicalizeJcs(signedCore), "utf8"),
      Buffer.from(receipt.signatureHex, "hex"),
    );
  } catch {
    return false;
  }
}

/**
 * Self-contained FayID 1.0 Account & Authority Directory enforcing:
 * 1. Single-layer coFay ownership (`HumanID | OrganizationID`, forbidding `iFay` & `coFay` nesting)
 * 2. Orthogonal single-hop `managers` authority axis (no re-delegation; owner unchanged)
 * 3. Self-contained single-parent acyclic Organization Hierarchy (two-party consent, no 16-depth cap, no coFay rollup)
 * 4. Unlinkable `Dynamic Code` (`dyn_`) issuance & single-use TTL/replay-protected verification
 * 5. `Auth Exchange` scoped grants (`grt_`), verification receipts (`vrf_`), and deterministic cascading revocation
 */
export class AccountDirectory {
  constructor(options = {}) {
    const secret = options.authoritySecret ? Buffer.from(options.authoritySecret) : randomBytes(32);
    const normalizedSecret = secret.length >= 32
      ? secret
      : createHash("sha256").update(secret).digest();
    const exchangeSub = derivePurposeSubkey(
      normalizedSecret,
      subkeyDomains.AUTH_EXCHANGE,
      "grant-and-receipt-signer",
    );
    this._exchangeKey = exchangeSub.value;
    this._hmacSecret = Buffer.from(
      hkdfSync("sha256", normalizedSecret, Buffer.alloc(0), Buffer.from("ifay.fayid.internal-hmac.v1", "utf8"), 32),
    );
    this._resolverBlindSalt = Buffer.from(
      hkdfSync("sha256", normalizedSecret, Buffer.alloc(0), Buffer.from("ifay.fayid.resolver-blind.v1", "utf8"), 32),
    );

    this.humans = new Set();
    this.ifays = new Map();
    this.orgs = new Map();
    this.cofays = new Map();
    this.orgParents = new Map();
    this.revokedEntities = new Set();

    this._dynamicIndex = new Map();
    this._usedDynamicNonces = new Set();
    this.grants = new Map();
    this._grantCounter = 0;
    this._receiptCounter = 0;
  }

  isEntityRevoked(entityId) {
    if (typeof entityId !== "string") return false;
    return this.revokedEntities.has(entityId.toLowerCase());
  }

  _entityExists(kind, normId) {
    if (kind === "HUMAN_ID") return this.humans.has(normId);
    if (kind === "IFAY_ID") return this.ifays.has(normId);
    if (kind === "COFAY_ID") return this.cofays.has(normId);
    if (kind === "ORGANIZATION_ID") return this.orgs.has(normId);
    return false;
  }

  _protectOutboundSubjectRef(kind, normId) {
    if (kind !== "HUMAN_ID") return normId;
    const mac = createHmac("sha256", this._hmacSecret).update(`hid-proof:${normId}`, "utf8").digest();
    return `hidproof_${base32EncodeNoPad(mac.subarray(0, 20))}`;
  }

  registerHuman(humanId) {
    const parsed = parseCanonicalFayID(humanId);
    if (!parsed.ok || parsed.value.kind !== "HUMAN_ID") {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    if (this.revokedEntities.has(parsed.value.value)) {
      return err(accountErrorCodes.ENTITY_REVOKED);
    }
    this.humans.add(parsed.value.value);
    return ok(parsed.value.value);
  }

  registerIFay(ifayId, ownerHumanId) {
    const pIfay = parseCanonicalFayID(ifayId);
    const pHid = parseCanonicalFayID(ownerHumanId);
    if (!pIfay.ok || pIfay.value.kind !== "IFAY_ID" || !pHid.ok || pHid.value.kind !== "HUMAN_ID") {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    if (this.revokedEntities.has(pIfay.value.value) || this.revokedEntities.has(pHid.value.value)) {
      return err(accountErrorCodes.ENTITY_REVOKED);
    }
    this.ifays.set(pIfay.value.value, { id: pIfay.value.value, ownerHumanId: pHid.value.value });
    return ok(pIfay.value.value);
  }

  registerOrganization(orgId, stewardId) {
    const pOrg = parseCanonicalFayID(orgId);
    const pSteward = parseCanonicalFayID(stewardId);
    if (!pOrg.ok || pOrg.value.kind !== "ORGANIZATION_ID" || !pSteward.ok) {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    if (pSteward.value.kind !== "HUMAN_ID") {
      return err(accountErrorCodes.STEWARD_TYPE_NOT_ALLOWED);
    }
    if (this.revokedEntities.has(pOrg.value.value) || this.revokedEntities.has(pSteward.value.value)) {
      return err(accountErrorCodes.ENTITY_REVOKED);
    }
    this.orgs.set(pOrg.value.value, {
      id: pOrg.value.value,
      stewardHumanId: pSteward.value.value,
      managers: new Set(),
    });
    if (!this.orgParents.has(pOrg.value.value)) {
      this.orgParents.set(pOrg.value.value, null);
    }
    return ok(pOrg.value.value);
  }

  registerCoFay(cofayId, ownerId, signerId) {
    const pCofay = parseCanonicalFayID(cofayId);
    const pOwner = parseCanonicalFayID(ownerId);
    if (!pCofay.ok || pCofay.value.kind !== "COFAY_ID" || !pOwner.ok) {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    if (pOwner.value.kind !== "HUMAN_ID" && pOwner.value.kind !== "ORGANIZATION_ID") {
      return err(accountErrorCodes.OWNER_TYPE_NOT_ALLOWED);
    }
    const normOwner = pOwner.value.value;
    if (this.revokedEntities.has(pCofay.value.value) || this.revokedEntities.has(normOwner)) {
      return err(accountErrorCodes.ENTITY_REVOKED);
    }
    const normSigner = typeof signerId === "string" ? signerId.toLowerCase() : "";
    if (this.revokedEntities.has(normSigner)) {
      return err(accountErrorCodes.ENTITY_REVOKED);
    }
    if (pOwner.value.kind === "HUMAN_ID" && normSigner !== normOwner) {
      return err(accountErrorCodes.OWNERSHIP_NOT_PROVEN);
    }
    if (pOwner.value.kind === "ORGANIZATION_ID") {
      const orgRec = this.orgs.get(normOwner);
      if (!orgRec || (normSigner !== normOwner && normSigner !== orgRec.stewardHumanId)) {
        return err(accountErrorCodes.OWNERSHIP_NOT_PROVEN);
      }
    }
    const record = {
      id: pCofay.value.value,
      owner: normOwner,
      ownerKind: pOwner.value.kind === "HUMAN_ID" ? "human" : "organization",
      managers: new Set(),
    };
    this.cofays.set(pCofay.value.value, record);
    return ok({ id: record.id, owner: record.owner, ownerKind: record.ownerKind });
  }

  getCoFay(cofayId) {
    const rec = this.cofays.get(cofayId.toLowerCase());
    if (!rec) return null;
    return {
      id: rec.id,
      owner: rec.owner,
      ownerKind: rec.ownerKind,
      managers: Array.from(rec.managers),
    };
  }

  grantCoFayManager(cofayId, managerIfayId, signerId) {
    const rec = this.cofays.get(cofayId.toLowerCase());
    const pMgr = parseCanonicalFayID(managerIfayId);
    if (!rec || !pMgr.ok || pMgr.value.kind !== "IFAY_ID") {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    if (
      this.revokedEntities.has(rec.id) ||
      this.revokedEntities.has(rec.owner) ||
      this.revokedEntities.has(pMgr.value.value)
    ) {
      return err(accountErrorCodes.ENTITY_REVOKED);
    }
    const normSigner = signerId.toLowerCase();
    const isOwnerAuthorized =
      rec.ownerKind === "human"
        ? normSigner === rec.owner
        : normSigner === rec.owner || normSigner === this.orgs.get(rec.owner)?.stewardHumanId;
    if (!isOwnerAuthorized) {
      return err(accountErrorCodes.AUTHORITY_GRANT_UNAUTHORIZED);
    }
    rec.managers.add(pMgr.value.value);
    return ok({ id: rec.id, owner: rec.owner, managers: Array.from(rec.managers) });
  }

  revokeCoFayManager(cofayId, managerIfayId, signerId) {
    const rec = this.cofays.get(cofayId.toLowerCase());
    if (!rec) return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    const normSigner = signerId.toLowerCase();
    const isOwnerAuthorized =
      rec.ownerKind === "human"
        ? normSigner === rec.owner
        : normSigner === rec.owner || normSigner === this.orgs.get(rec.owner)?.stewardHumanId;
    if (!isOwnerAuthorized) {
      return err(accountErrorCodes.AUTHORITY_GRANT_UNAUTHORIZED);
    }
    rec.managers.delete(managerIfayId.toLowerCase());
    return ok({ id: rec.id, owner: rec.owner, managers: Array.from(rec.managers) });
  }

  canActForCoFay(cofayId, actorId) {
    const rec = this.cofays.get(cofayId.toLowerCase());
    if (!rec) return false;
    const normActor = actorId.toLowerCase();
    if (
      this.revokedEntities.has(rec.id) ||
      this.revokedEntities.has(rec.owner) ||
      this.revokedEntities.has(normActor)
    ) {
      return false;
    }
    return normActor === rec.owner || rec.managers.has(normActor);
  }

  setOrganizationParent({ org, parent, childSigned, parentSigned }) {
    const normOrg = org.toLowerCase();
    const normParent = parent === null ? null : parent.toLowerCase();
    if (!this.orgs.has(normOrg) || (normParent !== null && !this.orgs.has(normParent))) {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    if (this.revokedEntities.has(normOrg) || (normParent !== null && this.revokedEntities.has(normParent))) {
      return err(accountErrorCodes.ENTITY_REVOKED);
    }
    if (!childSigned || (normParent !== null && !parentSigned)) {
      return err(accountErrorCodes.HIERARCHY_CONSENT_MISSING);
    }
    if (normParent !== null) {
      if (normParent === normOrg) {
        return err(accountErrorCodes.HIERARCHY_CYCLE_CONFLICT);
      }
      let cursor = normParent;
      while (cursor !== null) {
        if (cursor === normOrg) {
          return err(accountErrorCodes.HIERARCHY_CYCLE_CONFLICT);
        }
        cursor = this.orgParents.get(cursor) ?? null;
      }
    }
    this.orgParents.set(normOrg, normParent);
    return ok({ org: normOrg, parent: normParent });
  }

  getAncestorChain(orgId) {
    const normOrg = orgId.toLowerCase();
    if (!this.orgs.has(normOrg)) return [];
    const reversed = [];
    let cursor = normOrg;
    while (cursor !== null) {
      reversed.push(cursor);
      cursor = this.orgParents.get(cursor) ?? null;
    }
    return reversed.reverse();
  }

  /**
   * Issues a short-lived, nonce-salted unlinkable `DynamicCode` (`dyn_<base32>`) bound to a
   * `HumanID`, `iFayID`, or `coFayID`. Rejects `OrganizationID`, excessive TTL, or nonce reuse.
   */
  issueDynamicCode({ subjectId, holderSecret, nonce, issuedAtSec, expiresAtSec }) {
    const parsed = parseCanonicalFayID(subjectId);
    if (!parsed.ok) {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    const { kind, value: normId } = parsed.value;
    if (kind === "ORGANIZATION_ID") {
      return err(accountErrorCodes.DYNAMIC_CODE_TARGET_NOT_ALLOWED);
    }
    if (kind !== "HUMAN_ID" && kind !== "IFAY_ID" && kind !== "COFAY_ID") {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    if (!this._entityExists(kind, normId)) {
      return err(accountErrorCodes.DYNAMIC_CODE_INVALID);
    }
    if (this.revokedEntities.has(normId)) {
      return err(accountErrorCodes.ENTITY_REVOKED);
    }
    if (!holderSecret || Buffer.from(holderSecret).length < 16) {
      return err(accountErrorCodes.INSUFFICIENT_ENTROPY);
    }
    const nonceBuf = nonce ? Buffer.from(nonce) : randomBytes(16);
    if (nonceBuf.length < 8) {
      return err(accountErrorCodes.INSUFFICIENT_ENTROPY);
    }
    if (
      typeof issuedAtSec !== "number" ||
      typeof expiresAtSec !== "number" ||
      expiresAtSec <= issuedAtSec ||
      expiresAtSec - issuedAtSec > baselineLimits.DYNAMIC_CODE_MAX_TTL_SECONDS
    ) {
      return err(accountErrorCodes.DYNAMIC_CODE_INVALID);
    }

    const nonceKey = `${normId}:${nonceBuf.toString("hex")}`;
    if (this._usedDynamicNonces.has(nonceKey)) {
      return err(accountErrorCodes.DYNAMIC_CODE_REPLAYED);
    }

    const subjectSecret = Buffer.from(
      hkdfSync(
        "sha256",
        Buffer.from(holderSecret),
        Buffer.from(normId, "utf8"),
        Buffer.from(subkeyDomains.DYNAMIC_CODE, "utf8"),
        32,
      ),
    );
    const payload = Buffer.from(
      hkdfSync(
        "sha256",
        subjectSecret,
        nonceBuf,
        Buffer.from(`${subkeyDomains.DYNAMIC_CODE}:${issuedAtSec}:${expiresAtSec}`, "utf8"),
        16,
      ),
    );
    subjectSecret.fill(0);

    const code = `${prefixes.DYNAMIC_CODE}${base32EncodeNoPad(payload)}`;
    const lookupKey = createHmac("sha256", this._hmacSecret).update(`dyn:${code}`, "utf8").digest("hex");
    if (this._dynamicIndex.has(lookupKey)) {
      return err(accountErrorCodes.DYNAMIC_CODE_INVALID);
    }

    this._usedDynamicNonces.add(nonceKey);
    this._dynamicIndex.set(lookupKey, {
      subjectKind: kind,
      subjectId: normId,
      issuedAtSec,
      expiresAtSec,
      consumed: false,
    });

    return ok({
      code,
      issuedAtSec,
      expiresAtSec,
    });
  }

  /**
   * Resolves and consumes a `dyn_<base32>` token with strict `expiresAt` TTL check and single-use
   * replay rejection. For `HumanID`, returns a blind `gmcref_` commitment rather than plaintext `hid_`.
   */
  verifyDynamicCode(code, nowSec) {
    const parsed = parseCanonicalFayID(code);
    if (!parsed.ok || parsed.value.kind !== "DYNAMIC_CODE") {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    const normCode = parsed.value.value;
    const lookupKey = createHmac("sha256", this._hmacSecret).update(`dyn:${normCode}`, "utf8").digest("hex");
    const entry = this._dynamicIndex.get(lookupKey);
    if (!entry) {
      return err(accountErrorCodes.DYNAMIC_CODE_INVALID);
    }
    if (this.revokedEntities.has(entry.subjectId)) {
      return err(accountErrorCodes.ENTITY_REVOKED);
    }
    if (typeof nowSec !== "number" || nowSec > entry.expiresAtSec) {
      return err(accountErrorCodes.DYNAMIC_CODE_EXPIRED);
    }
    if (entry.consumed) {
      return err(accountErrorCodes.DYNAMIC_CODE_REPLAYED);
    }
    entry.consumed = true;

    let resolvedRef = entry.subjectId;
    if (entry.subjectKind === "HUMAN_ID") {
      const blindRes = deriveBlindGmcRef(entry.subjectId, this._resolverBlindSalt, "ifay.fayid.resolver-ref.v1");
      if (!blindRes.ok) return blindRes;
      resolvedRef = blindRes.value;
    }

    return ok({
      code: normCode,
      subjectKind: entry.subjectKind,
      resolvedRef,
      issuedAtSec: entry.issuedAtSec,
      expiresAtSec: entry.expiresAtSec,
    });
  }

  /**
   * Issues a scoped `Auth Exchange` credential grant (`grt_<base32>`).
   */
  issueAuthGrant({
    targetId,
    actorId,
    resourceRef,
    scopeMode = "EXACT",
    legacySourceKind = "ACCESS_TOKEN",
    legacyIssuer = "local",
    legacySubject = "holder",
    issuedAtSec,
    expiresAtSec,
  }) {
    const pTarget = parseCanonicalFayID(targetId);
    if (
      !pTarget.ok ||
      (pTarget.value.kind !== "HUMAN_ID" &&
        pTarget.value.kind !== "IFAY_ID" &&
        pTarget.value.kind !== "COFAY_ID")
    ) {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    const normTarget = pTarget.value.value;
    const targetKind = pTarget.value.kind;
    if (!this._entityExists(targetKind, normTarget)) {
      return err(accountErrorCodes.TARGET_OWNERSHIP_NOT_PROVEN);
    }

    const pActor = actorId ? parseCanonicalFayID(actorId) : pTarget;
    if (!pActor.ok) {
      return err(accountErrorCodes.TARGET_OWNERSHIP_NOT_PROVEN);
    }
    const normActor = pActor.value.value;

    if (this.revokedEntities.has(normTarget) || this.revokedEntities.has(normActor)) {
      return err(accountErrorCodes.ENTITY_REVOKED);
    }

    let ownerEntityId = normTarget;
    if (targetKind === "HUMAN_ID") {
      if (normActor !== normTarget) return err(accountErrorCodes.TARGET_OWNERSHIP_NOT_PROVEN);
    } else if (targetKind === "IFAY_ID") {
      const ifayRec = this.ifays.get(normTarget);
      ownerEntityId = ifayRec.ownerHumanId;
      if (this.revokedEntities.has(ownerEntityId)) return err(accountErrorCodes.ENTITY_REVOKED);
      if (normActor !== normTarget && normActor !== ownerEntityId) {
        return err(accountErrorCodes.TARGET_OWNERSHIP_NOT_PROVEN);
      }
    } else if (targetKind === "COFAY_ID") {
      const cofayRec = this.cofays.get(normTarget);
      ownerEntityId = cofayRec.owner;
      if (this.revokedEntities.has(ownerEntityId)) return err(accountErrorCodes.ENTITY_REVOKED);
      const orgSteward = cofayRec.ownerKind === "organization"
        ? this.orgs.get(cofayRec.owner)?.stewardHumanId
        : null;
      const authorized =
        normActor === normTarget ||
        this.canActForCoFay(normTarget, normActor) ||
        (orgSteward !== null && normActor === orgSteward);
      if (!authorized) {
        return err(accountErrorCodes.TARGET_OWNERSHIP_NOT_PROVEN);
      }
    }

    if (scopeMode !== "EXACT" && scopeMode !== "PREFIX") {
      return err(accountErrorCodes.GRANT_INVALID);
    }
    const normRes = normalizeResourceRef(resourceRef);
    if (!normRes.ok) {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    const trustLevel = LEGACY_TRUST_DEFAULTS[legacySourceKind];
    if (!trustLevel || typeof legacyIssuer !== "string" || !legacyIssuer || legacyIssuer.includes(":")) {
      return err(accountErrorCodes.LEGACY_AUTH_FAILED);
    }

    const maxTtl =
      trustLevel === "LOW"
        ? baselineLimits.LOW_TRUST_GRANT_MAX_TTL_SECONDS
        : baselineLimits.GRANT_MAX_TTL_SECONDS;
    if (
      typeof issuedAtSec !== "number" ||
      typeof expiresAtSec !== "number" ||
      expiresAtSec <= issuedAtSec ||
      expiresAtSec - issuedAtSec > maxTtl
    ) {
      return err(accountErrorCodes.GRANT_INVALID);
    }

    const subjectMac = createHmac("sha256", this._hmacSecret)
      .update(`${legacySourceKind}:${legacyIssuer}:${legacySubject}`, "utf8")
      .digest();
    const legacySubjectRef = `${legacySourceKind}:${legacyIssuer}:${base32EncodeNoPad(subjectMac.subarray(0, 20))}`;

    this._grantCounter += 1;
    const outboundTargetRef = this._protectOutboundSubjectRef(targetKind, normTarget);
    const grantDigest = createHmac("sha256", this._hmacSecret)
      .update(`grt:${this._grantCounter}:${outboundTargetRef}:${normRes.value}:${issuedAtSec}`, "utf8")
      .digest();
    const grantId = `${prefixes.AUTHORIZATION_GRANT}${base32EncodeNoPad(grantDigest.subarray(0, 16))}`;

    const signedCore = {
      version: "1.0",
      grantId,
      targetRef: outboundTargetRef,
      legacySubjectRef,
      legacySourceKind,
      legacyTrustLevel: trustLevel,
      resourceRef: normRes.value,
      scopeMode,
      issuedAtSec,
      expiresAtSec,
      initialStatusVersion: 1,
    };
    const signatureHex = this._exchangeKey
      .signPayload(Buffer.from(canonicalizeJcs(signedCore), "utf8"))
      .toString("hex");

    this.grants.set(grantId, {
      ...signedCore,
      signatureHex,
      issuerPublicKeyHex: this._exchangeKey.publicKeyHex,
      rawTargetId: normTarget,
      rawActorId: normActor,
      ownerEntityId,
      statusVersion: 1,
      state: "ACTIVE",
    });

    return ok({
      ...signedCore,
      signatureHex,
      issuerPublicKeyHex: this._exchangeKey.publicKeyHex,
      statusVersion: 1,
      state: "ACTIVE",
    });
  }

  /**
   * Verifies an `Auth Exchange` grant (`grt_`) and emits a signed Verification Receipt (`vrf_`).
   */
  verifyAuthGrant({ grantId, requestedResourceRef, nowSec }) {
    const parsed = parseCanonicalFayID(grantId);
    if (!parsed.ok || parsed.value.kind !== "AUTHORIZATION_GRANT") {
      return err(accountErrorCodes.GRANT_INVALID);
    }
    const rec = this.grants.get(parsed.value.value);
    if (!rec) {
      return err(accountErrorCodes.GRANT_INVALID);
    }

    const signedCore = {
      version: rec.version,
      grantId: rec.grantId,
      targetRef: rec.targetRef,
      legacySubjectRef: rec.legacySubjectRef,
      legacySourceKind: rec.legacySourceKind,
      legacyTrustLevel: rec.legacyTrustLevel,
      resourceRef: rec.resourceRef,
      scopeMode: rec.scopeMode,
      issuedAtSec: rec.issuedAtSec,
      expiresAtSec: rec.expiresAtSec,
      initialStatusVersion: rec.initialStatusVersion,
    };
    const sigOk = verifyEd25519Signature(
      Buffer.from(rec.issuerPublicKeyHex, "hex"),
      Buffer.from(canonicalizeJcs(signedCore), "utf8"),
      Buffer.from(rec.signatureHex, "hex"),
    );
    if (!sigOk) {
      return err(accountErrorCodes.GRANT_INVALID);
    }

    if (
      rec.state === "REVOKED" ||
      this.revokedEntities.has(rec.rawTargetId) ||
      this.revokedEntities.has(rec.rawActorId) ||
      this.revokedEntities.has(rec.ownerEntityId)
    ) {
      if (rec.state !== "REVOKED") {
        rec.state = "REVOKED";
        rec.statusVersion += 1;
      }
      return err(accountErrorCodes.GRANT_REVOKED);
    }

    if (typeof nowSec !== "number" || nowSec > rec.expiresAtSec) {
      return err(accountErrorCodes.GRANT_EXPIRED);
    }

    if (!matchesResourceRef(rec.resourceRef, requestedResourceRef, rec.scopeMode)) {
      return err(accountErrorCodes.GRANT_INVALID);
    }

    const normReq = normalizeResourceRef(requestedResourceRef);
    this._receiptCounter += 1;
    const receiptDigest = createHmac("sha256", this._hmacSecret)
      .update(`vrf:${this._receiptCounter}:${rec.grantId}:${normReq.value}:${nowSec}`, "utf8")
      .digest();
    const receiptId = `${prefixes.VERIFICATION_CODE}${base32EncodeNoPad(receiptDigest.subarray(0, 16))}`;
    const receiptCore = {
      version: "1.0",
      receiptId,
      grantId: rec.grantId,
      requestedResourceRef: normReq.value,
      scopeMode: rec.scopeMode,
      verifiedAtSec: nowSec,
      statusVersion: rec.statusVersion,
      verifierPublicKeyHex: this._exchangeKey.publicKeyHex,
    };
    const receiptSigHex = this._exchangeKey
      .signPayload(Buffer.from(canonicalizeJcs(receiptCore), "utf8"))
      .toString("hex");

    return ok({
      valid: true,
      grantId: rec.grantId,
      receipt: {
        ...receiptCore,
        signatureHex: receiptSigHex,
      },
    });
  }

  /**
   * Explicitly revokes a single `grt_` grant idempotently.
   */
  revokeGrant(grantId, signerId) {
    const parsed = parseCanonicalFayID(grantId);
    if (!parsed.ok || parsed.value.kind !== "AUTHORIZATION_GRANT") {
      return err(accountErrorCodes.GRANT_INVALID);
    }
    const rec = this.grants.get(parsed.value.value);
    if (!rec) {
      return err(accountErrorCodes.GRANT_INVALID);
    }
    const normSigner = typeof signerId === "string" ? signerId.toLowerCase() : "";
    const orgSteward = this.orgs.get(rec.ownerEntityId)?.stewardHumanId ?? null;
    if (
      normSigner !== rec.rawTargetId &&
      normSigner !== rec.rawActorId &&
      normSigner !== rec.ownerEntityId &&
      normSigner !== orgSteward
    ) {
      return err(accountErrorCodes.OWNERSHIP_NOT_PROVEN);
    }
    if (rec.state !== "REVOKED") {
      rec.state = "REVOKED";
      rec.statusVersion += 1;
    }
    return ok({ grantId: rec.grantId, state: rec.state, statusVersion: rec.statusVersion });
  }

  _collectOrgDescendants(rootOrgId) {
    const visited = new Set([rootOrgId]);
    const queue = [rootOrgId];
    while (queue.length > 0) {
      const current = queue.shift();
      for (const [orgId, parentId] of this.orgParents.entries()) {
        if (parentId === current && !visited.has(orgId)) {
          visited.add(orgId);
          queue.push(orgId);
        }
      }
    }
    return visited;
  }

  /**
   * Deterministically revokes a `HumanID`, `OrganizationID`, `iFayID`, or `coFayID` and cascades
   * revocation across all downstream owned/managed entities and active `grt_` grants.
   */
  revokeEntity(entityId, signerId) {
    const parsed = parseCanonicalFayID(entityId);
    if (!parsed.ok) {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }
    const { kind, value: normId } = parsed.value;
    if (!this._entityExists(kind, normId)) {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
    }

    if (signerId !== undefined) {
      const normSigner = String(signerId).toLowerCase();
      if (kind === "HUMAN_ID") {
        if (normSigner !== normId) return err(accountErrorCodes.HUMAN_ID_OWNERSHIP_NOT_PROVEN);
      } else if (kind === "IFAY_ID") {
        const ifayRec = this.ifays.get(normId);
        if (normSigner !== normId && normSigner !== ifayRec.ownerHumanId) {
          return err(accountErrorCodes.HUMAN_ID_OWNERSHIP_NOT_PROVEN);
        }
      } else if (kind === "ORGANIZATION_ID") {
        const orgRec = this.orgs.get(normId);
        if (normSigner !== normId && normSigner !== orgRec.stewardHumanId) {
          return err(accountErrorCodes.OWNERSHIP_NOT_PROVEN);
        }
      } else if (kind === "COFAY_ID") {
        const cofayRec = this.cofays.get(normId);
        const orgSteward = cofayRec.ownerKind === "organization"
          ? this.orgs.get(cofayRec.owner)?.stewardHumanId
          : null;
        if (normSigner !== cofayRec.owner && normSigner !== orgSteward) {
          return err(accountErrorCodes.OWNERSHIP_NOT_PROVEN);
        }
      }
    }

    const cascaded = new Set();
    if (kind === "HUMAN_ID") {
      cascaded.add(normId);
      for (const ifayRec of this.ifays.values()) {
        if (ifayRec.ownerHumanId === normId) cascaded.add(ifayRec.id);
      }
      for (const orgRec of this.orgs.values()) {
        if (orgRec.stewardHumanId === normId) {
          for (const descOrg of this._collectOrgDescendants(orgRec.id)) {
            cascaded.add(descOrg);
          }
        }
      }
      for (const cofayRec of this.cofays.values()) {
        if (cofayRec.owner === normId || cascaded.has(cofayRec.owner)) {
          cascaded.add(cofayRec.id);
        }
      }
    } else if (kind === "ORGANIZATION_ID") {
      for (const descOrg of this._collectOrgDescendants(normId)) {
        cascaded.add(descOrg);
      }
      for (const cofayRec of this.cofays.values()) {
        if (cascaded.has(cofayRec.owner)) {
          cascaded.add(cofayRec.id);
        }
      }
    } else if (kind === "IFAY_ID" || kind === "COFAY_ID") {
      cascaded.add(normId);
    }

    for (const id of cascaded) {
      this.revokedEntities.add(id);
    }

    for (const cofayRec of this.cofays.values()) {
      if (this.revokedEntities.has(cofayRec.id)) {
        cofayRec.managers.clear();
      } else {
        for (const mgr of Array.from(cofayRec.managers)) {
          if (this.revokedEntities.has(mgr)) cofayRec.managers.delete(mgr);
        }
      }
    }
    for (const orgRec of this.orgs.values()) {
      if (this.revokedEntities.has(orgRec.id)) {
        orgRec.managers.clear();
      } else {
        for (const mgr of Array.from(orgRec.managers)) {
          if (this.revokedEntities.has(mgr)) orgRec.managers.delete(mgr);
        }
      }
    }

    const revokedGrants = [];
    for (const grantRec of this.grants.values()) {
      if (
        cascaded.has(grantRec.rawTargetId) ||
        cascaded.has(grantRec.rawActorId) ||
        cascaded.has(grantRec.ownerEntityId)
      ) {
        if (grantRec.state !== "REVOKED") {
          grantRec.state = "REVOKED";
          grantRec.statusVersion += 1;
        }
        revokedGrants.push(grantRec.grantId);
      }
    }

    return ok({
      revokedEntities: Array.from(cascaded).sort(),
      revokedGrants: revokedGrants.sort(),
    });
  }
}
