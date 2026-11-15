import {
  createHash,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  sign,
  verify,
} from "node:crypto";
import { normalizeFayID, prefixes, errorCodes, ok, err } from "../schema/draft/testkit/reference/fayid.js";

const RFC4648_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export const accountErrorCodes = Object.freeze({
  ...errorCodes,
  OWNER_TYPE_NOT_ALLOWED: "OWNER_TYPE_NOT_ALLOWED",
  HIERARCHY_CONSENT_MISSING: "HIERARCHY_CONSENT_MISSING",
  HIERARCHY_CYCLE_CONFLICT: "HIERARCHY_CYCLE_CONFLICT",
  AUTHORITY_GRANT_UNAUTHORIZED: "AUTHORITY_GRANT_UNAUTHORIZED",
  STEWARD_TYPE_NOT_ALLOWED: "STEWARD_TYPE_NOT_ALLOWED",
});

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
  const privKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, buf.subarray(0, 32)]),
    format: "der",
    type: "pkcs8",
  });
  const pubKey = createPublicKey(privKey);
  const spki = pubKey.export({ format: "der", type: "spki" });
  const publicKeyRaw = Buffer.from(spki.subarray(spki.length - 32));
  const idBytes = createHash("sha256").update(publicKeyRaw).digest();
  const humanId = `${prefixes.HUMAN_ID}${base32EncodeNoPad(idBytes)}`;

  return {
    humanId,
    idBytes,
    publicKeyRaw,
    signPayload(payloadBytes) {
      return sign(null, Buffer.from(payloadBytes), privKey);
    },
  };
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
 * Holder-of-Key Dynamic Code derivation (§6.3) using local root derive key.
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
 * Blind OpaqueRef (`gmcref_`) derivation (§6.5) for GMChain natural-person voting normalization
 * and cold-start Sybil deduplication without exposing plaintext `HumanID` (ADR 0002).
 */
export function deriveOpaqueRef(humanIdBytes, gmcNamespaceSecret) {
  const derived = Buffer.from(
    hkdfSync("sha256", Buffer.from(gmcNamespaceSecret), Buffer.from(humanIdBytes), Buffer.from("fayid/gmc/v1", "utf8"), 32),
  );
  return `${prefixes.OPAQUE_REF}${base32EncodeNoPad(derived)}`;
}

/**
 * Self-contained FayID Account Directory enforcing:
 * 1. Single-layer coFay ownership (`HumanID | OrganizationID`, forbidding `iFay` & `coFay` nesting)
 * 2. Orthogonal single-hop `managers` authority axis (no re-delegation; owner unchanged)
 * 3. Self-contained single-parent acyclic Organization Hierarchy (two-party consent, no 16-depth cap, no coFay rollup)
 */
export class AccountDirectory {
  constructor() {
    this.humans = new Set();
    this.ifays = new Map();
    this.orgs = new Map();
    this.cofays = new Map();
    this.orgParents = new Map();
  }

  registerHuman(humanId) {
    const parsed = parseCanonicalFayID(humanId);
    if (!parsed.ok || parsed.value.kind !== "HUMAN_ID") {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
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
    if (pOwner.value.kind === "HUMAN_ID" && signerId !== normOwner) {
      return err(accountErrorCodes.OWNERSHIP_NOT_PROVEN);
    }
    if (pOwner.value.kind === "ORGANIZATION_ID") {
      const orgRec = this.orgs.get(normOwner);
      if (!orgRec || (signerId !== normOwner && signerId !== orgRec.stewardHumanId)) {
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
    return normActor === rec.owner || rec.managers.has(normActor);
  }

  setOrganizationParent({ org, parent, childSigned, parentSigned }) {
    const normOrg = org.toLowerCase();
    const normParent = parent === null ? null : parent.toLowerCase();
    if (!this.orgs.has(normOrg) || (normParent !== null && !this.orgs.has(normParent))) {
      return err(accountErrorCodes.MALFORMED_FAYID_STRING);
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
}
