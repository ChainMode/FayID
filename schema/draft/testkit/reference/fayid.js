export const prefixes = Object.freeze({
  HUMAN_ID: "hid_",
  IFAY_ID: "ifay_",
  COFAY_ID: "cofay_",
  ORGANIZATION_ID: "org_",
  DYNAMIC_CODE: "dyn_",
  VERIFICATION_CODE: "vrf_",
  AUTHORIZATION_GRANT: "grt_",
  OPAQUE_REF: "gmcref_",
});

export const errorCodes = Object.freeze({
  INSUFFICIENT_ENTROPY: "INSUFFICIENT_ENTROPY",
  HUMAN_ID_OWNERSHIP_NOT_PROVEN: "HUMAN_ID_OWNERSHIP_NOT_PROVEN",
  OWNERSHIP_NOT_PROVEN: "OWNERSHIP_NOT_PROVEN",
  TARGET_OWNERSHIP_NOT_PROVEN: "TARGET_OWNERSHIP_NOT_PROVEN",
  LEGACY_SUBJECT_MISMATCH: "LEGACY_SUBJECT_MISMATCH",
  DYNAMIC_CODE_EXPIRED: "DYNAMIC_CODE_EXPIRED",
  DYNAMIC_CODE_INVALID: "DYNAMIC_CODE_INVALID",
  VERIFICATION_RATE_LIMITED: "VERIFICATION_RATE_LIMITED",
  IDENTITY_REVOKED: "IDENTITY_REVOKED",
  LEGACY_AUTH_FAILED: "LEGACY_AUTH_FAILED",
  GRANT_EXPIRED: "GRANT_EXPIRED",
  GRANT_REVOKED: "GRANT_REVOKED",
  GRANT_INVALID: "GRANT_INVALID",
  MALFORMED_FAYID_STRING: "MALFORMED_FAYID_STRING",
});

export const baselineLimits = Object.freeze({
  DYNAMIC_CODE_MAX_TTL_SECONDS: 600,
  PROOF_CHALLENGE_MAX_TTL_SECONDS: 300,
  GRANT_MAX_TTL_SECONDS: 3600,
  LOW_TRUST_GRANT_MAX_TTL_SECONDS: 900,
  VERIFY_GRANT_CACHE_MAX_SECONDS: 60,
  VERIFICATION_CODE_FAILURE_WINDOW_SECONDS: 600,
  VERIFICATION_CODE_FAILURE_THRESHOLD: 5,
  VERIFICATION_CODE_INITIAL_BACKOFF_SECONDS: 300,
  VERIFICATION_CODE_MAX_BACKOFF_SECONDS: 3600,
});

const base32NoPad = /^[a-z2-7]+$/;
const orgBody = /^[a-z0-9-]+$/;

const kinds = [
  ["OPAQUE_REF", prefixes.OPAQUE_REF, base32NoPad],
  ["VERIFICATION_CODE", prefixes.VERIFICATION_CODE, base32NoPad],
  ["AUTHORIZATION_GRANT", prefixes.AUTHORIZATION_GRANT, base32NoPad],
  ["DYNAMIC_CODE", prefixes.DYNAMIC_CODE, base32NoPad],
  ["COFAY_ID", prefixes.COFAY_ID, base32NoPad],
  ["IFAY_ID", prefixes.IFAY_ID, base32NoPad],
  ["ORGANIZATION_ID", prefixes.ORGANIZATION_ID, orgBody],
  ["HUMAN_ID", prefixes.HUMAN_ID, base32NoPad],
];

export function normalizeFayID(input) {
  if (typeof input !== "string" || input.length === 0) {
    return err(errorCodes.MALFORMED_FAYID_STRING);
  }
  const normalized = input.toLowerCase();
  const match = kinds.find(([, prefix]) => normalized.startsWith(prefix));
  if (!match) return err(errorCodes.MALFORMED_FAYID_STRING);

  const [kind, prefix, bodyPattern] = match;
  const body = normalized.slice(prefix.length);
  if (body.length === 0 || !bodyPattern.test(body)) {
    return err(errorCodes.MALFORMED_FAYID_STRING);
  }
  return ok({ kind, value: normalized });
}

export function parseFayID(input) {
  return normalizeFayID(input);
}

export function serializeFayID(entity) {
  if (!entity || typeof entity !== "object") {
    return err(errorCodes.MALFORMED_FAYID_STRING);
  }
  if (entity.kind === "OPAQUE_REF") return normalizeFayID(entity.value);
  if (typeof entity.id === "string") return normalizeFayID(entity.id);
  if (typeof entity.code === "string") return normalizeFayID(entity.code);
  if (typeof entity.grantID === "string") {
    return normalizeFayID(entity.grantID);
  }
  return err(errorCodes.MALFORMED_FAYID_STRING);
}

export function normalizeResourceRef(input) {
  let url;
  try {
    url = new URL(input);
  } catch {
    return err(errorCodes.MALFORMED_FAYID_STRING);
  }

  if (url.username || url.password) {
    return err(errorCodes.MALFORMED_FAYID_STRING);
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return ok(input);
  }

  url.protocol = url.protocol.toLowerCase();
  url.hostname = url.hostname.toLowerCase();
  if (
    (url.protocol === "http:" && url.port === "80") ||
    (url.protocol === "https:" && url.port === "443")
  ) {
    url.port = "";
  }

  return ok(url.toString());
}

export function matchesResourceRef(grantRef, requestRef, scopeMode = "EXACT") {
  const grant = normalizeResourceRef(grantRef);
  const request = normalizeResourceRef(requestRef);
  if (!grant.ok || !request.ok) return false;
  if (scopeMode === "EXACT") return grant.value === request.value;
  if (scopeMode !== "PREFIX") return false;

  const grantUrl = new URL(grant.value);
  const requestUrl = new URL(request.value);
  if (
    grantUrl.protocol !== requestUrl.protocol ||
    grantUrl.host !== requestUrl.host
  ) {
    return false;
  }

  const base = stripTrailingSlash(grantUrl.pathname);
  const path = stripTrailingSlash(requestUrl.pathname);
  return path === base || path.startsWith(`${base}/`);
}

export function ok(value) {
  return { ok: true, value };
}

export function err(error) {
  return { ok: false, error };
}

function stripTrailingSlash(value) {
  return value.length > 1 ? value.replace(/\/+$/u, "") : value;
}
