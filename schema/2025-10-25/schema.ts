// FayID 1.0 Normative TypeScript Schema (2025-10-25 Edition)

export const FAYID_VERSION = "1.0" as const;

export const FAYID_PREFIXES = {
  HUMAN_ID: "hid_",
  IFAY_ID: "ifay_",
  COFAY_ID: "cofay_",
  ORGANIZATION_ID: "org_",
  DYNAMIC_CODE: "dyn_",
  VERIFICATION_CODE: "vrf_",
  AUTHORIZATION_GRANT: "grt_",
  OPAQUE_REF: "gmcref_",
} as const;

export const SUBKEY_DOMAINS = {
  ENTITY: "ifay.fayid.entity.v1",
  EGO_PACKAGE_SIGNING: "ifay.ego.package-signing.v1",
  DYNAMIC_CODE: "ifay.fayid.dynamic-code.v1",
  AUTH_EXCHANGE: "ifay.fayid.auth-exchange.v1",
  GMC_NATURAL_PERSON: "ifay.gmc.natural-person.v1",
} as const;

export const FAYID_ERROR_CODES = {
  INSUFFICIENT_ENTROPY: "INSUFFICIENT_ENTROPY",
  HUMAN_ID_OWNERSHIP_NOT_PROVEN: "HUMAN_ID_OWNERSHIP_NOT_PROVEN",
  OWNERSHIP_NOT_PROVEN: "OWNERSHIP_NOT_PROVEN",
  TARGET_OWNERSHIP_NOT_PROVEN: "TARGET_OWNERSHIP_NOT_PROVEN",
  LEGACY_SUBJECT_MISMATCH: "LEGACY_SUBJECT_MISMATCH",
  DYNAMIC_CODE_EXPIRED: "DYNAMIC_CODE_EXPIRED",
  DYNAMIC_CODE_INVALID: "DYNAMIC_CODE_INVALID",
  DYNAMIC_CODE_REPLAYED: "DYNAMIC_CODE_REPLAYED",
  DYNAMIC_CODE_TARGET_NOT_ALLOWED: "DYNAMIC_CODE_TARGET_NOT_ALLOWED",
  VERIFICATION_RATE_LIMITED: "VERIFICATION_RATE_LIMITED",
  IDENTITY_REVOKED: "IDENTITY_REVOKED",
  ENTITY_REVOKED: "ENTITY_REVOKED",
  LEGACY_AUTH_FAILED: "LEGACY_AUTH_FAILED",
  GRANT_EXPIRED: "GRANT_EXPIRED",
  GRANT_REVOKED: "GRANT_REVOKED",
  GRANT_INVALID: "GRANT_INVALID",
  MALFORMED_FAYID_STRING: "MALFORMED_FAYID_STRING",
  OWNER_TYPE_NOT_ALLOWED: "OWNER_TYPE_NOT_ALLOWED",
  HIERARCHY_CONSENT_MISSING: "HIERARCHY_CONSENT_MISSING",
  HIERARCHY_CYCLE_CONFLICT: "HIERARCHY_CYCLE_CONFLICT",
  AUTHORITY_GRANT_UNAUTHORIZED: "AUTHORITY_GRANT_UNAUTHORIZED",
  STEWARD_TYPE_NOT_ALLOWED: "STEWARD_TYPE_NOT_ALLOWED",
  DOMAIN_SEPARATION_REQUIRED: "DOMAIN_SEPARATION_REQUIRED",
  RECEIPT_INVALID: "RECEIPT_INVALID",
} as const;

export type FayIDErrorCode =
  (typeof FAYID_ERROR_CODES)[keyof typeof FAYID_ERROR_CODES];
export type OwnerKind = "HUMAN" | "ORGANIZATION";
export type ScopeMode = "EXACT" | "PREFIX";
export type GrantState = "ACTIVE" | "EXPIRED" | "REVOKED";

export interface VerificationReceipt {
  version: "1.0";
  receiptId: string;
  grantId: string;
  requestedResourceRef: string;
  scopeMode: ScopeMode;
  verifiedAtSec: number;
  statusVersion: number;
  verifierPublicKeyHex: string;
  signatureHex: string;
}

export interface EgoPackageSignatureEnvelope {
  version: "1.0";
  domain: "ifay.ego.package-signing.v1";
  signerFayId: string;
  keyIndex: number;
  publicKeyHex: string;
  payloadDigestHex: string;
  signatureHex: string;
}
