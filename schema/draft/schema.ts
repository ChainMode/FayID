// FayID Schema (Draft)
// Mirrors docs/zh-CN/specification/draft/fayid-protocol.md.

export const FAYID_VERSION = "draft" as const;

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

export type EntityKind = keyof typeof FAYID_PREFIXES;
export type FayIDPrefix = (typeof FAYID_PREFIXES)[EntityKind];

export const MIN_ENTROPY_BITS = {
  HUMAN_ID: 256,
  IFAY_ID: 192,
  COFAY_ID: 192,
  DYNAMIC_CODE_PAYLOAD: 128,
  VERIFICATION_CODE: 128,
  AUTHORIZATION_GRANT: 128,
  OPAQUE_REF: 256,
} as const;

export const FAYID_ERROR_CODES = {
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
} as const;

export type FayIDErrorCode =
  (typeof FAYID_ERROR_CODES)[keyof typeof FAYID_ERROR_CODES];

export type OwnerKind = "HUMAN" | "ORGANIZATION";
export type LegacySourceKind =
  | "PASSWORD"
  | "CERTIFICATE"
  | "AUTHORIZATION"
  | "ACCESS_TOKEN"
  | "SMART_CONTRACT";
export type LegacyTrustLevel = "LOW" | "MEDIUM" | "HIGH";
export type GrantState = "ACTIVE" | "EXPIRED" | "REVOKED";
export type ScopeMode = "EXACT" | "PREFIX";

export const LEGACY_TRUST_LEVEL_BY_SOURCE: Record<
  LegacySourceKind,
  LegacyTrustLevel
> = {
  PASSWORD: "LOW",
  ACCESS_TOKEN: "MEDIUM",
  AUTHORIZATION: "MEDIUM",
  CERTIFICATE: "HIGH",
  SMART_CONTRACT: "HIGH",
};

export const BASELINE_LIMITS = {
  DYNAMIC_CODE_MAX_TTL_SECONDS: 10 * 60,
  PROOF_CHALLENGE_MAX_TTL_SECONDS: 5 * 60,
  GRANT_MAX_TTL_SECONDS: 60 * 60,
  LOW_TRUST_GRANT_MAX_TTL_SECONDS: 15 * 60,
  VERIFY_GRANT_CACHE_MAX_SECONDS: 60,
  VERIFICATION_CODE_FAILURE_WINDOW_SECONDS: 10 * 60,
  VERIFICATION_CODE_FAILURE_THRESHOLD: 5,
  VERIFICATION_CODE_INITIAL_BACKOFF_SECONDS: 5 * 60,
  VERIFICATION_CODE_MAX_BACKOFF_SECONDS: 60 * 60,
} as const;

export type Bytes = Uint8Array | string;
export type Timestamp = string;

export interface HumanID {
  kind: "HUMAN_ID";
  id: Bytes;
  publicKey: Bytes;
  createdAt: Timestamp;
}

export interface IFayID {
  kind: "IFAY_ID";
  id: Bytes;
  ownerHumanID: HumanIDRef;
  publicKey?: Bytes;
  ownerSignature?: Bytes;
  createdAt: Timestamp;
  revoked: boolean;
}

export interface CoFayID {
  kind: "COFAY_ID";
  id: Bytes;
  ownerKind: OwnerKind;
  ownerRef: HumanIDRef | OrganizationIDRef;
  publicKey?: Bytes;
  ownerSignature?: Bytes;
  verificationCode: Bytes;
  verificationCodeVersion: number;
  createdAt: Timestamp;
  revoked: boolean;
}

export interface OrganizationID {
  kind: "ORGANIZATION_ID";
  id: string;
  displayName?: string;
  createdAt: Timestamp;
}

export interface DynamicCode {
  kind: "DYNAMIC_CODE";
  code: string;
  humanIDRef: HumanIDRef;
  issuedAt: Timestamp;
  expiresAt: Timestamp;
  nonce: Bytes;
  lookupKey: Bytes;
}

export interface VerificationCode {
  kind: "VERIFICATION_CODE";
  code: Bytes;
  cofayIDRef: CoFayIDRef;
  version: number;
  issuedAt: Timestamp;
}

export interface AuthorizationGrant {
  kind: "AUTHORIZATION_GRANT";
  grantID: Bytes;
  targetFayID: IFayIDRef | HumanIDProofRef;
  legacySubjectRef: LegacySubjectRef;
  legacySourceKind: LegacySourceKind;
  legacyTrustLevel: LegacyTrustLevel;
  resourceRef: string;
  scopeMode: ScopeMode;
  issuedAt: Timestamp;
  expiresAt: Timestamp;
  signature: Bytes;
  statusVersion: number;
  state: GrantState;
}

export interface OpaqueRef {
  kind: "OPAQUE_REF";
  value: string;
}

export type FayIDEntity =
  | HumanID
  | IFayID
  | CoFayID
  | OrganizationID
  | DynamicCode
  | VerificationCode
  | AuthorizationGrant
  | OpaqueRef;

export type HumanIDRef = string & { readonly __brand: "HumanIDRef" };
export type IFayIDRef = string & { readonly __brand: "IFayIDRef" };
export type CoFayIDRef = string & { readonly __brand: "CoFayIDRef" };
export type OrganizationIDRef = string & {
  readonly __brand: "OrganizationIDRef";
};
export type HumanIDProofRef = string & { readonly __brand: "HumanIDProofRef" };
export type LegacySubjectRef = string & {
  readonly __brand: "LegacySubjectRef";
};

export interface ProofChallenge {
  challengeID: string;
  nonce: Bytes;
  audience: "issuer" | "resolver" | "auth-exchange" | "gmc-interface";
  intent:
    | "create-ifay"
    | "create-cofay"
    | "issue-dynamic-code"
    | "exchange-grant"
    | "revoke-grant"
    | "revoke-ifay"
    | "revoke-cofay"
    | "list-ifays";
  subjectRef: HumanIDRef | IFayIDRef | CoFayIDRef | OrganizationIDRef;
  issuedAt: Timestamp;
  expiresAt: Timestamp;
}

export interface Proof {
  challenge: ProofChallenge;
  signature: Bytes;
  publicKey: Bytes;
}

export type ProofOfHuman = Proof;
export type ProofOfOwner = Proof;
export type ProofOfTarget = Proof;

export interface LegacyCredential {
  sourceKind: LegacySourceKind;
  payload: unknown;
}

export interface GrantSignedPayload {
  grantID: Bytes;
  targetFayID: IFayIDRef | HumanIDProofRef;
  legacySubjectRef: LegacySubjectRef;
  legacySourceKind: LegacySourceKind;
  legacyTrustLevel: LegacyTrustLevel;
  resourceRef: string;
  scopeMode: ScopeMode;
  issuedAt: Timestamp;
  expiresAt: Timestamp;
  statusVersion: number;
}

export type Result<T, E extends FayIDErrorCode> =
  | { ok: true; value: T }
  | { ok: false; error: E };

export interface Issuer {
  createHumanID(
    entropy: Bytes,
  ): Result<{ humanID: HumanID; mnemonic: string }, "INSUFFICIENT_ENTROPY">;
  deriveHumanIDFromMnemonic(mnemonic: string): HumanID;
  issueDynamicCode(
    proofOfHuman: ProofOfHuman,
  ): Result<DynamicCode, "HUMAN_ID_OWNERSHIP_NOT_PROVEN">;
  createIFayID(
    proofOfHuman: ProofOfHuman,
  ): Result<IFayID, "HUMAN_ID_OWNERSHIP_NOT_PROVEN">;
  createCoFayID(
    ownerRef: HumanIDRef | OrganizationIDRef,
    proofOfOwner: ProofOfOwner,
  ): Result<
    { cofayID: CoFayID; verificationCode: VerificationCode },
    "OWNERSHIP_NOT_PROVEN"
  >;
  rotateVerificationCode(
    proofOfOwner: ProofOfOwner,
    cofayID: CoFayID,
  ): Result<VerificationCode, "OWNERSHIP_NOT_PROVEN">;
  revokeIFayID(
    proofOfHuman: ProofOfHuman,
    ifayID: IFayID,
  ): Result<void, "HUMAN_ID_OWNERSHIP_NOT_PROVEN">;
  revokeCoFayID(
    proofOfOwner: ProofOfOwner,
    cofayID: CoFayID,
  ): Result<void, "OWNERSHIP_NOT_PROVEN">;
}

export interface Resolver {
  resolveDynamicCode(
    dynamicCode: string,
  ): Result<
    OpaqueRef,
    "DYNAMIC_CODE_EXPIRED" | "DYNAMIC_CODE_INVALID" | "MALFORMED_FAYID_STRING"
  >;
  resolveIFayID(ifayID: IFayID): {
    ownerHumanIDOpaqueRef: OpaqueRef;
    revoked: boolean;
  };
  resolveCoFayID(cofayID: CoFayID): {
    ownerKind: OwnerKind;
    ownerOpaqueRef: OpaqueRef | OrganizationIDRef;
    revoked: boolean;
  };
  verifyCoFayCode(
    cofayID: CoFayID,
    verificationCode: string,
  ): Result<boolean, "VERIFICATION_RATE_LIMITED" | "MALFORMED_FAYID_STRING">;
  resolveOrganizationID(
    organizationID: string,
  ): Result<OrganizationID, "MALFORMED_FAYID_STRING">;
  listIFayIDsOfHuman(
    proofOfHuman: ProofOfHuman,
  ): Result<IFayID[], "HUMAN_ID_OWNERSHIP_NOT_PROVEN">;
}

export interface AuthExchange {
  exchangeLegacyForGrant(
    legacyCred: LegacyCredential,
    targetFayID: IFayIDRef | HumanIDProofRef,
    proofOfTarget: ProofOfTarget,
    resourceRef: string,
    scopeMode?: ScopeMode,
  ): Result<
    AuthorizationGrant,
    | "TARGET_OWNERSHIP_NOT_PROVEN"
    | "LEGACY_AUTH_FAILED"
    | "LEGACY_SUBJECT_MISMATCH"
    | "IDENTITY_REVOKED"
    | "MALFORMED_FAYID_STRING"
  >;
  verifyGrant(
    grant: AuthorizationGrant,
    resourceRef: string,
  ): Result<boolean, "GRANT_EXPIRED" | "GRANT_REVOKED" | "GRANT_INVALID">;
  revokeGrant(
    proofOfOwner: ProofOfOwner,
    grantID: Bytes,
  ): Result<void, "OWNERSHIP_NOT_PROVEN">;
  listGrantsOfHuman(
    presented: ProofOfHuman | DynamicCode,
    resourceRef: string,
  ): Result<
    AuthorizationGrant[],
    "DYNAMIC_CODE_INVALID" | "HUMAN_ID_OWNERSHIP_NOT_PROVEN"
  >;
}

export interface GMCInterface {
  gmcLookupOwnership(
    idStr: string,
  ): Result<
    { ownerKind: OwnerKind; ownerOpaqueRef: OpaqueRef | OrganizationIDRef },
    "MALFORMED_FAYID_STRING"
  >;
  gmcResolvePublicEntity(
    idStr: string,
  ): Result<
    {
      kind: "IFAY" | "COFAY" | "ORGANIZATION";
      revoked: boolean;
      displayMetadata: unknown;
    },
    "MALFORMED_FAYID_STRING"
  >;
}
