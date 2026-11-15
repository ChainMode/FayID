export const subkeyDomains: Readonly<{
  ENTITY: "ifay.fayid.entity.v1";
  EGO_PACKAGE_SIGNING: "ifay.ego.package-signing.v1";
  DYNAMIC_CODE: "ifay.fayid.dynamic-code.v1";
  AUTH_EXCHANGE: "ifay.fayid.auth-exchange.v1";
  GMC_NATURAL_PERSON: "ifay.gmc.natural-person.v1";
}>;

export const accountErrorCodes: Readonly<Record<string, string>>;

export function canonicalizeJcs(value: unknown): string;
export function base32EncodeNoPad(bytes: Uint8Array): string;
export function base32DecodeNoPad(input: string): Buffer | null;
export function parseCanonicalFayID(
  input: string,
): { ok: true; value: { kind: string; value: string } } | { ok: false; error: string };
export function fromLegacyHexIdentity(
  entityPrefix: "hid" | "ifay" | "cofay" | "org" | "gmcref",
  hex64: string,
): { ok: true; value: string } | { ok: false; error: string };
export function deriveHumanIdentityFromSeed(seed32: Uint8Array): {
  humanId: string;
  idBytes: Buffer;
  publicKeyRaw: Buffer;
  signPayload(payloadBytes: Uint8Array): Buffer;
  toPublicRecord(): { kind: string; publicKeyHex: string };
};
export function derivePurposeSubkey(
  masterSeed: Uint8Array,
  domain: string,
  context?: string,
):
  | {
      ok: true;
      value: {
        domain: string;
        context: string;
        publicKeyRaw: Buffer;
        publicKeyHex: string;
        signPayload(payloadBytes: Uint8Array): Buffer;
        toPublicRecord(): { domain: string; context: string; publicKeyHex: string };
      };
    }
  | { ok: false; error: string };
export function deriveEntityKeypair(
  masterSeed: Uint8Array,
  entityPrefix: "hid" | "ifay" | "cofay" | "org",
  slotOrSlug?: number | string,
):
  | {
      ok: true;
      value: {
        entityId: string;
        kind: string;
        domain: string;
        publicKeyRaw: Buffer;
        publicKeyHex: string;
        signPayload(payloadBytes: Uint8Array): Buffer;
        toPublicRecord(): Record<string, unknown>;
      };
    }
  | { ok: false; error: string };
export function deriveEgoPackageSigningKey(
  masterSeed: Uint8Array,
  signerFayId: string,
  keyIndex?: number,
):
  | {
      ok: true;
      value: {
        domain: string;
        signerFayId: string;
        keyIndex: number;
        publicKeyRaw: Buffer;
        publicKeyHex: string;
        signPayload(payloadBytes: Uint8Array): Buffer;
        signEgoPackageManifest(manifestOrBytes: unknown): {
          version: string;
          domain: string;
          signerFayId: string;
          keyIndex: number;
          publicKeyHex: string;
          payloadDigestHex: string;
          signatureHex: string;
        };
        toPublicRecord(): Record<string, unknown>;
      };
    }
  | { ok: false; error: string };
export function verifyEgoPackageEnvelope(envelope: Record<string, unknown>, manifestOrBytes: unknown): boolean;
export function verifyEd25519Signature(
  publicKeyRaw: Uint8Array,
  payloadBytes: Uint8Array,
  signatureBytes: Uint8Array,
): boolean;
export function deriveDynamicCode(
  localRootKey: Uint8Array,
  humanIdStr: string,
  nonceBytes: Uint8Array,
  issuedAtSec: number,
  expiresAtSec: number,
): { code: string; lookupKeyHex: string; issuedAtSec: number; expiresAtSec: number };
export function deriveOpaqueRef(
  humanIdBytes: Uint8Array,
  gmcNamespaceSecret: Uint8Array,
): string;
export function deriveBlindGmcRef(
  humanIdOrBytes: string | Uint8Array,
  userBlindSalt: Uint8Array,
  namespace?: string,
): { ok: true; value: string } | { ok: false; error: string };
export function verifyAuthReceipt(receipt: Record<string, unknown>): boolean;

export class AccountDirectory {
  constructor(options?: { authoritySecret?: Uint8Array });
  isEntityRevoked(entityId: string): boolean;
  registerHuman(humanId: string): { ok: boolean; value?: string; error?: string };
  registerIFay(ifayId: string, ownerHumanId: string): { ok: boolean; value?: string; error?: string };
  registerOrganization(orgId: string, stewardId: string): { ok: boolean; value?: string; error?: string };
  registerCoFay(
    cofayId: string,
    ownerId: string,
    signerId: string,
  ): { ok: boolean; value?: { id: string; owner: string; ownerKind: string }; error?: string };
  getCoFay(cofayId: string): { id: string; owner: string; ownerKind: string; managers: string[] } | null;
  grantCoFayManager(
    cofayId: string,
    managerIfayId: string,
    signerId: string,
  ): { ok: boolean; value?: { id: string; owner: string; managers: string[] }; error?: string };
  revokeCoFayManager(
    cofayId: string,
    managerIfayId: string,
    signerId: string,
  ): { ok: boolean; value?: { id: string; owner: string; managers: string[] }; error?: string };
  canActForCoFay(cofayId: string, actorId: string): boolean;
  setOrganizationParent(input: {
    org: string;
    parent: string | null;
    childSigned: boolean;
    parentSigned: boolean;
  }): { ok: boolean; value?: { org: string; parent: string | null }; error?: string };
  getAncestorChain(orgId: string): string[];
  issueDynamicCode(input: {
    subjectId: string;
    holderSecret: Uint8Array;
    nonce?: Uint8Array;
    issuedAtSec: number;
    expiresAtSec: number;
  }): { ok: boolean; value?: { code: string; issuedAtSec: number; expiresAtSec: number }; error?: string };
  verifyDynamicCode(
    code: string,
    nowSec: number,
  ): {
    ok: boolean;
    value?: {
      code: string;
      subjectKind: string;
      resolvedRef: string;
      issuedAtSec: number;
      expiresAtSec: number;
    };
    error?: string;
  };
  issueAuthGrant(input: {
    targetId: string;
    actorId?: string;
    resourceRef: string;
    scopeMode?: "EXACT" | "PREFIX";
    legacySourceKind?: "PASSWORD" | "CERTIFICATE" | "AUTHORIZATION" | "ACCESS_TOKEN" | "SMART_CONTRACT";
    legacyIssuer?: string;
    legacySubject?: string;
    issuedAtSec: number;
    expiresAtSec: number;
  }): { ok: boolean; value?: Record<string, unknown>; error?: string };
  verifyAuthGrant(input: {
    grantId: string;
    requestedResourceRef: string;
    nowSec: number;
  }): { ok: boolean; value?: { valid: boolean; grantId: string; receipt: Record<string, unknown> }; error?: string };
  revokeGrant(grantId: string, signerId: string): { ok: boolean; value?: Record<string, unknown>; error?: string };
  revokeEntity(
    entityId: string,
    signerId?: string,
  ): { ok: boolean; value?: { revokedEntities: string[]; revokedGrants: string[] }; error?: string };
}
