export const accountErrorCodes: Readonly<Record<string, string>>;

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
};
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

export class AccountDirectory {
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
}
