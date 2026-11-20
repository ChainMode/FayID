export * from "./fayid-toolkit.mjs";

export const PLATFORM_CATEGORIES: Readonly<{
  REAL_NAME: "REAL_NAME";
  EXPERT: "EXPERT";
  COMMERCE: "COMMERCE";
  SERVICE: "SERVICE";
}>;

export type PlatformCategory = "REAL_NAME" | "EXPERT" | "COMMERCE" | "SERVICE";

export interface PlatformRegistrationAttestation {
  version: "1.0";
  domain: "ifay.fayid.platform-attestation.v1";
  registrationId: string;
  subjectId: string;
  subjectKind: "IFAY_ID" | "COFAY_ID";
  subjectPublicKeyHex: string;
  platformId: string;
  platformCategory: PlatformCategory;
  platformPublicKeyHex: string;
  handle: string;
  scopes: string[];
  claims: Record<string, unknown>;
  discoverable: boolean;
  blindHumanAnchor?: string;
  issuedAtSec: number;
  expiresAtSec: number;
  optInSignatureHex: string;
  platformSignatureHex: string;
}

export class MonotonicRevocationList {
  sequence: number;
  updatedAtSec: number;
  constructor(options?: { initialNowSec?: number; federationSalt?: Uint8Array | string });
  revoke(
    targetId: string,
    meta?: { reason?: string; revokedAtSec?: number },
  ): { ok: boolean; value?: { sequence: number; revokedRef: string; blindTag: string }; error?: string };
  isRevoked(idOrTag: string | null | undefined): boolean;
  exportSnapshot(): {
    version: "1.0";
    sequence: number;
    updatedAtSec: number;
    revokedIds: string[];
    revokedBlindTags: string[];
  };
  exportSignedBundle(
    signer: { publicKeyHex: string; signPayload(bytes: Uint8Array): Uint8Array },
    issuerId: string,
  ): Record<string, unknown>;
  importBundle(
    bundle: Record<string, unknown>,
    options?: { expectedPublicKeyHex?: string },
  ): { ok: boolean; value?: { sequence: number; totalRevoked: number }; error?: string };
}

export class PlatformRegistry {
  revocationList: MonotonicRevocationList;
  constructor(options?: { revocationList?: MonotonicRevocationList; federationSalt?: Uint8Array | string });
  recordRegistration(attestation: PlatformRegistrationAttestation): { ok: boolean; value?: string; error?: string };
  getRegistration(registrationId: string): PlatformRegistrationAttestation | null;
  isRegistrationRevoked(registrationId: string): boolean;
  resolveDiscoverableSubject(
    subjectId: string,
    options?: { nowSec?: number; category?: PlatformCategory; platformId?: string },
  ): { ok: boolean; value?: Record<string, unknown>; error?: string };
}

export function issuePlatformRegistration(input: {
  subjectId: string;
  subjectSigner: { publicKeyHex: string; signPayload(bytes: Uint8Array): Uint8Array };
  platformId: string;
  platformCategory: PlatformCategory;
  platformSigner: { publicKeyHex: string; signPayload(bytes: Uint8Array): Uint8Array };
  handle?: string;
  scopes?: string[];
  claims?: Record<string, unknown>;
  discoverable?: boolean;
  blindHumanAnchor?: string | null;
  issuedAtSec?: number;
  expiresAtSec?: number;
  registry?: PlatformRegistry | null;
}): { ok: true; value: PlatformRegistrationAttestation } | { ok: false; error: string };

export function verifyPlatformRegistration(
  attestation: PlatformRegistrationAttestation,
  options?: {
    revocationList?: MonotonicRevocationList;
    directory?: import("./fayid-toolkit.mjs").AccountDirectory;
    registry?: PlatformRegistry;
    trustedPlatformKeys?: Map<string, string> | Record<string, string>;
    expectedSubjectId?: string;
    requiredCategory?: PlatformCategory;
    requiredPlatformId?: string;
    requiredScopes?: string[];
    nowSec?: number;
  },
): { ok: true; value: Record<string, unknown> } | { ok: false; error: string };

export function revokePlatformRegistration(
  registrationOrId: PlatformRegistrationAttestation | string,
  actorId: string,
  options?: {
    registry?: PlatformRegistry;
    revocationList?: MonotonicRevocationList;
    reason?: string;
    nowSec?: number;
  },
): { ok: true; value: Record<string, unknown> } | { ok: false; error: string };

export function issueDynamicPresentation(input: {
  masterSeed: Uint8Array;
  subjectId: string;
  ttlSec?: number;
  issuedAtSec?: number;
  nonce?: Uint8Array;
  useDyncAlias?: boolean;
  blindSalt?: Uint8Array;
  federationSalt?: Uint8Array | string;
  directory?: import("./fayid-toolkit.mjs").AccountDirectory | null;
}): { ok: true; value: Record<string, unknown> } | { ok: false; error: string };

export function signFayIdRequest(input: {
  method?: string;
  url?: string;
  body?: string | Uint8Array | Record<string, unknown>;
  presenterId?: string;
  signer?: { publicKeyHex: string; signPayload(bytes: Uint8Array): Uint8Array };
  dynamicPresentation?: Record<string, unknown> | null;
  challenge?: string | null;
  registrations?: PlatformRegistrationAttestation[];
  nowSec?: number;
  nonce?: string;
}): Record<string, string>;

export interface FayIdVerifier {
  (req: unknown, res: unknown, next?: () => void): Promise<{ ok: boolean; value?: Record<string, unknown>; error?: string }>;
  middleware: FayIdVerifier;
  verifyRequest(input: {
    method?: string;
    url?: string;
    headers?: Record<string, unknown> | Headers;
    body?: unknown;
    nowSec?: number;
  }): { ok: true; value: Record<string, unknown> } | { ok: false; error: string };
  verifyFetch(
    request: Request,
    nowSec?: number,
  ): Promise<{ ok: true; value: Record<string, unknown> } | { ok: false; error: string }>;
  protectFetch(
    handler: (request: Request, fayidContext: Record<string, unknown>) => Response | Promise<Response>,
  ): (request: Request) => Promise<Response>;
  createChallenge(nowSec?: number, ttlSec?: number): { challenge: string; issuedAtSec: number; expiresAtSec: number };
  revocationList: MonotonicRevocationList;
}

export function createFayIdVerifier(options?: {
  maxClockSkewSec?: number;
  revocationList?: MonotonicRevocationList;
  directory?: import("./fayid-toolkit.mjs").AccountDirectory;
  platformRegistry?: PlatformRegistry;
  trustedPlatformKeys?: Map<string, string> | Record<string, string>;
  requiredPlatformCategory?: PlatformCategory;
  requiredPlatformId?: string;
  requiredScopes?: string[];
  requireChallenge?: boolean;
}): FayIdVerifier;

export type LegacyCredentialKind =
  | "PASSWORD"
  | "OAUTH_TOKEN"
  | "API_KEY"
  | "CERTIFICATE"
  | "SMART_CONTRACT";

export class AuthExchangeVault {
  directory: import("./fayid-toolkit.mjs").AccountDirectory;
  constructor(options?: {
    vaultMasterKey?: Uint8Array | string;
    vaultSalt?: Uint8Array;
    directory?: import("./fayid-toolkit.mjs").AccountDirectory;
  });
  sealCredential(input: {
    credentialKind: LegacyCredentialKind;
    label?: string;
    resourceRef: string;
    issuer?: string;
    subject?: string;
    ownerHumanId: string;
    secretMaterial: Record<string, unknown> | string;
    injectionPolicy?: { headerName?: string; headerScheme?: string };
    createdAtSec?: number;
  }): { ok: true; value: Record<string, unknown> } | { ok: false; error: string };
  listCredentials(): Array<Record<string, unknown>>;
  exchangeGrant(input: {
    credentialId: string;
    targetFayId: string;
    actorId?: string;
    resourceRef?: string;
    scopeMode?: "EXACT" | "PREFIX";
    ttlSec?: number;
    issuedAtSec?: number;
  }): { ok: true; value: Record<string, unknown> } | { ok: false; error: string };
  revokeGrant(
    grantOrTicket: string,
    signerId?: string,
  ): { ok: true; value: Record<string, unknown> } | { ok: false; error: string };
  saveToFile(filePath: string): void;
  static openFile(filePath: string, vaultMasterKey: Uint8Array | string): AuthExchangeVault;
}

export function createAuthExchangeProxyServer(options: {
  vault: AuthExchangeVault;
  host?: string;
  port?: number;
  adminToken?: string;
  requireHolderSignature?: boolean;
  fetchImpl?: typeof fetch;
  vaultFilePath?: string | null;
}): {
  server: import("node:http").Server;
  adminToken: string;
  listen(): Promise<{ host: string; port: number; url: string; adminToken: string }>;
  close(): Promise<void>;
};
