import { z } from "zod";
import {
  hashBearerSecret,
  parseBearerSecret,
  parseCapabilityLocator,
  type BearerAuthorizationHash,
  type CapabilityLocator,
  type OwnerBearerSecret,
  type PublicBearerSecret
} from "./capability-authority";

const SHA_PATTERN = /^[a-f0-9]{40}$/u;
const UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/iu;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const GITHUB_RUN_ID_PATTERN = /^[1-9][0-9]{0,19}$/u;
const HMAC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
type StagingReliabilityCase = "claim_replay" | "concurrent_claim" | "uncertain_restore";
export const STAGING_RELIABILITY_WORKFLOW_NAME = "onceurl-staging-reliability";
export const STAGING_RELIABILITY_CONCURRENT_CLAIMS = 8;
export const STAGING_RELIABILITY_CAPABILITY_COUNT = 3;
export const stagingReliabilityIdentitySchema = z.strictObject({
  canonicalSourceSha: z.string().regex(SHA_PATTERN),
  publicSourceSha: z.string().regex(SHA_PATTERN),
  exportDigest: z.string().regex(DIGEST_PATTERN),
  publicationSequence: z.number().int().min(2).safe(),
  acceptedRecordDigest: z.string().regex(DIGEST_PATTERN),
  publicCiWorkflowRunId: z.string().regex(GITHUB_RUN_ID_PATTERN),
  publicCiWorkflowRunAttempt: z.number().int().positive().max(1000),
  publicCiJobId: z.string().regex(GITHUB_RUN_ID_PATTERN),
  workflowRunId: z.string().regex(GITHUB_RUN_ID_PATTERN),
  workflowRunAttempt: z.number().int().positive().max(1000),
  campaignId: z.string().regex(/^ou-staging-[1-9][0-9]*-[1-9][0-9]*-[a-f0-9]{12}$/u),
  configurationDigest: z.string().regex(DIGEST_PATTERN)
});
export const stagingReliabilityInputSchema = z.strictObject({
  schemaVersion: z.literal(2),
  deploymentEnvironment: z.literal("staging"),
  ...stagingReliabilityIdentitySchema.shape,
  functionalVersionId: z.string().regex(UUID_PATTERN),
  functionalVersionTag: z.string().regex(/^staging-[a-f0-9]{12}$/u),
  marketingVersionId: z.string().regex(UUID_PATTERN),
  marketingVersionTag: z.string().regex(/^staging-[a-f0-9]{12}$/u),
  providerWorkflowVersionId: z.string().regex(UUID_PATTERN),
  smokeEvidenceDigest: z.string().regex(DIGEST_PATTERN),
  releaseAssertionDigest: z.string().regex(DIGEST_PATTERN),
  campaignAssertionDigest: z.string().regex(DIGEST_PATTERN),
  campaignIssuedAt: z.number().int().nonnegative().safe(),
  campaignExpiresAt: z.number().int().positive().safe()
});
export type StagingReliabilityInput = z.infer<typeof stagingReliabilityInputSchema>;
export interface StagingReliabilityProvenanceEnv {
  readonly DEPLOYMENT_ENVIRONMENT: string;
  readonly STAGING_CANONICAL_SOURCE_SHA?: string;
  readonly STAGING_PUBLIC_SOURCE_SHA?: string;
  readonly STAGING_EXPORT_DIGEST?: string;
  readonly STAGING_PUBLICATION_SEQUENCE?: string;
  readonly STAGING_ACCEPTED_RECORD_DIGEST?: string;
  readonly STAGING_PUBLIC_CI_RUN_ID?: string;
  readonly STAGING_PUBLIC_CI_RUN_ATTEMPT?: string;
  readonly STAGING_PUBLIC_CI_JOB_ID?: string;
  readonly STAGING_WORKFLOW_RUN_ID?: string;
  readonly STAGING_WORKFLOW_RUN_ATTEMPT?: string;
  readonly STAGING_CAMPAIGN_ID?: string;
  readonly STAGING_CONFIGURATION_DIGEST?: string;
  readonly FUNCTIONAL_ORIGIN: string;
  readonly MARKETING_ORIGIN: string;
  readonly CF_VERSION_METADATA?: WorkerVersionMetadata;
  readonly STAGING_RELIABILITY_HMAC_KEY?: string;
}
export type StagingReliabilityPreflightEvidence = Omit<
  StagingReliabilityInput,
  "schemaVersion" | "deploymentEnvironment" | "campaignIssuedAt" | "campaignExpiresAt"
>;
export const STAGING_IDENTITY_BINDINGS = {
  canonicalSourceSha: "STAGING_CANONICAL_SOURCE_SHA",
  publicSourceSha: "STAGING_PUBLIC_SOURCE_SHA",
  exportDigest: "STAGING_EXPORT_DIGEST",
  publicationSequence: "STAGING_PUBLICATION_SEQUENCE",
  acceptedRecordDigest: "STAGING_ACCEPTED_RECORD_DIGEST",
  publicCiWorkflowRunId: "STAGING_PUBLIC_CI_RUN_ID",
  publicCiWorkflowRunAttempt: "STAGING_PUBLIC_CI_RUN_ATTEMPT",
  publicCiJobId: "STAGING_PUBLIC_CI_JOB_ID",
  workflowRunId: "STAGING_WORKFLOW_RUN_ID",
  workflowRunAttempt: "STAGING_WORKFLOW_RUN_ATTEMPT",
  campaignId: "STAGING_CAMPAIGN_ID",
  configurationDigest: "STAGING_CONFIGURATION_DIGEST"
} as const;

export interface SyntheticCapabilityIdentity {
  readonly capabilityId: string;
  readonly locator: CapabilityLocator;
  readonly publicBearerSecret: PublicBearerSecret;
  readonly ownerBearerSecret: OwnerBearerSecret;
  readonly publicBearerSecretHash: BearerAuthorizationHash;
  readonly ownerBearerSecretHash: BearerAuthorizationHash;
  readonly createdAt: string;
  readonly policy: {
    readonly kind: "secret";
    readonly expiresAt: number;
    readonly maxConsumptions: 1;
    readonly reactivation: "forbidden";
    readonly postConsumption: { readonly behavior: "delete_capability" };
  };
  readonly policyHash: string;
  readonly ciphertextEnvelope: {
    readonly version: "ouzk-v1";
    readonly alg: "AES-256-GCM";
    readonly nonce: string;
    readonly ciphertext: string;
    readonly ad: {
      readonly capabilityId: string;
      readonly createdAt: string;
      readonly kind: "secret";
      readonly locator: string;
      readonly policyHash: string;
      readonly purpose: "onceurl.phase1a.secret-text";
      readonly version: "ouzk-v1";
    };
  };
}

export function validateStagingReliabilityPreflight(
  inputValue: unknown,
  instanceId: string,
  env: StagingReliabilityProvenanceEnv
): {
  readonly input: StagingReliabilityInput;
  readonly evidence: StagingReliabilityPreflightEvidence;
} {
  const parsed = stagingReliabilityInputSchema.safeParse(inputValue);
  if (!parsed.success) throw new Error("staging_reliability_invalid_input");
  const input = parsed.data;
  if (
    instanceId !== input.campaignId ||
    input.campaignId !==
      `ou-staging-${input.workflowRunId}-${input.workflowRunAttempt}-${input.publicSourceSha.slice(0, 12)}`
  )
    throw new Error("staging_reliability_instance_mismatch");
  if (env.DEPLOYMENT_ENVIRONMENT !== "staging")
    throw new Error("staging_reliability_non_staging_environment");
  for (const [field, binding] of Object.entries(STAGING_IDENTITY_BINDINGS)) {
    if (
      env[binding as keyof StagingReliabilityProvenanceEnv] !==
      String(input[field as keyof StagingReliabilityInput])
    )
      throw new Error("staging_reliability_identity_mismatch");
  }
  if (
    env.CF_VERSION_METADATA?.id !== input.functionalVersionId ||
    env.CF_VERSION_METADATA.tag !== input.functionalVersionTag ||
    input.functionalVersionTag !== `staging-${input.publicSourceSha.slice(0, 12)}` ||
    input.marketingVersionTag !== input.functionalVersionTag
  )
    throw new Error("staging_reliability_worker_version_mismatch");
  if (
    input.campaignExpiresAt <= input.campaignIssuedAt ||
    input.campaignExpiresAt - input.campaignIssuedAt > 60
  )
    throw new Error("staging_reliability_grant_window");
  validateStagingOriginPair(env.MARKETING_ORIGIN, env.FUNCTIONAL_ORIGIN);
  parseStagingReliabilityHmacKey(env.STAGING_RELIABILITY_HMAC_KEY);
  const evidence = Object.fromEntries(
    Object.entries(input).filter(
      ([key]) =>
        ![
          "schemaVersion",
          "deploymentEnvironment",
          "campaignIssuedAt",
          "campaignExpiresAt"
        ].includes(key)
    )
  ) as StagingReliabilityPreflightEvidence;
  return { input, evidence };
}

export async function deriveSyntheticCapability(
  hmacKeyValue: string | undefined,
  input: StagingReliabilityInput,
  caseName: StagingReliabilityCase,
  createdAtMilliseconds: number
): Promise<SyntheticCapabilityIdentity> {
  if (!Number.isSafeInteger(createdAtMilliseconds) || createdAtMilliseconds <= 0) {
    throw new Error("staging_reliability_invalid_creation_time");
  }
  const hmacKey = await importStagingReliabilityHmacKey(hmacKeyValue);
  const domain = `${syntheticDomain(input)}\u0000${caseName}\u0000`;
  const capabilityId = `mis27_${base64urlEncode(await deriveBytes(hmacKey, domain, "capability", 18))}`;
  const locator = parseCapabilityLocator(
    `loc1_${hexEncode(await deriveBytes(hmacKey, domain, "locator", 24))}`
  );
  const publicBearerSecret = parseBearerSecret(
    "public",
    `pub1_${base64urlEncode(await deriveBytes(hmacKey, domain, "public-bearer", 32))}`
  );
  const ownerBearerSecret = parseBearerSecret(
    "owner",
    `own1_${base64urlEncode(await deriveBytes(hmacKey, domain, "owner-bearer", 32))}`
  );
  if (locator === null || publicBearerSecret === null || ownerBearerSecret === null) {
    throw new Error("staging_reliability_identity_derivation_failed");
  }
  const createdAt = new Date(createdAtMilliseconds).toISOString();
  const policyHash = `mis27ph_${base64urlEncode(await deriveBytes(hmacKey, domain, "policy-hash", 24))}`;
  const policy = {
    kind: "secret",
    expiresAt: createdAtMilliseconds + 24 * 60 * 60 * 1_000,
    maxConsumptions: 1,
    reactivation: "forbidden",
    postConsumption: { behavior: "delete_capability" }
  } as const;
  return {
    capabilityId,
    locator,
    publicBearerSecret,
    ownerBearerSecret,
    publicBearerSecretHash: await hashBearerSecret("public", publicBearerSecret),
    ownerBearerSecretHash: await hashBearerSecret("owner", ownerBearerSecret),
    createdAt,
    policy,
    policyHash,
    ciphertextEnvelope: {
      version: "ouzk-v1",
      alg: "AES-256-GCM",
      nonce: base64urlEncode(await deriveBytes(hmacKey, domain, "ciphertext-nonce", 12)),
      ciphertext: base64urlEncode(await deriveBytes(hmacKey, domain, "ciphertext", 32)),
      ad: {
        capabilityId,
        createdAt,
        kind: "secret",
        locator,
        policyHash,
        purpose: "onceurl.phase1a.secret-text",
        version: "ouzk-v1"
      }
    }
  };
}

export async function deriveSyntheticOperationId(
  hmacKeyValue: string | undefined,
  input: StagingReliabilityInput,
  caseName: string,
  operationName: string
): Promise<string> {
  const hmacKey = await importStagingReliabilityHmacKey(hmacKeyValue);
  const domain = `${syntheticDomain(input)}\u0000${caseName}\u0000${operationName}`;
  return `mis27op_${base64urlEncode(await deriveBytes(hmacKey, domain, "operation", 24))}`;
}

export async function deriveSyntheticNonce(
  hmacKeyValue: string | undefined,
  input: StagingReliabilityInput,
  caseName: string,
  nonceName: string
): Promise<string> {
  const hmacKey = await importStagingReliabilityHmacKey(hmacKeyValue);
  const domain = `${syntheticDomain(input)}\u0000${caseName}\u0000${nonceName}`;
  return `mis27nonce_${base64urlEncode(await deriveBytes(hmacKey, domain, "nonce", 18))}`;
}

function syntheticDomain(input: StagingReliabilityInput): string {
  return JSON.stringify(
    Object.keys(STAGING_IDENTITY_BINDINGS).map((field) => [
      field,
      input[field as keyof StagingReliabilityInput]
    ])
  );
}

function validateStagingOriginPair(marketingValue: string, functionalValue: string): void {
  const marketing = parseStagingOrigin(marketingValue);
  const functional = parseStagingOrigin(functionalValue);
  if (marketing.origin === functional.origin) {
    throw new Error("staging_reliability_origin_collapse");
  }
}

function parseStagingOrigin(value: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("staging_reliability_invalid_origin");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    !parsed.hostname.endsWith(".onceurl.mistyislesoftware.co.uk") ||
    value !== parsed.origin
  ) {
    throw new Error("staging_reliability_invalid_origin");
  }
  return parsed;
}

function parseStagingReliabilityHmacKey(value: string | undefined): Uint8Array {
  if (value === undefined || !HMAC_KEY_PATTERN.test(value)) {
    throw new Error("staging_reliability_hmac_unavailable");
  }
  const decoded = base64urlDecode(value);
  if (decoded === null || decoded.byteLength !== 32 || base64urlEncode(decoded) !== value) {
    throw new Error("staging_reliability_hmac_unavailable");
  }
  return decoded;
}

async function importStagingReliabilityHmacKey(value: string | undefined): Promise<CryptoKey> {
  const keyBytes = parseStagingReliabilityHmacKey(value);
  try {
    return await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
  } finally {
    keyBytes.fill(0);
  }
}

async function deriveBytes(
  key: CryptoKey,
  domain: string,
  label: string,
  length: number
): Promise<Uint8Array> {
  if (!Number.isInteger(length) || length < 1 || length > 32) {
    throw new Error("staging_reliability_invalid_derivation_length");
  }
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`onceurl.staging-reliability.v2\u0000${domain}\u0000${label}`)
  );
  return new Uint8Array(signature).slice(0, length);
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64urlDecode(value: string): Uint8Array | null {
  try {
    const padded = value
      .replaceAll("-", "+")
      .replaceAll("_", "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=");
    return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
