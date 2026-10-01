import { z } from "zod";
import {
  bearerSecretsHaveEqualPayload,
  buildCapabilityRoutePaths,
  generateCapabilityRouteSecrets,
  hashBearerSecret,
  parseBearerSecret,
  parseCapabilityLocator,
  type RandomBytesSource
} from "./capability-authority";
import { parseAccessCodeVerifier, type AccessCodeVerifier } from "./access-code";

export const SECRET_EXPIRY_SECONDS = [3_600, 86_400, 604_800, 2_592_000] as const;
export const CREATION_COMPLETION_WINDOW_MS = 15 * 60 * 1_000;
export const PREPARATION_PROOF_VERSION = "prep1" as const;
export const PREPARATION_PROOF_DOMAIN = "onceurl.secret-preparation-proof.v1" as const;

const canonicalTimestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const canonicalBase64url32Pattern = /^[A-Za-z0-9_-]{43}$/u;
const capabilityIdPattern = /^cap1_[0-9a-f]{48}$/u;
const operationIdPattern = /^op1_[A-Za-z0-9_-]{43}$/u;
const preparationProofPattern = /^prep1_[A-Za-z0-9_-]{43}$/u;
const challengeIdPattern = /^chl2_[pa]_\d{1,16}_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}$/u;

const accessCodeVerifierSchema = z
  .unknown()
  .refine((value) => parseAccessCodeVerifier(value) !== null)
  .transform((value) => parseAccessCodeVerifier(value) as AccessCodeVerifier);

const preparationRequestSchema = z.strictObject({
  expires_in_seconds: z.union(SECRET_EXPIRY_SECONDS.map((seconds) => z.literal(seconds))),
  challenge_id: z.string().regex(challengeIdPattern),
  access_code_verifier: accessCodeVerifierSchema.optional()
});

const creationDescriptorSchema = z.strictObject({
  operation_id: z.string().regex(operationIdPattern),
  capability_id: z.string().regex(capabilityIdPattern),
  locator: z.string().refine((value) => parseCapabilityLocator(value) !== null),
  created_at: z.string().regex(canonicalTimestampPattern).refine(isCanonicalTimestamp),
  policy_hash: z.string().regex(canonicalBase64url32Pattern),
  public_bearer: z.string().refine((value) => parseBearerSecret("public", value) !== null),
  owner_bearer: z.string().refine((value) => parseBearerSecret("owner", value) !== null),
  access_code_verifier: accessCodeVerifierSchema.optional()
});

const publicPolicySchema = z.strictObject({
  kind: z.literal("secret"),
  expires_at: z.string().regex(canonicalTimestampPattern).refine(isCanonicalTimestamp),
  max_consumptions: z.literal(1),
  reactivation: z.literal("forbidden"),
  post_consumption: z.strictObject({
    behavior: z.literal("retain_capability"),
    retention: z.strictObject({ mode: z.literal("until_expiry") })
  })
});

const preparationProofSchema = z
  .string()
  .regex(preparationProofPattern)
  .refine((value) => decodePreparationProof(value) !== null);

const associatedDataSchema = z.strictObject({
  capabilityId: z.string(),
  createdAt: z.string(),
  kind: z.literal("secret"),
  locator: z.string(),
  policyHash: z.string(),
  purpose: z.literal("onceurl.phase1a.secret-text"),
  version: z.literal("ouzk-v1")
});

const envelopeSchema = z.strictObject({
  version: z.literal("ouzk-v1"),
  alg: z.literal("AES-256-GCM"),
  nonce: z.string().regex(/^[A-Za-z0-9_-]+$/u),
  ciphertext: z.string().regex(/^[A-Za-z0-9_-]+$/u),
  ad: associatedDataSchema
});

const completionRequestSchema = z.strictObject({
  creation: creationDescriptorSchema,
  policy: publicPolicySchema,
  complete_by: z.string().regex(canonicalTimestampPattern).refine(isCanonicalTimestamp),
  preparation_proof: preparationProofSchema,
  ciphertext_envelope: envelopeSchema
});

export type SecretPreparationRequest = z.infer<typeof preparationRequestSchema>;
export type SecretCompletionRequest = z.infer<typeof completionRequestSchema>;

export interface SecretPreparationProofMaterial {
  readonly creation: z.infer<typeof creationDescriptorSchema>;
  readonly policy: z.infer<typeof publicPolicySchema>;
  readonly complete_by: string;
}

export interface SecretPreparationResponse extends SecretPreparationProofMaterial {
  readonly preparation_proof: string;
}

export interface SecretPreparationVerificationKeys {
  readonly current: string;
  readonly previous?: string;
}

export interface ValidatedSecretCompletion {
  readonly operationId: string;
  readonly capabilityId: string;
  readonly locator: string;
  readonly createdAt: string;
  readonly policyHash: string;
  readonly policy: {
    readonly kind: "secret";
    readonly expiresAt: number;
    readonly maxConsumptions: 1;
    readonly reactivation: "forbidden";
    readonly postConsumption: {
      readonly behavior: "retain_capability";
      readonly retention: { readonly mode: "until_expiry" };
    };
  };
  readonly publicBearerSecretHash: string;
  readonly ownerBearerSecretHash: string;
  readonly accessCodeVerifier: AccessCodeVerifier | null;
  readonly ciphertextEnvelope: SecretCompletionRequest["ciphertext_envelope"];
  readonly recipientPath: string;
  readonly ownerPath: string;
  readonly expiresAt: string;
}

export class SecretPreparationConfigurationError extends Error {
  constructor() {
    super("Secret preparation is unavailable");
    this.name = "SecretPreparationConfigurationError";
  }
}

export function parseSecretPreparationRequest(input: unknown): SecretPreparationRequest | null {
  const result = preparationRequestSchema.safeParse(input);
  return result.success ? result.data : null;
}

export async function prepareSecretCreation(
  expiresInSeconds: (typeof SECRET_EXPIRY_SECONDS)[number],
  now: number,
  signingKeys: SecretPreparationVerificationKeys,
  randomBytes: RandomBytesSource = secureRandomBytes,
  accessCodeVerifier?: AccessCodeVerifier
): Promise<SecretPreparationResponse> {
  if (signingKeys.previous !== undefined) {
    await importPreparationSigningKey(signingKeys.previous, ["verify"]);
  }
  const createdAt = new Date(now).toISOString();
  const expiresAt = new Date(now + expiresInSeconds * 1_000).toISOString();
  const secrets = generateCapabilityRouteSecrets(randomBytes);
  const policy = publicPolicy(expiresAt);
  const material: SecretPreparationProofMaterial = {
    creation: {
      operation_id: `op1_${base64urlEncode(exactRandomBytes(randomBytes, 32))}`,
      capability_id: `cap1_${hexEncode(exactRandomBytes(randomBytes, 24))}`,
      locator: secrets.locator,
      created_at: createdAt,
      policy_hash: await hashCanonicalPolicy(policy),
      public_bearer: secrets.publicBearerSecret,
      owner_bearer: secrets.ownerBearerSecret,
      ...(accessCodeVerifier === undefined ? {} : { access_code_verifier: accessCodeVerifier })
    },
    policy,
    complete_by: new Date(now + CREATION_COMPLETION_WINDOW_MS).toISOString()
  };
  return {
    ...material,
    preparation_proof: await createSecretPreparationProof(material, signingKeys.current)
  };
}

export async function createSecretPreparationProof(
  material: SecretPreparationProofMaterial,
  signingKey: string
): Promise<string> {
  const key = await importPreparationSigningKey(signingKey, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, canonicalPreparationMessage(material));
  return preparationProofSchema.parse(
    `${PREPARATION_PROOF_VERSION}_${base64urlEncode(new Uint8Array(signature))}`
  );
}

export async function validateSecretCompletion(
  input: unknown,
  idempotencyKey: string | undefined,
  now: number,
  verificationKeys: SecretPreparationVerificationKeys,
  bearerHasher: typeof hashBearerSecret = hashBearerSecret
): Promise<ValidatedSecretCompletion | null> {
  if (
    !isRecord(input) ||
    !isRecord(input.ciphertext_envelope) ||
    !isRecord(input.ciphertext_envelope.ad) ||
    !hasExactKeyOrder(input.ciphertext_envelope.ad, [
      "capabilityId",
      "createdAt",
      "kind",
      "locator",
      "policyHash",
      "purpose",
      "version"
    ])
  ) {
    return null;
  }
  const result = completionRequestSchema.safeParse(input);
  if (!result.success) {
    return null;
  }
  const completion = result.data;
  if (idempotencyKey !== completion.creation.operation_id) {
    return null;
  }

  const createdAtMs = Date.parse(completion.creation.created_at);
  const completeByMs = Date.parse(completion.complete_by);
  const expiresAtMs = Date.parse(completion.policy.expires_at);
  const expirySeconds = (expiresAtMs - createdAtMs) / 1_000;
  if (
    !Number.isSafeInteger(createdAtMs) ||
    !Number.isSafeInteger(completeByMs) ||
    !Number.isSafeInteger(expiresAtMs) ||
    createdAtMs > now + 5_000 ||
    completeByMs - createdAtMs !== CREATION_COMPLETION_WINDOW_MS ||
    now > completeByMs ||
    !SECRET_EXPIRY_SECONDS.includes(expirySeconds as (typeof SECRET_EXPIRY_SECONDS)[number])
  ) {
    return null;
  }

  const proofMaterial: SecretPreparationProofMaterial = {
    creation: completion.creation,
    policy: completion.policy,
    complete_by: completion.complete_by
  };
  if (
    !(await verifySecretPreparationProof(
      proofMaterial,
      completion.preparation_proof,
      verificationKeys
    ))
  ) {
    return null;
  }

  const publicBearer = parseBearerSecret("public", completion.creation.public_bearer);
  const ownerBearer = parseBearerSecret("owner", completion.creation.owner_bearer);
  const locator = parseCapabilityLocator(completion.creation.locator);
  if (
    publicBearer === null ||
    ownerBearer === null ||
    locator === null ||
    bearerSecretsHaveEqualPayload(publicBearer, ownerBearer)
  ) {
    return null;
  }

  const expectedPolicyHash = await hashCanonicalPolicy(completion.policy);
  if (expectedPolicyHash !== completion.creation.policy_hash) {
    return null;
  }
  const expectedAssociatedData = {
    capabilityId: completion.creation.capability_id,
    createdAt: completion.creation.created_at,
    kind: "secret",
    locator,
    policyHash: completion.creation.policy_hash,
    purpose: "onceurl.phase1a.secret-text",
    version: "ouzk-v1"
  } as const;
  if (
    JSON.stringify(completion.ciphertext_envelope.ad) !== JSON.stringify(expectedAssociatedData)
  ) {
    return null;
  }

  const paths = buildCapabilityRoutePaths(locator, publicBearer, ownerBearer);
  const [publicBearerSecretHash, ownerBearerSecretHash] = await Promise.all([
    bearerHasher("public", publicBearer),
    bearerHasher("owner", ownerBearer)
  ]);
  return {
    operationId: completion.creation.operation_id,
    capabilityId: completion.creation.capability_id,
    locator,
    createdAt: completion.creation.created_at,
    policyHash: completion.creation.policy_hash,
    policy: {
      kind: "secret",
      expiresAt: expiresAtMs,
      maxConsumptions: 1,
      reactivation: "forbidden",
      postConsumption: {
        behavior: "retain_capability",
        retention: { mode: "until_expiry" }
      }
    },
    publicBearerSecretHash,
    ownerBearerSecretHash,
    accessCodeVerifier: completion.creation.access_code_verifier ?? null,
    ciphertextEnvelope: completion.ciphertext_envelope,
    recipientPath: paths.publicPath,
    ownerPath: paths.ownerPath,
    expiresAt: completion.policy.expires_at
  };
}

async function verifySecretPreparationProof(
  material: SecretPreparationProofMaterial,
  proof: string,
  verificationKeys: SecretPreparationVerificationKeys
): Promise<boolean> {
  const signature = decodePreparationProof(proof);
  if (signature === null) {
    return false;
  }
  const keyValues =
    verificationKeys.previous === undefined
      ? [verificationKeys.current]
      : [verificationKeys.current, verificationKeys.previous];
  const keys = await Promise.all(
    keyValues.map((value) => importPreparationSigningKey(value, ["verify"]))
  );
  const message = canonicalPreparationMessage(material);
  try {
    const results = await Promise.all(
      keys.map((key) => crypto.subtle.verify("HMAC", key, signature, message))
    );
    return results.some(Boolean);
  } finally {
    signature.fill(0);
  }
}

function canonicalPreparationMessage(material: SecretPreparationProofMaterial): Uint8Array {
  const canonical = {
    domain: PREPARATION_PROOF_DOMAIN,
    version: PREPARATION_PROOF_VERSION,
    creation: {
      operation_id: material.creation.operation_id,
      capability_id: material.creation.capability_id,
      locator: material.creation.locator,
      created_at: material.creation.created_at,
      policy_hash: material.creation.policy_hash,
      public_bearer: material.creation.public_bearer,
      owner_bearer: material.creation.owner_bearer,
      ...(material.creation.access_code_verifier === undefined
        ? {}
        : { access_code_verifier: material.creation.access_code_verifier })
    },
    policy: {
      kind: material.policy.kind,
      expires_at: material.policy.expires_at,
      max_consumptions: material.policy.max_consumptions,
      reactivation: material.policy.reactivation,
      post_consumption: {
        behavior: material.policy.post_consumption.behavior,
        retention: { mode: material.policy.post_consumption.retention.mode }
      }
    },
    complete_by: material.complete_by
  };
  return new TextEncoder().encode(JSON.stringify(canonical));
}

async function importPreparationSigningKey(
  value: unknown,
  usages: readonly ("sign" | "verify")[]
): Promise<CryptoKey> {
  if (typeof value !== "string" || !canonicalBase64url32Pattern.test(value)) {
    throw new SecretPreparationConfigurationError();
  }
  const bytes = base64urlDecode(value);
  if (bytes?.byteLength !== 32) {
    throw new SecretPreparationConfigurationError();
  }
  try {
    return await crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-256" }, false, [
      ...usages
    ]);
  } catch {
    throw new SecretPreparationConfigurationError();
  } finally {
    bytes.fill(0);
  }
}

function decodePreparationProof(value: string): Uint8Array | null {
  if (!preparationProofPattern.test(value)) {
    return null;
  }
  const bytes = base64urlDecode(value.slice("prep1_".length));
  return bytes?.byteLength === 32 ? bytes : null;
}

function hasExactKeyOrder(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const candidateKeys = Object.keys(value);
  return (
    candidateKeys.length === keys.length && keys.every((key, index) => candidateKeys[index] === key)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function publicPolicy(expiresAt: string): SecretPreparationResponse["policy"] {
  return {
    kind: "secret",
    expires_at: expiresAt,
    max_consumptions: 1,
    reactivation: "forbidden",
    post_consumption: {
      behavior: "retain_capability",
      retention: { mode: "until_expiry" }
    }
  };
}

async function hashCanonicalPolicy(policy: SecretPreparationResponse["policy"]): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify(policy))
  );
  return base64urlEncode(new Uint8Array(digest));
}

function secureRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function exactRandomBytes(source: RandomBytesSource, length: number): Uint8Array {
  const bytes = source(length);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== length) {
    throw new Error("Invalid cryptographic random source");
  }
  return bytes;
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64urlDecode(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/u.test(value) || value.length % 4 === 1) {
    return null;
  }
  try {
    const padded = value
      .replaceAll("-", "+")
      .replaceAll("_", "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=");
    const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    return base64urlEncode(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function isCanonicalTimestamp(value: string): boolean {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}
