import {
  buildRecipientFragment,
  decodeBase64url,
  encodeBase64url,
  encryptSecret,
  type OuzkEnvelopeV1
} from "./zero-knowledge";
import {
  deriveAccessCodeVerifier,
  isAccessCodeVerifier,
  type AccessCodeVerifier
} from "./access-code";

export const SECRET_EXPIRY_OPTIONS = [3_600, 86_400, 604_800, 2_592_000] as const;
export type SecretExpirySeconds = (typeof SECRET_EXPIRY_OPTIONS)[number];
export const COMPLETION_ATTEMPT_TIMEOUT_MS = 30_000;
export const COMPLETION_RECOVERY_RESERVE_MS = 60_000;

export interface SecretPreparation {
  readonly creation: {
    readonly operation_id: string;
    readonly capability_id: string;
    readonly locator: string;
    readonly created_at: string;
    readonly policy_hash: string;
    readonly public_bearer: string;
    readonly owner_bearer: string;
    readonly access_code_verifier?: AccessCodeVerifier;
  };
  readonly policy: {
    readonly kind: "secret";
    readonly expires_at: string;
    readonly max_consumptions: 1;
    readonly reactivation: "forbidden";
    readonly post_consumption: {
      readonly behavior: "retain_capability";
      readonly retention: { readonly mode: "until_expiry" };
    };
  };
  readonly complete_by: string;
  readonly preparation_proof: string;
}

interface CompletionBody {
  readonly creation: SecretPreparation["creation"];
  readonly policy: SecretPreparation["policy"];
  readonly complete_by: string;
  readonly preparation_proof: string;
  readonly ciphertext_envelope: OuzkEnvelopeV1;
}

export interface PendingSecretCreation {
  readonly operationId: string;
  readonly keyBytes: Uint8Array;
  readonly body: CompletionBody;
  readonly recoveryDeadlineMonotonicMs: number;
}

export interface CompletedSecretCreation {
  readonly recipientUrl: string;
  readonly ownerUrl: string;
  readonly expiresAt: string;
}

export type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
export type MonotonicNow = () => number;

export interface PrepareEncryptedSecretOptions {
  readonly challengeId: string;
  readonly accessCode?: string;
  readonly fetcher?: Fetcher;
  readonly monotonicNow?: MonotonicNow;
}

export interface SubmitEncryptedSecretOptions {
  readonly fetcher?: Fetcher;
  readonly monotonicNow?: MonotonicNow;
  readonly uncertaintyAlreadyKnown?: boolean;
}

export class CreationRequestError extends Error {
  readonly ambiguous: boolean;

  constructor(ambiguous: boolean) {
    super(
      ambiguous
        ? "The creation result is uncertain. Retry this same encrypted request; do not create a replacement yet."
        : "The secret could not be created. Check the form and try again."
    );
    this.name = "CreationRequestError";
    this.ambiguous = ambiguous;
  }
}

export async function prepareEncryptedSecret(
  plaintext: string,
  expiresInSeconds: SecretExpirySeconds,
  options: PrepareEncryptedSecretOptions
): Promise<PendingSecretCreation> {
  const fetcher = options.fetcher ?? fetch;
  const preparationRequestedAt = (options.monotonicNow ?? readMonotonicTime)();
  const accessCodeVerifier =
    options.accessCode === undefined
      ? undefined
      : await deriveAccessCodeVerifier(options.accessCode);
  let response: Response;
  try {
    response = await fetcher("/api/v1/secrets/prepare", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        expires_in_seconds: expiresInSeconds,
        challenge_id: options.challengeId,
        ...(accessCodeVerifier === undefined ? {} : { access_code_verifier: accessCodeVerifier })
      })
    });
  } catch {
    throw new CreationRequestError(false);
  }
  if (!response.ok) {
    throw new CreationRequestError(false);
  }
  const preparation = parsePreparation(await safeJson(response));
  if (
    JSON.stringify(preparation.creation.access_code_verifier) !== JSON.stringify(accessCodeVerifier)
  ) {
    throw new CreationRequestError(false);
  }
  const encrypted = await encryptSecret(plaintext, {
    capabilityId: preparation.creation.capability_id,
    createdAt: preparation.creation.created_at,
    locator: preparation.creation.locator,
    policyHash: preparation.creation.policy_hash
  });
  return {
    operationId: preparation.creation.operation_id,
    keyBytes: decodeBase64url(encrypted.keyBase64url, 32),
    body: {
      creation: preparation.creation,
      policy: preparation.policy,
      complete_by: preparation.complete_by,
      preparation_proof: preparation.preparation_proof,
      ciphertext_envelope: encrypted.envelope
    },
    recoveryDeadlineMonotonicMs:
      preparationRequestedAt +
      Date.parse(preparation.complete_by) -
      Date.parse(preparation.creation.created_at)
  };
}

export async function submitEncryptedSecret(
  pending: PendingSecretCreation,
  origin: string,
  options: SubmitEncryptedSecretOptions = {}
): Promise<CompletedSecretCreation> {
  const fetcher = options.fetcher ?? fetch;
  const monotonicNow = options.monotonicNow ?? readMonotonicTime;
  const creationError = (latestAttemptAmbiguous: boolean): CreationRequestError =>
    new CreationRequestError(options.uncertaintyAlreadyKnown === true || latestAttemptAmbiguous);
  const availableAttemptTime = (): number => {
    const remainingRecoveryMs = pending.recoveryDeadlineMonotonicMs - monotonicNow();
    return options.uncertaintyAlreadyKnown === true
      ? remainingRecoveryMs
      : remainingRecoveryMs - COMPLETION_RECOVERY_RESERVE_MS;
  };
  if (availableAttemptTime() <= 0) {
    throw creationError(false);
  }
  let serializedBody: string;
  try {
    serializedBody = JSON.stringify(pending.body);
  } catch {
    throw creationError(false);
  }
  if (availableAttemptTime() <= 0) {
    throw creationError(false);
  }
  const requestAndParse = async (): Promise<ReturnType<typeof parseCompletion>> => {
    const controller = new AbortController();
    const requestInit: RequestInit = {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": pending.operationId
      },
      body: serializedBody,
      signal: controller.signal
    };
    const dispatchAndParse = async (): Promise<ReturnType<typeof parseCompletion>> => {
      const dispatchAvailableAttemptMs = availableAttemptTime();
      const canDispatch =
        options.uncertaintyAlreadyKnown === true
          ? dispatchAvailableAttemptMs > 0
          : dispatchAvailableAttemptMs >= COMPLETION_ATTEMPT_TIMEOUT_MS;
      if (!canDispatch) {
        throw creationError(false);
      }
      let response: Response;
      try {
        response = await fetcher("/api/v1/secrets", requestInit);
      } catch {
        throw creationError(true);
      }
      if (!response.ok) {
        throw creationError(response.status >= 500);
      }
      try {
        const completion = parseCompletion(await safeJson(response));
        if (
          completion.recipient_path !==
            `/s/${pending.body.creation.locator}/${pending.body.creation.public_bearer}` ||
          completion.owner_path !==
            `/m/${pending.body.creation.locator}/${pending.body.creation.owner_bearer}` ||
          completion.expires_at !== pending.body.policy.expires_at
        ) {
          throw new Error("completion mismatch");
        }
        return completion;
      } catch {
        throw creationError(true);
      }
    };
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const timedAttempt = new Promise<never>((_resolve, reject) => {
      timeout = setTimeout(() => {
        controller.abort();
        reject(creationError(true));
      }, COMPLETION_ATTEMPT_TIMEOUT_MS);
    });
    try {
      return await Promise.race([dispatchAndParse(), timedAttempt]);
    } finally {
      clearTimeout(timeout);
    }
  };
  const completion = await requestAndParse();
  const recipient = new URL(completion.recipient_path, origin);
  recipient.hash = buildRecipientFragment(encodeBase64url(pending.keyBytes)).slice(1);
  const owner = new URL(completion.owner_path, origin);
  if (owner.hash !== "") {
    throw creationError(false);
  }
  const completed = {
    recipientUrl: recipient.toString(),
    ownerUrl: owner.toString(),
    expiresAt: completion.expires_at
  };
  clearPendingSecret(pending);
  return completed;
}

export function clearPendingSecret(pending: PendingSecretCreation | null): void {
  pending?.keyBytes.fill(0);
}

export function isCompletionRecoveryExpired(
  pending: PendingSecretCreation,
  monotonicNow: number = readMonotonicTime()
): boolean {
  return monotonicNow > pending.recoveryDeadlineMonotonicMs;
}

function readMonotonicTime(): number {
  return globalThis.performance.now();
}

function parsePreparation(value: unknown): SecretPreparation {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["creation", "policy", "complete_by", "preparation_proof"])
  ) {
    throw new CreationRequestError(false);
  }
  const creation = value.creation;
  const policy = value.policy;
  if (
    !isRecord(creation) ||
    !hasExactKeys(creation, [
      "operation_id",
      "capability_id",
      "locator",
      "created_at",
      "policy_hash",
      "public_bearer",
      "owner_bearer",
      ...(Object.hasOwn(creation, "access_code_verifier") ? ["access_code_verifier"] : [])
    ]) ||
    [
      creation.operation_id,
      creation.capability_id,
      creation.locator,
      creation.created_at,
      creation.policy_hash,
      creation.public_bearer,
      creation.owner_bearer
    ].some((entry) => typeof entry !== "string") ||
    (Object.hasOwn(creation, "access_code_verifier") &&
      !isAccessCodeVerifier(creation.access_code_verifier)) ||
    !String(creation.operation_id).startsWith("op1_") ||
    !isCanonical32ByteBase64url(String(creation.operation_id).slice(4)) ||
    !/^cap1_[0-9a-f]{48}$/u.test(String(creation.capability_id)) ||
    !/^loc1_[0-9a-f]{48}$/u.test(String(creation.locator)) ||
    !isCanonical32ByteBase64url(String(creation.policy_hash)) ||
    !isCanonicalBearer(String(creation.public_bearer), "pub1_") ||
    !isCanonicalBearer(String(creation.owner_bearer), "own1_") ||
    String(creation.public_bearer).slice(5) === String(creation.owner_bearer).slice(5) ||
    !isCanonicalTimestamp(String(creation.created_at)) ||
    !isRecord(policy) ||
    !hasExactKeys(policy, [
      "kind",
      "expires_at",
      "max_consumptions",
      "reactivation",
      "post_consumption"
    ]) ||
    policy.kind !== "secret" ||
    typeof policy.expires_at !== "string" ||
    !isCanonicalTimestamp(policy.expires_at) ||
    policy.max_consumptions !== 1 ||
    policy.reactivation !== "forbidden" ||
    !isRecord(policy.post_consumption) ||
    !hasExactKeys(policy.post_consumption, ["behavior", "retention"]) ||
    policy.post_consumption.behavior !== "retain_capability" ||
    !isRecord(policy.post_consumption.retention) ||
    !hasExactKeys(policy.post_consumption.retention, ["mode"]) ||
    policy.post_consumption.retention.mode !== "until_expiry" ||
    typeof value.complete_by !== "string" ||
    !isCanonicalTimestamp(value.complete_by) ||
    typeof value.preparation_proof !== "string" ||
    !/^prep1_[A-Za-z0-9_-]{43}$/u.test(value.preparation_proof) ||
    !isCanonical32ByteBase64url(value.preparation_proof.slice("prep1_".length)) ||
    !SECRET_EXPIRY_OPTIONS.includes(
      ((Date.parse(policy.expires_at) - Date.parse(String(creation.created_at))) /
        1_000) as SecretExpirySeconds
    ) ||
    Date.parse(value.complete_by) - Date.parse(String(creation.created_at)) !== 15 * 60 * 1_000
  ) {
    throw new CreationRequestError(false);
  }
  return value as unknown as SecretPreparation;
}

function parseCompletion(value: unknown): {
  readonly recipient_path: string;
  readonly owner_path: string;
  readonly expires_at: string;
} {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["recipient_path", "owner_path", "expires_at"]) ||
    typeof value.recipient_path !== "string" ||
    typeof value.owner_path !== "string" ||
    typeof value.expires_at !== "string" ||
    !/^\/s\/loc1_[0-9a-f]{48}\/pub1_[A-Za-z0-9_-]{43}$/u.test(value.recipient_path) ||
    !/^\/m\/loc1_[0-9a-f]{48}\/own1_[A-Za-z0-9_-]{43}$/u.test(value.owner_path) ||
    !isCanonicalTimestamp(value.expires_at) ||
    value.recipient_path.includes("#") ||
    value.owner_path.includes("#")
  ) {
    throw new CreationRequestError(false);
  }
  return value as { recipient_path: string; owner_path: string; expires_at: string };
}

async function safeJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw new CreationRequestError(false);
  }
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const candidateKeys = Object.keys(value);
  return candidateKeys.length === keys.length && keys.every((key) => candidateKeys.includes(key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCanonicalBearer(value: string, prefix: "pub1_" | "own1_"): boolean {
  return value.startsWith(prefix) && isCanonical32ByteBase64url(value.slice(prefix.length));
}

function isCanonical32ByteBase64url(value: string): boolean {
  try {
    const bytes = decodeBase64url(value, 32);
    bytes.fill(0);
    return true;
  } catch {
    return false;
  }
}

function isCanonicalTimestamp(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    return false;
  }
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}
