import { z } from "zod";
import {
  CAPABILITY_STATES,
  parseCapabilityPolicy,
  parseEpochMilliseconds,
  transitionCapability,
  type CapabilityDomainEvent,
  type CapabilityLifecycle,
  type CapabilityPolicy,
  type CapabilityTransitionError
} from "@onceurl/domain";
import {
  parseAuthorizationHash,
  parseBearerSecret,
  parseCapabilityLocator,
  verifyBearerSecret,
  type CapabilityAuthority
} from "./capability-authority";
import { parseAccessCodeVerifier, verifyAccessCode, type AccessCodeVerifier } from "./access-code";

const RECORD_SCHEMA_VERSION = 3;
const ACCESS_CODE_RECORD_SCHEMA_VERSION = 2;
const SUPPORT_RECORD_SCHEMA_VERSION = 1;
const SUPPORT_SCHEMA_VERSION = 1;
const OUTBOX_SCHEMA_VERSION = 2;
const MAX_ENVELOPE_BYTES = 96 * 1024;
const MAX_ASSOCIATED_DATA_BYTES = 2 * 1024;
const MAX_OPAQUE_FIELD_BYTES = 512;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const CANONICAL_UTC_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

const RECORD_KEY = "capability:v1:record";
const CLAIM_PREFIX = "capability:v1:claim:";
const OUTBOX_PREFIX = "capability:v1:outbox:";
const PASSIVE_RATE_KEY = "capability:v1:rate:passive";
const REVEAL_RATE_KEY = "capability:v1:rate:reveal";
const ACCESS_CODE_STATE_KEY = "capability:v1:access-code";
const PASSIVE_RATE_LIMIT = 60;
const REVEAL_RATE_LIMIT = 10;
const RATE_WINDOW_MS = 60_000;
const UNRESOLVED_ACCESS_LOCK_MS = 72 * 60 * 60 * 1_000;
const DELIVERED_OUTBOX_RETENTION_MS = 7 * 24 * 60 * 60 * 1_000;
const UNRESOLVED_OUTBOX_RETENTION_MS = 30 * 24 * 60 * 60 * 1_000;
const MAX_OUTBOX_DELIVERY_ATTEMPTS_BEFORE_UNRESOLVED = 10;
const MAX_OUTBOX_BATCH = 16;
const MAX_OUTBOX_BACKOFF_MS = 15 * 60 * 1_000;

const boundedOpaqueString = z
  .string()
  .min(1)
  .max(MAX_OPAQUE_FIELD_BYTES)
  .refine((value) => value.trim().length > 0)
  .refine((value) => utf8ByteLength(value) <= MAX_OPAQUE_FIELD_BYTES);
const capabilityLocator = z.string().refine((value) => parseCapabilityLocator(value) !== null);
const authorizationHash = z.string().refine((value) => parseAuthorizationHash(value) !== null);
const publicBearerSecret = z
  .string()
  .refine((value) => parseBearerSecret("public", value) !== null);
const ownerBearerSecret = z.string().refine((value) => parseBearerSecret("owner", value) !== null);

const canonicalUtcTimestamp = z.string().refine(isCanonicalUtcTimestamp);
const epochMilliseconds = z.number().refine((value) => Number.isSafeInteger(value) && value >= 0);
const positiveEpochMilliseconds = z
  .number()
  .refine((value) => Number.isSafeInteger(value) && value > 0);

const createCapabilityCommandSchema = z
  .strictObject({
    operationId: boundedOpaqueString,
    capabilityId: boundedOpaqueString,
    locator: capabilityLocator,
    createdAt: canonicalUtcTimestamp,
    policy: z.unknown(),
    policyHash: boundedOpaqueString,
    publicBearerSecretHash: authorizationHash,
    ownerBearerSecretHash: authorizationHash,
    ciphertextEnvelope: z.unknown(),
    accessCodeVerifier: z.unknown().nullable().optional(),
    now: epochMilliseconds
  })
  .refine((command) => command.publicBearerSecretHash !== command.ownerBearerSecretHash, {
    path: ["ownerBearerSecretHash"]
  });

const claimCapabilityCommandSchema = z.strictObject({
  publicBearerSecret,
  operationId: boundedOpaqueString,
  nonce: boundedOpaqueString,
  accessCode: z.unknown().optional(),
  challengeVerified: z.boolean().optional(),
  now: epochMilliseconds
});

const authorizeCapabilityCommandSchema = z.discriminatedUnion("authority", [
  z.strictObject({
    authority: z.literal("public"),
    bearerSecret: publicBearerSecret,
    now: epochMilliseconds
  }),
  z.strictObject({
    authority: z.literal("owner"),
    bearerSecret: ownerBearerSecret,
    now: epochMilliseconds
  })
]);

const decideAbuseLockCommandSchema = z.strictObject({
  operationId: boundedOpaqueString,
  privilegedDecisionId: boundedOpaqueString,
  decision: z.enum(["release", "disable", "delete"]),
  now: epochMilliseconds
});

const deleteCapabilityCommandSchema = z.strictObject({
  ownerBearerSecret,
  operationId: boundedOpaqueString,
  now: epochMilliseconds
});

const terminalEvidenceSchema = z.strictObject({
  capabilityId: boundedOpaqueString,
  locator: capabilityLocator,
  eventId: boundedOpaqueString,
  state: z.enum(["CONSUMED", "EXPIRED", "DELETED"]),
  version: z.number().int().positive(),
  occurredAt: epochMilliseconds
});

const reconcileCapabilityCommandSchema = z.strictObject({
  now: epochMilliseconds,
  terminalEvidence: terminalEvidenceSchema.nullable().optional()
});

const outboxDeliveryCommandSchema = z.strictObject({
  eventId: boundedOpaqueString,
  now: epochMilliseconds
});

const projectionAcknowledgementCommandSchema = z.strictObject({
  eventId: boundedOpaqueString,
  projectionVersion: z.number().int().positive(),
  now: epochMilliseconds
});

const projectionTransitionSchema = z.strictObject({
  eventId: boundedOpaqueString,
  type: z.enum([
    "capability_activated",
    "capability_consumption_committed",
    "capability_expired",
    "capability_disabled",
    "capability_abuse_locked",
    "capability_reactivated",
    "capability_abuse_lock_decided",
    "capability_deleted"
  ]),
  occurredAt: epochMilliseconds,
  fromState: z.enum(CAPABILITY_STATES),
  toState: z.enum(CAPABILITY_STATES)
});

const capabilityProjectionMessageSchema = z.strictObject({
  schemaVersion: z.literal(1),
  job: z.literal("capability_projection"),
  deliveryEventId: boundedOpaqueString.nullable(),
  event: projectionTransitionSchema,
  projection: z.strictObject({
    capabilityId: boundedOpaqueString,
    locator: capabilityLocator,
    kind: z.literal("secret"),
    state: z.enum(CAPABILITY_STATES),
    createdAt: epochMilliseconds,
    updatedAt: epochMilliseconds,
    expiresAt: epochMilliseconds.nullable(),
    consumedAt: epochMilliseconds.nullable(),
    disabledAt: epochMilliseconds.nullable(),
    deletedAt: epochMilliseconds.nullable(),
    version: z.number().int().positive(),
    policy: z.unknown(),
    automaticDeleteAt: epochMilliseconds.nullable()
  })
});

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
  nonce: z.string(),
  ciphertext: z.string(),
  ad: associatedDataSchema
});

const persistedRecordFields = {
  capabilityId: boundedOpaqueString,
  locator: capabilityLocator,
  createdAt: canonicalUtcTimestamp,
  policy: z.unknown(),
  policyHash: boundedOpaqueString,
  lifecycle: z.strictObject({
    state: z.enum(CAPABILITY_STATES),
    committedConsumptions: z.number().refine((value) => Number.isSafeInteger(value) && value >= 0)
  }),
  publicBearerSecretHash: authorizationHash,
  ownerBearerSecretHash: authorizationHash,
  ciphertextEnvelope: z.unknown().nullable()
} as const;

const persistedRecordSchema = z.union([
  z.strictObject({
    schemaVersion: z.literal(SUPPORT_RECORD_SCHEMA_VERSION),
    ...persistedRecordFields
  }),
  z.strictObject({
    schemaVersion: z.literal(ACCESS_CODE_RECORD_SCHEMA_VERSION),
    ...persistedRecordFields,
    accessCodeVerifier: z.unknown().nullable()
  }),
  z.strictObject({
    schemaVersion: z.literal(RECORD_SCHEMA_VERSION),
    ...persistedRecordFields,
    accessCodeVerifier: z.unknown().nullable(),
    projectionVersion: z.number().int().positive(),
    lastTransition: z.strictObject({
      eventId: boundedOpaqueString,
      type: z.enum([
        "capability_activated",
        "capability_consumption_committed",
        "capability_expired",
        "capability_disabled",
        "capability_abuse_locked",
        "capability_reactivated",
        "capability_abuse_lock_decided",
        "capability_deleted"
      ]),
      occurredAt: epochMilliseconds,
      fromState: z.enum(CAPABILITY_STATES),
      toState: z.enum(CAPABILITY_STATES)
    })
  })
]);

const claimReplayRecordSchema = z.strictObject({
  schemaVersion: z.literal(SUPPORT_SCHEMA_VERSION),
  operationId: boundedOpaqueString,
  nonce: boundedOpaqueString,
  bearerSecretHash: authorizationHash
});

const rateRecordSchema = z.strictObject({
  schemaVersion: z.literal(SUPPORT_SCHEMA_VERSION),
  attempts: z.array(epochMilliseconds).max(PASSIVE_RATE_LIMIT)
});

const accessCodeStateSchema = z.strictObject({
  schemaVersion: z.literal(SUPPORT_SCHEMA_VERSION),
  failureCount: z.number().int().min(0).max(10),
  challengeRequired: z.boolean(),
  backoffUntil: positiveEpochMilliseconds.nullable(),
  deleteAt: positiveEpochMilliseconds.nullable()
});

export interface CapabilityObjectTransaction {
  get<T = unknown>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  list<T = unknown>(options?: { readonly prefix?: string }): Promise<Map<string, T>>;
  getAlarm(): Promise<number | null>;
  setAlarm(scheduledTime: number): Promise<void>;
  deleteAlarm(): Promise<void>;
}

export interface CapabilityObjectStorage extends CapabilityObjectTransaction {
  transaction<T>(closure: (txn: CapabilityObjectTransaction) => Promise<T>): Promise<T>;
}

export type CreateCapabilityCommand = z.infer<typeof createCapabilityCommandSchema>;
export type ClaimCapabilityCommand = z.infer<typeof claimCapabilityCommandSchema>;
export type AuthorizeCapabilityCommand = z.infer<typeof authorizeCapabilityCommandSchema>;
export type DecideAbuseLockCommand = z.infer<typeof decideAbuseLockCommandSchema>;
export type DeleteCapabilityCommand = z.infer<typeof deleteCapabilityCommandSchema>;
export type ReconcileCapabilityCommand = z.infer<typeof reconcileCapabilityCommandSchema>;

type EnvelopeValidationContext = Pick<
  CreateCapabilityCommand,
  "capabilityId" | "locator" | "createdAt" | "policyHash"
>;

type OuzkEnvelopeV1 = z.infer<typeof envelopeSchema>;

export type CreateFailureCode =
  | "invalid_command"
  | "invalid_policy"
  | "invalid_ciphertext"
  | "already_exists"
  | "event_conflict"
  | "malformed_state"
  | "unavailable";

export type CreateCapabilityResult =
  { readonly ok: true } | { readonly ok: false; readonly code: CreateFailureCode };

export type ClaimCapabilityResult =
  | { readonly ok: true; readonly outcome: "released"; readonly ciphertextEnvelope: unknown }
  | { readonly ok: false; readonly code: ClaimFailureCode; readonly retryAfter?: number };

export type DecideAbuseLockResult =
  { readonly ok: true } | { readonly ok: false; readonly code: DecideAbuseLockFailureCode };

export type DeleteCapabilityResult =
  { readonly ok: true } | { readonly ok: false; readonly code: DeleteCapabilityFailureCode };

export type OutboxDeliveryResult =
  | { readonly ok: true; readonly retained: boolean }
  | { readonly ok: false; readonly code: "invalid_command" | "malformed_state" };

export type ReconcileCapabilityResult =
  | {
      readonly ok: true;
      readonly message: CapabilityProjectionMessage;
      readonly pendingOutboxCount: number;
      readonly nextDueAt: number | null;
    }
  | { readonly ok: false; readonly code: "invalid_command" | "not_found" | "malformed_state" };

export type AuthorizeCapabilityResult =
  | {
      readonly ok: true;
      readonly authority: CapabilityAuthority;
      readonly capability: {
        readonly kind: "secret";
        readonly state: CapabilityLifecycle["state"];
        readonly createdAt: string;
        readonly expiresAt: number | null;
        readonly isAvailable: boolean;
        readonly policy: { readonly maxConsumptions: 1 };
        readonly accessCodeRequired: boolean;
        readonly events?: readonly CoarseCapabilityEvent[];
      };
    }
  | { readonly ok: false; readonly code: AuthorizeFailureCode; readonly retryAfter?: number };

export type AuthorizeFailureCode =
  "invalid_command" | "not_found" | "unauthorized" | "rate_limited" | "malformed_state";

export type ClaimFailureCode =
  | "invalid_command"
  | "not_found"
  | "unauthorized"
  | "nonce_conflict"
  | "event_conflict"
  | "rate_limited"
  | "challenge_required"
  | "verification_failed"
  | "unavailable"
  | "malformed_state";

export type DecideAbuseLockFailureCode =
  "invalid_command" | "not_found" | "event_conflict" | "unavailable" | "malformed_state";

export type DeleteCapabilityFailureCode =
  | "invalid_command"
  | "not_found"
  | "unauthorized"
  | "event_conflict"
  | "unavailable"
  | "malformed_state";

interface CapabilityRecord {
  readonly schemaVersion: 1 | 2 | 3;
  readonly capabilityId: string;
  readonly locator: string;
  readonly createdAt: string;
  readonly policy: CapabilityPolicy;
  readonly policyHash: string;
  readonly lifecycle: CapabilityLifecycle;
  readonly publicBearerSecretHash: string;
  readonly ownerBearerSecretHash: string;
  readonly ciphertextEnvelope: OuzkEnvelopeV1 | null;
  readonly accessCodeVerifier: AccessCodeVerifier | null;
  readonly projectionVersion: number;
  readonly lastTransition: ProjectionTransition;
}

interface ProjectionTransition {
  readonly eventId: string;
  readonly type: CapabilityDomainEvent["type"];
  readonly occurredAt: number;
  readonly fromState: CapabilityLifecycle["state"];
  readonly toState: CapabilityLifecycle["state"];
}

interface ClaimReplayRecordV1 {
  readonly schemaVersion: 1;
  readonly operationId: string;
  readonly nonce: string;
  readonly bearerSecretHash: string;
}

interface RateRecordV1 {
  readonly schemaVersion: 1;
  readonly attempts: readonly number[];
}

interface AccessCodeStateV1 {
  readonly schemaVersion: 1;
  readonly failureCount: number;
  readonly challengeRequired: boolean;
  readonly backoffUntil: number | null;
  readonly deleteAt: number | null;
}

interface OutboxRecordBase {
  readonly eventId: string;
  readonly event: CapabilityDomainEvent;
  readonly recordedAt: number;
  readonly status: "pending" | "unresolved" | "delivered";
  readonly attemptCount: number;
  readonly lastAttemptedAt: number | null;
  readonly nextAttemptAt: number | null;
  readonly deliveredAt: number | null;
  readonly retentionEligibleAt: number;
}

interface LegacyOutboxRecord extends OutboxRecordBase {
  readonly schemaVersion: 1;
  readonly projectionVersion: null;
}

interface OutboxRecord extends OutboxRecordBase {
  readonly schemaVersion: 2;
  readonly projectionVersion: number;
}

type ParsedOutboxRecord = LegacyOutboxRecord | OutboxRecord;

export interface CapabilityProjectionMessage {
  readonly schemaVersion: 1;
  readonly job: "capability_projection";
  readonly deliveryEventId: string | null;
  readonly event: ProjectionTransition;
  readonly projection: {
    readonly capabilityId: string;
    readonly locator: string;
    readonly kind: "secret";
    readonly state: CapabilityLifecycle["state"];
    readonly createdAt: number;
    readonly updatedAt: number;
    readonly expiresAt: number | null;
    readonly consumedAt: number | null;
    readonly disabledAt: number | null;
    readonly deletedAt: number | null;
    readonly version: number;
    readonly policy: CapabilityPolicy;
    readonly automaticDeleteAt: number | null;
  };
}

export function parseCapabilityProjectionMessage(
  value: unknown
): CapabilityProjectionMessage | null {
  const parsed = capabilityProjectionMessageSchema.safeParse(value);
  if (!parsed.success) return null;
  const policy = parseCapabilityPolicy(parsed.data.projection.policy);
  if (!policy.ok || policy.value.kind !== "secret") return null;
  const projection = parsed.data.projection;
  const event = parsed.data.event;
  const deliveryIdentityIsCoherent =
    parsed.data.deliveryEventId === null || parsed.data.deliveryEventId === event.eventId;
  const transitionIsCoherent =
    projection.state === event.toState && projection.updatedAt === event.occurredAt;
  const stateTimesAreCoherent =
    (projection.state === "CONSUMED") === (projection.consumedAt !== null) &&
    (projection.state === "DISABLED") === (projection.disabledAt !== null) &&
    (projection.state === "DELETED") === (projection.deletedAt !== null) &&
    (projection.state === "ABUSE_LOCKED") === (projection.automaticDeleteAt !== null);
  const expectedAutomaticDeleteAt =
    projection.state === "ABUSE_LOCKED"
      ? unresolvedAccessLockDeleteAt(policy.value, event.occurredAt)
      : null;
  if (
    !deliveryIdentityIsCoherent ||
    !transitionIsCoherent ||
    !stateTimesAreCoherent ||
    projection.expiresAt !== policy.value.expiresAt ||
    projection.automaticDeleteAt !== expectedAutomaticDeleteAt
  ) {
    return null;
  }
  return {
    ...parsed.data,
    projection: { ...projection, policy: policy.value }
  };
}

interface CoarseCapabilityEvent {
  readonly type:
    | "created"
    | "consumed"
    | "expired"
    | "disabled"
    | "abuse_locked"
    | "reactivated"
    | "abuse_lock_decided"
    | "deleted";
  readonly occurredAt: number;
}

export async function createCapability(
  storage: CapabilityObjectStorage,
  input: unknown
): Promise<CreateCapabilityResult> {
  const commandResult = createCapabilityCommandSchema.safeParse(input);
  if (!commandResult.success) {
    return { ok: false, code: "invalid_command" };
  }
  const command = commandResult.data;

  const policy = parseCapabilityPolicy(command.policy);
  if (!policy.ok || policy.value.kind !== "secret") {
    return { ok: false, code: "invalid_policy" };
  }
  const envelope = parseEnvelope(command.ciphertextEnvelope, command);
  if (envelope === null) {
    return { ok: false, code: "invalid_ciphertext" };
  }
  const accessCodeVerifier =
    command.accessCodeVerifier === undefined || command.accessCodeVerifier === null
      ? null
      : parseAccessCodeVerifier(command.accessCodeVerifier);
  if (
    command.accessCodeVerifier !== undefined &&
    command.accessCodeVerifier !== null &&
    accessCodeVerifier === null
  ) {
    return { ok: false, code: "invalid_command" };
  }
  const at = parseEpochMilliseconds(command.now);
  if (!at.ok) {
    return { ok: false, code: "invalid_command" };
  }
  const activation = transitionCapability(
    { state: "DRAFT", committedConsumptions: 0 },
    policy.value,
    { type: "activate", commandId: command.operationId, at: at.value }
  );
  if (!activation.ok) {
    return { ok: false, code: failureCode(activation.error) };
  }

  return storage.transaction(async (txn) => {
    const existing = await txn.get(RECORD_KEY);
    if (existing !== undefined) {
      const record = parsePersistedRecord(existing);
      const activationOutbox = await txn.get(`${OUTBOX_PREFIX}${command.operationId}`);
      return record !== null &&
        isSameCreation(record, command, policy.value, envelope, accessCodeVerifier) &&
        isMatchingActivationOutbox(activationOutbox, command.operationId)
        ? { ok: true }
        : { ok: false, code: "already_exists" };
    }

    const outboxKey = `${OUTBOX_PREFIX}${activation.value.event.eventId}`;
    if ((await txn.get(outboxKey)) !== undefined) {
      return { ok: false, code: "event_conflict" };
    }

    const record: CapabilityRecord = {
      schemaVersion: RECORD_SCHEMA_VERSION,
      capabilityId: command.capabilityId,
      locator: command.locator,
      createdAt: command.createdAt,
      policy: policy.value,
      policyHash: command.policyHash,
      lifecycle: activation.value.lifecycle,
      publicBearerSecretHash: command.publicBearerSecretHash,
      ownerBearerSecretHash: command.ownerBearerSecretHash,
      ciphertextEnvelope: envelope,
      accessCodeVerifier,
      projectionVersion: 1,
      lastTransition: projectionTransition(activation.value.event)
    };
    const outbox = outboxRecord(activation.value.event, command.now, record.projectionVersion);

    await txn.put(RECORD_KEY, record);
    await txn.put(outboxKey, outbox);
    await scheduleAlarmAtOrBefore(txn, command.now);
    return { ok: true };
  });
}

export async function claimCapability(
  storage: CapabilityObjectStorage,
  input: unknown
): Promise<ClaimCapabilityResult> {
  const commandResult = claimCapabilityCommandSchema.safeParse(input);
  if (!commandResult.success) {
    return { ok: false, code: "invalid_command" };
  }
  const command = commandResult.data;
  const at = parseEpochMilliseconds(command.now);
  if (!at.ok) {
    return { ok: false, code: "invalid_command" };
  }

  return storage.transaction(async (txn) => {
    const storedRecord = await txn.get(RECORD_KEY);
    if (storedRecord === undefined) {
      return { ok: false, code: "not_found" };
    }
    let record = parsePersistedRecord(storedRecord);
    if (record === null) {
      return { ok: false, code: "malformed_state" };
    }
    const authorization = await verifyBearerSecret(
      "public",
      command.publicBearerSecret,
      record.publicBearerSecretHash
    );
    if (authorization === "invalid_hash") {
      return { ok: false, code: "malformed_state" };
    }
    if (authorization !== "match") {
      return { ok: false, code: "unauthorized" };
    }

    const bearerSecretHash = record.publicBearerSecretHash;

    const accessState = parseAccessCodeState(await txn.get(ACCESS_CODE_STATE_KEY));
    if (accessState === null || !accessStateMatchesRecord(record, accessState)) {
      return { ok: false, code: "malformed_state" };
    }
    const projectionState = await normalizeProjectionState(
      txn,
      record,
      await txn.list({ prefix: OUTBOX_PREFIX })
    );
    if (projectionState === null) return { ok: false, code: "malformed_state" };
    record = projectionState.record;

    const revealQuota = await consumeCapabilityQuota(
      txn,
      REVEAL_RATE_KEY,
      REVEAL_RATE_LIMIT,
      command.now
    );
    if (revealQuota === "malformed") {
      return { ok: false, code: "malformed_state" };
    }
    if (revealQuota !== null) {
      return { ok: false, code: "rate_limited", retryAfter: revealQuota };
    }

    const replayKey = `${CLAIM_PREFIX}${command.operationId}`;
    const storedReplay = await txn.get(replayKey);
    if (storedReplay !== undefined) {
      const replayResult = claimReplayRecordSchema.safeParse(storedReplay);
      if (!replayResult.success || replayResult.data.operationId !== command.operationId) {
        return { ok: false, code: "malformed_state" };
      }
      const replay = replayResult.data;
      return opaqueValuesEqual(replay.nonce, command.nonce) &&
        opaqueValuesEqual(replay.bearerSecretHash, bearerSecretHash)
        ? { ok: false, code: "unavailable" }
        : { ok: false, code: "nonce_conflict" };
    }

    const outboxKey = `${OUTBOX_PREFIX}${command.operationId}`;
    if ((await txn.get(outboxKey)) !== undefined) {
      return { ok: false, code: "event_conflict" };
    }

    if (record.ciphertextEnvelope === null) {
      return { ok: false, code: "unavailable" };
    }

    if (
      record.lifecycle.state !== "ACTIVE" ||
      (record.policy.expiresAt !== null && command.now >= record.policy.expiresAt)
    ) {
      return { ok: false, code: "unavailable" };
    }

    if (record.accessCodeVerifier !== null) {
      if (accessState.backoffUntil !== null && command.now < accessState.backoffUntil) {
        return {
          ok: false,
          code: "rate_limited",
          retryAfter: Math.max(1, Math.ceil((accessState.backoffUntil - command.now) / 1_000))
        };
      }
      if (accessState.challengeRequired && command.challengeVerified !== true) {
        return { ok: false, code: "challenge_required" };
      }

      const matches = await verifyAccessCode(command.accessCode, record.accessCodeVerifier);
      if (!matches) {
        const failureCount = Math.min(accessState.failureCount + 1, 10);
        const backoffSeconds = accessBackoffSeconds(failureCount);
        const deleteAt =
          failureCount === 10 ? unresolvedAccessLockDeleteAt(record.policy, command.now) : null;
        const nextAccessState: AccessCodeStateV1 = {
          schemaVersion: SUPPORT_SCHEMA_VERSION,
          failureCount,
          challengeRequired: failureCount >= 3,
          backoffUntil: backoffSeconds === null ? null : command.now + backoffSeconds * 1_000,
          deleteAt
        };

        if (failureCount === 10) {
          const transition = transitionCapability(record.lifecycle, record.policy, {
            type: "abuse_lock",
            commandId: command.operationId,
            at: at.value
          });
          if (!transition.ok) {
            return { ok: false, code: failureCode(transition.error) };
          }
          const abuseOutboxKey = `${OUTBOX_PREFIX}${transition.value.event.eventId}`;
          if ((await txn.get(abuseOutboxKey)) !== undefined) {
            return { ok: false, code: "event_conflict" };
          }
          await txn.put(RECORD_KEY, {
            ...record,
            schemaVersion: RECORD_SCHEMA_VERSION,
            lifecycle: transition.value.lifecycle,
            projectionVersion: record.projectionVersion + 1,
            lastTransition: projectionTransition(transition.value.event)
          });
          await txn.put(ACCESS_CODE_STATE_KEY, nextAccessState);
          await txn.put(
            abuseOutboxKey,
            outboxRecord(transition.value.event, command.now, record.projectionVersion + 1)
          );
          await scheduleAlarmAtOrBefore(txn, command.now);
          return { ok: false, code: "unavailable" };
        }

        await txn.put(ACCESS_CODE_STATE_KEY, nextAccessState);
        return backoffSeconds === null
          ? { ok: false, code: "verification_failed" }
          : { ok: false, code: "rate_limited", retryAfter: backoffSeconds };
      }
    }

    const transition = transitionCapability(record.lifecycle, record.policy, {
      type: "consume",
      commandId: command.operationId,
      consumptionId: command.nonce,
      at: at.value
    });
    if (!transition.ok) {
      return { ok: false, code: failureCode(transition.error) };
    }

    const result: ClaimCapabilityResult = {
      ok: true,
      outcome: "released",
      ciphertextEnvelope: record.ciphertextEnvelope
    };
    const nextRecord: CapabilityRecord = {
      ...record,
      schemaVersion: RECORD_SCHEMA_VERSION,
      lifecycle: transition.value.lifecycle,
      ciphertextEnvelope: null,
      projectionVersion: record.projectionVersion + 1,
      lastTransition: projectionTransition(transition.value.event)
    };
    const outbox = outboxRecord(transition.value.event, command.now, nextRecord.projectionVersion);
    const replayRecord: ClaimReplayRecordV1 = {
      schemaVersion: SUPPORT_SCHEMA_VERSION,
      operationId: command.operationId,
      nonce: command.nonce,
      bearerSecretHash
    };

    await txn.put(RECORD_KEY, nextRecord);
    if (record.accessCodeVerifier !== null) {
      await txn.put(ACCESS_CODE_STATE_KEY, emptyAccessCodeState());
    }
    await txn.put(outboxKey, outbox);
    await txn.put(replayKey, replayRecord);
    await scheduleAlarmAtOrBefore(txn, command.now);
    return result;
  });
}

export async function authorizeCapability(
  storage: CapabilityObjectStorage,
  input: unknown
): Promise<AuthorizeCapabilityResult> {
  const commandResult = authorizeCapabilityCommandSchema.safeParse(input);
  if (!commandResult.success) {
    return { ok: false, code: "invalid_command" };
  }
  const command = commandResult.data;
  const authorizationResult = await storage.transaction(async (txn) => {
    const storedRecord = await txn.get(RECORD_KEY);
    if (storedRecord === undefined) {
      return { ok: false, code: "not_found" } as const;
    }
    const record = parsePersistedRecord(storedRecord);
    if (record === null) {
      return { ok: false, code: "malformed_state" } as const;
    }

    const expectedHash =
      command.authority === "public" ? record.publicBearerSecretHash : record.ownerBearerSecretHash;
    const authorization = await verifyBearerSecret(
      command.authority,
      command.bearerSecret,
      expectedHash
    );
    if (authorization === "invalid_hash") {
      return { ok: false, code: "malformed_state" } as const;
    }
    if (authorization !== "match") {
      return { ok: false, code: "unauthorized" } as const;
    }

    const accessState = parseAccessCodeState(await txn.get(ACCESS_CODE_STATE_KEY));
    if (accessState === null || !accessStateMatchesRecord(record, accessState)) {
      return { ok: false, code: "malformed_state" } as const;
    }

    const passiveQuota = await consumeCapabilityQuota(
      txn,
      PASSIVE_RATE_KEY,
      PASSIVE_RATE_LIMIT,
      command.now
    );
    if (passiveQuota === "malformed") {
      return { ok: false, code: "malformed_state" } as const;
    }
    if (passiveQuota !== null) {
      return { ok: false, code: "rate_limited", retryAfter: passiveQuota } as const;
    }

    return { ok: true, record } as const;
  });
  if (!authorizationResult.ok) {
    return authorizationResult;
  }

  const events =
    command.authority === "owner"
      ? parseCoarseEvents(await storage.list({ prefix: OUTBOX_PREFIX }))
      : [];
  if (events === null) {
    return { ok: false, code: "malformed_state" };
  }
  const record = authorizationResult.record;
  return {
    ok: true,
    authority: command.authority,
    capability: {
      kind: "secret",
      state: record.lifecycle.state,
      createdAt: record.createdAt,
      expiresAt: record.policy.expiresAt,
      isAvailable:
        record.lifecycle.state === "ACTIVE" &&
        record.ciphertextEnvelope !== null &&
        (record.policy.expiresAt === null || command.now < record.policy.expiresAt),
      policy: { maxConsumptions: 1 },
      accessCodeRequired: record.accessCodeVerifier !== null,
      ...(command.authority === "owner" ? { events } : {})
    }
  };
}

export async function decideAbuseLock(
  storage: CapabilityObjectStorage,
  input: unknown
): Promise<DecideAbuseLockResult> {
  const commandResult = decideAbuseLockCommandSchema.safeParse(input);
  if (!commandResult.success) {
    return { ok: false, code: "invalid_command" };
  }
  const command = commandResult.data;
  const at = parseEpochMilliseconds(command.now);
  if (!at.ok) {
    return { ok: false, code: "invalid_command" };
  }

  return storage.transaction(async (txn) => {
    const stored = await txn.get(RECORD_KEY);
    if (stored === undefined) return { ok: false, code: "not_found" };
    let record = parsePersistedRecord(stored);
    if (record === null) return { ok: false, code: "malformed_state" };
    const accessState = parseAccessCodeState(await txn.get(ACCESS_CODE_STATE_KEY));
    if (accessState === null || !accessStateMatchesRecord(record, accessState)) {
      return { ok: false, code: "malformed_state" };
    }
    const projectionState = await normalizeProjectionState(
      txn,
      record,
      await txn.list({ prefix: OUTBOX_PREFIX })
    );
    if (projectionState === null) return { ok: false, code: "malformed_state" };
    record = projectionState.record;

    if (accessState.deleteAt !== null && command.now >= accessState.deleteAt) {
      const transition = transitionCapability(record.lifecycle, record.policy, {
        type: "decide_abuse_lock",
        commandId: `automatic-delete:${accessState.deleteAt}`,
        privilegedDecisionId: "system:unresolved-access-lock",
        decision: "delete",
        at: at.value
      });
      if (!transition.ok) return { ok: false, code: failureCode(transition.error) };
      await persistMaintenanceTransition(txn, record, transition.value, command.now, true);
      await txn.put(ACCESS_CODE_STATE_KEY, emptyAccessCodeState());
      await scheduleAlarmAtOrBefore(txn, command.now);
      return { ok: false, code: "unavailable" };
    }

    const transition = transitionCapability(record.lifecycle, record.policy, {
      type: "decide_abuse_lock",
      commandId: command.operationId,
      privilegedDecisionId: command.privilegedDecisionId,
      decision: command.decision,
      at: at.value
    });
    if (!transition.ok) return { ok: false, code: failureCode(transition.error) };

    const outboxKey = `${OUTBOX_PREFIX}${transition.value.event.eventId}`;
    if ((await txn.get(outboxKey)) !== undefined) {
      return { ok: false, code: "event_conflict" };
    }
    await txn.put(RECORD_KEY, {
      ...record,
      schemaVersion: RECORD_SCHEMA_VERSION,
      lifecycle: transition.value.lifecycle,
      ...(command.decision === "delete" ? { ciphertextEnvelope: null } : {}),
      projectionVersion: record.projectionVersion + 1,
      lastTransition: projectionTransition(transition.value.event)
    });
    await txn.put(ACCESS_CODE_STATE_KEY, emptyAccessCodeState());
    await txn.put(
      outboxKey,
      outboxRecord(transition.value.event, command.now, record.projectionVersion + 1)
    );
    await scheduleAlarmAtOrBefore(txn, command.now);
    return { ok: true };
  });
}

export async function deleteCapability(
  storage: CapabilityObjectStorage,
  input: unknown
): Promise<DeleteCapabilityResult> {
  const commandResult = deleteCapabilityCommandSchema.safeParse(input);
  if (!commandResult.success) return { ok: false, code: "invalid_command" };
  const command = commandResult.data;
  const at = parseEpochMilliseconds(command.now);
  if (!at.ok) return { ok: false, code: "invalid_command" };

  return storage.transaction(async (txn) => {
    const stored = await txn.get(RECORD_KEY);
    if (stored === undefined) return { ok: false, code: "not_found" };
    let record = parsePersistedRecord(stored);
    if (record === null) return { ok: false, code: "malformed_state" };
    const authorization = await verifyBearerSecret(
      "owner",
      command.ownerBearerSecret,
      record.ownerBearerSecretHash
    );
    if (authorization === "invalid_hash") return { ok: false, code: "malformed_state" };
    if (authorization !== "match") return { ok: false, code: "unauthorized" };
    if (record.lifecycle.state === "DELETED") return { ok: true };
    const projectionState = await normalizeProjectionState(
      txn,
      record,
      await txn.list({ prefix: OUTBOX_PREFIX })
    );
    if (projectionState === null) return { ok: false, code: "malformed_state" };
    record = projectionState.record;

    const transition = transitionCapability(record.lifecycle, record.policy, {
      type: "delete",
      commandId: command.operationId,
      at: at.value
    });
    if (!transition.ok) return { ok: false, code: failureCode(transition.error) };
    const outboxKey = `${OUTBOX_PREFIX}${transition.value.event.eventId}`;
    if ((await txn.get(outboxKey)) !== undefined) {
      return { ok: false, code: "event_conflict" };
    }
    const projectionVersion = record.projectionVersion + 1;
    await txn.put(RECORD_KEY, {
      ...record,
      schemaVersion: RECORD_SCHEMA_VERSION,
      lifecycle: transition.value.lifecycle,
      ciphertextEnvelope: null,
      projectionVersion,
      lastTransition: projectionTransition(transition.value.event)
    });
    await txn.put(ACCESS_CODE_STATE_KEY, emptyAccessCodeState());
    await txn.put(outboxKey, outboxRecord(transition.value.event, command.now, projectionVersion));
    await scheduleAlarmAtOrBefore(txn, command.now);
    return { ok: true };
  });
}

export interface CapabilityQueuePublisher {
  send(message: CapabilityProjectionMessage): Promise<unknown>;
}

export interface OutboxDeliverySummary {
  readonly selected: number;
  readonly submitted: number;
  readonly failed: number;
  readonly pendingAgeBucket: string;
  readonly retryStateBucket: string;
}

export async function deliverPendingOutbox(
  storage: CapabilityObjectStorage,
  queue: CapabilityQueuePublisher,
  now: number
): Promise<OutboxDeliverySummary> {
  const prepared = await preparePendingOutbox(storage, now);
  let submitted = 0;
  let failed = 0;
  for (const message of prepared.messages) {
    try {
      await queue.send(message);
      submitted += 1;
    } catch {
      failed += 1;
    }
  }
  return {
    selected: prepared.messages.length,
    submitted,
    failed,
    pendingAgeBucket: prepared.pendingAgeBucket,
    retryStateBucket: prepared.retryStateBucket
  };
}

export async function acknowledgeOutboxDelivery(
  storage: CapabilityObjectStorage,
  input: unknown
): Promise<OutboxDeliveryResult> {
  const commandResult = projectionAcknowledgementCommandSchema.safeParse(input);
  if (!commandResult.success) return { ok: false, code: "invalid_command" };
  const { eventId, projectionVersion, now } = commandResult.data;
  return storage.transaction(async (txn) => {
    const key = `${OUTBOX_PREFIX}${eventId}`;
    const storedRecord = await txn.get(RECORD_KEY);
    if (storedRecord === undefined) return { ok: true, retained: false };
    const record = parsePersistedRecord(storedRecord);
    if (record === null) return { ok: false, code: "malformed_state" };
    const projectionState = await normalizeProjectionState(
      txn,
      record,
      await txn.list({ prefix: OUTBOX_PREFIX })
    );
    if (projectionState === null) return { ok: false, code: "malformed_state" };
    const outbox = projectionState.outboxes.get(key);
    if (outbox === undefined) return { ok: true, retained: false };
    if (outbox.projectionVersion !== projectionVersion) {
      return { ok: false, code: "malformed_state" };
    }
    if (outbox.status === "delivered") return { ok: true, retained: true };
    await txn.put(key, {
      ...outbox,
      schemaVersion: OUTBOX_SCHEMA_VERSION,
      status: "delivered",
      nextAttemptAt: null,
      deliveredAt: now,
      retentionEligibleAt: now + DELIVERED_OUTBOX_RETENTION_MS
    } satisfies OutboxRecord);
    await rescheduleFromStoredState(txn, now);
    return { ok: true, retained: true };
  });
}

export async function markOutboxDeadLetter(
  storage: CapabilityObjectStorage,
  input: unknown
): Promise<OutboxDeliveryResult> {
  const commandResult = outboxDeliveryCommandSchema.safeParse(input);
  if (!commandResult.success) return { ok: false, code: "invalid_command" };
  const { eventId, now } = commandResult.data;
  return storage.transaction(async (txn) => {
    const key = `${OUTBOX_PREFIX}${eventId}`;
    const storedRecord = await txn.get(RECORD_KEY);
    if (storedRecord === undefined) return { ok: true, retained: false };
    const record = parsePersistedRecord(storedRecord);
    if (record === null) return { ok: false, code: "malformed_state" };
    const projectionState = await normalizeProjectionState(
      txn,
      record,
      await txn.list({ prefix: OUTBOX_PREFIX })
    );
    if (projectionState === null) return { ok: false, code: "malformed_state" };
    const outbox = projectionState.outboxes.get(key);
    if (outbox === undefined) return { ok: true, retained: false };
    if (outbox.status === "delivered") return { ok: true, retained: true };
    await txn.put(key, {
      ...outbox,
      schemaVersion: OUTBOX_SCHEMA_VERSION,
      status: "unresolved",
      nextAttemptAt: Math.min(now + MAX_OUTBOX_BACKOFF_MS, outbox.retentionEligibleAt)
    } satisfies OutboxRecord);
    await rescheduleFromStoredState(txn, now);
    return { ok: true, retained: true };
  });
}

export async function maintainCapability(
  storage: CapabilityObjectStorage,
  now: number,
  terminalEvidence?: z.infer<typeof terminalEvidenceSchema> | null
): Promise<void> {
  const at = parseEpochMilliseconds(now);
  if (!at.ok) throw new Error("Invalid maintenance time");
  await storage.transaction(async (txn) => {
    const stored = await txn.get(RECORD_KEY);
    if (stored === undefined) {
      await txn.deleteAlarm();
      return;
    }
    let record = parsePersistedRecord(stored);
    if (record === null) throw new Error("Malformed capability state");
    let accessState = parseAccessCodeState(await txn.get(ACCESS_CODE_STATE_KEY));
    if (accessState === null || !accessStateMatchesRecord(record, accessState)) {
      throw new Error("Malformed capability access state");
    }
    const normalizedProjectionState = await normalizeProjectionState(
      txn,
      record,
      await txn.list({ prefix: OUTBOX_PREFIX })
    );
    if (normalizedProjectionState === null) {
      throw new Error("Malformed capability projection history");
    }
    record = normalizedProjectionState.record;

    if (terminalEvidence !== undefined && terminalEvidence !== null) {
      if (
        terminalEvidence.capabilityId !== record.capabilityId ||
        terminalEvidence.locator !== record.locator
      ) {
        throw new Error("Terminal evidence does not identify this capability");
      }
      if (
        record.ciphertextEnvelope !== null ||
        !["CONSUMED", "EXPIRED", "DELETED"].includes(record.lifecycle.state) ||
        record.projectionVersion < terminalEvidence.version
      ) {
        record = await applyFailClosedTerminalEvidence(txn, record, terminalEvidence, at.value);
        accessState = emptyAccessCodeState();
      }
    }

    if (
      record.lifecycle.state === "ABUSE_LOCKED" &&
      accessState.deleteAt !== null &&
      now >= accessState.deleteAt
    ) {
      const transition = transitionCapability(record.lifecycle, record.policy, {
        type: "decide_abuse_lock",
        commandId: `automatic-delete:${accessState.deleteAt}`,
        privilegedDecisionId: "system:unresolved-access-lock",
        decision: "delete",
        at: at.value
      });
      if (!transition.ok) throw new Error("Automatic lock deletion transition failed");
      record = await persistMaintenanceTransition(txn, record, transition.value, now, true);
      accessState = emptyAccessCodeState();
      await txn.put(ACCESS_CODE_STATE_KEY, accessState);
    } else if (
      (record.lifecycle.state === "ACTIVE" || record.lifecycle.state === "DISABLED") &&
      record.policy.expiresAt !== null &&
      now >= record.policy.expiresAt
    ) {
      const transition = transitionCapability(record.lifecycle, record.policy, {
        type: "expire",
        commandId: `automatic-expiry:${record.policy.expiresAt}`,
        at: at.value
      });
      if (!transition.ok) throw new Error("Automatic expiry transition failed");
      record = await persistMaintenanceTransition(txn, record, transition.value, now, true);
      accessState = emptyAccessCodeState();
      await txn.put(ACCESS_CODE_STATE_KEY, accessState);
    }

    const storedOutboxes = await txn.list({ prefix: OUTBOX_PREFIX });
    for (const [key, value] of storedOutboxes) {
      const outbox = parseStoredOutbox(value);
      if (outbox !== null && now >= outbox.retentionEligibleAt) {
        await txn.delete(key);
        storedOutboxes.delete(key);
      }
    }
    await setNextAlarm(txn, record, accessState, storedOutboxes, now);
  });
}

export async function reconcileCapability(
  storage: CapabilityObjectStorage,
  input: unknown
): Promise<ReconcileCapabilityResult> {
  const commandResult = reconcileCapabilityCommandSchema.safeParse(input);
  if (!commandResult.success) return { ok: false, code: "invalid_command" };
  const command = commandResult.data;
  try {
    await maintainCapability(storage, command.now, command.terminalEvidence ?? null);
  } catch {
    return { ok: false, code: "malformed_state" };
  }
  return storage.transaction(async (txn) => {
    const stored = await txn.get(RECORD_KEY);
    if (stored === undefined) return { ok: false, code: "not_found" };
    const record = parsePersistedRecord(stored);
    if (record === null) return { ok: false, code: "malformed_state" };
    const accessState = parseAccessCodeState(await txn.get(ACCESS_CODE_STATE_KEY));
    if (accessState === null || !accessStateMatchesRecord(record, accessState)) {
      return { ok: false, code: "malformed_state" };
    }
    const outboxes = await txn.list({ prefix: OUTBOX_PREFIX });
    const projectionState = await normalizeProjectionState(txn, record, outboxes);
    if (projectionState === null) return { ok: false, code: "malformed_state" };
    let pendingOutboxCount = 0;
    for (const outbox of projectionState.outboxes.values()) {
      if (outbox.status !== "delivered") pendingOutboxCount += 1;
    }
    return {
      ok: true,
      message: buildCurrentProjectionMessage(projectionState.record, accessState),
      pendingOutboxCount,
      nextDueAt: calculateNextDue(
        projectionState.record,
        accessState,
        projectionState.outboxes,
        command.now
      )
    };
  });
}

async function preparePendingOutbox(
  storage: CapabilityObjectStorage,
  now: number
): Promise<{
  readonly messages: readonly CapabilityProjectionMessage[];
  readonly pendingAgeBucket: string;
  readonly retryStateBucket: string;
}> {
  return storage.transaction(async (txn) => {
    const stored = await txn.get(RECORD_KEY);
    if (stored === undefined) {
      return { messages: [], pendingAgeBucket: "none", retryStateBucket: "none" };
    }
    const record = parsePersistedRecord(stored);
    if (record === null) throw new Error("Malformed capability state");
    const accessState = parseAccessCodeState(await txn.get(ACCESS_CODE_STATE_KEY));
    if (accessState === null || !accessStateMatchesRecord(record, accessState)) {
      throw new Error("Malformed capability access state");
    }
    const projectionState = await normalizeProjectionState(
      txn,
      record,
      await txn.list({ prefix: OUTBOX_PREFIX })
    );
    if (projectionState === null) {
      console.error("capability_outbox_state_invalid", { category: "malformed_record" });
      throw new Error("Malformed capability projection history");
    }
    const normalizedRecord = projectionState.record;
    const storedOutboxes = projectionState.outboxes;
    const candidates = [...storedOutboxes.entries()]
      .map(([key, outbox]) => ({ key, outbox }))
      .filter(
        ({ outbox }) =>
          outbox.status !== "delivered" &&
          outbox.nextAttemptAt !== null &&
          outbox.nextAttemptAt <= now &&
          outbox.retentionEligibleAt > now
      )
      .sort(
        (left, right) =>
          left.outbox.recordedAt - right.outbox.recordedAt ||
          left.outbox.eventId.localeCompare(right.outbox.eventId)
      )
      .slice(0, MAX_OUTBOX_BATCH);
    const messages: CapabilityProjectionMessage[] = [];
    const retryStates = new Set<string>();
    for (const { key, outbox } of candidates) {
      const attemptCount = outbox.attemptCount + 1;
      const delay = Math.min(
        5_000 * 2 ** Math.min(Math.max(attemptCount - 1, 0), 8),
        MAX_OUTBOX_BACKOFF_MS
      );
      const next: OutboxRecord = {
        ...outbox,
        schemaVersion: OUTBOX_SCHEMA_VERSION,
        status:
          attemptCount >= MAX_OUTBOX_DELIVERY_ATTEMPTS_BEFORE_UNRESOLVED ? "unresolved" : "pending",
        attemptCount,
        lastAttemptedAt: now,
        nextAttemptAt: Math.min(now + delay, outbox.retentionEligibleAt)
      };
      await txn.put(key, next);
      storedOutboxes.set(key, next);
      messages.push(buildOutboxProjectionMessage(normalizedRecord, outbox));
      retryStates.add(
        next.status === "unresolved" ? "unresolved" : attemptCount === 1 ? "initial" : "retry"
      );
    }
    await setNextAlarm(txn, normalizedRecord, accessState, storedOutboxes, now);
    const oldestAge = candidates.reduce(
      (maximum, { outbox }) => Math.max(maximum, now - outbox.recordedAt),
      0
    );
    return {
      messages,
      pendingAgeBucket: candidates.length === 0 ? "none" : operationalAgeBucket(oldestAge),
      retryStateBucket:
        retryStates.size === 0
          ? "none"
          : retryStates.size === 1
            ? (retryStates.values().next().value ?? "none")
            : "mixed"
    };
  });
}

function operationalAgeBucket(ageMilliseconds: number): string {
  if (ageMilliseconds < 60_000) return "under_1m";
  if (ageMilliseconds < 15 * 60_000) return "1m_to_15m";
  if (ageMilliseconds < 60 * 60_000) return "15m_to_1h";
  if (ageMilliseconds < 24 * 60 * 60_000) return "1h_to_24h";
  return "over_24h";
}

async function persistMaintenanceTransition(
  txn: CapabilityObjectTransaction,
  record: CapabilityRecord,
  transition: { readonly lifecycle: CapabilityLifecycle; readonly event: CapabilityDomainEvent },
  now: number,
  deleteCiphertext: boolean
): Promise<CapabilityRecord> {
  const outboxKey = `${OUTBOX_PREFIX}${transition.event.eventId}`;
  if ((await txn.get(outboxKey)) !== undefined) {
    throw new Error("Maintenance event conflict");
  }
  const next: CapabilityRecord = {
    ...record,
    schemaVersion: RECORD_SCHEMA_VERSION,
    lifecycle: transition.lifecycle,
    ...(deleteCiphertext ? { ciphertextEnvelope: null } : {}),
    projectionVersion: record.projectionVersion + 1,
    lastTransition: projectionTransition(transition.event)
  };
  await txn.put(RECORD_KEY, next);
  await txn.put(outboxKey, outboxRecord(transition.event, now, next.projectionVersion));
  return next;
}

async function applyFailClosedTerminalEvidence(
  txn: CapabilityObjectTransaction,
  record: CapabilityRecord,
  evidence: z.infer<typeof terminalEvidenceSchema>,
  now: CapabilityDomainEvent["occurredAt"]
): Promise<CapabilityRecord> {
  const event: CapabilityDomainEvent = {
    type: "capability_deleted",
    eventId: `restore-delete:${evidence.occurredAt}:${evidence.version}`,
    occurredAt: now,
    fromState: record.lifecycle.state,
    toState: "DELETED"
  };
  const outboxKey = `${OUTBOX_PREFIX}${event.eventId}`;
  const existing = await txn.get(outboxKey);
  if (existing !== undefined) {
    const parsed = parseStoredOutbox(existing);
    if (parsed === null) throw new Error("Malformed restoration outbox");
    const next: CapabilityRecord = {
      ...record,
      schemaVersion: RECORD_SCHEMA_VERSION,
      lifecycle: { ...record.lifecycle, state: "DELETED" },
      ciphertextEnvelope: null,
      projectionVersion: Math.max(record.projectionVersion, evidence.version + 1),
      lastTransition: projectionTransition(parsed.event)
    };
    await txn.put(RECORD_KEY, next);
    await txn.put(ACCESS_CODE_STATE_KEY, emptyAccessCodeState());
    return next;
  }
  const next: CapabilityRecord = {
    ...record,
    schemaVersion: RECORD_SCHEMA_VERSION,
    lifecycle: { ...record.lifecycle, state: "DELETED" },
    ciphertextEnvelope: null,
    projectionVersion: Math.max(record.projectionVersion + 1, evidence.version + 1),
    lastTransition: projectionTransition(event)
  };
  await txn.put(RECORD_KEY, next);
  await txn.put(outboxKey, outboxRecord(event, now, next.projectionVersion));
  await txn.put(ACCESS_CODE_STATE_KEY, emptyAccessCodeState());
  return next;
}

function buildCurrentProjectionMessage(
  record: CapabilityRecord,
  accessState: AccessCodeStateV1
): CapabilityProjectionMessage {
  return buildProjectionMessage(
    record,
    record.lastTransition,
    record.projectionVersion,
    null,
    record.lifecycle.state === "ABUSE_LOCKED" ? accessState.deleteAt : null
  );
}

function buildOutboxProjectionMessage(
  record: CapabilityRecord,
  outbox: OutboxRecord
): CapabilityProjectionMessage {
  const transition = projectionTransition(outbox.event);
  return buildProjectionMessage(
    record,
    transition,
    outbox.projectionVersion,
    outbox.eventId,
    transition.toState === "ABUSE_LOCKED"
      ? unresolvedAccessLockDeleteAt(record.policy, transition.occurredAt)
      : null
  );
}

function buildProjectionMessage(
  record: CapabilityRecord,
  transition: ProjectionTransition,
  projectionVersion: number,
  deliveryEventId: string | null,
  automaticDeleteAt: number | null
): CapabilityProjectionMessage {
  const changedAt = transition.occurredAt;
  const state = transition.toState;
  return {
    schemaVersion: 1,
    job: "capability_projection",
    deliveryEventId,
    event: transition,
    projection: {
      capabilityId: record.capabilityId,
      locator: record.locator,
      kind: "secret",
      state,
      createdAt: Date.parse(record.createdAt),
      updatedAt: changedAt,
      expiresAt: record.policy.expiresAt,
      consumedAt: state === "CONSUMED" ? changedAt : null,
      disabledAt: state === "DISABLED" ? changedAt : null,
      deletedAt: state === "DELETED" ? changedAt : null,
      version: projectionVersion,
      policy: record.policy,
      automaticDeleteAt
    }
  };
}

async function rescheduleFromStoredState(
  txn: CapabilityObjectTransaction,
  now: number
): Promise<void> {
  const stored = await txn.get(RECORD_KEY);
  if (stored === undefined) {
    await txn.deleteAlarm();
    return;
  }
  const record = parsePersistedRecord(stored);
  const accessState = parseAccessCodeState(await txn.get(ACCESS_CODE_STATE_KEY));
  if (record === null || accessState === null || !accessStateMatchesRecord(record, accessState)) {
    throw new Error("Malformed capability scheduler state");
  }
  await setNextAlarm(txn, record, accessState, await txn.list({ prefix: OUTBOX_PREFIX }), now);
}

async function setNextAlarm(
  txn: CapabilityObjectTransaction,
  record: CapabilityRecord,
  accessState: AccessCodeStateV1,
  outboxes: Map<string, unknown>,
  now: number
): Promise<void> {
  const nextDue = calculateNextDue(record, accessState, outboxes, now);
  if (nextDue === null) {
    await txn.deleteAlarm();
  } else {
    await txn.setAlarm(nextDue);
  }
}

function calculateNextDue(
  record: CapabilityRecord,
  accessState: AccessCodeStateV1,
  outboxes: Map<string, unknown>,
  now: number
): number | null {
  const duties: number[] = [];
  if (
    (record.lifecycle.state === "ACTIVE" || record.lifecycle.state === "DISABLED") &&
    record.policy.expiresAt !== null
  ) {
    duties.push(record.policy.expiresAt);
  }
  if (record.lifecycle.state === "ABUSE_LOCKED" && accessState.deleteAt !== null) {
    duties.push(accessState.deleteAt);
  }
  let malformed = false;
  for (const value of outboxes.values()) {
    const outbox = parseStoredOutbox(value);
    if (outbox === null) {
      malformed = true;
      continue;
    }
    duties.push(outbox.retentionEligibleAt);
    if (outbox.status !== "delivered" && outbox.nextAttemptAt !== null) {
      duties.push(outbox.nextAttemptAt);
    }
  }
  if (malformed) duties.push(now + MAX_OUTBOX_BACKOFF_MS);
  return duties.length === 0 ? null : Math.min(...duties);
}

async function consumeCapabilityQuota(
  txn: CapabilityObjectTransaction,
  key: string,
  limit: number,
  now: number
): Promise<number | "malformed" | null> {
  const stored = await txn.get(key);
  const parsed =
    stored === undefined
      ? { schemaVersion: SUPPORT_SCHEMA_VERSION, attempts: [] as number[] }
      : rateRecordSchema.safeParse(stored).success
        ? rateRecordSchema.parse(stored)
        : null;
  if (parsed === null) return "malformed";

  const attempts = parsed.attempts.filter(
    (attempt) => attempt > now - RATE_WINDOW_MS && attempt <= now
  );
  if (attempts.length >= limit) {
    const oldest = attempts[attempts.length - limit];
    return oldest === undefined
      ? "malformed"
      : Math.max(1, Math.ceil((oldest + RATE_WINDOW_MS - now) / 1_000));
  }

  const next: RateRecordV1 = {
    schemaVersion: SUPPORT_SCHEMA_VERSION,
    attempts: [...attempts, now]
  };
  await txn.put(key, next);
  return null;
}

function parseAccessCodeState(value: unknown): AccessCodeStateV1 | null {
  if (value === undefined) return emptyAccessCodeState();
  const parsed = accessCodeStateSchema.safeParse(value);
  if (!parsed.success) return null;
  const { failureCount, challengeRequired, backoffUntil, deleteAt } = parsed.data;
  const exactCombination =
    failureCount <= 2
      ? !challengeRequired && backoffUntil === null && deleteAt === null
      : failureCount === 3
        ? challengeRequired && backoffUntil === null && deleteAt === null
        : failureCount <= 9
          ? challengeRequired && backoffUntil !== null && deleteAt === null
          : challengeRequired && backoffUntil === null && deleteAt !== null;
  if (!exactCombination) return null;
  return parsed.data;
}

function accessStateMatchesRecord(
  record: CapabilityRecord,
  accessState: AccessCodeStateV1
): boolean {
  if (record.accessCodeVerifier === null) {
    return accessState.failureCount === 0;
  }
  return (record.lifecycle.state === "ABUSE_LOCKED") === (accessState.failureCount === 10);
}

function emptyAccessCodeState(): AccessCodeStateV1 {
  return {
    schemaVersion: SUPPORT_SCHEMA_VERSION,
    failureCount: 0,
    challengeRequired: false,
    backoffUntil: null,
    deleteAt: null
  };
}

function accessBackoffSeconds(failureCount: number): number | null {
  if (failureCount < 4) return null;
  if (failureCount === 4) return 30;
  if (failureCount === 5) return 120;
  if (failureCount === 6) return 600;
  return failureCount < 10 ? 3_600 : null;
}

function unresolvedAccessLockDeleteAt(policy: CapabilityPolicy, lockedAt: number): number {
  return Math.min(
    lockedAt + UNRESOLVED_ACCESS_LOCK_MS,
    policy.expiresAt ?? Number.MAX_SAFE_INTEGER
  );
}

function outboxRecord(
  event: CapabilityDomainEvent,
  recordedAt: number,
  projectionVersion: number
): OutboxRecord {
  return {
    schemaVersion: OUTBOX_SCHEMA_VERSION,
    eventId: event.eventId,
    event,
    recordedAt,
    projectionVersion,
    status: "pending",
    attemptCount: 0,
    lastAttemptedAt: null,
    nextAttemptAt: recordedAt,
    deliveredAt: null,
    retentionEligibleAt: recordedAt + UNRESOLVED_OUTBOX_RETENTION_MS
  };
}

function projectionTransition(event: CapabilityDomainEvent): ProjectionTransition {
  return {
    eventId: event.eventId,
    type: event.type,
    occurredAt: event.occurredAt,
    fromState: event.fromState,
    toState: event.toState
  };
}

async function scheduleAlarmAtOrBefore(
  txn: CapabilityObjectTransaction,
  dueAt: number
): Promise<void> {
  const existing = await txn.getAlarm();
  if (existing === null || dueAt < existing) {
    await txn.setAlarm(dueAt);
  }
}

function isSameCreation(
  record: CapabilityRecord,
  command: CreateCapabilityCommand,
  policy: CapabilityPolicy,
  envelope: OuzkEnvelopeV1,
  accessCodeVerifier: AccessCodeVerifier | null
): boolean {
  return (
    record.lifecycle.state === "ACTIVE" &&
    record.lifecycle.committedConsumptions === 0 &&
    record.capabilityId === command.capabilityId &&
    record.locator === command.locator &&
    record.createdAt === command.createdAt &&
    record.policyHash === command.policyHash &&
    record.publicBearerSecretHash === command.publicBearerSecretHash &&
    record.ownerBearerSecretHash === command.ownerBearerSecretHash &&
    JSON.stringify(record.accessCodeVerifier) === JSON.stringify(accessCodeVerifier) &&
    JSON.stringify(record.policy) === JSON.stringify(policy) &&
    JSON.stringify(record.ciphertextEnvelope) === JSON.stringify(envelope)
  );
}

function isMatchingActivationOutbox(value: unknown, operationId: string): boolean {
  const outbox = parseStoredOutbox(value);
  return (
    outbox !== null &&
    outbox.eventId === operationId &&
    outbox.event.type === "capability_activated" &&
    outbox.event.eventId === operationId
  );
}

function parseCoarseEvents(values: Map<string, unknown>): readonly CoarseCapabilityEvent[] | null {
  if (values.size > 64) {
    return null;
  }
  const events: CoarseCapabilityEvent[] = [];
  for (const value of values.values()) {
    const outbox = parseStoredOutbox(value);
    if (outbox === null) {
      return null;
    }
    const type = coarseEventType(outbox.event.type);
    if (type === null) {
      return null;
    }
    events.push({ type, occurredAt: outbox.event.occurredAt });
  }
  return events.sort(
    (left, right) =>
      left.occurredAt - right.occurredAt ||
      coarseEventOrder(left.type) - coarseEventOrder(right.type)
  );
}

function parseStoredOutbox(value: unknown): ParsedOutboxRecord | null {
  if (!isRecord(value)) return null;
  const baseValid =
    boundedOpaqueString.safeParse(value.eventId).success &&
    typeof value.recordedAt === "number" &&
    Number.isSafeInteger(value.recordedAt) &&
    value.recordedAt >= 0 &&
    isValidStoredEvent(value.event) &&
    value.event.occurredAt === value.recordedAt &&
    value.event.eventId === value.eventId;
  if (!baseValid || !isValidStoredEvent(value.event)) return null;

  if (
    value.schemaVersion === SUPPORT_SCHEMA_VERSION &&
    hasExactKeys(value, ["schemaVersion", "eventId", "event", "pending", "recordedAt"]) &&
    value.pending === true
  ) {
    return {
      schemaVersion: SUPPORT_SCHEMA_VERSION,
      eventId: value.eventId as string,
      event: value.event,
      recordedAt: value.recordedAt as number,
      projectionVersion: null,
      status: "pending",
      attemptCount: 0,
      lastAttemptedAt: null,
      nextAttemptAt: value.recordedAt as number,
      deliveredAt: null,
      retentionEligibleAt: (value.recordedAt as number) + UNRESOLVED_OUTBOX_RETENTION_MS
    };
  }

  if (
    value.schemaVersion !== OUTBOX_SCHEMA_VERSION ||
    !hasExactKeys(value, [
      "schemaVersion",
      "eventId",
      "event",
      "recordedAt",
      "projectionVersion",
      "status",
      "attemptCount",
      "lastAttemptedAt",
      "nextAttemptAt",
      "deliveredAt",
      "retentionEligibleAt"
    ]) ||
    typeof value.projectionVersion !== "number" ||
    !Number.isSafeInteger(value.projectionVersion) ||
    value.projectionVersion <= 0 ||
    !["pending", "unresolved", "delivered"].includes(String(value.status)) ||
    typeof value.attemptCount !== "number" ||
    !Number.isSafeInteger(value.attemptCount) ||
    value.attemptCount < 0 ||
    !isNullableEpoch(value.lastAttemptedAt) ||
    !isNullableEpoch(value.nextAttemptAt) ||
    !isNullableEpoch(value.deliveredAt) ||
    typeof value.retentionEligibleAt !== "number" ||
    !Number.isSafeInteger(value.retentionEligibleAt) ||
    value.retentionEligibleAt < (value.recordedAt as number)
  ) {
    return null;
  }
  const status = value.status as OutboxRecord["status"];
  if (
    (status === "delivered") !== (value.deliveredAt !== null) ||
    (status === "delivered") !== (value.nextAttemptAt === null)
  ) {
    return null;
  }
  return value as unknown as OutboxRecord;
}

function isNullableEpoch(value: unknown): value is number | null {
  return value === null || (typeof value === "number" && Number.isSafeInteger(value) && value >= 0);
}

interface NormalizedProjectionState {
  readonly record: CapabilityRecord;
  readonly outboxes: Map<string, OutboxRecord>;
}

async function normalizeProjectionState(
  txn: CapabilityObjectTransaction,
  record: CapabilityRecord,
  storedOutboxes: Map<string, unknown>
): Promise<NormalizedProjectionState | null> {
  const parsedEntries: { readonly key: string; readonly outbox: ParsedOutboxRecord }[] = [];
  for (const [key, value] of storedOutboxes) {
    const outbox = parseStoredOutbox(value);
    if (outbox === null || key !== `${OUTBOX_PREFIX}${outbox.eventId}`) return null;
    parsedEntries.push({ key, outbox });
  }

  const currentProjectionVersions = parsedEntries.flatMap(({ outbox }) =>
    outbox.schemaVersion === OUTBOX_SCHEMA_VERSION ? [outbox.projectionVersion] : []
  );
  const requiresLegacyNormalization =
    record.schemaVersion !== RECORD_SCHEMA_VERSION ||
    parsedEntries.some(({ outbox }) => outbox.schemaVersion === SUPPORT_SCHEMA_VERSION) ||
    new Set(currentProjectionVersions).size !== currentProjectionVersions.length;
  if (!requiresLegacyNormalization) {
    const outboxes = new Map<string, OutboxRecord>();
    for (const { key, outbox } of parsedEntries) {
      if (outbox.schemaVersion !== OUTBOX_SCHEMA_VERSION) return null;
      outboxes.set(key, outbox);
    }
    return { record, outboxes };
  }

  const ordered = [...parsedEntries].sort(
    (left, right) =>
      left.outbox.event.occurredAt - right.outbox.event.occurredAt ||
      left.outbox.eventId.localeCompare(right.outbox.eventId)
  );
  if (
    ordered.length === 0 ||
    ordered.some(
      ({ outbox }, index) =>
        index > 0 && outbox.event.occurredAt === ordered[index - 1]?.outbox.event.occurredAt
    )
  ) {
    return null;
  }

  let lifecycle: CapabilityLifecycle = { state: "DRAFT", committedConsumptions: 0 };
  const normalizedOutboxes = new Map<string, OutboxRecord>();
  for (const [index, { key, outbox }] of ordered.entries()) {
    const nextLifecycle = replayLegacyEvent(lifecycle, record.policy, outbox.event);
    if (nextLifecycle === null) return null;
    lifecycle = nextLifecycle;
    normalizedOutboxes.set(key, {
      ...outbox,
      schemaVersion: OUTBOX_SCHEMA_VERSION,
      projectionVersion: index + 1
    });
  }
  if (!sameLifecycle(lifecycle, record.lifecycle)) return null;

  const latest = ordered.at(-1)?.outbox;
  if (latest === undefined) return null;
  const latestTransition = projectionTransition(latest.event);
  if (
    record.schemaVersion === RECORD_SCHEMA_VERSION &&
    !sameProjectionTransition(record.lastTransition, latestTransition)
  ) {
    return null;
  }

  const normalizedRecord: CapabilityRecord = {
    ...record,
    schemaVersion: RECORD_SCHEMA_VERSION,
    projectionVersion: ordered.length,
    lastTransition: latestTransition
  };
  await txn.put(RECORD_KEY, normalizedRecord);
  for (const [key, outbox] of normalizedOutboxes) await txn.put(key, outbox);
  return { record: normalizedRecord, outboxes: normalizedOutboxes };
}

function replayLegacyEvent(
  lifecycle: CapabilityLifecycle,
  policy: CapabilityPolicy,
  event: CapabilityDomainEvent
): CapabilityLifecycle | null {
  const transition = (() => {
    switch (event.type) {
      case "capability_activated":
        return transitionCapability(lifecycle, policy, {
          type: "activate",
          commandId: event.eventId,
          at: event.occurredAt
        });
      case "capability_consumption_committed":
        return transitionCapability(lifecycle, policy, {
          type: "consume",
          commandId: event.eventId,
          consumptionId: event.consumptionId,
          at: event.occurredAt
        });
      case "capability_expired":
        return transitionCapability(lifecycle, policy, {
          type: "expire",
          commandId: event.eventId,
          at: event.occurredAt
        });
      case "capability_disabled":
        return transitionCapability(lifecycle, policy, {
          type: "disable",
          commandId: event.eventId,
          at: event.occurredAt
        });
      case "capability_abuse_locked":
        return transitionCapability(lifecycle, policy, {
          type: "abuse_lock",
          commandId: event.eventId,
          at: event.occurredAt
        });
      case "capability_reactivated":
        return transitionCapability(lifecycle, policy, {
          type: "reactivate",
          commandId: event.eventId,
          at: event.occurredAt
        });
      case "capability_abuse_lock_decided":
        return transitionCapability(lifecycle, policy, {
          type: "decide_abuse_lock",
          commandId: event.eventId,
          privilegedDecisionId: event.privilegedDecisionId,
          decision: event.decision,
          at: event.occurredAt
        });
      case "capability_deleted":
        return transitionCapability(lifecycle, policy, {
          type: "delete",
          commandId: event.eventId,
          at: event.occurredAt
        });
    }
  })();
  return transition.ok && sameDomainEvent(transition.value.event, event)
    ? transition.value.lifecycle
    : null;
}

function sameLifecycle(left: CapabilityLifecycle, right: CapabilityLifecycle): boolean {
  return left.state === right.state && left.committedConsumptions === right.committedConsumptions;
}

function sameProjectionTransition(
  left: ProjectionTransition,
  right: ProjectionTransition
): boolean {
  return (
    left.eventId === right.eventId &&
    left.type === right.type &&
    left.occurredAt === right.occurredAt &&
    left.fromState === right.fromState &&
    left.toState === right.toState
  );
}

function sameDomainEvent(left: CapabilityDomainEvent, right: CapabilityDomainEvent): boolean {
  if (!sameProjectionTransition(projectionTransition(left), projectionTransition(right))) {
    return false;
  }
  if (left.type === "capability_consumption_committed") {
    return (
      right.type === left.type &&
      left.consumptionId === right.consumptionId &&
      left.committedConsumptions === right.committedConsumptions &&
      left.exhausted === right.exhausted
    );
  }
  if (left.type === "capability_abuse_lock_decided") {
    return (
      right.type === left.type &&
      left.decision === right.decision &&
      left.privilegedDecisionId === right.privilegedDecisionId
    );
  }
  return right.type === left.type;
}

function isValidStoredEvent(value: unknown): value is CapabilityDomainEvent {
  if (
    !isRecord(value) ||
    !boundedOpaqueString.safeParse(value.eventId).success ||
    typeof value.occurredAt !== "number" ||
    !Number.isSafeInteger(value.occurredAt) ||
    value.occurredAt < 0 ||
    typeof value.fromState !== "string" ||
    typeof value.toState !== "string" ||
    !CAPABILITY_STATES.includes(value.fromState as CapabilityLifecycle["state"]) ||
    !CAPABILITY_STATES.includes(value.toState as CapabilityLifecycle["state"])
  ) {
    return false;
  }
  const baseKeys = ["type", "eventId", "occurredAt", "fromState", "toState"];
  if (value.type === "capability_consumption_committed") {
    return (
      hasExactKeys(value, [...baseKeys, "consumptionId", "committedConsumptions", "exhausted"]) &&
      boundedOpaqueString.safeParse(value.consumptionId).success &&
      typeof value.committedConsumptions === "number" &&
      Number.isSafeInteger(value.committedConsumptions) &&
      value.committedConsumptions > 0 &&
      typeof value.exhausted === "boolean"
    );
  }
  if (value.type === "capability_abuse_lock_decided") {
    return (
      hasExactKeys(value, [...baseKeys, "decision", "privilegedDecisionId"]) &&
      ["release", "disable", "delete"].includes(String(value.decision)) &&
      boundedOpaqueString.safeParse(value.privilegedDecisionId).success
    );
  }
  return (
    [
      "capability_activated",
      "capability_expired",
      "capability_disabled",
      "capability_abuse_locked",
      "capability_reactivated",
      "capability_deleted"
    ].includes(String(value.type)) && hasExactKeys(value, baseKeys)
  );
}

function coarseEventType(value: unknown): CoarseCapabilityEvent["type"] | null {
  switch (value) {
    case "capability_activated":
      return "created";
    case "capability_consumption_committed":
      return "consumed";
    case "capability_expired":
      return "expired";
    case "capability_disabled":
      return "disabled";
    case "capability_abuse_locked":
      return "abuse_locked";
    case "capability_reactivated":
      return "reactivated";
    case "capability_abuse_lock_decided":
      return "abuse_lock_decided";
    case "capability_deleted":
      return "deleted";
    default:
      return null;
  }
}

function coarseEventOrder(type: CoarseCapabilityEvent["type"]): number {
  return [
    "created",
    "consumed",
    "expired",
    "disabled",
    "abuse_locked",
    "reactivated",
    "abuse_lock_decided",
    "deleted"
  ].indexOf(type);
}

function parsePersistedRecord(value: unknown): CapabilityRecord | null {
  const recordResult = persistedRecordSchema.safeParse(value);
  if (!recordResult.success) {
    return null;
  }
  const stored = recordResult.data;
  if (stored.publicBearerSecretHash === stored.ownerBearerSecretHash) {
    return null;
  }

  const policy = parseCapabilityPolicy(stored.policy);
  if (!policy.ok || policy.value.kind !== "secret") {
    return null;
  }

  const context: EnvelopeValidationContext = {
    capabilityId: stored.capabilityId,
    locator: stored.locator,
    createdAt: stored.createdAt,
    policyHash: stored.policyHash
  };
  const envelope =
    stored.ciphertextEnvelope === null ? null : parseEnvelope(stored.ciphertextEnvelope, context);
  if (stored.ciphertextEnvelope !== null && envelope === null) {
    return null;
  }

  if (!isCoherentSecretRecord(stored.lifecycle, policy.value, envelope)) {
    return null;
  }
  const hasAccessCodeField = stored.schemaVersion >= ACCESS_CODE_RECORD_SCHEMA_VERSION;
  const storedAccessCodeVerifier =
    "accessCodeVerifier" in stored ? stored.accessCodeVerifier : null;
  const accessCodeVerifier =
    hasAccessCodeField && storedAccessCodeVerifier !== null
      ? parseAccessCodeVerifier(storedAccessCodeVerifier)
      : null;
  if (hasAccessCodeField && storedAccessCodeVerifier !== null && accessCodeVerifier === null) {
    return null;
  }

  const legacyChangedAt =
    stored.lifecycle.state === "EXPIRED" && policy.value.expiresAt !== null
      ? policy.value.expiresAt
      : Date.parse(stored.createdAt);
  const lastTransition =
    stored.schemaVersion === RECORD_SCHEMA_VERSION
      ? stored.lastTransition
      : legacyTransition(stored.lifecycle.state, legacyChangedAt);
  if (lastTransition.toState !== stored.lifecycle.state) {
    return null;
  }

  return {
    schemaVersion: stored.schemaVersion,
    capabilityId: stored.capabilityId,
    locator: stored.locator,
    createdAt: stored.createdAt,
    policy: policy.value,
    policyHash: stored.policyHash,
    lifecycle: stored.lifecycle,
    publicBearerSecretHash: stored.publicBearerSecretHash,
    ownerBearerSecretHash: stored.ownerBearerSecretHash,
    ciphertextEnvelope: envelope,
    accessCodeVerifier,
    projectionVersion:
      stored.schemaVersion === RECORD_SCHEMA_VERSION
        ? stored.projectionVersion
        : stored.lifecycle.state === "ACTIVE"
          ? 1
          : 2,
    lastTransition
  };
}

function legacyTransition(
  state: CapabilityLifecycle["state"],
  occurredAt: number
): ProjectionTransition {
  const type: CapabilityDomainEvent["type"] =
    state === "CONSUMED"
      ? "capability_consumption_committed"
      : state === "EXPIRED"
        ? "capability_expired"
        : state === "DISABLED"
          ? "capability_disabled"
          : state === "ABUSE_LOCKED"
            ? "capability_abuse_locked"
            : state === "DELETED"
              ? "capability_deleted"
              : "capability_activated";
  return {
    eventId: `legacy:${state}:${occurredAt}`,
    type,
    occurredAt,
    fromState: state === "ACTIVE" ? "DRAFT" : state,
    toState: state
  };
}

function isCoherentSecretRecord(
  lifecycle: CapabilityLifecycle,
  policy: CapabilityPolicy,
  envelope: OuzkEnvelopeV1 | null
): boolean {
  if (policy.kind !== "secret" || lifecycle.committedConsumptions > policy.maxConsumptions) {
    return false;
  }

  switch (lifecycle.state) {
    case "ACTIVE":
    case "DISABLED":
    case "ABUSE_LOCKED":
      return lifecycle.committedConsumptions === 0 && envelope !== null;
    case "CONSUMED":
      return lifecycle.committedConsumptions === 1 && envelope === null;
    case "EXPIRED":
      return lifecycle.committedConsumptions === 0 && envelope === null;
    case "DELETED":
      return envelope === null;
    case "DRAFT":
      return false;
  }
}

function parseEnvelope(value: unknown, context: EnvelopeValidationContext): OuzkEnvelopeV1 | null {
  if (
    !isRecord(value) ||
    !isRecord(value.ad) ||
    !hasExactKeyOrder(value.ad, [
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
  const envelopeResult = envelopeSchema.safeParse(value);
  if (!envelopeResult.success) {
    return null;
  }
  const envelope = envelopeResult.data;
  const envelopeBytes = jsonByteLength(envelope);
  if (envelopeBytes < 0 || envelopeBytes > MAX_ENVELOPE_BYTES) {
    return null;
  }
  if (decodedBase64urlLength(envelope.nonce) !== 12) {
    return null;
  }
  const ciphertextLength = decodedBase64urlLength(envelope.ciphertext);
  if (ciphertextLength < 17 || ciphertextLength > 65_552) {
    return null;
  }
  const associatedDataBytes = jsonByteLength(envelope.ad);
  if (associatedDataBytes < 0 || associatedDataBytes > MAX_ASSOCIATED_DATA_BYTES) {
    return null;
  }

  return envelope.ad.capabilityId === context.capabilityId &&
    envelope.ad.createdAt === context.createdAt &&
    envelope.ad.locator === context.locator &&
    envelope.ad.policyHash === context.policyHash
    ? envelope
    : null;
}

function hasExactKeyOrder(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const candidateKeys = Object.keys(value);
  return (
    candidateKeys.length === keys.length && keys.every((key, index) => candidateKeys[index] === key)
  );
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const candidateKeys = Object.keys(value);
  return candidateKeys.length === keys.length && keys.every((key) => candidateKeys.includes(key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCanonicalUtcTimestamp(value: string): boolean {
  if (!CANONICAL_UTC_TIMESTAMP_PATTERN.test(value)) {
    return false;
  }
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function jsonByteLength(value: unknown): number {
  try {
    const encoded = JSON.stringify(value);
    return encoded === undefined ? -1 : utf8ByteLength(encoded);
  } catch {
    return -1;
  }
}

function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function decodedBase64urlLength(value: string): number {
  if (!BASE64URL_PATTERN.test(value) || value.length % 4 === 1) {
    return -1;
  }

  try {
    const padded = value
      .replaceAll("-", "+")
      .replaceAll("_", "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=");
    const decoded = atob(padded);
    const canonical = btoa(decoded).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    return canonical === value ? decoded.length : -1;
  } catch {
    return -1;
  }
}

function opaqueValuesEqual(left: string, right: string): boolean {
  const encoder = new TextEncoder();
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  let difference = leftBytes.length ^ rightBytes.length;

  for (let index = 0; index < MAX_OPAQUE_FIELD_BYTES; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }

  return difference === 0;
}

function failureCode(error: CapabilityTransitionError): "malformed_state" | "unavailable" {
  return error.code === "invalid_count" ? "malformed_state" : "unavailable";
}
