import { env } from "cloudflare:workers";
import { parseCapabilityPolicy } from "@onceurl/domain";
import {
  applyD1Migrations,
  createExecutionContext,
  createMessageBatch,
  getQueueResult,
  runInDurableObject,
  type D1Migration
} from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  claimCapability,
  createCapability,
  decideAbuseLock,
  deliverPendingOutbox,
  type CapabilityProjectionMessage
} from "./capability-durable-object-core";
import { handleCapabilityQueue, handleCapabilityReconciliation } from "./capability-delivery";
import {
  applyCapabilityProjection,
  cleanupProjectionRetention,
  completeProjectionReconciliation,
  listDueReconciliationCandidates,
  RECONCILIATION_BATCH_LIMIT
} from "./capability-projection";
import type { WorkerEnv } from "./env";

const DAY_MS = 24 * 60 * 60 * 1_000;
const LOCATOR = `loc1_${"c".repeat(48)}`;
const POLICY = {
  kind: "secret",
  expiresAt: null,
  maxConsumptions: 1,
  reactivation: "forbidden",
  postConsumption: { behavior: "delete_capability" }
} as const;
const parsedPolicy = parseCapabilityPolicy(POLICY);
if (!parsedPolicy.ok) throw new Error("Runtime test policy must be valid");
const ACCESS_CODE_VERIFIER = {
  version: "acv1",
  algorithm: "PBKDF2-SHA-256",
  iterations: 210_000,
  salt: "AAAAAAAAAAAAAAAAAAAAAA",
  digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
} as const;

const runtimeEnv = env as WorkerEnv & { TEST_D1_MIGRATIONS: D1Migration[] };

beforeEach(async () => {
  if (runtimeEnv.DB === undefined) throw new Error("Runtime test requires D1");
  await applyD1Migrations(runtimeEnv.DB, runtimeEnv.TEST_D1_MIGRATIONS);
  await runtimeEnv.DB.batch([
    runtimeEnv.DB.prepare("DELETE FROM capability_reconciliation_candidates"),
    runtimeEnv.DB.prepare("DELETE FROM capability_projection_events"),
    runtimeEnv.DB.prepare("DELETE FROM capability_terminal_tombstones"),
    runtimeEnv.DB.prepare("DELETE FROM capabilities")
  ]);
});

describe("capability Queue and D1 runtime projection", () => {
  it("is idempotent under duplicate and out-of-order terminal delivery", async () => {
    const database = requiredDatabase();
    const activation = projectionMessage("ACTIVE", 1, 1_000, "event_activate");
    const consumed = projectionMessage("CONSUMED", 2, 2_000, "event_consume");

    await applyCapabilityProjection(database, activation, 1_100);
    await applyCapabilityProjection(database, consumed, 2_100);
    await completeProjectionReconciliation(database, consumed, 2_100);
    await applyCapabilityProjection(database, activation, 3_100);
    await completeProjectionReconciliation(database, activation, 3_100);
    await applyCapabilityProjection(database, consumed, 4_100);
    await completeProjectionReconciliation(database, consumed, 4_100);

    const capability = await database
      .prepare("SELECT state, version, consumed_at FROM capabilities WHERE id = ?")
      .bind(consumed.projection.capabilityId)
      .first<{ state: string; version: number; consumed_at: number }>();
    expect(capability).toEqual({ state: "CONSUMED", version: 2, consumed_at: 2_000 });
    const eventCount = await database
      .prepare("SELECT count(*) AS count FROM capability_projection_events WHERE capability_id = ?")
      .bind(consumed.projection.capabilityId)
      .first<{ count: number }>();
    expect(eventCount?.count).toBe(2);
    await expect(
      database
        .prepare(
          "SELECT reason, retain_until FROM capability_reconciliation_candidates WHERE capability_id = ?"
        )
        .bind(consumed.projection.capabilityId)
        .first()
    ).resolves.toEqual({
      reason: "terminal_verification",
      retain_until: 2_000 + 30 * DAY_MS
    });
  });

  it("keeps a deletion tombstone from being resurrected by an older projection", async () => {
    const database = requiredDatabase();
    const deleted = projectionMessage("DELETED", 3, 3_000, "event_delete");
    await applyCapabilityProjection(
      database,
      projectionMessage("ACTIVE", 1, 1_000, "event_activate"),
      1_100
    );
    await applyCapabilityProjection(database, deleted, 3_100);
    await applyCapabilityProjection(
      database,
      projectionMessage("ACTIVE", 1, 1_000, "event_activate"),
      4_100
    );

    expect(
      await database
        .prepare("SELECT state FROM capabilities WHERE id = ?")
        .bind(deleted.projection.capabilityId)
        .first()
    ).toBeNull();
    await expect(
      database
        .prepare(
          "SELECT terminal_state, projection_version FROM capability_terminal_tombstones WHERE capability_id = ?"
        )
        .bind(deleted.projection.capabilityId)
        .first()
    ).resolves.toEqual({ terminal_state: "DELETED", projection_version: 3 });
  });

  it("processes valid messages while isolating poison messages for retry", async () => {
    const occurredAt = Date.now();
    const valid = projectionMessage("ACTIVE", 1, occurredAt, "event_queue");
    const batch = createMessageBatch("onceurl-local-async-jobs", [
      {
        id: "poison",
        timestamp: new Date(occurredAt),
        body: { secret: "must-not-log" },
        attempts: 1
      },
      { id: "valid", timestamp: new Date(occurredAt), body: valid, attempts: 1 }
    ]);
    const context = createExecutionContext();
    const warning = vi.spyOn(console, "warn").mockImplementation(() => undefined);

    try {
      await handleCapabilityQueue(batch, runtimeEnv);
      const queueResult: unknown = await getQueueResult(batch, context);
      expect(queueResult).toMatchObject({
        retryMessages: [{ msgId: "poison" }],
        explicitAcks: ["valid"]
      });
      expect(JSON.stringify(warning.mock.calls)).not.toContain("must-not-log");
    } finally {
      warning.mockRestore();
    }

    await expect(
      requiredDatabase()
        .prepare("SELECT state, version FROM capabilities WHERE id = ?")
        .bind(valid.projection.capabilityId)
        .first()
    ).resolves.toEqual({ state: "ACTIVE", version: 1 });
  });

  it("retries an injected D1 failure and applies the replay exactly once", async () => {
    const database = requiredDatabase();
    const occurredAt = Date.now();
    const message = projectionMessage("ACTIVE", 1, occurredAt, "event_d1_retry");
    const failingDatabase = {
      prepare: database.prepare.bind(database),
      batch: () => Promise.reject(new Error("injected D1 outage"))
    } as unknown as D1Database;
    const failingEnvironment = {
      DB: failingDatabase,
      CAPABILITY_STATE: runtimeEnv.CAPABILITY_STATE
    } as WorkerEnv;
    const failedBatch = createMessageBatch("onceurl-local-async-jobs", [
      { id: "d1-retry", timestamp: new Date(occurredAt), body: message, attempts: 1 }
    ]);
    const failedContext = createExecutionContext();
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      await handleCapabilityQueue(failedBatch, failingEnvironment);
      await expect(getQueueResult(failedBatch, failedContext)).resolves.toMatchObject({
        retryMessages: [{ msgId: "d1-retry" }]
      });
      expect(JSON.stringify(error.mock.calls)).not.toContain("injected D1 outage");
    } finally {
      error.mockRestore();
    }

    for (const id of ["d1-replay", "d1-duplicate"]) {
      const replay = createMessageBatch("onceurl-local-async-jobs", [
        { id, timestamp: new Date(occurredAt), body: message, attempts: 2 }
      ]);
      const context = createExecutionContext();
      await handleCapabilityQueue(replay, runtimeEnv);
      await expect(getQueueResult(replay, context)).resolves.toMatchObject({
        explicitAcks: [id],
        retryMessages: []
      });
    }

    await expect(
      database
        .prepare(
          "SELECT count(*) AS count FROM capability_projection_events WHERE capability_id = ?"
        )
        .bind(message.projection.capabilityId)
        .first<{ count: number }>()
    ).resolves.toEqual({ count: 1 });
  });

  it("uses a bounded candidate sweep to re-enter the authoritative object and redrive outbox", async () => {
    const now = Date.now();
    const namespace = runtimeEnv.CAPABILITY_STATE;
    if (namespace === undefined) throw new Error("Runtime test requires capability objects");
    const stub = namespace.getByName(LOCATOR);
    await runInDurableObject(stub, async (_instance, state) => {
      await createCapability(state.storage, createCommand(now));
    });
    const projection = projectionMessage("ACTIVE", 1, now, "op_create_reconcile");
    await applyCapabilityProjection(requiredDatabase(), projection, now);

    await handleCapabilityReconciliation(runtimeEnv, now);

    const outbox = await runInDurableObject(stub, async (_instance, state) =>
      state.storage.get<Record<string, unknown>>("capability:v1:outbox:op_create_reconcile")
    );
    expect(outbox).toMatchObject({ attemptCount: 1 });
    expect(typeof outbox?.lastAttemptedAt).toBe("number");
    const candidate = await requiredDatabase()
      .prepare(
        "SELECT attempt_count, next_attempt_at FROM capability_reconciliation_candidates WHERE capability_id = ?"
      )
      .bind(projection.projection.capabilityId)
      .first<{ attempt_count: number; next_attempt_at: number }>();
    expect(candidate?.attempt_count).toBe(0);
    expect(candidate?.next_attempt_at).toBeGreaterThan(now);

    const checkpoint = structuredClone(candidate);
    const outboxAfterFirstSweep = structuredClone(outbox);
    await handleCapabilityReconciliation(runtimeEnv, now);
    await expect(
      requiredDatabase()
        .prepare(
          "SELECT attempt_count, next_attempt_at FROM capability_reconciliation_candidates WHERE capability_id = ?"
        )
        .bind(projection.projection.capabilityId)
        .first()
    ).resolves.toEqual(checkpoint);
    await expect(
      runInDurableObject(stub, async (_instance, state) =>
        state.storage.get("capability:v1:outbox:op_create_reconcile")
      )
    ).resolves.toEqual(outboxAfterFirstSweep);
  });

  it("anchors a genuine schema-v2 consumed reconciliation to the legacy consume time", async () => {
    const database = requiredDatabase();
    const now = Date.now();
    const createdAt = now - 4 * DAY_MS;
    const consumedAt = createdAt + 2 * DAY_MS;
    const reconciliationAt = consumedAt + DAY_MS + 1;
    const locator = `loc1_${"e".repeat(48)}`;
    const namespace = runtimeEnv.CAPABILITY_STATE;
    if (namespace === undefined) throw new Error("Runtime test requires capability objects");
    const stub = namespace.getByName(locator);

    const messages = await runInDurableObject(stub, async (_instance, state) => {
      const command = createCommand(createdAt);
      const creation = await createCapability(state.storage, {
        ...command,
        locator,
        ciphertextEnvelope: {
          ...command.ciphertextEnvelope,
          ad: { ...command.ciphertextEnvelope.ad, locator }
        }
      });
      if (!creation.ok) throw new Error("Legacy runtime fixture creation failed");
      const claim = await claimCapability(state.storage, {
        publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        operationId: "op_legacy_consume_runtime",
        nonce: "nonce_legacy_consume_runtime",
        now: consumedAt
      });
      if (!claim.ok) throw new Error("Legacy runtime fixture claim failed");

      const legacyOutboxes = await rewriteDurableObjectAsLegacySchema2(state.storage);
      const captured: CapabilityProjectionMessage[] = [];
      await deliverPendingOutbox(
        state.storage,
        {
          send(message) {
            captured.push(message);
            return Promise.resolve();
          }
        },
        consumedAt
      );
      for (const [key, value] of legacyOutboxes) await state.storage.put(key, value);
      return captured;
    });
    const activation = messages.find((message) => message.event.type === "capability_activated");
    const consumption = messages.find(
      (message) => message.event.type === "capability_consumption_committed"
    );
    if (activation === undefined || consumption === undefined) {
      throw new Error("Legacy runtime fixture did not emit both lifecycle outboxes");
    }

    await applyCapabilityProjection(database, activation, createdAt + 1);
    await completeProjectionReconciliation(database, activation, createdAt + 1);
    await expect(
      database
        .prepare("SELECT state, version FROM capabilities WHERE id = ?")
        .bind(activation.projection.capabilityId)
        .first()
    ).resolves.toEqual({ state: "ACTIVE", version: 1 });

    await handleCapabilityReconciliation(runtimeEnv, reconciliationAt);

    await expect(
      database
        .prepare(
          "SELECT terminal_at, retain_until FROM capability_terminal_tombstones WHERE capability_id = ?"
        )
        .bind(consumption.projection.capabilityId)
        .first()
    ).resolves.toEqual({
      terminal_at: consumedAt,
      retain_until: consumedAt + 30 * DAY_MS
    });
    await expect(
      runInDurableObject(stub, async (_instance, state) =>
        state.storage.get<Record<string, unknown>>("capability:v1:record")
      )
    ).resolves.toMatchObject({
      schemaVersion: 3,
      projectionVersion: 2,
      lastTransition: {
        eventId: "op_legacy_consume_runtime",
        occurredAt: consumedAt,
        toState: "CONSUMED"
      }
    });

    const batch = createMessageBatch("onceurl-local-async-jobs", [
      {
        id: "legacy-consume-delayed",
        timestamp: new Date(now),
        body: consumption,
        attempts: 1
      }
    ]);
    const context = createExecutionContext();
    await handleCapabilityQueue(batch, runtimeEnv);
    await expect(getQueueResult(batch, context)).resolves.toMatchObject({
      explicitAcks: ["legacy-consume-delayed"],
      retryMessages: []
    });
    await expect(
      database
        .prepare(
          "SELECT terminal_at, retain_until FROM capability_terminal_tombstones WHERE capability_id = ?"
        )
        .bind(consumption.projection.capabilityId)
        .first()
    ).resolves.toEqual({
      terminal_at: consumedAt,
      retain_until: consumedAt + 30 * DAY_MS
    });
  });

  it("converges a legacy lock-before-release projection to ACTIVE version 3", async () => {
    const database = requiredDatabase();
    const now = Date.now();
    const createdAt = now - 4 * DAY_MS;
    const lockedAt = createdAt + DAY_MS;
    const releasedAt = createdAt + 2 * DAY_MS;
    const lockDeliveredAt = releasedAt + 1;
    const reconciliationAt = lockDeliveredAt + DAY_MS + 1;
    const locator = `loc1_${"f".repeat(48)}`;
    const namespace = runtimeEnv.CAPABILITY_STATE;
    if (namespace === undefined) throw new Error("Runtime test requires capability objects");
    const stub = namespace.getByName(locator);

    const messages = await runInDurableObject(stub, async (_instance, state) => {
      const command = createCommand(createdAt);
      const creation = await createCapability(state.storage, {
        ...command,
        locator,
        accessCodeVerifier: ACCESS_CODE_VERIFIER,
        ciphertextEnvelope: {
          ...command.ciphertextEnvelope,
          ad: { ...command.ciphertextEnvelope.ad, locator }
        }
      });
      if (!creation.ok) throw new Error("Legacy lock/release fixture creation failed");

      const record = await state.storage.get<Record<string, unknown>>("capability:v1:record");
      if (record === undefined) throw new Error("Legacy lock/release record is missing");
      await state.storage.put("capability:v1:record", {
        ...record,
        lifecycle: { state: "ABUSE_LOCKED", committedConsumptions: 0 },
        projectionVersion: 2,
        lastTransition: {
          eventId: "op_legacy_lock_runtime",
          type: "capability_abuse_locked",
          occurredAt: lockedAt,
          fromState: "ACTIVE",
          toState: "ABUSE_LOCKED"
        }
      });
      await state.storage.put("capability:v1:access-code", {
        schemaVersion: 1,
        failureCount: 10,
        challengeRequired: true,
        backoffUntil: null,
        deleteAt: lockedAt + 72 * 60 * 60 * 1_000
      });
      await state.storage.put("capability:v1:outbox:op_legacy_lock_runtime", {
        schemaVersion: 1,
        eventId: "op_legacy_lock_runtime",
        event: {
          type: "capability_abuse_locked",
          eventId: "op_legacy_lock_runtime",
          occurredAt: lockedAt,
          fromState: "ACTIVE",
          toState: "ABUSE_LOCKED"
        },
        pending: true,
        recordedAt: lockedAt
      });
      const decision = await decideAbuseLock(state.storage, {
        operationId: "op_legacy_release_runtime",
        privilegedDecisionId: "decision_legacy_release_runtime",
        decision: "release",
        now: releasedAt
      });
      if (!decision.ok) throw new Error("Legacy lock/release fixture decision failed");

      const legacyOutboxes = await rewriteDurableObjectAsLegacySchema2(state.storage);
      const legacyRecord = await state.storage.get<Record<string, unknown>>("capability:v1:record");
      if (legacyRecord === undefined) throw new Error("Legacy normalized record is missing");
      const captured: CapabilityProjectionMessage[] = [];
      await deliverPendingOutbox(
        state.storage,
        {
          send(message) {
            captured.push(message);
            return Promise.resolve();
          }
        },
        releasedAt
      );
      await state.storage.put("capability:v1:record", legacyRecord);
      for (const [key, value] of legacyOutboxes) await state.storage.put(key, value);
      await state.storage.deleteAlarm();
      return captured;
    });
    const lock = messages.find((message) => message.event.type === "capability_abuse_locked");
    const release = messages.find(
      (message) =>
        message.event.type === "capability_abuse_lock_decided" && message.event.toState === "ACTIVE"
    );
    if (lock === undefined || release === undefined) {
      throw new Error("Legacy lock/release fixture did not emit both transitions");
    }
    expect(messages.map((message) => message.projection.version)).toEqual([1, 2, 3]);

    await applyCapabilityProjection(database, lock, lockDeliveredAt);
    await completeProjectionReconciliation(database, lock, lockDeliveredAt);
    await expect(
      database
        .prepare("SELECT state, version, updated_at FROM capabilities WHERE id = ?")
        .bind(lock.projection.capabilityId)
        .first()
    ).resolves.toEqual({ state: "ABUSE_LOCKED", version: 2, updated_at: lockedAt });

    await handleCapabilityReconciliation(runtimeEnv, reconciliationAt);
    await expect(
      database
        .prepare("SELECT state, version, updated_at FROM capabilities WHERE id = ?")
        .bind(release.projection.capabilityId)
        .first()
    ).resolves.toEqual({ state: "ACTIVE", version: 3, updated_at: releasedAt });
    await expect(
      runInDurableObject(stub, async (_instance, state) =>
        state.storage.get<Record<string, unknown>>("capability:v1:record")
      )
    ).resolves.toMatchObject({
      schemaVersion: 3,
      lifecycle: { state: "ACTIVE", committedConsumptions: 0 },
      projectionVersion: 3,
      lastTransition: { eventId: "op_legacy_release_runtime", occurredAt: releasedAt }
    });

    const batch = createMessageBatch("onceurl-local-async-jobs", [
      {
        id: "legacy-release-delayed",
        timestamp: new Date(now),
        body: release,
        attempts: 1
      }
    ]);
    const context = createExecutionContext();
    await handleCapabilityQueue(batch, runtimeEnv);
    await expect(getQueueResult(batch, context)).resolves.toMatchObject({
      explicitAcks: ["legacy-release-delayed"],
      retryMessages: []
    });
    await expect(
      database
        .prepare("SELECT state, version, updated_at FROM capabilities WHERE id = ?")
        .bind(release.projection.capabilityId)
        .first()
    ).resolves.toEqual({ state: "ACTIVE", version: 3, updated_at: releasedAt });
  });

  it.each(["CONSUMED", "EXPIRED"] as const)(
    "removes %s catalogue and operational identifiers at the 30-day boundary",
    async (state) => {
      const database = requiredDatabase();
      const terminal = projectionMessage(state, 2, 2_000, `event_retention_${state}`);
      await applyCapabilityProjection(database, terminal, 2_100);

      await cleanupProjectionRetention(database, 2_000 + 30 * DAY_MS);

      for (const table of [
        "capabilities",
        "capability_projection_events",
        "capability_terminal_tombstones",
        "capability_reconciliation_candidates"
      ]) {
        const count = await database
          .prepare(`SELECT count(*) AS count FROM ${table}`)
          .first<{ count: number }>();
        expect(count?.count).toBe(0);
      }
    }
  );

  it("acknowledges an expired queued event without resurrecting state after tombstone cleanup", async () => {
    const database = requiredDatabase();
    const now = Date.now();
    const terminalAt = now - 30 * DAY_MS;
    const staleAt = terminalAt - 1_000;
    const stale = projectionMessage("ACTIVE", 1, staleAt, "event_stale_after_retention");
    const deleted = projectionMessage("DELETED", 2, terminalAt, "event_delete_before_cleanup");
    await applyCapabilityProjection(database, stale, staleAt + 1);
    await applyCapabilityProjection(database, deleted, terminalAt + 1);
    await cleanupProjectionRetention(database, now);

    const batch = createMessageBatch("onceurl-local-async-jobs", [
      {
        id: "stale-after-retention",
        timestamp: new Date(now),
        body: stale,
        attempts: 1
      }
    ]);
    const context = createExecutionContext();
    await handleCapabilityQueue(batch, runtimeEnv);
    await expect(getQueueResult(batch, context)).resolves.toMatchObject({
      explicitAcks: ["stale-after-retention"],
      retryMessages: []
    });

    for (const table of [
      "capabilities",
      "capability_projection_events",
      "capability_terminal_tombstones",
      "capability_reconciliation_candidates"
    ]) {
      await expect(
        database.prepare(`SELECT count(*) AS count FROM ${table}`).first<{ count: number }>()
      ).resolves.toEqual({ count: 0 });
    }
  });

  it("still applies an aged projection returned by authoritative reconciliation", async () => {
    const database = requiredDatabase();
    const now = Date.now();
    const aged = projectionMessage("ACTIVE", 1, now - 30 * DAY_MS, "event_aged_reconciliation");

    await expect(
      applyCapabilityProjection(database, { ...aged, deliveryEventId: null }, now)
    ).resolves.toBe("applied");
    await expect(
      database
        .prepare("SELECT state, version FROM capabilities WHERE id = ?")
        .bind(aged.projection.capabilityId)
        .first()
    ).resolves.toEqual({ state: "ACTIVE", version: 1 });
  });

  it("selects reconciliation candidates in a deterministic bounded batch", async () => {
    const database = requiredDatabase();
    await database.batch(
      Array.from({ length: RECONCILIATION_BATCH_LIMIT + 1 }, (_, index) => {
        const suffix = String(index).padStart(3, "0");
        return database
          .prepare(
            `INSERT INTO capability_reconciliation_candidates (
              capability_id, routing_locator, reason, next_attempt_at,
              attempt_count, last_attempt_at, created_at, retain_until
            ) VALUES (?, ?, 'test', 1, 0, NULL, 1, NULL)`
          )
          .bind(`candidate_${suffix}`, `locator_${suffix}`);
      })
    );

    const candidates = await listDueReconciliationCandidates(database, 1);
    expect(candidates).toHaveLength(RECONCILIATION_BATCH_LIMIT);
    expect(candidates[0]?.capabilityId).toBe("candidate_000");
    expect(candidates.at(-1)?.capabilityId).toBe("candidate_049");
  });

  it("cannot use a stale D1 projection to reopen an authoritative consumed capability", async () => {
    const now = Date.now();
    const namespace = runtimeEnv.CAPABILITY_STATE;
    if (namespace === undefined) throw new Error("Runtime test requires capability objects");
    const locator = `loc1_${"d".repeat(48)}`;
    const stub = namespace.getByName(locator);
    const command = createCommand(now);
    await runInDurableObject(stub, async (_instance, state) => {
      await createCapability(state.storage, {
        ...command,
        locator,
        ciphertextEnvelope: {
          ...command.ciphertextEnvelope,
          ad: { ...command.ciphertextEnvelope.ad, locator }
        }
      });
      await claimCapability(state.storage, {
        publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        operationId: "op_consumed_before_stale_d1",
        nonce: "nonce_consumed_before_stale_d1",
        now: now + 1
      });
    });
    const staleProjection = projectionMessage("ACTIVE", 1, now, "event_stale_active");
    await applyCapabilityProjection(
      requiredDatabase(),
      {
        ...staleProjection,
        projection: { ...staleProjection.projection, locator }
      },
      now + 2
    );

    const response = await stub.fetch(
      new Request("https://capability.invalid/internal/capability/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          operationId: "op_after_stale_d1",
          nonce: "nonce_after_stale_d1",
          now: now + 3
        })
      })
    );
    await expect(response.json()).resolves.toEqual({ ok: false, code: "unavailable" });
  });
});

function requiredDatabase(): D1Database {
  if (runtimeEnv.DB === undefined) throw new Error("Runtime test requires D1");
  return runtimeEnv.DB;
}

function projectionMessage(
  state: "ACTIVE" | "CONSUMED" | "EXPIRED" | "DELETED",
  version: number,
  occurredAt: number,
  eventId: string
): CapabilityProjectionMessage {
  const projectionPolicyResult =
    state === "EXPIRED"
      ? parseCapabilityPolicy({ ...POLICY, expiresAt: occurredAt })
      : parsedPolicy;
  if (!projectionPolicyResult.ok) throw new Error("Projection fixture policy must be valid");
  const projectionPolicy = projectionPolicyResult.value;
  return {
    schemaVersion: 1,
    job: "capability_projection",
    deliveryEventId: eventId,
    event: {
      eventId,
      type:
        state === "ACTIVE"
          ? "capability_activated"
          : state === "CONSUMED"
            ? "capability_consumption_committed"
            : state === "EXPIRED"
              ? "capability_expired"
              : "capability_deleted",
      occurredAt,
      fromState: state === "ACTIVE" ? "DRAFT" : "ACTIVE",
      toState: state
    },
    projection: {
      capabilityId: "cap_projection_runtime",
      locator: LOCATOR,
      kind: "secret",
      state,
      createdAt: 1_000,
      updatedAt: occurredAt,
      expiresAt: projectionPolicy.expiresAt,
      consumedAt: state === "CONSUMED" ? occurredAt : null,
      disabledAt: null,
      deletedAt: state === "DELETED" ? occurredAt : null,
      version,
      policy: projectionPolicy,
      automaticDeleteAt: null
    }
  };
}

function createCommand(now = 1_000) {
  const createdAt = new Date(now).toISOString();
  return {
    operationId: "op_create_reconcile",
    capabilityId: "cap_projection_runtime",
    locator: LOCATOR,
    createdAt,
    policy: POLICY,
    policyHash: "policy_hash_runtime",
    publicBearerSecretHash: "bh1_AfZsOtbRWT9tmoTvsqNOTGRcSnDN_sX_ip2zb4v2Zdk",
    ownerBearerSecretHash: "bh1_fPMtNFmwccxj2Z6fkMWWH0TDFqAWQwqfQTmejZo1XsU",
    ciphertextEnvelope: {
      version: "ouzk-v1",
      alg: "AES-256-GCM",
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: "AAAAAAAAAAAAAAAAAAAAAAA",
      ad: {
        capabilityId: "cap_projection_runtime",
        createdAt,
        kind: "secret",
        locator: LOCATOR,
        policyHash: "policy_hash_runtime",
        purpose: "onceurl.phase1a.secret-text",
        version: "ouzk-v1"
      }
    },
    now
  };
}

async function rewriteDurableObjectAsLegacySchema2(
  storage: DurableObjectStorage
): Promise<Map<string, unknown>> {
  const record = await storage.get<Record<string, unknown>>("capability:v1:record");
  if (record === undefined) throw new Error("Legacy runtime fixture record is missing");
  const legacyRecord = structuredClone(record);
  delete legacyRecord.projectionVersion;
  delete legacyRecord.lastTransition;
  await storage.put("capability:v1:record", { ...legacyRecord, schemaVersion: 2 });

  const storedOutboxes = await storage.list<Record<string, unknown>>({
    prefix: "capability:v1:outbox:"
  });
  const legacyOutboxes = new Map<string, unknown>();
  for (const [key, outbox] of storedOutboxes) {
    const legacyOutbox = {
      schemaVersion: 1,
      eventId: outbox.eventId,
      event: outbox.event,
      pending: true,
      recordedAt: outbox.recordedAt
    };
    legacyOutboxes.set(key, legacyOutbox);
    await storage.put(key, legacyOutbox);
  }
  return legacyOutboxes;
}
