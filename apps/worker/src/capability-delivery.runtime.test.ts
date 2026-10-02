import {
  applyD1Migrations,
  createExecutionContext,
  createMessageBatch,
  getQueueResult,
  runInDurableObject
} from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { handleCapabilityQueue } from "./capability-delivery";
import type { WorkerEnv } from "./env";
import {
  applyCapabilityProjection,
  cleanupProjectionRetention,
  completeProjectionReconciliation,
  listDueReconciliationCandidates,
  RECONCILIATION_BATCH_LIMIT
} from "./capability-projection";
import {
  DAY_MS,
  runtimeEnv,
  requiredDatabase,
  projectionMessage,
  producerLocators,
  expectNoProducerState
} from "./testing/capability-delivery-runtime";

beforeEach(async () => {
  const namespace = runtimeEnv.CAPABILITY_STATE;
  if (namespace === undefined) throw new Error("Runtime test requires capability objects");
  for (const locator of producerLocators) {
    await runInDurableObject(namespace.getByName(locator), async (_instance, state) => {
      await expectNoProducerState(state);
    });
  }
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
  it("keeps producer re-entry and alarm work outside the following Queue consumer", async () => {
    const database = requiredDatabase();
    const namespace = runtimeEnv.CAPABILITY_STATE;
    if (namespace === undefined) throw new Error("Runtime test requires capability objects");
    const now = Date.now();
    const message = projectionMessage("ACTIVE", 1, now, "event_consumer_boundary");
    const batch = createMessageBatch("onceurl-local-async-jobs", [
      { id: "consumer-boundary", timestamp: new Date(now), body: message, attempts: 1 }
    ]);
    const context = createExecutionContext();
    await handleCapabilityQueue(batch, runtimeEnv);
    await expect(getQueueResult(batch, context)).resolves.toMatchObject({
      explicitAcks: ["consumer-boundary"],
      retryMessages: []
    });

    // Force the formerly retained objects through actual alarm duties instead
    // of waiting for a timer. Even the reused identity must have no producer state.
    for (const locator of producerLocators) {
      await runInDurableObject(namespace.getByName(locator), async (instance, state) => {
        await expectNoProducerState(state);
        await instance.alarm();
        await expectNoProducerState(state);
      });
    }
    await expect(
      database.prepare("SELECT id, state, version FROM capabilities").all()
    ).resolves.toMatchObject({
      results: [{ id: "cap_projection_runtime", state: "ACTIVE", version: 1 }]
    });
    await expect(
      database.prepare("SELECT event_id FROM capability_projection_events").all()
    ).resolves.toMatchObject({ results: [{ event_id: "event_consumer_boundary" }] });
    for (const [table, count] of [
      ["capabilities", 1],
      ["capability_projection_events", 1],
      ["capability_terminal_tombstones", 0],
      ["capability_reconciliation_candidates", 1]
    ] as const) {
      await expect(
        database.prepare(`SELECT count(*) AS count FROM ${table}`).first(),
        table
      ).resolves.toEqual({ count });
    }
  });

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
});
