import { applyD1Migrations } from "cloudflare:test";
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import {
  aggregateMetric,
  cleanupMetrics,
  readMetrics,
  metricEvent,
  METRIC_DAY,
  METRIC_EVENT_RETENTION,
  METRIC_AGGREGATE_RETENTION,
  METRIC_HOURLY_ADMISSION_LIMIT
} from "./phase1a-metrics";
import { runtimeEnv, requiredDatabase, createCommand } from "./testing/capability-delivery-runtime";
import {
  createCapability,
  deliverPendingOutbox,
  acknowledgeOutboxDelivery,
  maintainCapability,
  administerCapability,
  type CapabilityProjectionMessage
} from "./capability-durable-object-core";
import { TransactionalCapabilityStorage } from "./testing/transactional-capability-storage";
import {
  storeSecurityMetric,
  projectMetricOutbox,
  SECURITY_METRIC_PREFIX
} from "./security-metrics-outbox";
import { handleCapabilityQueue } from "./capability-delivery";
import { createTestApp } from "./app";
import {
  adminTestEnv,
  adminTestAssertion,
  ADMIN_TEST_JWKS,
  ADMIN_TEST_OPERATOR
} from "./testing/admin";

const start = 1_800_000_000_000; // Exact UTC hour, deterministic and independent of wall time.
const database = () => requiredDatabase();
const event = (at = start) => {
  const value = metricEvent("local", at, {
    family: "reveal",
    category: "committed",
    routeTemplate: "claim",
    lifecycleTransition: "consumed"
  });
  if (value === null) throw new Error("Invalid metric fixture");
  return value;
};
async function seedExpired(count: number) {
  const dimensions = JSON.stringify(event().dimensions);
  // Exercise the actual migrated retention constraints and indexes, not a mock.
  await database()
    .prepare(
      `WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i + 1 < ?)
    INSERT INTO phase1a_metric_receipts (event_id, time_bucket, dimensions, processed_at, retain_until, applied)
    SELECT 'expired-' || i, ? - i * 3600000, ?, ?, ? - i * 3600000 + ?, 1 FROM n`
    )
    .bind(
      count,
      start - METRIC_EVENT_RETENTION,
      dimensions,
      start,
      start - METRIC_EVENT_RETENTION,
      METRIC_EVENT_RETENTION
    )
    .run();
  await database()
    .prepare(
      `WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i + 1 < ?)
    INSERT INTO phase1a_metric_aggregates (time_bucket, dimensions, count, processed_at, retain_until)
    SELECT ? - i * 3600000, ?, 1, ?, ? - i * 3600000 + ? FROM n`
    )
    .bind(
      count,
      start - METRIC_AGGREGATE_RETENTION,
      dimensions,
      start,
      start - METRIC_AGGREGATE_RETENTION,
      METRIC_AGGREGATE_RETENTION
    )
    .run();
}
async function seedAdmittedHour(count: number) {
  const dimensions = {
    ...event().dimensions,
    category: "accepted_response" as const,
    lifecycleTransition: "none" as const
  };
  await database()
    .prepare(
      `WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i + 1 < ?)
    INSERT INTO phase1a_metric_receipts (event_id, time_bucket, dimensions, processed_at, retain_until, applied)
    SELECT printf('%08x-0000-4000-8000-000000000000', i), ?, ?, ?, ?, 1 FROM n`
    )
    .bind(count, start, JSON.stringify(dimensions), start, start + METRIC_EVENT_RETENTION)
    .run();
  await database()
    .prepare(
      `INSERT INTO phase1a_metric_aggregates (time_bucket, dimensions, count, processed_at, retain_until)
    VALUES (?, ?, ?, ?, ?)`
    )
    .bind(start, JSON.stringify(dimensions), count, start, start + METRIC_AGGREGATE_RETENTION)
    .run();
  return { ...event(), eventId: "00000000-0000-4000-8000-000000000000", dimensions };
}
async function expiredCounts() {
  const receipt = await database()
    .prepare("SELECT count(*) AS n FROM phase1a_metric_receipts WHERE retain_until <= ?")
    .bind(start)
    .first<{ n: number }>();
  const aggregate = await database()
    .prepare("SELECT count(*) AS n FROM phase1a_metric_aggregates WHERE retain_until <= ?")
    .bind(start)
    .first<{ n: number }>();
  return [receipt?.n, aggregate?.n];
}

beforeEach(async () => {
  await applyD1Migrations(database(), runtimeEnv.TEST_D1_MIGRATIONS);
  await database().exec("DROP TRIGGER IF EXISTS fail_metric;");
  await database().exec("DROP TRIGGER IF EXISTS fail_cleanup;");
  for (const table of [
    "phase1a_metric_receipts",
    "phase1a_metric_aggregates",
    "phase1a_metrics_clock"
  ]) {
    await database().prepare(`DELETE FROM ${table}`).run();
  }
});
afterEach(() => vi.unstubAllGlobals());

describe("real SQLite metric receipt and aggregate boundary", () => {
  it("enforces the source-hour admission bound atomically across dimensions and exposes partial rates", async () => {
    const duplicate = await seedAdmittedHour(METRIC_HOURLY_ADMISSION_LIMIT - 1);
    const outcomes = await Promise.allSettled([
      aggregateMetric(database(), event(), start),
      aggregateMetric(
        database(),
        {
          ...event(),
          dimensions: {
            ...event().dimensions,
            family: "creation",
            routeTemplate: "complete",
            lifecycleTransition: "activated"
          }
        },
        start
      )
    ]);
    expect(outcomes.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((result) => result.status === "rejected")).toHaveLength(1);
    await expect(aggregateMetric(database(), event(), start)).rejects.toThrow(
      "Metric hourly admission limit"
    );
    await aggregateMetric(database(), duplicate, start);
    const readout = await readMetrics(database(), start);
    expect(readout.aggregates.reduce((sum, row) => sum + row.count, 0)).toBe(
      METRIC_HOURLY_ADMISSION_LIMIT
    );
    expect(readout.reconciliation.matches).toBe(true);
    expect(readout.admission).toEqual({
      perSourceHourLimit: 8000,
      saturatedHours: [start],
      truncated: false
    });
    expect(readout.summaries.find((row) => row.environment === "local")).toMatchObject({
      partial: true,
      observedTechnicalSuccess: null,
      confirmedReportsPer1000Creations: null
    });
    await aggregateMetric(database(), event(start + 3_600_000), start + 3_600_000);
    expect(
      (await readMetrics(database(), start + 3_600_000)).aggregates.reduce(
        (sum, row) => sum + row.count,
        0
      )
    ).toBe(METRIC_HOURLY_ADMISSION_LIMIT + 1);
  });
  it("drains a maximum admitted cohort without new traffic and preserves aggregates against late replay", async () => {
    const duplicate = await seedAdmittedHour(METRIC_HOURLY_ADMISSION_LIMIT);
    const now = start + METRIC_EVENT_RETENTION;
    expect(await cleanupMetrics(database(), now, () => 0)).toEqual({
      removedReceipts: 8000,
      removedAggregates: 0,
      complete: true,
      budgetExhausted: false
    });
    expect(
      await database().prepare("SELECT count(*) AS n FROM phase1a_metric_receipts").first()
    ).toEqual({ n: 0 });
    await aggregateMetric(database(), duplicate, now);
    expect((await readMetrics(database(), now)).aggregates[0]?.count).toBe(8000);
  });
  it("keeps an admission-limited committed source durable without restamping it or changing authority", async () => {
    await seedAdmittedHour(METRIC_HOURLY_ADMISSION_LIMIT);
    const storage = new TransactionalCapabilityStorage();
    await createCapability(storage, createCommand(start));
    await acknowledgeOutboxDelivery(storage, {
      eventId: "op_create_reconcile",
      projectionVersion: 1,
      now: start
    });
    await projectMetricOutbox(storage, database(), "local", start);
    const sources = [
      ...(
        await storage.list<{ timeBucket: number; nextAttemptAt: number }>({
          prefix: SECURITY_METRIC_PREFIX
        })
      ).values()
    ];
    expect(sources).toHaveLength(1);
    expect(sources[0]).toMatchObject({ timeBucket: start, nextAttemptAt: start + 300_000 });
    await maintainCapability(storage, start + METRIC_EVENT_RETENTION);
    expect((await storage.list({ prefix: SECURITY_METRIC_PREFIX })).size).toBe(0);
    expect(await storage.get("capability:v1:record")).toMatchObject({
      lifecycle: { state: "ACTIVE" }
    });
    expect(
      (await readMetrics(database(), start + METRIC_EVENT_RETENTION)).aggregates[0]?.count
    ).toBe(8000);
  });
  it("drains more than one retention batch while preserving current rows and repeating safely", async () => {
    await aggregateMetric(database(), event(), start);
    await seedExpired(2501);
    expect(await cleanupMetrics(database(), start)).toEqual({
      removedReceipts: 2501,
      removedAggregates: 2501,
      complete: true,
      budgetExhausted: false
    });
    expect(await expiredCounts()).toEqual([0, 0]);
    expect((await readMetrics(database(), start)).aggregates[0]?.count).toBe(1);
    expect(await cleanupMetrics(database(), start)).toEqual({
      removedReceipts: 0,
      removedAggregates: 0,
      complete: true,
      budgetExhausted: false
    });
  });
  it("commits bounded cleanup progress across an interrupted later batch and recovers", async () => {
    await seedExpired(2501);
    // Oldest 1000 commit. The second batch encounters this newer row and rolls back.
    await database()
      .prepare(
        `CREATE TRIGGER fail_cleanup BEFORE DELETE ON phase1a_metric_receipts WHEN OLD.event_id = 'expired-1000' BEGIN SELECT RAISE(ABORT, 'injected later batch failure'); END;`
      )
      .run();
    await expect(cleanupMetrics(database(), start)).rejects.toThrow();
    expect(await expiredCounts()).toEqual([1501, 1501]);
    await database().exec("DROP TRIGGER fail_cleanup;");
    expect(await cleanupMetrics(database(), start)).toMatchObject({
      removedReceipts: 1501,
      removedAggregates: 1501,
      complete: true
    });
    expect(await expiredCounts()).toEqual([0, 0]);
  });
  it("stops starting cleanup batches at its elapsed budget and resumes the backlog", async () => {
    await seedExpired(2501);
    let clock = 0;
    expect(await cleanupMetrics(database(), start, () => (clock++ === 0 ? 0 : 5000))).toEqual({
      removedReceipts: 1000,
      removedAggregates: 1000,
      complete: false,
      budgetExhausted: true
    });
    expect(await expiredCounts()).toEqual([1501, 1501]);
    expect(await cleanupMetrics(database(), start)).toMatchObject({
      removedReceipts: 1501,
      removedAggregates: 1501,
      complete: true
    });
  });
  it("caps cleanup at eight batches even when elapsed time remains available", async () => {
    await seedExpired(8001);
    expect(await cleanupMetrics(database(), start, () => 0)).toEqual({
      removedReceipts: 8000,
      removedAggregates: 8000,
      complete: false,
      budgetExhausted: true
    });
    expect(await expiredCounts()).toEqual([1, 1]);
    expect(await cleanupMetrics(database(), start)).toMatchObject({
      removedReceipts: 1,
      removedAggregates: 1,
      complete: true
    });
  });
  it.each(["disable", "delete"] as const)(
    "counts administrative %s once across idempotent replay",
    async (action) => {
      const storage = new TransactionalCapabilityStorage();
      const command = createCommand(start);
      await createCapability(storage, command);
      const mutation = {
        mutation: {
          locator: command.locator,
          operation_id: crypto.randomUUID(),
          action,
          reason: "other",
          confirm_abuse: false
        },
        actor: ADMIN_TEST_OPERATOR,
        now: start + 1
      };
      expect(await administerCapability(storage, mutation)).toEqual({ ok: true });
      expect(await administerCapability(storage, mutation)).toEqual({ ok: true });
      await projectMetricOutbox(storage, database(), "local", start + 1);
      expect(
        (await readMetrics(database(), start + 1)).aggregates
          .filter((row) => row.dimensions.category === "enforcement")
          .map((row) => row.count)
      ).toEqual([1]);
      expect((await storage.list({ prefix: "capability:security:v1:" })).size).toBe(1);
    }
  );
  it("pays down expired data before admitting ingestion and retries once without inflation", async () => {
    await seedExpired(251);
    const value = event();
    await expect(aggregateMetric(database(), value, start)).rejects.toThrow(
      "Metric retention backlog"
    );
    expect(await expiredCounts()).toEqual([151, 151]);
    expect(
      await database()
        .prepare("SELECT event_id FROM phase1a_metric_receipts WHERE event_id = ?")
        .bind(value.eventId)
        .first()
    ).toBeNull();
    await expect(aggregateMetric(database(), value, start)).rejects.toThrow(
      "Metric retention backlog"
    );
    expect(await expiredCounts()).toEqual([51, 51]);
    await aggregateMetric(database(), value, start);
    await aggregateMetric(database(), value, start);
    expect(await expiredCounts()).toEqual([0, 0]);
    expect((await readMetrics(database(), start)).aggregates[0]?.count).toBe(1);
  });
  it("rolls back metric transfer with operational acknowledgement and keeps it beyond operational pruning", async () => {
    const storage = new TransactionalCapabilityStorage();
    await createCapability(storage, createCommand(start));
    const before = storage.snapshot();
    storage.failNextTransaction({ phase: "mutation", mutation: 2 });
    const ack = { eventId: "op_create_reconcile", projectionVersion: 1, now: start };
    await expect(acknowledgeOutboxDelivery(storage, ack)).rejects.toThrow();
    expect(storage.snapshot()).toEqual(before);
    expect(await acknowledgeOutboxDelivery(storage, ack)).toEqual({ ok: true, retained: true });
    expect((await storage.list({ prefix: SECURITY_METRIC_PREFIX })).size).toBe(1);
    await maintainCapability(storage, start + 7 * METRIC_DAY);
    expect(await storage.get("capability:v1:outbox:op_create_reconcile")).toBeUndefined();
    expect((await storage.list({ prefix: SECURITY_METRIC_PREFIX })).size).toBe(1);
    await projectMetricOutbox(storage, database(), "local", start + 7 * METRIC_DAY);
    await acknowledgeOutboxDelivery(storage, ack);
    expect((await storage.list({ prefix: SECURITY_METRIC_PREFIX })).size).toBe(0);
    expect((await readMetrics(database(), start + 7 * METRIC_DAY)).aggregates[0]?.count).toBe(1);
  });
  it("audits enforcement and release idempotently without counting release as enforcement", async () => {
    const storage = new TransactionalCapabilityStorage();
    const command = createCommand(start);
    await createCapability(storage, command);
    const lock = {
      mutation: {
        locator: command.locator,
        operation_id: crypto.randomUUID(),
        action: "abuse_lock",
        reason: "other",
        confirm_abuse: false
      },
      actor: ADMIN_TEST_OPERATOR,
      now: start + 1
    };
    expect(await administerCapability(storage, lock)).toEqual({ ok: true });
    expect(await administerCapability(storage, lock)).toEqual({ ok: true });
    const release = {
      ...lock,
      mutation: { ...lock.mutation, operation_id: crypto.randomUUID(), action: "release" },
      now: start + 2
    };
    expect(await administerCapability(storage, release)).toEqual({ ok: true });
    expect(await administerCapability(storage, release)).toEqual({ ok: true });
    expect((await storage.list({ prefix: "capability:security:v1:" })).size).toBe(2);
    expect((await storage.list({ prefix: SECURITY_METRIC_PREFIX })).size).toBe(1);
    await projectMetricOutbox(storage, database(), "local", start + 2);
    expect(
      (await readMetrics(database(), start + 2)).aggregates
        .filter((row) => row.dimensions.category === "enforcement")
        .map((row) => row.count)
    ).toEqual([1]);
    expect(await administerCapability(storage, lock)).toEqual({ ok: true });
    expect(await administerCapability(storage, release)).toEqual({ ok: true });
    expect((await storage.list({ prefix: SECURITY_METRIC_PREFIX })).size).toBe(0);
  });
  it("deduplicates concurrent, retried and out-of-order events and exposes no event identities", async () => {
    const first = event(),
      second = event(start - 3_600_000);
    await Promise.all(
      Array.from({ length: 16 }, () => aggregateMetric(database(), first, start + 1000))
    );
    await aggregateMetric(database(), second, start + 2000);
    const readout = await readMetrics(database(), start + 3000);
    expect(readout.aggregates.reduce((count, row) => count + row.count, 0)).toBe(2);
    expect(readout.reconciliation).toMatchObject({ complete: true, matches: true });
    expect(JSON.stringify(readout)).not.toContain(first.eventId);
    expect(JSON.stringify(readout)).not.toContain("eventId");
    expect(JSON.stringify(readout)).not.toContain("capabilityId");
    await aggregateMetric(
      database(),
      { ...first, dimensions: { ...first.dimensions, category: "policy_rejected" } },
      start + 4000
    );
    expect(
      (await readMetrics(database(), start + 4000)).aggregates.reduce(
        (count, row) => count + row.count,
        0
      )
    ).toBe(2);
  });
  it("rejects delayed and replayed messages after dedupe expiry, including clock rollback", async () => {
    const value = event();
    await aggregateMetric(database(), value, start + METRIC_EVENT_RETENTION - 1);
    await cleanupMetrics(database(), start + METRIC_EVENT_RETENTION);
    expect(
      await database().prepare("SELECT count(*) AS n FROM phase1a_metric_receipts").first()
    ).toEqual({ n: 0 });
    await aggregateMetric(database(), value, start + METRIC_EVENT_RETENTION);
    await aggregateMetric(database(), value, start + 1000);
    await aggregateMetric(database(), event(), start + METRIC_EVENT_RETENTION + METRIC_DAY);
    const readout = await readMetrics(database(), start + METRIC_EVENT_RETENTION + METRIC_DAY);
    expect(readout.aggregates[0]?.count).toBe(1);
    expect(readout.reconciliation.olderHistory).toBe("source_expired_unverified");
    await cleanupMetrics(database(), start + METRIC_AGGREGATE_RETENTION);
    expect((await readMetrics(database(), start + METRIC_AGGREGATE_RETENTION)).aggregates).toEqual(
      []
    );
  });
  it("rejects future buckets without retaining dedupe and permits them only once they become current", async () => {
    const value = event(start + 3_600_000);
    await aggregateMetric(database(), value, start);
    expect((await readMetrics(database(), start)).aggregates).toEqual([]);
    await aggregateMetric(database(), value, start + 3_600_000);
    expect((await readMetrics(database(), start + 3_600_000)).aggregates[0]?.count).toBe(1);
  });
  it("rolls back a failed aggregate batch and recovers once without duplicate inflation", async () => {
    const value = event();
    await database().exec(
      "CREATE TRIGGER fail_metric BEFORE INSERT ON phase1a_metric_aggregates BEGIN SELECT RAISE(ABORT, 'injected metric failure'); END;"
    );
    await expect(aggregateMetric(database(), value, start)).rejects.toThrow();
    expect(
      await database().prepare("SELECT count(*) AS n FROM phase1a_metric_receipts").first()
    ).toEqual({ n: 0 });
    await database().exec("DROP TRIGGER fail_metric;");
    await aggregateMetric(database(), value, start);
    await aggregateMetric(database(), value, start + 1);
    expect((await readMetrics(database(), start + 1)).aggregates[0]?.count).toBe(1);
  });
  it("detects aggregate drift using grouped retained receipts and fails closed on hostile dimensions", async () => {
    await aggregateMetric(database(), event(), start);
    await database().exec("UPDATE phase1a_metric_aggregates SET count = 2;");
    expect((await readMetrics(database(), start)).reconciliation.matches).toBe(false);
    await database()
      .prepare("UPDATE phase1a_metric_aggregates SET dimensions = ?")
      .bind(JSON.stringify({ bearer: "secret" }))
      .run();
    await expect(readMetrics(database(), start)).rejects.toThrow();
  });
  it("retains a random lifecycle UUID through failed sends and persists it with the committed outbox", async () => {
    const storage = new TransactionalCapabilityStorage();
    expect(await createCapability(storage, createCommand(start))).toEqual({ ok: true });
    const messages: CapabilityProjectionMessage[] = [];
    await deliverPendingOutbox(
      storage,
      {
        send: (message) => {
          messages.push(message);
          return Promise.reject(new Error("injected send"));
        }
      },
      start
    );
    await deliverPendingOutbox(
      storage,
      {
        send: (message) => {
          messages.push(message);
          return Promise.resolve();
        }
      },
      start + 60_000
    );
    expect(messages).toHaveLength(2);
    expect(messages[0]?.metricEventId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
    );
    expect(messages[1]).toEqual(messages[0]);
  });
  it("replays a committed measurement once when source deletion fails after the D1 commit", async () => {
    const storage = new TransactionalCapabilityStorage();
    await createCapability(storage, createCommand(start));
    await acknowledgeOutboxDelivery(storage, {
      eventId: "op_create_reconcile",
      projectionVersion: 1,
      now: start
    });
    const source = [...(await storage.list({ prefix: SECURITY_METRIC_PREFIX })).values()][0];
    const failure = vi
      .spyOn(storage, "delete")
      .mockRejectedValueOnce(new Error("injected source deletion failure"));
    await projectMetricOutbox(storage, database(), "local", start);
    failure.mockRestore();
    expect((await storage.list({ prefix: SECURITY_METRIC_PREFIX })).size).toBe(1);
    expect((await readMetrics(database(), start)).aggregates[0]?.count).toBe(1);
    await projectMetricOutbox(storage, database(), "local", start + 300_000);
    expect((await storage.list({ prefix: SECURITY_METRIC_PREFIX })).size).toBe(0);
    expect((await readMetrics(database(), start + 300_000)).aggregates[0]?.count).toBe(1);
    expect(JSON.stringify(source)).not.toContain(createCommand(start).locator);
  });
  it("retries a durable security metric without copying operator or report identifiers", async () => {
    const storage = new TransactionalCapabilityStorage();
    await storage.transaction((txn) => storeSecurityMetric(txn, "enforcement", start));
    await database().exec(
      "CREATE TRIGGER fail_metric BEFORE INSERT ON phase1a_metric_aggregates BEGIN SELECT RAISE(ABORT, 'injected'); END;"
    );
    await projectMetricOutbox(storage, database(), "local", start);
    expect((await storage.list({ prefix: SECURITY_METRIC_PREFIX })).size).toBe(1);
    await database().exec("DROP TRIGGER fail_metric;");
    await projectMetricOutbox(storage, database(), "local", start + 300_000);
    expect((await storage.list({ prefix: SECURITY_METRIC_PREFIX })).size).toBe(0);
    expect(
      (await readMetrics(database(), start + 300_000)).aggregates[0]?.dimensions
    ).toMatchObject({ family: "abuse", category: "enforcement" });
  });
  it("removes source metric UUID at 30 days while keeping the separately approved delivered outbox", async () => {
    const storage = new TransactionalCapabilityStorage();
    await createCapability(storage, createCommand(start));
    await deliverPendingOutbox(storage, { send: () => Promise.resolve() }, start);
    await acknowledgeOutboxDelivery(storage, {
      eventId: "op_create_reconcile",
      projectionVersion: 1,
      now: start + 29 * METRIC_DAY
    });
    await maintainCapability(storage, start + METRIC_EVENT_RETENTION);
    const outbox = await storage.get<{
      metricEventId?: string;
      status: string;
      retentionEligibleAt: number;
    }>("capability:v1:outbox:op_create_reconcile");
    expect((await storage.list({ prefix: SECURITY_METRIC_PREFIX })).size).toBe(0);
    expect(outbox?.metricEventId).toBeUndefined();
    expect(outbox?.status).toBe("delivered");
    expect(outbox?.retentionEligibleAt).toBe(start + 36 * METRIC_DAY);
  });
  it("acknowledges a Queue metric only after projection, retries D1 failure and deduplicates replay", async () => {
    const value = event(Math.floor(Date.now() / 3_600_000) * 3_600_000);
    const ack = vi.fn(),
      retry = vi.fn();
    const message = { body: value, ack, retry } as unknown as Message<unknown>;
    const batch = {
      messages: [message],
      queue: "onceurl-local-async"
    } as unknown as MessageBatch<unknown>;
    await database().exec(
      "CREATE TRIGGER fail_metric BEFORE INSERT ON phase1a_metric_aggregates BEGIN SELECT RAISE(ABORT, 'injected'); END;"
    );
    await handleCapabilityQueue(batch, runtimeEnv);
    expect(ack).not.toHaveBeenCalled();
    expect(retry).toHaveBeenCalledOnce();
    await database().exec("DROP TRIGGER fail_metric;");
    await handleCapabilityQueue(batch, runtimeEnv);
    await handleCapabilityQueue(batch, runtimeEnv);
    expect(ack).toHaveBeenCalledTimes(2);
    expect((await readMetrics(database(), Date.now())).aggregates[0]?.count).toBe(1);
  });
  it("never exposes the readout through an unauthenticated admin request", async () => {
    const response = await createTestApp().request(
      runtimeEnv.FUNCTIONAL_ORIGIN + "/internal/admin/metrics",
      {},
      runtimeEnv
    );
    expect([401, 403, 503]).toContain(response.status);
    expect(await response.text()).not.toContain("aggregates");
  });
  it("serves identifier-free aggregate data only after pinned Access assertion and exact operator verification", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(Response.json(ADMIN_TEST_JWKS)))
    );
    const value = event(Math.floor(Date.now() / 3_600_000) * 3_600_000);
    await aggregateMetric(database(), value, Date.now());
    const configuration = { ...adminTestEnv(), DB: database() };
    const assertion = await adminTestAssertion(Date.now());
    const response = await createTestApp().request(
      configuration.FUNCTIONAL_ORIGIN + "/internal/admin/metrics",
      { headers: { "Cf-Access-Jwt-Assertion": assertion } },
      configuration
    );
    expect(response.status).toBe(200);
    const body = await response.text();
    expect(body).toContain("aggregates");
    expect(body).not.toContain(value.eventId);
    expect(response.headers.get("Cache-Control")).toContain("no-store");
  });
});
