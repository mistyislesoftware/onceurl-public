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
import { beforeEach, describe, expect, it } from "vitest";
import type { CapabilityProjectionMessage } from "./capability-durable-object-core";
import { handleCapabilityQueue } from "./capability-delivery";
import { applyCapabilityProjection, cleanupProjectionRetention } from "./capability-projection";
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
const runtimeEnv = env as WorkerEnv & { TEST_D1_MIGRATIONS: D1Migration[] };

beforeEach(async () => {
  await applyD1Migrations(requiredDatabase(), runtimeEnv.TEST_D1_MIGRATIONS);
});

// Workers storage isolation is per file. Keep this scenario separate from tests
// that publish recent outboxes: Miniflare buffers accepted Queue messages and
// flush timers in memory, so clearing D1 or reset() cannot isolate those deliveries.
describe("expired Queue delivery after tombstone retention", () => {
  it("acknowledges an expired queued event without resurrecting state after tombstone cleanup", async () => {
    const database = requiredDatabase();
    const now = Date.now();
    // Reuse the earlier delivery file's identity deliberately. A misplaced test
    // must expose retained authoritative state before it can contaminate cleanup.
    const namespace = runtimeEnv.CAPABILITY_STATE;
    if (namespace === undefined) throw new Error("Runtime test requires capability objects");
    await runInDurableObject(namespace.getByName(LOCATOR), async (_instance, state) => {
      expect((await state.storage.get("capability:v1:record")) !== undefined).toBe(false);
      expect((await state.storage.list({ prefix: "capability:v1:outbox:" })).size).toBe(0);
      expect(await state.storage.getAlarm()).toBeNull();
    });

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
        database.prepare(`SELECT count(*) AS count FROM ${table}`).first<{ count: number }>(),
        table
      ).resolves.toEqual({ count: 0 });
    }
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
