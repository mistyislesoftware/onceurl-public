import { env } from "cloudflare:workers";
import { parseCapabilityPolicy } from "@onceurl/domain";
import { applyD1Migrations, runInDurableObject, type D1Migration } from "cloudflare:test";
import { expect } from "vitest";
import type { CapabilityProjectionMessage } from "../capability-durable-object-core";
import type { WorkerEnv } from "../env";

export const DAY_MS = 24 * 60 * 60 * 1_000;
export const LOCATOR = `loc1_${"c".repeat(48)}`;
const POLICY = {
  kind: "secret",
  expiresAt: null,
  maxConsumptions: 1,
  reactivation: "forbidden",
  postConsumption: { behavior: "delete_capability" }
} as const;
const parsedPolicy = parseCapabilityPolicy(POLICY);
if (!parsedPolicy.ok) throw new Error("Runtime test policy must be valid");
export const ACCESS_CODE_VERIFIER = {
  version: "acv1",
  algorithm: "PBKDF2-SHA-256",
  iterations: 210_000,
  salt: "AAAAAAAAAAAAAAAAAAAAAA",
  digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
} as const;

export const runtimeEnv = env as WorkerEnv & { TEST_D1_MIGRATIONS: D1Migration[] };
export function requiredDatabase(): D1Database {
  if (runtimeEnv.DB === undefined) throw new Error("Runtime test requires D1");
  return runtimeEnv.DB;
}

export function projectionMessage(
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

export function createCommand(now = 1_000) {
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

export async function rewriteDurableObjectAsLegacySchema2(
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

// These identities belong to the four real-background producer files. D1-only
// cleanup must never hide their retained objects/outboxes/alarms in a consumer.
export const producerLocators = ["c", "d", "e", "f"].map((value) => `loc1_${value.repeat(48)}`);

export async function expectNoProducerState(state: DurableObjectState): Promise<void> {
  expect((await state.storage.get("capability:v1:record")) !== undefined).toBe(false);
  expect((await state.storage.list({ prefix: "capability:v1:outbox:" })).size).toBe(0);
  expect(await state.storage.getAlarm()).toBeNull();
}

export async function prepareIsolatedProducer(): Promise<void> {
  const namespace = runtimeEnv.CAPABILITY_STATE;
  if (namespace === undefined) throw new Error("Runtime test requires capability objects");
  for (const locator of producerLocators) {
    await runInDurableObject(namespace.getByName(locator), async (_instance, state) => {
      await expectNoProducerState(state);
    });
  }
  const database = requiredDatabase();
  await applyD1Migrations(database, runtimeEnv.TEST_D1_MIGRATIONS);
  for (const table of [
    "capabilities",
    "capability_projection_events",
    "capability_terminal_tombstones",
    "capability_reconciliation_candidates"
  ]) {
    await expect(
      database.prepare(`SELECT count(*) AS count FROM ${table}`).first(),
      table
    ).resolves.toEqual({ count: 0 });
  }
}
