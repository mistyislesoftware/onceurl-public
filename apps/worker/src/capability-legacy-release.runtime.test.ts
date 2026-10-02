import {
  createExecutionContext,
  createMessageBatch,
  getQueueResult,
  runInDurableObject
} from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import {
  createCapability,
  decideAbuseLock,
  deliverPendingOutbox,
  type CapabilityProjectionMessage
} from "./capability-durable-object-core";
import { handleCapabilityQueue, handleCapabilityReconciliation } from "./capability-delivery";
import {
  applyCapabilityProjection,
  completeProjectionReconciliation
} from "./capability-projection";
import {
  runtimeEnv,
  prepareIsolatedProducer,
  requiredDatabase,
  DAY_MS,
  ACCESS_CODE_VERIFIER,
  createCommand,
  rewriteDurableObjectAsLegacySchema2
} from "./testing/capability-delivery-runtime";

// This scenario intentionally accepts real Queue/DO background work. The pool
// owns its entire lifetime here: no following test may share this file's state.
beforeEach(prepareIsolatedProducer);

describe("capability legacy-release isolated producer", () => {
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
});
