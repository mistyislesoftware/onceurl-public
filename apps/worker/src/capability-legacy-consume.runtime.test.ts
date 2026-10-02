import {
  createExecutionContext,
  createMessageBatch,
  getQueueResult,
  runInDurableObject
} from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import {
  claimCapability,
  createCapability,
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
  createCommand,
  rewriteDurableObjectAsLegacySchema2
} from "./testing/capability-delivery-runtime";

// This scenario intentionally accepts real Queue/DO background work. The pool
// owns its entire lifetime here: no following test may share this file's state.
beforeEach(prepareIsolatedProducer);

describe("capability legacy-consume isolated producer", () => {
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
});
