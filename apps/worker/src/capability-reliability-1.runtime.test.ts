import {
  applyD1Migrations,
  createExecutionContext,
  createMessageBatch,
  getQueueResult,
  runInDurableObject
} from "cloudflare:test";
import { beforeEach, expect, it } from "vitest";
import {
  claimCapability,
  createCapability,
  deliverPendingOutbox
} from "./capability-durable-object-core";
import { handleCapabilityQueue, handleCapabilityReconciliation } from "./capability-delivery";
import { runtimeEnv, requiredDatabase, createCommand } from "./testing/capability-delivery-runtime";
import type { CapabilityProjectionMessage } from "./capability-durable-object-core";
// One producer scenario per runtime file: the Workers pool owns its complete
// background lifetime, preserving current-main producer/consumer isolation.
beforeEach(async () => {
  if (!runtimeEnv.DB) throw new Error("Runtime requires D1");
  await applyD1Migrations(runtimeEnv.DB, runtimeEnv.TEST_D1_MIGRATIONS);
});
it("keeps reverse Queue delivery and duplicate redelivery harmless around reconciliation", async () => {
  const database = requiredDatabase();
  const now = Date.now();
  const capabilityId = "cap_projection_reverse_queue";
  const locator = `loc1_${"6".repeat(48)}`;
  const namespace = runtimeEnv.CAPABILITY_STATE;
  if (namespace === undefined) throw new Error("Runtime test requires capability objects");
  const stub = namespace.getByName(locator);
  const messages = await runInDurableObject(stub, async (_instance, state) => {
    await createCapability(
      state.storage,
      identityCommand(now, capabilityId, locator, "op_reverse_queue_create")
    );
    await claimCapability(state.storage, {
      publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      operationId: "op_reverse_queue_consume",
      nonce: "nonce_reverse_queue_consume",
      now: now + 1
    });
    const captured: CapabilityProjectionMessage[] = [];
    await deliverPendingOutbox(
      state.storage,
      {
        send(message) {
          captured.push(message);
          return Promise.resolve();
        }
      },
      now + 1
    );
    return captured;
  });
  const active = messages.find((message) => message.projection.state === "ACTIVE");
  const consumed = messages.find((message) => message.projection.state === "CONSUMED");
  if (active === undefined || consumed === undefined) {
    throw new Error("Reverse Queue fixture did not capture both projections");
  }

  const deliveries = [
    { id: "reverse-consumed-first", message: consumed },
    { id: "reverse-active-late", message: active },
    { id: "reverse-consumed-duplicate", message: consumed }
  ];
  for (const [index, delivery] of deliveries.entries()) {
    const batch = createMessageBatch("onceurl-local-async-jobs", [
      {
        id: delivery.id,
        timestamp: new Date(now + index),
        body: delivery.message,
        attempts: index + 1
      }
    ]);
    const context = createExecutionContext();
    await handleCapabilityQueue(batch, runtimeEnv);
    await expect(getQueueResult(batch, context)).resolves.toMatchObject({
      explicitAcks: [delivery.id],
      retryMessages: []
    });
    if (index === 0) await handleCapabilityReconciliation(runtimeEnv, now + index);
  }

  await expect(
    database
      .prepare("SELECT state, version FROM capabilities WHERE id = ?")
      .bind(capabilityId)
      .first()
  ).resolves.toEqual({ state: "CONSUMED", version: 2 });
  await expect(
    database
      .prepare("SELECT count(*) AS count FROM capability_projection_events WHERE capability_id = ?")
      .bind(capabilityId)
      .first()
  ).resolves.toEqual({ count: 2 });
  await expect(
    runInDurableObject(stub, async (_instance, state) => [
      ...(
        await state.storage.list<Record<string, unknown>>({ prefix: "capability:v1:outbox:" })
      ).values()
    ])
  ).resolves.toEqual(
    expect.arrayContaining([
      expect.objectContaining({ status: "delivered", projectionVersion: 1 }),
      expect.objectContaining({ status: "delivered", projectionVersion: 2 })
    ])
  );
});
function identityCommand(now: number, capabilityId: string, locator: string, operationId: string) {
  const command = createCommand(now);
  return {
    ...command,
    operationId,
    capabilityId,
    locator,
    ciphertextEnvelope: {
      ...command.ciphertextEnvelope,
      ad: { ...command.ciphertextEnvelope.ad, capabilityId, locator }
    }
  };
}
