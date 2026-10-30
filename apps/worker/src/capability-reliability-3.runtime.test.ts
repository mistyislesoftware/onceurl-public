import {
  applyD1Migrations,
  createExecutionContext,
  createMessageBatch,
  getQueueResult,
  runInDurableObject
} from "cloudflare:test";
import { beforeEach, expect, it, vi } from "vitest";
import { createCapability, deliverPendingOutbox } from "./capability-durable-object-core";
import { handleCapabilityQueue } from "./capability-delivery";
import { runtimeEnv, createCommand } from "./testing/capability-delivery-runtime";
import type { CapabilityProjectionMessage } from "./capability-durable-object-core";
// One producer scenario per runtime file: the Workers pool owns its complete
// background lifetime, preserving current-main producer/consumer isolation.
beforeEach(async () => {
  if (!runtimeEnv.DB) throw new Error("Runtime requires D1");
  await applyD1Migrations(runtimeEnv.DB, runtimeEnv.TEST_D1_MIGRATIONS);
});
it("marks a valid dead letter unresolved and later recovers it through normal redelivery", async () => {
  const now = Date.now();
  const capabilityId = "cap_projection_dead_letter_recovery";
  const locator = `loc1_${"1".repeat(48)}`;
  const operationId = "op_projection_dead_letter_recovery";
  const namespace = runtimeEnv.CAPABILITY_STATE;
  if (namespace === undefined) throw new Error("Runtime test requires capability objects");
  const stub = namespace.getByName(locator);
  const [message] = await runInDurableObject(stub, async (_instance, state) => {
    await createCapability(state.storage, identityCommand(now, capabilityId, locator, operationId));
    const captured: CapabilityProjectionMessage[] = [];
    await deliverPendingOutbox(
      state.storage,
      {
        send(value) {
          captured.push(value);
          return Promise.resolve();
        }
      },
      now
    );
    return captured;
  });
  if (message === undefined) throw new Error("Dead-letter fixture has no outbox message");

  const deadLetter = createMessageBatch("onceurl-local-async-jobs-dead-letter", [
    { id: "valid-dead-letter", timestamp: new Date(now), body: message, attempts: 9 }
  ]);
  const deadLetterContext = createExecutionContext();
  const warning = vi.spyOn(console, "warn").mockImplementation(() => undefined);
  try {
    await handleCapabilityQueue(deadLetter, runtimeEnv);
    await expect(getQueueResult(deadLetter, deadLetterContext)).resolves.toMatchObject({
      explicitAcks: ["valid-dead-letter"],
      retryMessages: []
    });
  } finally {
    warning.mockRestore();
  }
  const unresolved = await runInDurableObject(stub, async (_instance, state) =>
    state.storage.get<{ status: string; nextAttemptAt: number }>(
      `capability:v1:outbox:${operationId}`
    )
  );
  expect(unresolved).toMatchObject({ status: "unresolved" });

  const recovered: CapabilityProjectionMessage[] = [];
  await runInDurableObject(stub, async (_instance, state) =>
    deliverPendingOutbox(
      state.storage,
      {
        send(value) {
          recovered.push(value);
          return Promise.resolve();
        }
      },
      unresolved?.nextAttemptAt ?? Number.MAX_SAFE_INTEGER
    )
  );
  expect(recovered).toHaveLength(1);
  const normalDelivery = createMessageBatch("onceurl-local-async-jobs", [
    {
      id: "dead-letter-recovered",
      timestamp: new Date(now),
      body: recovered[0],
      attempts: 10
    }
  ]);
  const normalContext = createExecutionContext();
  await handleCapabilityQueue(normalDelivery, runtimeEnv);
  await expect(getQueueResult(normalDelivery, normalContext)).resolves.toMatchObject({
    explicitAcks: ["dead-letter-recovered"],
    retryMessages: []
  });
  await expect(
    runInDurableObject(stub, async (_instance, state) =>
      state.storage.get(`capability:v1:outbox:${operationId}`)
    )
  ).resolves.toMatchObject({ status: "delivered" });
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
