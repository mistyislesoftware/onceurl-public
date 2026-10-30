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
import { runtimeEnv, requiredDatabase, createCommand } from "./testing/capability-delivery-runtime";
import type { WorkerEnv } from "./env";
import type { CapabilityProjectionMessage } from "./capability-durable-object-core";
// One producer scenario per runtime file: the Workers pool owns its complete
// background lifetime, preserving current-main producer/consumer isolation.
beforeEach(async () => {
  if (!runtimeEnv.DB) throw new Error("Runtime requires D1");
  await applyD1Migrations(runtimeEnv.DB, runtimeEnv.TEST_D1_MIGRATIONS);
});
it("replays safely when D1 commits but the projection response is lost before outbox ack", async () => {
  const database = requiredDatabase();
  const now = Date.now();
  const capabilityId = "cap_projection_commit_response_loss";
  const locator = `loc1_${"4".repeat(48)}`;
  const namespace = runtimeEnv.CAPABILITY_STATE;
  if (namespace === undefined) throw new Error("Runtime test requires capability objects");
  const stub = namespace.getByName(locator);
  const messages = await runInDurableObject(stub, async (_instance, state) => {
    await createCapability(
      state.storage,
      identityCommand(now, capabilityId, locator, "op_projection_commit_response_loss")
    );
    const captured: CapabilityProjectionMessage[] = [];
    await deliverPendingOutbox(
      state.storage,
      {
        send(message) {
          captured.push(message);
          return Promise.resolve();
        }
      },
      now
    );
    return captured;
  });
  const message = messages[0];
  if (message === undefined) throw new Error("Projection response-loss fixture has no outbox");

  const commitThenLoseResponse = {
    prepare: database.prepare.bind(database),
    async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
      await database.batch<T>(statements);
      throw new Error("injected response loss after D1 commit");
    }
  } as D1Database;
  const firstBatch = createMessageBatch("onceurl-local-async-jobs", [
    { id: "projection-response-lost", timestamp: new Date(now), body: message, attempts: 1 }
  ]);
  const firstContext = createExecutionContext();
  const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
  try {
    await handleCapabilityQueue(firstBatch, {
      DB: commitThenLoseResponse,
      CAPABILITY_STATE: namespace
    } as WorkerEnv);
    await expect(getQueueResult(firstBatch, firstContext)).resolves.toMatchObject({
      retryMessages: [{ msgId: "projection-response-lost" }]
    });
  } finally {
    error.mockRestore();
  }
  await expect(
    database
      .prepare("SELECT count(*) AS count FROM capability_projection_events WHERE capability_id = ?")
      .bind(capabilityId)
      .first()
  ).resolves.toEqual({ count: 1 });
  await expect(
    runInDurableObject(stub, async (_instance, state) =>
      state.storage.get("capability:v1:outbox:op_projection_commit_response_loss")
    )
  ).resolves.toMatchObject({ status: "pending" });

  const replay = createMessageBatch("onceurl-local-async-jobs", [
    { id: "projection-response-replay", timestamp: new Date(now), body: message, attempts: 2 }
  ]);
  const replayContext = createExecutionContext();
  await handleCapabilityQueue(replay, runtimeEnv);
  await expect(getQueueResult(replay, replayContext)).resolves.toMatchObject({
    explicitAcks: ["projection-response-replay"],
    retryMessages: []
  });
  await expect(
    database
      .prepare("SELECT count(*) AS count FROM capability_projection_events WHERE capability_id = ?")
      .bind(capabilityId)
      .first()
  ).resolves.toEqual({ count: 1 });
  await expect(
    runInDurableObject(stub, async (_instance, state) =>
      state.storage.get("capability:v1:outbox:op_projection_commit_response_loss")
    )
  ).resolves.toMatchObject({ status: "delivered", projectionVersion: 1 });
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
