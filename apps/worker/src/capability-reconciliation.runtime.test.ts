import { runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { createCapability } from "./capability-durable-object-core";
import { handleCapabilityReconciliation } from "./capability-delivery";
import { applyCapabilityProjection } from "./capability-projection";
import {
  runtimeEnv,
  prepareIsolatedProducer,
  requiredDatabase,
  LOCATOR,
  createCommand,
  projectionMessage
} from "./testing/capability-delivery-runtime";

// This scenario intentionally accepts real Queue/DO background work. The pool
// owns its entire lifetime here: no following test may share this file's state.
beforeEach(prepareIsolatedProducer);

describe("capability reconciliation isolated producer", () => {
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
});
