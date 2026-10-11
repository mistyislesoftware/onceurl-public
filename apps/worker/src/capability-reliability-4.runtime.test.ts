import { applyD1Migrations, runInDurableObject } from "cloudflare:test";
import { beforeEach, expect, it, vi } from "vitest";
import { createCapability, reconcileCapability } from "./capability-durable-object-core";
import { handleCapabilityReconciliation } from "./capability-delivery";
import { applyCapabilityProjection } from "./capability-projection";
import { runtimeEnv, requiredDatabase, createCommand } from "./testing/capability-delivery-runtime";
import type { WorkerEnv } from "./env";
// One producer scenario per runtime file: the Workers pool owns its complete
// background lifetime, preserving current-main producer/consumer isolation.
beforeEach(async () => {
  if (!runtimeEnv.DB) throw new Error("Runtime requires D1");
  await applyD1Migrations(runtimeEnv.DB, runtimeEnv.TEST_D1_MIGRATIONS);
});
it("defers a reconciliation during D1 outage and repairs a missing catalogue row after recovery", async () => {
  const database = requiredDatabase();
  const now = Date.now();
  const capabilityId = "cap_projection_reconciliation_outage";
  const locator = `loc1_${"2".repeat(48)}`;
  const namespace = runtimeEnv.CAPABILITY_STATE;
  if (namespace === undefined) throw new Error("Runtime test requires capability objects");
  const stub = namespace.getByName(locator);
  const message = await runInDurableObject(stub, async (_instance, state) => {
    await createCapability(
      state.storage,
      identityCommand(now, capabilityId, locator, "op_reconciliation_outage")
    );
    const result = await reconcileCapability(state.storage, { now });
    if (!result.ok) throw new Error("Reconciliation outage fixture failed");
    return result.message;
  });
  await applyCapabilityProjection(database, message, now);
  await database.prepare("DELETE FROM capabilities WHERE id = ?").bind(capabilityId).run();

  const unavailableDatabase = {
    prepare: database.prepare.bind(database),
    batch: () => Promise.reject(new Error("injected reconciliation D1 outage"))
  } as unknown as D1Database;
  const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
  try {
    await handleCapabilityReconciliation(
      { DB: unavailableDatabase, CAPABILITY_STATE: namespace } as WorkerEnv,
      now
    );
  } finally {
    error.mockRestore();
  }
  await expect(
    database
      .prepare(
        "SELECT attempt_count, next_attempt_at FROM capability_reconciliation_candidates WHERE capability_id = ?"
      )
      .bind(capabilityId)
      .first()
  ).resolves.toEqual({ attempt_count: 1, next_attempt_at: now + 5 * 60 * 1_000 });
  await expect(
    database.prepare("SELECT state FROM capabilities WHERE id = ?").bind(capabilityId).first()
  ).resolves.toBeNull();

  await handleCapabilityReconciliation(runtimeEnv, now + 5 * 60 * 1_000);
  await expect(
    database
      .prepare("SELECT state, version FROM capabilities WHERE id = ?")
      .bind(capabilityId)
      .first()
  ).resolves.toEqual({ state: "ACTIVE", version: 1 });
  await expect(
    database
      .prepare(
        "SELECT attempt_count FROM capability_reconciliation_candidates WHERE capability_id = ?"
      )
      .bind(capabilityId)
      .first()
  ).resolves.toEqual({ attempt_count: 0 });
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
