import { applyD1Migrations, runInDurableObject } from "cloudflare:test";
import { beforeEach, expect, it } from "vitest";
import {
  claimCapability,
  createCapability,
  deliverPendingOutbox
} from "./capability-durable-object-core";
import { handleCapabilityReconciliation } from "./capability-delivery";
import { applyCapabilityProjection } from "./capability-projection";
import { runtimeEnv, requiredDatabase, createCommand } from "./testing/capability-delivery-runtime";
import type { CapabilityProjectionMessage } from "./capability-durable-object-core";
// One producer scenario per runtime file: the Workers pool owns its complete
// background lifetime, preserving current-main producer/consumer isolation.
beforeEach(async () => {
  if (!runtimeEnv.DB) throw new Error("Runtime requires D1");
  await applyD1Migrations(runtimeEnv.DB, runtimeEnv.TEST_D1_MIGRATIONS);
});
it("keeps repeated Durable Object and D1 restore simulations quarantined and fail-closed", async () => {
  const database = requiredDatabase();
  const now = Date.now();
  const capabilityId = "cap_projection_restore_campaign";
  const locator = `loc1_${"3".repeat(48)}`;
  const namespace = runtimeEnv.CAPABILITY_STATE;
  if (namespace === undefined) throw new Error("Runtime test requires capability objects");
  const stub = namespace.getByName(locator);
  const fixture = await runInDurableObject(stub, async (_instance, state) => {
    await createCapability(
      state.storage,
      identityCommand(now, capabilityId, locator, "op_restore_campaign_create")
    );
    const activeValues = await state.storage.list();
    const activeAlarm = await state.storage.getAlarm();
    const consumed = await claimCapability(state.storage, {
      publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      operationId: "op_restore_campaign_consume",
      nonce: "nonce_restore_campaign_consume",
      now: now + 1
    });
    if (!consumed.ok) throw new Error("Restore campaign consume failed");
    const messages: CapabilityProjectionMessage[] = [];
    await deliverPendingOutbox(
      state.storage,
      {
        send(message) {
          messages.push(message);
          return Promise.resolve();
        }
      },
      now + 1
    );
    return { activeValues, activeAlarm, messages };
  });
  const active = fixture.messages.find((message) => message.projection.state === "ACTIVE");
  const consumed = fixture.messages.find((message) => message.projection.state === "CONSUMED");
  if (active === undefined || consumed === undefined) {
    throw new Error("Restore campaign did not capture both lifecycle projections");
  }
  await applyCapabilityProjection(database, active, now + 2);
  await applyCapabilityProjection(database, consumed, now + 3);

  const restoreActiveSnapshot = () =>
    runInDurableObject(stub, async (_instance, state) => {
      for (const key of (await state.storage.list()).keys()) await state.storage.delete(key);
      for (const [key, value] of fixture.activeValues) await state.storage.put(key, value);
      if (fixture.activeAlarm === null) await state.storage.deleteAlarm();
      else await state.storage.setAlarm(fixture.activeAlarm);
    });

  for (let cycle = 0; cycle < 2; cycle += 1) {
    await restoreActiveSnapshot();
    await database
      .prepare(
        "UPDATE capability_reconciliation_candidates SET next_attempt_at = ? WHERE capability_id = ?"
      )
      .bind(now + 4 + cycle, capabilityId)
      .run();
    // The restored object is not served while the external quarantine is in force.
    await handleCapabilityReconciliation(runtimeEnv, now + 4 + cycle);
    await expect(
      runInDurableObject(stub, async (_instance, state) =>
        state.storage.get("capability:v1:record")
      )
    ).resolves.toMatchObject({
      lifecycle: { state: "DELETED" },
      ciphertextEnvelope: null,
      projectionVersion: 3 + cycle
    });
    await expect(
      database
        .prepare(
          "SELECT terminal_state, projection_version FROM capability_terminal_tombstones WHERE capability_id = ?"
        )
        .bind(capabilityId)
        .first()
    ).resolves.toEqual({ terminal_state: "DELETED", projection_version: 3 + cycle });
    const claim = await stub.fetch(
      new Request("https://capability.invalid/internal/capability/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          operationId: `op_restore_campaign_after_${cycle}`,
          nonce: `nonce_restore_campaign_after_${cycle}`,
          now: now + 10 + cycle
        })
      })
    );
    await expect(claim.json()).resolves.toEqual({ ok: false, code: "unavailable" });
  }

  // Quarantine must also wait for this fixture's existing producer to drain
  // before deleting D1 state. Otherwise an in-flight Queue projection can
  // overwrite the synthetic restoration/candidate timing below.
  await expect
    .poll(
      () =>
        runInDurableObject(stub, async (_instance, state) => {
          const outboxes = await state.storage.list<{ status: string }>({
            prefix: "capability:v1:outbox:"
          });
          return [...outboxes.values()].every((outbox) => outbox.status === "delivered");
        }),
      { timeout: 10_000 }
    )
    .toBe(true);

  for (let cycle = 0; cycle < 2; cycle += 1) {
    await deleteProjectionRows(database, capabilityId);
    await applyCapabilityProjection(database, active, now + 20 + cycle * 2);
    await expect(
      database
        .prepare("SELECT state, version FROM capabilities WHERE id = ?")
        .bind(capabilityId)
        .first()
    ).resolves.toEqual({ state: "ACTIVE", version: 1 });

    const claim = await stub.fetch(
      new Request("https://capability.invalid/internal/capability/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          operationId: `op_stale_d1_after_restore_${cycle}`,
          nonce: `nonce_stale_d1_after_restore_${cycle}`,
          now: now + 21 + cycle * 2
        })
      })
    );
    await expect(claim.json()).resolves.toEqual({ ok: false, code: "unavailable" });
    await database
      .prepare(
        "UPDATE capability_reconciliation_candidates SET next_attempt_at = ? WHERE capability_id = ?"
      )
      .bind(now + 21 + cycle * 2, capabilityId)
      .run();
    await handleCapabilityReconciliation(runtimeEnv, now + 21 + cycle * 2);
    await expect(
      database.prepare("SELECT state FROM capabilities WHERE id = ?").bind(capabilityId).first()
    ).resolves.toBeNull();
    await expect(
      database
        .prepare(
          "SELECT terminal_state, projection_version FROM capability_terminal_tombstones WHERE capability_id = ?"
        )
        .bind(capabilityId)
        .first()
    ).resolves.toEqual({ terminal_state: "DELETED", projection_version: 4 });
  }
}, 20_000);
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
async function deleteProjectionRows(database: D1Database, capabilityId: string): Promise<void> {
  await database.batch([
    database
      .prepare("DELETE FROM capability_reconciliation_candidates WHERE capability_id = ?")
      .bind(capabilityId),
    database
      .prepare("DELETE FROM capability_projection_events WHERE capability_id = ?")
      .bind(capabilityId),
    database
      .prepare("DELETE FROM capability_terminal_tombstones WHERE capability_id = ?")
      .bind(capabilityId),
    database.prepare("DELETE FROM capabilities WHERE id = ?").bind(capabilityId)
  ]);
}
