import { applyD1Migrations, runInDurableObject } from "cloudflare:test";
import { beforeEach, expect, it } from "vitest";
import {
  claimCapability,
  createCapability,
  failClosedUncertainRestore,
  reconcileCapability
} from "./capability-durable-object-core";
import {
  applyCapabilityProjection,
  completeProjectionReconciliation,
  listDueReconciliationCandidates
} from "./capability-projection";
import { runtimeEnv, requiredDatabase, createCommand } from "./testing/capability-delivery-runtime";
// One producer scenario per runtime file: the Workers pool owns its complete
// background lifetime, preserving current-main producer/consumer isolation.
beforeEach(async () => {
  if (!runtimeEnv.DB) throw new Error("Runtime requires D1");
  await applyD1Migrations(runtimeEnv.DB, runtimeEnv.TEST_D1_MIGRATIONS);
});
it("fails closed across combined Durable Object and D1 rewind without terminal evidence", async () => {
  const database = requiredDatabase();
  const now = Date.now();
  const capabilityId = "cap_projection_uncertain_restore";
  const locator = `loc1_${"8".repeat(48)}`;
  const namespace = runtimeEnv.CAPABILITY_STATE;
  if (namespace === undefined) throw new Error("Runtime test requires capability objects");
  const stub = namespace.getByName(locator);
  const fixture = await runInDurableObject(stub, async (_instance, state) => {
    await createCapability(
      state.storage,
      identityCommand(now, capabilityId, locator, "op_uncertain_restore_create")
    );
    const active = await reconcileCapability(state.storage, { now });
    if (!active.ok) throw new Error("Uncertain restore ACTIVE projection failed");
    const activeValues = await state.storage.list();
    const activeAlarm = await state.storage.getAlarm();
    const consumed = await claimCapability(state.storage, {
      publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      operationId: "op_uncertain_restore_consume",
      nonce: "nonce_uncertain_restore_consume",
      now: now + 1
    });
    if (!consumed.ok) throw new Error("Uncertain restore consume failed");
    return { activeValues, activeAlarm, activeMessage: active.message };
  });

  await applyCapabilityProjection(database, fixture.activeMessage, now + 2);
  await expect(
    database
      .prepare("SELECT state, version FROM capabilities WHERE id = ?")
      .bind(capabilityId)
      .first()
  ).resolves.toEqual({ state: "ACTIVE", version: 1 });
  await expect(
    database
      .prepare("SELECT terminal_state FROM capability_terminal_tombstones WHERE capability_id = ?")
      .bind(capabilityId)
      .first()
  ).resolves.toBeNull();

  const restoreActiveSnapshot = () =>
    runInDurableObject(stub, async (_instance, state) => {
      for (const key of (await state.storage.list()).keys()) await state.storage.delete(key);
      for (const [key, value] of fixture.activeValues) await state.storage.put(key, value);
      if (fixture.activeAlarm === null) await state.storage.deleteAlarm();
      else await state.storage.setAlarm(fixture.activeAlarm);
    });
  const decision = {
    operationId: "op_uncertain_restore_quarantine_delete",
    capabilityId,
    locator,
    decision: "delete_uncertain_restored_state",
    now: now + 20
  } as const;

  for (let cycle = 0; cycle < 2; cycle += 1) {
    await deleteProjectionRows(database, capabilityId);
    await applyCapabilityProjection(database, fixture.activeMessage, now + 5 + cycle);
    await expect(
      database
        .prepare("SELECT state, version FROM capabilities WHERE id = ?")
        .bind(capabilityId)
        .first()
    ).resolves.toEqual({ state: "ACTIVE", version: 1 });
    await expect(
      database
        .prepare(
          "SELECT terminal_state FROM capability_terminal_tombstones WHERE capability_id = ?"
        )
        .bind(capabilityId)
        .first()
    ).resolves.toBeNull();
    await restoreActiveSnapshot();
    await database
      .prepare(
        "UPDATE capability_reconciliation_candidates SET next_attempt_at = ? WHERE capability_id = ?"
      )
      .bind(now + 10 + cycle, capabilityId)
      .run();

    // Missing D1 terminal evidence is not itself a deletion instruction.
    const candidates = await listDueReconciliationCandidates(database, now + 10 + cycle);
    expect(candidates).toContainEqual({
      capabilityId,
      routingLocator: locator,
      attemptCount: 0,
      retainUntil: null,
      terminalEvidence: null
    });
    const reconciliation = await runInDurableObject(stub, async (_instance, state) =>
      reconcileCapability(state.storage, { now: now + 10 + cycle })
    );
    expect(reconciliation).toMatchObject({
      ok: true,
      message: { projection: { state: "ACTIVE", version: 1 } }
    });
    if (!reconciliation.ok) throw new Error("Uncertain restore reconciliation failed");
    await applyCapabilityProjection(database, reconciliation.message, now + 10 + cycle);
    await completeProjectionReconciliation(database, reconciliation.message, now + 10 + cycle);
    await expect(
      runInDurableObject(stub, async (_instance, state) =>
        state.storage.get("capability:v1:record")
      )
    ).resolves.toMatchObject({
      lifecycle: { state: "ACTIVE" },
      ciphertextEnvelope: identityCommand(now, capabilityId, locator, "op_uncertain_restore_create")
        .ciphertextEnvelope
    });

    // The operations owner invokes this internal command only while external quarantine blocks serving.
    for (let invocation = 0; invocation < 3; invocation += 1) {
      await expect(
        runInDurableObject(stub, async (_instance, state) =>
          failClosedUncertainRestore(state.storage, decision)
        )
      ).resolves.toEqual({
        ok: true,
        state: "DELETED",
        projectionVersion: 2,
        ciphertextPresent: false
      });
    }

    await expect(
      runInDurableObject(stub, async (_instance, state) => ({
        record: await state.storage.get("capability:v1:record"),
        deletionOutbox: await state.storage.get(`capability:v1:outbox:${decision.operationId}`)
      }))
    ).resolves.toMatchObject({
      record: {
        lifecycle: { state: "DELETED" },
        ciphertextEnvelope: null,
        projectionVersion: 2,
        lastTransition: {
          eventId: decision.operationId,
          type: "capability_deleted",
          fromState: "ACTIVE",
          toState: "DELETED"
        }
      },
      deletionOutbox: {
        eventId: decision.operationId,
        projectionVersion: 2,
        event: { type: "capability_deleted" }
      }
    });
    await expect(
      runInDurableObject(stub, async (_instance, state) =>
        claimCapability(state.storage, {
          publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          operationId: `op_after_uncertain_restore_${cycle}`,
          nonce: `nonce_after_uncertain_restore_${cycle}`,
          now: now + 30 + cycle
        })
      )
    ).resolves.toEqual({ ok: false, code: "unavailable" });
  }

  await deleteProjectionRows(database, capabilityId);
  await applyCapabilityProjection(database, fixture.activeMessage, now + 40);
  await expect(
    database
      .prepare("SELECT state, version FROM capabilities WHERE id = ?")
      .bind(capabilityId)
      .first()
  ).resolves.toEqual({ state: "ACTIVE", version: 1 });
  await expect(
    runInDurableObject(stub, async (_instance, state) =>
      claimCapability(state.storage, {
        publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        operationId: "op_after_stale_d1_uncertain_restore",
        nonce: "nonce_after_stale_d1_uncertain_restore",
        now: now + 41
      })
    )
  ).resolves.toEqual({
    ok: false,
    code: "unavailable"
  });
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
