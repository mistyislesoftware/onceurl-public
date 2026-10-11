import { applyD1Migrations, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { runtimeEnv, requiredDatabase, createCommand } from "./testing/capability-delivery-runtime";
import { createCapability, claimCapability } from "./capability-durable-object-core";
import { SECURITY_METRIC_PREFIX } from "./security-metrics-outbox";
import { readMetrics } from "./phase1a-metrics";

// One owned native DO/Queue/D1 producer. Retire it only after source and metric drains.
describe("native authoritative metrics integration", () => {
  it("acknowledges operational delivery during a metrics D1 outage and independently recovers committed counts once", async () => {
    const database = requiredDatabase();
    await applyD1Migrations(database, runtimeEnv.TEST_D1_MIGRATIONS);
    await database.exec(
      "CREATE TRIGGER fail_committed_metric BEFORE INSERT ON phase1a_metric_aggregates WHEN json_extract(NEW.dimensions, '$.category') = 'committed' BEGIN SELECT RAISE(ABORT, 'injected metrics-only outage'); END;"
    );
    const namespace = runtimeEnv.CAPABILITY_STATE;
    if (namespace === undefined) throw new Error("Missing capability namespace");
    const locator = `loc1_${"9".repeat(48)}`;
    const stub = namespace.getByName(locator);
    const now = Date.now();
    const fixture = createCommand(now);
    const command = {
      ...fixture,
      locator,
      ciphertextEnvelope: {
        ...fixture.ciphertextEnvelope,
        ad: { ...fixture.ciphertextEnvelope.ad, locator }
      }
    };
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await createCapability(state.storage, command)).toEqual({ ok: true });
      const claim = await claimCapability(state.storage, {
        publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        operationId: "metric-owned-claim",
        nonce: "metric-owned-nonce",
        now
      });
      expect(claim.ok).toBe(true);
    });
    const replay = await stub.fetch(
      new Request("https://capability.invalid/internal/capability/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          operationId: "metric-owned-claim",
          nonce: "metric-owned-nonce",
          now
        })
      })
    );
    expect(await replay.json()).toEqual({ ok: false, code: "unavailable" });
    let ready = false;
    for (let attempt = 0; attempt < 80; attempt++) {
      const drained = await runInDurableObject(stub, async (_instance, state) => {
        const outboxes = await state.storage.list<{ status: string }>({
          prefix: "capability:v1:outbox:"
        });
        const sources = await state.storage.list<{ nextAttemptAt: number }>({
          prefix: SECURITY_METRIC_PREFIX
        });
        return (
          outboxes.size === 2 &&
          [...outboxes.values()].every((row) => row.status === "delivered") &&
          sources.size === 2 &&
          [...sources.values()].every((row) => row.nextAttemptAt > now + 240_000)
        );
      });
      if (drained) {
        ready = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    expect(ready).toBe(true);
    expect(
      (await readMetrics(database, Date.now())).aggregates.filter(
        (row) => row.dimensions.category === "committed"
      )
    ).toEqual([]);
    const projection = await database
      .prepare("SELECT state FROM capabilities WHERE id = ?")
      .bind(command.capabilityId)
      .first();
    expect(projection).toEqual({ state: "CONSUMED" });
    const replayAcks = await runInDurableObject(stub, async (_instance, state) => {
      const records = await state.storage.list<{ eventId: string; projectionVersion: number }>({
        prefix: "capability:v1:outbox:"
      });
      const sources = await state.storage.list<{ eventId: string; nextAttemptAt: number }>({
        prefix: SECURITY_METRIC_PREFIX
      });
      for (const source of sources.values()) {
        expect(JSON.stringify(source)).not.toContain(locator);
        expect(JSON.stringify(source)).not.toContain(command.capabilityId);
      }
      return [...records.values()].map((row) => ({
        eventId: row.eventId,
        projectionVersion: row.projectionVersion
      }));
    });
    await database.exec("DROP TRIGGER fail_committed_metric;");
    await runInDurableObject(stub, async (instance, state) => {
      for (const [key, source] of await state.storage.list<{ nextAttemptAt: number }>({
        prefix: SECURITY_METRIC_PREFIX
      }))
        await state.storage.put(key, { ...source, nextAttemptAt: Date.now() });
      await instance.alarm();
    });
    let recovered = false;
    for (let attempt = 0; attempt < 80; attempt++) {
      const committed = (await readMetrics(database, Date.now())).aggregates.filter(
        (row) => row.dimensions.category === "committed"
      );
      const remaining = await runInDurableObject(
        stub,
        async (_instance, state) =>
          (await state.storage.list({ prefix: SECURITY_METRIC_PREFIX })).size
      );
      if (committed.length === 2 && committed.every((row) => row.count === 1) && remaining === 0) {
        recovered = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    expect(recovered).toBe(true);
    // A repeated real native acknowledgement must not recreate a drained source.
    for (const ack of replayAcks) {
      const response = await stub.fetch(
        new Request("https://capability.invalid/internal/capability/projection-ack", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ ...ack, now: Date.now() })
        })
      );
      expect(await response.json()).toEqual({ ok: true, retained: true });
    }
    expect(
      await runInDurableObject(
        stub,
        async (_instance, state) =>
          (await state.storage.list({ prefix: SECURITY_METRIC_PREFIX })).size
      )
    ).toBe(0);
    const readout = await readMetrics(database, Date.now());
    expect(readout.reconciliation.matches).toBe(true);
    const serialized = JSON.stringify(readout);
    expect(serialized).not.toContain(locator);
    expect(serialized).not.toContain(command.capabilityId);
    await runInDurableObject(stub, async (_instance, state) => {
      const record = await state.storage.get<{
        ciphertextEnvelope: unknown;
        lifecycle: { state: string };
      }>("capability:v1:record");
      expect(record?.ciphertextEnvelope).toBeNull();
      expect(record?.lifecycle.state).toBe("CONSUMED");
    });
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(
      (await readMetrics(database, Date.now())).aggregates
        .filter((row) => row.dimensions.category === "committed")
        .map((row) => row.count)
    ).toEqual([1, 1]);
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.deleteAll();
      await state.storage.deleteAlarm();
    });
  }, 20_000);
});
