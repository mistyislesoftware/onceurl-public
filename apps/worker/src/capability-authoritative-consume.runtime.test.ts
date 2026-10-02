import { runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { claimCapability, createCapability } from "./capability-durable-object-core";
import { applyCapabilityProjection } from "./capability-projection";
import {
  runtimeEnv,
  prepareIsolatedProducer,
  requiredDatabase,
  createCommand,
  projectionMessage
} from "./testing/capability-delivery-runtime";

// This scenario intentionally accepts real Queue/DO background work. The pool
// owns its entire lifetime here: no following test may share this file's state.
beforeEach(prepareIsolatedProducer);

describe("capability authoritative-consume isolated producer", () => {
  it("cannot use a stale D1 projection to reopen an authoritative consumed capability", async () => {
    const now = Date.now();
    const namespace = runtimeEnv.CAPABILITY_STATE;
    if (namespace === undefined) throw new Error("Runtime test requires capability objects");
    const locator = `loc1_${"d".repeat(48)}`;
    const stub = namespace.getByName(locator);
    const command = createCommand(now);
    await runInDurableObject(stub, async (_instance, state) => {
      await createCapability(state.storage, {
        ...command,
        locator,
        ciphertextEnvelope: {
          ...command.ciphertextEnvelope,
          ad: { ...command.ciphertextEnvelope.ad, locator }
        }
      });
      await claimCapability(state.storage, {
        publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        operationId: "op_consumed_before_stale_d1",
        nonce: "nonce_consumed_before_stale_d1",
        now: now + 1
      });
    });
    const staleProjection = projectionMessage("ACTIVE", 1, now, "event_stale_active");
    await applyCapabilityProjection(
      requiredDatabase(),
      {
        ...staleProjection,
        projection: { ...staleProjection.projection, locator }
      },
      now + 2
    );

    const response = await stub.fetch(
      new Request("https://capability.invalid/internal/capability/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          publicBearerSecret: "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          operationId: "op_after_stale_d1",
          nonce: "nonce_after_stale_d1",
          now: now + 3
        })
      })
    );
    await expect(response.json()).resolves.toEqual({ ok: false, code: "unavailable" });
  });
});
