import { describe, expect, it } from "vitest";
import type { AccessCodeVerifier } from "./access-code";
import {
  acknowledgeOutboxDelivery,
  authorizeCapability,
  claimCapability,
  createCapability,
  decideAbuseLock,
  deleteCapability,
  deliverPendingOutbox,
  failClosedUncertainRestore,
  maintainCapability,
  reconcileCapability,
  type CreateCapabilityCommand
} from "./capability-durable-object-core";
import { TransactionalCapabilityStorage } from "./testing/transactional-capability-storage";

const LOCATOR = `loc1_${"a".repeat(48)}`;
const PUBLIC_BEARER = "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OWNER_BEARER = "own1_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const PUBLIC_HASH = "bh1_AfZsOtbRWT9tmoTvsqNOTGRcSnDN_sX_ip2zb4v2Zdk";
const OWNER_HASH = "bh1_fPMtNFmwccxj2Z6fkMWWH0TDFqAWQwqfQTmejZo1XsU";
const DAY_MS = 24 * 60 * 60 * 1_000;
const CIPHERTEXT = "AAAAAAAAAAAAAAAAAAAAAAA";

const policy = (expiresAt: number | null = null) =>
  ({
    kind: "secret",
    expiresAt,
    maxConsumptions: 1,
    reactivation: "forbidden",
    postConsumption: { behavior: "delete_capability" }
  }) as const;

function createCommand(
  operationId = "op_reliability_create",
  expiresAt: number | null = null,
  accessCodeVerifier: AccessCodeVerifier | null = null
): CreateCapabilityCommand {
  const createdAt = "2026-07-13T00:00:00.000Z";
  return {
    operationId,
    capabilityId: "cap_01HZXAMPLE0000000000000000",
    locator: LOCATOR,
    createdAt,
    policy: policy(expiresAt),
    policyHash: "policy_hash_123",
    publicBearerSecretHash: PUBLIC_HASH,
    ownerBearerSecretHash: OWNER_HASH,
    ciphertextEnvelope: {
      version: "ouzk-v1",
      alg: "AES-256-GCM",
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: CIPHERTEXT,
      ad: {
        capabilityId: "cap_01HZXAMPLE0000000000000000",
        createdAt,
        kind: "secret",
        locator: LOCATOR,
        policyHash: "policy_hash_123",
        purpose: "onceurl.phase1a.secret-text",
        version: "ouzk-v1"
      }
    },
    ...(accessCodeVerifier === null ? {} : { accessCodeVerifier }),
    now: 1_000
  };
}

function claim(operationId: string, now: number, overrides: Record<string, unknown> = {}) {
  return {
    publicBearerSecret: PUBLIC_BEARER,
    operationId,
    nonce: `nonce_${operationId}`,
    now,
    ...overrides
  };
}

async function activeStorage(
  expiresAt: number | null = null,
  accessCodeVerifier: AccessCodeVerifier | null = null
): Promise<TransactionalCapabilityStorage> {
  const storage = new TransactionalCapabilityStorage();
  await expect(
    createCapability(storage, createCommand(undefined, expiresAt, accessCodeVerifier))
  ).resolves.toEqual({ ok: true });
  return storage;
}

function released(result: unknown): boolean {
  return (
    typeof result === "object" &&
    result !== null &&
    "ok" in result &&
    result.ok === true &&
    "outcome" in result &&
    result.outcome === "released"
  );
}

describe("Phase 1A authoritative concurrency and crash boundaries", () => {
  it("releases one ciphertext across 128 simultaneous claims and every retry class", async () => {
    const storage = await activeStorage();
    const attempts = Array.from({ length: 128 }, (_, index) =>
      claimCapability(
        storage,
        claim(`op_high_concurrency_${String(index).padStart(3, "0")}`, 2_000)
      )
    );
    const results = await Promise.all(attempts);

    expect(results.filter(released)).toHaveLength(1);
    expect(
      results.every(
        (result) =>
          released(result) || (!result.ok && ["unavailable", "rate_limited"].includes(result.code))
      )
    ).toBe(true);

    const winningIndex = results.findIndex(released);
    await expect(
      claimCapability(
        storage,
        claim(`op_high_concurrency_${String(winningIndex).padStart(3, "0")}`, 62_000)
      )
    ).resolves.toEqual({ ok: false, code: "unavailable" });
    await expect(
      claimCapability(storage, claim("op_fresh_after_concurrency", 62_001))
    ).resolves.toEqual({ ok: false, code: "unavailable" });

    const entries = storage.entries();
    expect(entries["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "CONSUMED", committedConsumptions: 1 },
      ciphertextEnvelope: null,
      projectionVersion: 2,
      lastTransition: { type: "capability_consumption_committed" }
    });
    expect(
      Object.keys(entries).filter((key) => key.startsWith("capability:v1:claim:"))
    ).toHaveLength(1);
    expect(
      Object.values(entries).filter(
        (value) =>
          typeof value === "object" &&
          value !== null &&
          "event" in value &&
          typeof value.event === "object" &&
          value.event !== null &&
          "type" in value.event &&
          value.event.type === "capability_consumption_committed"
      )
    ).toHaveLength(1);
  });

  it.each([
    { name: "before transaction", fault: { phase: "before_transaction" } as const },
    ...Array.from({ length: 5 }, (_, index) => ({
      name: `durable mutation ${index + 1}`,
      fault: { phase: "mutation", mutation: index + 1 } as const
    }))
  ])("rolls back a claim failure at $name", async ({ fault }) => {
    const storage = await activeStorage();
    await storage.deleteAlarm();
    const before = storage.snapshot();
    storage.failNextTransaction(fault);

    await expect(claimCapability(storage, claim("op_faulted_claim", 2_000))).rejects.toThrow(
      "injected"
    );
    expect(storage.snapshot()).toEqual(before);
    expect(JSON.stringify(storage.entries())).toContain(CIPHERTEXT);

    await expect(
      claimCapability(storage, claim("op_after_faulted_claim", 2_001))
    ).resolves.toMatchObject({ ok: true, outcome: "released" });
  });

  it("preserves a committed consume when the caller loses the post-commit result", async () => {
    const storage = await activeStorage();
    storage.failNextTransaction({ phase: "after_commit" });

    await expect(claimCapability(storage, claim("op_commit_response_lost", 2_000))).rejects.toThrow(
      "injected after commit"
    );
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "CONSUMED", committedConsumptions: 1 },
      ciphertextEnvelope: null
    });
    expect(storage.entries()["capability:v1:outbox:op_commit_response_lost"]).toMatchObject({
      projectionVersion: 2,
      event: { type: "capability_consumption_committed" }
    });
    expect(storage.entries()["capability:v1:claim:op_commit_response_lost"]).toBeDefined();

    await expect(
      claimCapability(storage, claim("op_commit_response_lost", 62_000))
    ).resolves.toEqual({ ok: false, code: "unavailable" });
    await expect(
      claimCapability(storage, claim("op_new_after_response_loss", 62_001))
    ).resolves.toEqual({ ok: false, code: "unavailable" });
  });
});

describe("Phase 1A lifecycle and access-control interleavings", { timeout: 20_000 }, () => {
  it.each(["claim_first", "expiry_first"] as const)(
    "keeps claim-versus-expiry safe with $name ordering",
    async (ordering) => {
      const storage = await activeStorage(2_000);
      const claimPromise = () => claimCapability(storage, claim("op_expiry_race", 1_999));
      const expiryPromise = () => maintainCapability(storage, 2_000);
      const operations =
        ordering === "claim_first"
          ? [claimPromise(), expiryPromise()]
          : [expiryPromise(), claimPromise()];
      const results = await Promise.all(operations);
      const claimResult = results.find((result) => result !== undefined);

      expect(claimResult === undefined ? 0 : Number(released(claimResult))).toBe(
        ordering === "claim_first" ? 1 : 0
      );
      expect(storage.entries()["capability:v1:record"]).toMatchObject({
        lifecycle: { state: ordering === "claim_first" ? "CONSUMED" : "EXPIRED" },
        ciphertextEnvelope: null
      });
    }
  );

  it("never releases at the exact expiry boundary while expiry races the claim", async () => {
    const storage = await activeStorage(2_000);
    const [claimResult] = await Promise.all([
      claimCapability(storage, claim("op_exact_expiry", 2_000)),
      maintainCapability(storage, 2_000)
    ]);

    expect(claimResult).toEqual({ ok: false, code: "unavailable" });
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "EXPIRED", committedConsumptions: 0 },
      ciphertextEnvelope: null
    });
  });

  it.each(["claim_first", "delete_first"] as const)(
    "serializes owner delete versus claim with $name ordering",
    async (ordering) => {
      const storage = await activeStorage();
      const claimPromise = () => claimCapability(storage, claim("op_delete_race_claim", 2_000));
      const deletePromise = () =>
        deleteCapability(storage, {
          operationId: "op_delete_race_owner",
          ownerBearerSecret: OWNER_BEARER,
          now: 2_000
        });
      const operations =
        ordering === "claim_first"
          ? [claimPromise(), deletePromise()]
          : [deletePromise(), claimPromise()];
      const results = await Promise.all(operations);

      expect(results.filter(released)).toHaveLength(ordering === "claim_first" ? 1 : 0);
      expect(storage.entries()["capability:v1:record"]).toMatchObject({
        lifecycle: {
          state: "DELETED",
          committedConsumptions: ordering === "claim_first" ? 1 : 0
        },
        ciphertextEnvelope: null
      });
      expect(
        Object.keys(storage.entries()).filter((key) => key.includes("op_delete_race_claim"))
      ).toHaveLength(ordering === "claim_first" ? 2 : 0);
    }
  );

  it.each([
    { correctPosition: 0, expectedRelease: true },
    { correctPosition: 9, expectedRelease: true },
    { correctPosition: 10, expectedRelease: false }
  ])(
    "serializes access-code work with the correct attempt at position $correctPosition",
    async ({ correctPosition, expectedRelease }) => {
      const verifier = await accessCodeVerifier("correct horse");
      const storage = await activeStorage(null, verifier);
      const failureTimes = [
        2_000, 2_001, 2_002, 2_003, 32_003, 152_003, 752_003, 4_352_003, 7_952_003, 11_552_003
      ];
      const attempts: Array<ReturnType<typeof claimCapability>> = [];
      for (let position = 0; position <= 10; position += 1) {
        if (position === correctPosition) {
          attempts.push(
            claimCapability(
              storage,
              claim("op_access_correct", failureTimes[position] ?? 11_552_004, {
                accessCode: "correct horse",
                challengeVerified: true
              })
            )
          );
        }
        if (position < 10) {
          attempts.push(
            claimCapability(
              storage,
              claim(`op_access_wrong_${position + 1}`, failureTimes[position] ?? 0, {
                accessCode: "wrong",
                challengeVerified: true
              })
            )
          );
        }
      }

      const results = await Promise.all(attempts);
      expect(results.filter(released)).toHaveLength(expectedRelease ? 1 : 0);
      expect(storage.entries()["capability:v1:record"]).toMatchObject({
        lifecycle: { state: expectedRelease ? "CONSUMED" : "ABUSE_LOCKED" },
        ciphertextEnvelope: expectedRelease
          ? null
          : createCommand(undefined, null, verifier).ciphertextEnvelope
      });
      if (!expectedRelease) {
        expect(storage.entries()["capability:v1:access-code"]).toMatchObject({
          failureCount: 10,
          challengeRequired: true,
          backoffUntil: null
        });
      }
    },
    // Serial PBKDF2 work must also finish under the complete suite's CPU load.
    20_000
  );

  it("atomically releases a protective lock without resetting traffic windows", async () => {
    const verifier = await accessCodeVerifier("correct horse");
    const storage = await activeStorage(null, verifier);
    await authorizeCapability(storage, {
      authority: "public",
      bearerSecret: PUBLIC_BEARER,
      now: 1_500
    });
    const failureTimes = [
      2_000, 2_001, 2_002, 2_003, 32_003, 152_003, 752_003, 4_352_003, 7_952_003, 11_552_003
    ];
    for (const [index, now] of failureTimes.entries()) {
      await claimCapability(
        storage,
        claim(`op_protective_failure_${index + 1}`, now, {
          accessCode: "wrong",
          challengeVerified: true
        })
      );
    }
    const passiveBefore = storage.entries()["capability:v1:rate:passive"];
    const revealBefore = storage.entries()["capability:v1:rate:reveal"];

    await expect(
      decideAbuseLock(storage, {
        operationId: "op_privileged_release",
        privilegedDecisionId: "decision_privileged_release",
        decision: "release",
        now: 11_552_004
      })
    ).resolves.toEqual({ ok: true });

    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "ACTIVE", committedConsumptions: 0 },
      ciphertextEnvelope: createCommand(undefined, null, verifier).ciphertextEnvelope
    });
    expect(storage.entries()["capability:v1:access-code"]).toEqual({
      schemaVersion: 1,
      failureCount: 0,
      challengeRequired: false,
      backoffUntil: null,
      deleteAt: null
    });
    expect(storage.entries()["capability:v1:rate:passive"]).toEqual(passiveBefore);
    expect(storage.entries()["capability:v1:rate:reveal"]).toEqual(revealBefore);
    expect(storage.entries()["capability:v1:record"]).not.toHaveProperty("confirmedAbuse");
  });
});

describe("Phase 1A outbox and restoration recovery cycles", () => {
  it("recovers an unresolved outbox after ten failed sends without reopening consumption", async () => {
    const storage = await activeStorage();
    const activationMessages: unknown[] = [];
    await deliverPendingOutbox(
      storage,
      {
        send(message) {
          activationMessages.push(message);
          return Promise.resolve();
        }
      },
      1_000
    );
    await acknowledgeOutboxDelivery(storage, {
      eventId: "op_reliability_create",
      projectionVersion: 1,
      now: 1_001
    });
    await claimCapability(storage, claim("op_outbox_failure_consume", 2_000));

    for (let attempt = 1; attempt <= 10; attempt += 1) {
      const outbox = storage.entries()["capability:v1:outbox:op_outbox_failure_consume"] as {
        nextAttemptAt: number;
      };
      await expect(
        deliverPendingOutbox(
          storage,
          { send: () => Promise.reject(new Error("injected Queue failure")) },
          outbox.nextAttemptAt
        )
      ).resolves.toMatchObject({ selected: 1, submitted: 0, failed: 1 });
    }
    expect(storage.entries()["capability:v1:outbox:op_outbox_failure_consume"]).toMatchObject({
      status: "unresolved",
      attemptCount: 10
    });

    const recovered: unknown[] = [];
    const unresolved = storage.entries()["capability:v1:outbox:op_outbox_failure_consume"] as {
      nextAttemptAt: number;
    };
    await deliverPendingOutbox(
      storage,
      {
        send(message) {
          recovered.push(message);
          return Promise.resolve();
        }
      },
      unresolved.nextAttemptAt
    );
    expect(recovered).toHaveLength(1);
    expect(JSON.stringify(recovered)).not.toContain(CIPHERTEXT);
    await acknowledgeOutboxDelivery(storage, {
      eventId: "op_outbox_failure_consume",
      projectionVersion: 2,
      now: unresolved.nextAttemptAt + 1
    });

    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "CONSUMED", committedConsumptions: 1 },
      ciphertextEnvelope: null
    });
    expect(storage.entries()["capability:v1:outbox:op_outbox_failure_consume"]).toMatchObject({
      status: "delivered",
      attemptCount: 11
    });
    await maintainCapability(storage, unresolved.nextAttemptAt + 1 + 7 * DAY_MS);
    expect(storage.entries()["capability:v1:outbox:op_outbox_failure_consume"]).toBeUndefined();
  });

  it.each([
    { name: "pre-consume", terminalState: "CONSUMED" as const, eventId: "op_restore_consume" },
    { name: "pre-delete", terminalState: "DELETED" as const, eventId: "op_restore_delete" }
  ])("re-deletes a $name point-in-time snapshot before serving resumes", async (scenario) => {
    const storage = await activeStorage();
    const preTerminalSnapshot = storage.snapshot();
    if (scenario.terminalState === "CONSUMED") {
      await claimCapability(storage, claim(scenario.eventId, 2_000));
    } else {
      await deleteCapability(storage, {
        operationId: scenario.eventId,
        ownerBearerSecret: OWNER_BEARER,
        now: 2_000
      });
    }
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: scenario.terminalState },
      ciphertextEnvelope: null
    });

    const reconciliation = {
      now: 3_000,
      terminalEvidence: {
        capabilityId: createCommand().capabilityId,
        locator: LOCATOR,
        eventId: scenario.eventId,
        state: scenario.terminalState,
        version: 2,
        occurredAt: 2_000
      }
    };
    let expectedReconciledSnapshot: ReturnType<typeof storage.snapshot> | null = null;
    for (let cycle = 0; cycle < 3; cycle += 1) {
      storage.restore(preTerminalSnapshot);
      expect(storage.entries()["capability:v1:record"]).toMatchObject({
        lifecycle: { state: "ACTIVE" },
        ciphertextEnvelope: createCommand().ciphertextEnvelope
      });
      await expect(reconcileCapability(storage, reconciliation)).resolves.toMatchObject({
        ok: true,
        message: { projection: { state: "DELETED", version: 3 } }
      });
      const reconciled = storage.snapshot();
      if (expectedReconciledSnapshot === null) expectedReconciledSnapshot = reconciled;
      else expect(reconciled).toEqual(expectedReconciledSnapshot);
      await expect(
        claimCapability(storage, claim(`op_after_${scenario.name}_${cycle}`, 4_000 + cycle))
      ).resolves.toEqual({ ok: false, code: "unavailable" });
    }
  });

  it.each([
    { name: "consume", terminalOperationId: "op_uncertain_restore_consume" },
    { name: "owner delete", terminalOperationId: "op_uncertain_restore_owner_delete" }
  ])(
    "deletes an uncertain restored ACTIVE snapshot without inventing $name evidence",
    async ({ name, terminalOperationId }) => {
      const storage = await activeStorage();
      const activeSnapshot = storage.snapshot();
      if (name === "consume") {
        await expect(
          claimCapability(storage, claim(terminalOperationId, 2_000))
        ).resolves.toMatchObject({ ok: true, outcome: "released" });
      } else {
        await expect(
          deleteCapability(storage, {
            operationId: terminalOperationId,
            ownerBearerSecret: OWNER_BEARER,
            now: 2_000
          })
        ).resolves.toEqual({ ok: true });
      }

      const decision = {
        operationId: "op_quarantine_delete_uncertain_restore",
        capabilityId: createCommand().capabilityId,
        locator: LOCATOR,
        decision: "delete_uncertain_restored_state",
        now: 3_000
      } as const;
      let expectedDeletedSnapshot: ReturnType<typeof storage.snapshot> | null = null;

      for (let restoreCycle = 0; restoreCycle < 2; restoreCycle += 1) {
        storage.restore(activeSnapshot);
        await expect(reconcileCapability(storage, { now: 2_500 })).resolves.toMatchObject({
          ok: true,
          message: { projection: { state: "ACTIVE", version: 1 } }
        });
        expect(storage.entries()["capability:v1:record"]).toMatchObject({
          lifecycle: { state: "ACTIVE" },
          ciphertextEnvelope: createCommand().ciphertextEnvelope
        });

        await expect(failClosedUncertainRestore(storage, decision)).resolves.toEqual({
          ok: true,
          state: "DELETED",
          projectionVersion: 2,
          ciphertextPresent: false
        });
        const afterFirstDecision = storage.snapshot();
        await expect(failClosedUncertainRestore(storage, decision)).resolves.toEqual({
          ok: true,
          state: "DELETED",
          projectionVersion: 2,
          ciphertextPresent: false
        });
        await expect(failClosedUncertainRestore(storage, decision)).resolves.toEqual({
          ok: true,
          state: "DELETED",
          projectionVersion: 2,
          ciphertextPresent: false
        });
        expect(storage.snapshot()).toEqual(afterFirstDecision);
        if (expectedDeletedSnapshot === null) expectedDeletedSnapshot = afterFirstDecision;
        else expect(afterFirstDecision).toEqual(expectedDeletedSnapshot);

        expect(storage.entries()["capability:v1:record"]).toMatchObject({
          lifecycle: { state: "DELETED" },
          ciphertextEnvelope: null,
          projectionVersion: 2,
          lastTransition: {
            eventId: decision.operationId,
            type: "capability_deleted",
            fromState: "ACTIVE",
            toState: "DELETED"
          }
        });
        expect(storage.entries()[`capability:v1:outbox:${decision.operationId}`]).toMatchObject({
          eventId: decision.operationId,
          projectionVersion: 2,
          event: { type: "capability_deleted" }
        });
        expect(JSON.stringify(storage.entries())).not.toContain(CIPHERTEXT);
        await expect(
          claimCapability(
            storage,
            claim(`op_after_uncertain_restore_${name}_${restoreCycle}`, 4_000 + restoreCycle)
          )
        ).resolves.toEqual({ ok: false, code: "unavailable" });
      }
    }
  );

  it("rolls back the uncertain-restore deletion and outbox together at every mutation", async () => {
    const decision = {
      operationId: "op_uncertain_restore_atomic_delete",
      capabilityId: createCommand().capabilityId,
      locator: LOCATOR,
      decision: "delete_uncertain_restored_state",
      now: 3_000
    } as const;

    for (const mutation of [1, 2, 3]) {
      const storage = await activeStorage();
      const before = storage.snapshot();
      storage.failNextTransaction({ phase: "mutation", mutation });
      await expect(failClosedUncertainRestore(storage, decision)).rejects.toThrow(
        `injected transaction mutation ${mutation}`
      );
      expect(storage.snapshot()).toEqual(before);
    }
  });
});

async function accessCodeVerifier(code: string): Promise<AccessCodeVerifier> {
  const codeBytes = new TextEncoder().encode(code);
  const salt = new Uint8Array(16);
  const key = await crypto.subtle.importKey("raw", codeBytes, "PBKDF2", false, ["deriveBits"]);
  const digest = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: 210_000 },
      key,
      256
    )
  );
  const encode = (bytes: Uint8Array) => {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  };
  try {
    return {
      version: "acv1",
      algorithm: "PBKDF2-SHA-256",
      iterations: 210_000,
      salt: encode(salt),
      digest: encode(digest)
    };
  } finally {
    codeBytes.fill(0);
    salt.fill(0);
    digest.fill(0);
  }
}
