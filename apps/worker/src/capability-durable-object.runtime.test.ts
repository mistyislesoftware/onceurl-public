import { env } from "cloudflare:workers";
import {
  applyD1Migrations,
  evictDurableObject,
  runDurableObjectAlarm,
  runInDurableObject,
  type D1Migration
} from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { app } from "./app";
import { createChallengeTicket } from "./abuse-control";
import {
  claimCapability,
  createCapability,
  type CapabilityObjectStorage,
  type CapabilityObjectTransaction
} from "./capability-durable-object-core";
import { runCapabilityAlarmDuties } from "./capability-durable-object";
import type { WorkerEnv } from "./env";
import type { SecretPreparationResponse } from "./secret-creation";
import { createTestPreparationHmacKey, createTestWorkerEnv } from "./testing/env";

const policy = {
  kind: "secret",
  expiresAt: null,
  maxConsumptions: 1,
  reactivation: "forbidden",
  postConsumption: { behavior: "delete_capability" }
} as const;

const LOCATOR = `loc1_${"b".repeat(48)}`;
const PUBLIC_BEARER = "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OWNER_BEARER = "own1_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const PUBLIC_HASH = "bh1_AfZsOtbRWT9tmoTvsqNOTGRcSnDN_sX_ip2zb4v2Zdk";
const OWNER_HASH = "bh1_fPMtNFmwccxj2Z6fkMWWH0TDFqAWQwqfQTmejZo1XsU";
const ACCESS_CODE_VERIFIER = {
  version: "acv1",
  algorithm: "PBKDF2-SHA-256",
  iterations: 210_000,
  salt: "AAAAAAAAAAAAAAAAAAAAAA",
  digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
} as const;
const BASE_NOW = Date.now();
const CREATED_AT = new Date(BASE_NOW).toISOString();
const runtimeEnv = env as WorkerEnv & { TEST_D1_MIGRATIONS: D1Migration[] };

beforeEach(async () => {
  if (runtimeEnv.DB === undefined) throw new Error("Runtime test requires D1");
  await applyD1Migrations(runtimeEnv.DB, runtimeEnv.TEST_D1_MIGRATIONS);
});

function createCommand(operationId = "op_create_runtime") {
  return {
    operationId,
    capabilityId: "cap_runtime_01HZXAMPLE00000000000",
    locator: LOCATOR,
    createdAt: CREATED_AT,
    policy,
    policyHash: "policy_hash_runtime_123",
    publicBearerSecretHash: PUBLIC_HASH,
    ownerBearerSecretHash: OWNER_HASH,
    ciphertextEnvelope: {
      version: "ouzk-v1",
      alg: "AES-256-GCM",
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: "AAAAAAAAAAAAAAAAAAAAAAA",
      ad: {
        capabilityId: "cap_runtime_01HZXAMPLE00000000000",
        createdAt: CREATED_AT,
        kind: "secret",
        locator: LOCATOR,
        policyHash: "policy_hash_runtime_123",
        purpose: "onceurl.phase1a.secret-text",
        version: "ouzk-v1"
      }
    },
    now: BASE_NOW
  };
}

function claimCommand(operationId: string, nonce: string) {
  return {
    publicBearerSecret: PUBLIC_BEARER,
    operationId,
    nonce,
    now: BASE_NOW + 1_000
  };
}

function createCommandAt(operationId: string, now: number, expiresAt: number | null = null) {
  const createdAt = new Date(now).toISOString();
  const command = createCommand(operationId);
  return {
    ...command,
    createdAt,
    policy: { ...policy, expiresAt },
    ciphertextEnvelope: {
      ...command.ciphertextEnvelope,
      ad: { ...command.ciphertextEnvelope.ad, createdAt }
    },
    now
  };
}

function objectStub(name: string) {
  const capabilityState = env.CAPABILITY_STATE;
  if (!capabilityState) {
    throw new Error("Runtime test requires the CAPABILITY_STATE binding");
  }
  return capabilityState.getByName(`${name}-${crypto.randomUUID()}`);
}

async function commandRequest(
  stub: DurableObjectStub,
  path:
    | "/internal/capability/create"
    | "/internal/capability/claim"
    | "/internal/capability/authorize"
    | "/internal/capability/decide-abuse-lock",
  body: unknown
): Promise<{ response: Response; body: unknown }> {
  const response = await stub.fetch(
    new Request(`https://capability.invalid${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    })
  );
  return { response, body: await response.json() };
}

function isReleased(value: unknown): value is { ok: true; ciphertextEnvelope: unknown } {
  return (
    typeof value === "object" &&
    value !== null &&
    "ok" in value &&
    value.ok === true &&
    "ciphertextEnvelope" in value
  );
}

function runtimeWorkerEnv(currentKey: string, previousKey?: string): WorkerEnv {
  return createTestWorkerEnv({
    CAPABILITY_STATE: env.CAPABILITY_STATE,
    SECRET_PREPARATION_HMAC_KEY: currentKey,
    ...(previousKey === undefined ? {} : { SECRET_PREPARATION_HMAC_PREVIOUS_KEY: previousKey })
  });
}

function completionBody(prepared: SecretPreparationResponse) {
  return {
    creation: prepared.creation,
    policy: prepared.policy,
    complete_by: prepared.complete_by,
    preparation_proof: prepared.preparation_proof,
    ciphertext_envelope: {
      version: "ouzk-v1",
      alg: "AES-256-GCM",
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: "AAAAAAAAAAAAAAAAAAAAAAA",
      ad: {
        capabilityId: prepared.creation.capability_id,
        createdAt: prepared.creation.created_at,
        kind: "secret",
        locator: prepared.creation.locator,
        policyHash: prepared.creation.policy_hash,
        purpose: "onceurl.phase1a.secret-text",
        version: "ouzk-v1"
      }
    }
  } as const;
}

describe("Capability Durable Object Workers runtime boundary", () => {
  it("redrives simultaneous expiry and outbox duties after eviction without duplicate effects", async () => {
    const stub = objectStub("alarm-restart");
    const now = Date.now();
    await runInDurableObject(stub, async (_instance, state) => {
      await createCapability(
        state.storage,
        createCommandAt("op_alarm_restart", now - 2_000, now - 1_000)
      );
      await state.storage.setAlarm(now + 60_000);
    });

    await evictDurableObject(stub);
    await expect(runDurableObjectAlarm(stub)).resolves.toBe(true);
    const afterFirstAlarm = await runInDurableObject(stub, async (_instance, state) => ({
      record: await state.storage.get<Record<string, unknown>>("capability:v1:record"),
      outboxes: await state.storage.list<Record<string, unknown>>({
        prefix: "capability:v1:outbox:"
      })
    }));
    expect(afterFirstAlarm.record).toMatchObject({
      lifecycle: { state: "EXPIRED" },
      ciphertextEnvelope: null,
      projectionVersion: 2
    });
    expect(afterFirstAlarm.outboxes.size).toBe(2);
    for (const outbox of afterFirstAlarm.outboxes.values()) {
      expect(outbox).toMatchObject({ attemptCount: 1 });
    }

    await expect(runDurableObjectAlarm(stub)).resolves.toBe(true);
    const afterDuplicateAlarm = await runInDurableObject(stub, async (_instance, state) => ({
      record: await state.storage.get<Record<string, unknown>>("capability:v1:record"),
      outboxes: await state.storage.list<Record<string, unknown>>({
        prefix: "capability:v1:outbox:"
      })
    }));
    expect(afterDuplicateAlarm).toEqual(afterFirstAlarm);
  });

  it("redrives a pending outbox on later object activity", async () => {
    const stub = objectStub("activity-redrive");
    const now = Date.now();
    await runInDurableObject(stub, async (_instance, state) => {
      await createCapability(state.storage, createCommandAt("op_activity_redrive", now - 1_000));
    });

    const authorized = await commandRequest(stub, "/internal/capability/authorize", {
      authority: "owner",
      bearerSecret: OWNER_BEARER,
      now
    });
    expect(authorized.body).toMatchObject({ ok: true });
    await expect(
      runInDurableObject(stub, async (_instance, state) =>
        state.storage.get("capability:v1:outbox:op_activity_redrive")
      )
    ).resolves.toMatchObject({ attemptCount: 1 });
  });

  it("runs the outbox alarm duty even when maintenance fails", async () => {
    const calls: string[] = [];
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      await expect(
        runCapabilityAlarmDuties(
          () => {
            calls.push("maintenance");
            return Promise.reject(new Error("sensitive-injected-detail"));
          },
          () => {
            calls.push("outbox");
            return Promise.resolve();
          }
        )
      ).rejects.toThrow("One or more capability alarm duties failed");
      expect(calls).toEqual(["maintenance", "outbox"]);
      expect(JSON.stringify(error.mock.calls)).not.toContain("sensitive-injected-detail");
    } finally {
      error.mockRestore();
    }
  });

  it("deletes an overdue protective lock when a privileged decision beats the delayed alarm", async () => {
    const stub = objectStub("late-lock-alarm");
    const deleteAt = Date.now() + 60_000;
    const lockedAt = deleteAt - 1_000;
    await runInDurableObject(stub, async (_instance, state) => {
      await createCapability(state.storage, {
        ...createCommandAt("op_create_late_lock", lockedAt - 1_000),
        accessCodeVerifier: ACCESS_CODE_VERIFIER
      });
      const record = await state.storage.get<Record<string, unknown>>("capability:v1:record");
      await state.storage.put("capability:v1:record", {
        ...record,
        lifecycle: { state: "ABUSE_LOCKED", committedConsumptions: 0 },
        projectionVersion: 2,
        lastTransition: {
          eventId: "op_late_protective_lock",
          type: "capability_abuse_locked",
          occurredAt: lockedAt,
          fromState: "ACTIVE",
          toState: "ABUSE_LOCKED"
        }
      });
      await state.storage.put("capability:v1:access-code", {
        schemaVersion: 1,
        failureCount: 10,
        challengeRequired: true,
        backoffUntil: null,
        deleteAt
      });
      await state.storage.setAlarm(deleteAt);
    });

    const decision = await commandRequest(stub, "/internal/capability/decide-abuse-lock", {
      operationId: "op_release_after_deadline",
      privilegedDecisionId: "decision_release_after_deadline",
      decision: "release",
      now: deleteAt
    });
    expect(decision).toMatchObject({
      response: { status: 409 },
      body: { ok: false, code: "unavailable" }
    });

    const stored = await runInDurableObject(stub, async (_instance, state) => ({
      record: await state.storage.get("capability:v1:record"),
      automaticDelete: await state.storage.get(`capability:v1:outbox:automatic-delete:${deleteAt}`),
      privilegedRelease: await state.storage.get("capability:v1:outbox:op_release_after_deadline")
    }));
    expect(stored.record).toMatchObject({
      lifecycle: { state: "DELETED" },
      ciphertextEnvelope: null
    });
    expect(stored.automaticDelete).toMatchObject({
      event: { decision: "delete", toState: "DELETED" }
    });
    expect(stored.privilegedRelease).toBeUndefined();
  });

  it("recovers an exact completion retry across preparation-key rotation", async () => {
    const originalKey = createTestPreparationHmacKey();
    const rotatedKey = createTestPreparationHmacKey();
    const originalEnvironment = runtimeWorkerEnv(originalKey);
    const preparedResponse = await app.request(
      "/api/v1/secrets/prepare",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          expires_in_seconds: 3_600,
          challenge_id: await createChallengeTicket(
            originalEnvironment,
            "onceurl_prepare",
            Date.now()
          )
        })
      },
      originalEnvironment
    );
    expect(preparedResponse.status).toBe(200);
    const prepared = await preparedResponse.json<SecretPreparationResponse>();
    const body = completionBody(prepared);
    const completionRequest = () => ({
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": prepared.creation.operation_id
      },
      body: JSON.stringify(body)
    });

    const firstResponse = await app.request(
      "/api/v1/secrets",
      completionRequest(),
      originalEnvironment
    );
    expect(firstResponse.status).toBe(200);
    await firstResponse.body?.cancel();

    const capabilityState = env.CAPABILITY_STATE;
    if (!capabilityState) {
      throw new Error("Runtime test requires the CAPABILITY_STATE binding");
    }
    const stub = capabilityState.getByName(prepared.creation.locator);
    const storedAfterLostResponse = await runInDurableObject(stub, async (_instance, state) =>
      state.storage.get("capability:v1:record")
    );
    expect(storedAfterLostResponse).toMatchObject({
      capabilityId: prepared.creation.capability_id,
      lifecycle: { state: "ACTIVE", committedConsumptions: 0 },
      ciphertextEnvelope: body.ciphertext_envelope
    });

    const retryResponse = await app.request(
      "/api/v1/secrets",
      completionRequest(),
      runtimeWorkerEnv(rotatedKey, originalKey)
    );
    expect(retryResponse.status).toBe(200);
    await expect(retryResponse.json()).resolves.toEqual({
      recipient_path: `/s/${prepared.creation.locator}/${prepared.creation.public_bearer}`,
      owner_path: `/m/${prepared.creation.locator}/${prepared.creation.owner_bearer}`,
      expires_at: prepared.policy.expires_at
    });
  });

  it("authorizes both route authorities without consuming", async () => {
    const stub = objectStub("authorize");
    expect(
      (await commandRequest(stub, "/internal/capability/create", createCommand())).body
    ).toEqual({ ok: true });

    const publicResult = await commandRequest(stub, "/internal/capability/authorize", {
      authority: "public",
      bearerSecret: PUBLIC_BEARER,
      now: BASE_NOW + 500
    });
    const ownerResult = await commandRequest(stub, "/internal/capability/authorize", {
      authority: "owner",
      bearerSecret: OWNER_BEARER,
      now: BASE_NOW + 500
    });
    expect(publicResult).toMatchObject({
      response: { status: 200 },
      body: { ok: true, authority: "public", capability: { state: "ACTIVE" } }
    });
    expect(ownerResult).toMatchObject({
      response: { status: 200 },
      body: { ok: true, authority: "owner", capability: { state: "ACTIVE" } }
    });

    const stored = await runInDurableObject(stub, async (_instance, state) =>
      state.storage.get("capability:v1:record")
    );
    expect(stored).toMatchObject({
      lifecycle: { state: "ACTIVE", committedConsumptions: 0 },
      ciphertextEnvelope: createCommand().ciphertextEnvelope
    });
  });

  it("creates through CAPABILITY_STATE and releases once across concurrent claims", async () => {
    const stub = objectStub("concurrent");
    const created = await commandRequest(stub, "/internal/capability/create", createCommand());
    expect(created.response.status).toBe(200);
    expect(created.body).toEqual({ ok: true });

    const claims = await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        commandRequest(
          stub,
          "/internal/capability/claim",
          claimCommand(`op_concurrent_runtime_${index}`, `nonce_concurrent_runtime_${index}`)
        )
      )
    );
    const released = claims.filter(({ body }) => isReleased(body));
    expect(released).toHaveLength(1);
    expect(released[0]?.body).toMatchObject({
      ok: true,
      outcome: "released",
      ciphertextEnvelope: createCommand().ciphertextEnvelope
    });
    expect(
      claims
        .filter(({ body }) => !isReleased(body))
        .every(({ body }) => JSON.stringify(body).includes('"code":"unavailable"'))
    ).toBe(true);

    const operationId = claims.findIndex(({ body }) => isReleased(body));
    const retry = await commandRequest(
      stub,
      "/internal/capability/claim",
      claimCommand(
        `op_concurrent_runtime_${operationId}`,
        `nonce_concurrent_runtime_${operationId}`
      )
    );
    expect(retry.response.status).toBe(409);
    expect(retry.body).toEqual({ ok: false, code: "unavailable" });
    expect(JSON.stringify(retry.body)).not.toContain("ciphertext");

    const stored = await runInDurableObject(stub, async (_instance, state) => {
      const record = await state.storage.get("capability:v1:record");
      const outbox = await state.storage.list({ prefix: "capability:v1:outbox:" });
      return { record, outboxKeys: [...outbox.keys()] };
    });
    expect(stored.record).toMatchObject({
      lifecycle: { state: "CONSUMED", committedConsumptions: 1 },
      ciphertextEnvelope: null
    });
    expect(stored.outboxKeys).toContain("capability:v1:outbox:op_create_runtime");
    expect(stored.outboxKeys).toHaveLength(2);
  });

  it("returns controlled errors for malformed JSON and command bodies without consuming", async () => {
    const stub = objectStub("malformed");
    expect(
      (await commandRequest(stub, "/internal/capability/create", createCommand())).body
    ).toEqual({ ok: true });

    const malformed = await stub.fetch(
      new Request("https://capability.invalid/internal/capability/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: '{"publicBearerSecret":"bearer-leak-marker"'
      })
    );
    const malformedText = await malformed.text();
    expect(malformed.status).toBe(400);
    expect(JSON.parse(malformedText)).toEqual({ ok: false, code: "invalid_json" });
    expect(malformedText).not.toContain("bearer-leak-marker");

    const nonObject = await commandRequest(stub, "/internal/capability/claim", "not-an-object");
    expect(nonObject.response.status).toBe(400);
    expect(nonObject.body).toEqual({ ok: false, code: "invalid_command" });

    const emptyBearer = await commandRequest(stub, "/internal/capability/claim", {
      ...claimCommand("op_rejected", "nonce_rejected"),
      publicBearerSecret: ""
    });
    expect(emptyBearer.response.status).toBe(400);
    expect(emptyBearer.body).toEqual({ ok: false, code: "invalid_command" });

    const valid = await commandRequest(
      stub,
      "/internal/capability/claim",
      claimCommand("op_after_rejected", "nonce_after_rejected")
    );
    expect(valid.response.status).toBe(200);
    expect(isReleased(valid.body)).toBe(true);
  });

  it("rejects passive methods without invoking claim logic", async () => {
    const stub = objectStub("passive");
    await commandRequest(stub, "/internal/capability/create", createCommand());

    const passive = await stub.fetch(
      new Request("https://capability.invalid/internal/capability/claim", {
        method: "GET"
      })
    );
    expect(passive.status).toBe(405);
    expect(await passive.json()).toEqual({ ok: false, code: "method_not_allowed" });

    const valid = await commandRequest(
      stub,
      "/internal/capability/claim",
      claimCommand("op_after_passive", "nonce_after_passive")
    );
    expect(valid.response.status).toBe(200);
    expect(isReleased(valid.body)).toBe(true);
  });

  it("rolls back actual Durable Object storage when a claim transaction fails", async () => {
    const stub = objectStub("rollback");
    await commandRequest(stub, "/internal/capability/create", createCommand());

    await runInDurableObject(stub, async (_instance, state) => {
      const storage: CapabilityObjectStorage = {
        async get<T = unknown>(key: string): Promise<T | undefined> {
          return state.storage.get<T>(key);
        },
        async put<T>(key: string, value: T): Promise<void> {
          await state.storage.put(key, value);
        },
        async delete(key: string): Promise<boolean> {
          return state.storage.delete(key);
        },
        async getAlarm(): Promise<number | null> {
          return state.storage.getAlarm();
        },
        async setAlarm(scheduledTime: number): Promise<void> {
          await state.storage.setAlarm(scheduledTime);
        },
        async deleteAlarm(): Promise<void> {
          await state.storage.deleteAlarm();
        },
        async list<T = unknown>(options?: { readonly prefix?: string }): Promise<Map<string, T>> {
          return state.storage.list<T>(options);
        },
        async transaction<T>(
          closure: (txn: CapabilityObjectTransaction) => Promise<T>
        ): Promise<T> {
          return state.storage.transaction(async (txn) => {
            let writeCount = 0;
            const failingTransaction: CapabilityObjectTransaction = {
              async get<Value = unknown>(key: string): Promise<Value | undefined> {
                return txn.get<Value>(key);
              },
              async put<Value>(key: string, value: Value): Promise<void> {
                writeCount += 1;
                if (writeCount === 3) {
                  throw new Error("injected transaction failure");
                }
                await txn.put(key, value);
              },
              async delete(key: string): Promise<boolean> {
                return txn.delete(key);
              },
              async list<Value = unknown>(options?: {
                readonly prefix?: string;
              }): Promise<Map<string, Value>> {
                return txn.list<Value>(options);
              },
              async getAlarm(): Promise<number | null> {
                return txn.getAlarm();
              },
              async setAlarm(scheduledTime: number): Promise<void> {
                await txn.setAlarm(scheduledTime);
              },
              async deleteAlarm(): Promise<void> {
                await txn.deleteAlarm();
              }
            };
            return closure(failingTransaction);
          });
        }
      };

      await expect(
        claimCapability(storage, claimCommand("op_rollback", "nonce_rollback"))
      ).rejects.toThrow("injected transaction failure");

      expect(await state.storage.get("capability:v1:record")).toMatchObject({
        lifecycle: { state: "ACTIVE", committedConsumptions: 0 },
        ciphertextEnvelope: createCommand().ciphertextEnvelope
      });
      expect(await state.storage.get("capability:v1:outbox:op_rollback")).toBeUndefined();
      expect(await state.storage.get("capability:v1:claim:op_rollback")).toBeUndefined();
    });

    const valid = await commandRequest(
      stub,
      "/internal/capability/claim",
      claimCommand("op_after_rollback", "nonce_after_rollback")
    );
    expect(valid.response.status).toBe(200);
    expect(isReleased(valid.body)).toBe(true);
  });
});
