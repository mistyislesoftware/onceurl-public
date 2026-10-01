import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  authorizeCapability,
  acknowledgeOutboxDelivery,
  claimCapability,
  createCapability,
  decideAbuseLock,
  deleteCapability,
  deliverPendingOutbox,
  maintainCapability,
  markOutboxDeadLetter,
  parseCapabilityProjectionMessage,
  reconcileCapability,
  type CapabilityProjectionMessage,
  type CapabilityObjectStorage,
  type CapabilityObjectTransaction,
  type CreateCapabilityCommand
} from "./capability-durable-object-core";
import type { AccessCodeVerifier } from "./access-code";

const LOCATOR = `loc1_${"a".repeat(48)}`;
const PUBLIC_BEARER = "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OWNER_BEARER = "own1_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const OTHER_PUBLIC_BEARER = "pub1_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const OTHER_OWNER_BEARER = "own1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const PUBLIC_HASH = "bh1_AfZsOtbRWT9tmoTvsqNOTGRcSnDN_sX_ip2zb4v2Zdk";
const OWNER_HASH = "bh1_fPMtNFmwccxj2Z6fkMWWH0TDFqAWQwqfQTmejZo1XsU";
const DAY_MS = 24 * 60 * 60 * 1_000;

class MemoryDurableObjectStorage implements CapabilityObjectStorage {
  private readonly values = new Map<string, unknown>();
  private lock: Promise<void> = Promise.resolve();
  private alarm: number | null = null;

  async get<T = unknown>(key: string): Promise<T | undefined> {
    return Promise.resolve(this.values.get(key) as T | undefined);
  }

  async put<T>(key: string, value: T): Promise<void> {
    this.values.set(key, value);
    await Promise.resolve();
  }

  delete(key: string): Promise<boolean> {
    return Promise.resolve(this.values.delete(key));
  }

  getAlarm(): Promise<number | null> {
    return Promise.resolve(this.alarm);
  }

  async setAlarm(scheduledTime: number): Promise<void> {
    this.alarm = scheduledTime;
    await Promise.resolve();
  }

  async deleteAlarm(): Promise<void> {
    this.alarm = null;
    await Promise.resolve();
  }

  list<T = unknown>(options?: { readonly prefix?: string }): Promise<Map<string, T>> {
    return Promise.resolve(
      new Map(
        [...this.values.entries()].filter(([key]) =>
          options?.prefix === undefined ? true : key.startsWith(options.prefix)
        )
      ) as Map<string, T>
    );
  }

  async transaction<T>(closure: (txn: CapabilityObjectTransaction) => Promise<T>): Promise<T> {
    const previous = this.lock;
    let release!: () => void;
    this.lock = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await closure(this);
    } finally {
      release();
    }
  }

  entries(): Record<string, unknown> {
    return Object.fromEntries(this.values.entries());
  }

  alarmTime(): number | null {
    return this.alarm;
  }
}

const policy = {
  kind: "secret",
  expiresAt: null,
  maxConsumptions: 1,
  reactivation: "forbidden",
  postConsumption: { behavior: "delete_capability" }
} as const;

const baseCommand = (): CreateCapabilityCommand => ({
  operationId: "op_create",
  capabilityId: "cap_01HZXAMPLE0000000000000000",
  locator: LOCATOR,
  createdAt: "2026-07-13T00:00:00.000Z",
  policy,
  policyHash: "policy_hash_123",
  publicBearerSecretHash: PUBLIC_HASH,
  ownerBearerSecretHash: OWNER_HASH,
  ciphertextEnvelope: {
    version: "ouzk-v1",
    alg: "AES-256-GCM",
    nonce: "AAAAAAAAAAAAAAAA",
    ciphertext: "AAAAAAAAAAAAAAAAAAAAAAA",
    ad: {
      capabilityId: "cap_01HZXAMPLE0000000000000000",
      createdAt: "2026-07-13T00:00:00.000Z",
      kind: "secret",
      locator: LOCATOR,
      policyHash: "policy_hash_123",
      purpose: "onceurl.phase1a.secret-text",
      version: "ouzk-v1"
    }
  },
  now: 1_000
});

async function populatedStorage(): Promise<MemoryDurableObjectStorage> {
  const storage = new MemoryDurableObjectStorage();
  expect(await createCapability(storage, baseCommand())).toEqual({ ok: true });
  return storage;
}

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

async function lockedStorage(deleteAt = 3_000): Promise<MemoryDurableObjectStorage> {
  const storage = new MemoryDurableObjectStorage();
  await createCapability(storage, {
    ...baseCommand(),
    accessCodeVerifier: await accessCodeVerifier("correct horse")
  });
  const record = structuredClone(storage.entries()["capability:v1:record"]) as Record<
    string,
    unknown
  >;
  await storage.put("capability:v1:record", {
    ...record,
    lifecycle: { state: "ABUSE_LOCKED", committedConsumptions: 0 },
    projectionVersion: 2,
    lastTransition: {
      eventId: "op_protective_lock",
      type: "capability_abuse_locked",
      occurredAt: 2_000,
      fromState: "ACTIVE",
      toState: "ABUSE_LOCKED"
    }
  });
  await storage.put("capability:v1:access-code", {
    schemaVersion: 1,
    failureCount: 10,
    challengeRequired: true,
    backoffUntil: null,
    deleteAt
  });
  return storage;
}

async function rewriteAsLegacySchema2(storage: MemoryDurableObjectStorage): Promise<void> {
  const record = structuredClone(storage.entries()["capability:v1:record"]) as Record<
    string,
    unknown
  >;
  delete record.projectionVersion;
  delete record.lastTransition;
  await storage.put("capability:v1:record", { ...record, schemaVersion: 2 });

  for (const [key, value] of Object.entries(storage.entries())) {
    if (!key.startsWith("capability:v1:outbox:")) continue;
    const outbox = value as Record<string, unknown>;
    await storage.put(key, {
      schemaVersion: 1,
      eventId: outbox.eventId,
      event: outbox.event,
      pending: true,
      recordedAt: outbox.recordedAt
    });
  }
}

async function legacyProtectedDecisionStorage(
  decision: "release" | "disable"
): Promise<MemoryDurableObjectStorage> {
  const storage = await lockedStorage(10_000);
  await storage.put("capability:v1:outbox:op_protective_lock", {
    schemaVersion: 1,
    eventId: "op_protective_lock",
    event: {
      type: "capability_abuse_locked",
      eventId: "op_protective_lock",
      occurredAt: 2_000,
      fromState: "ACTIVE",
      toState: "ABUSE_LOCKED"
    },
    pending: true,
    recordedAt: 2_000
  });
  const result = await decideAbuseLock(storage, {
    operationId: `op_legacy_${decision}`,
    privilegedDecisionId: `decision_legacy_${decision}`,
    decision,
    now: 3_000
  });
  if (!result.ok) throw new Error(`Legacy ${decision} fixture decision failed`);
  await rewriteAsLegacySchema2(storage);
  return storage;
}

async function expectMalformedPersistedRecord(
  mutate: (record: Record<string, unknown>) => unknown
): Promise<void> {
  const storage = await populatedStorage();
  const recordKey = "capability:v1:record";
  const record = structuredClone(storage.entries()[recordKey]) as Record<string, unknown>;
  await storage.put(recordKey, mutate(record));
  const beforeClaim = structuredClone(storage.entries());

  const result = await claimCapability(storage, {
    publicBearerSecret: PUBLIC_BEARER,
    operationId: "op_malformed_record",
    nonce: "nonce_malformed_record",
    now: 2_000
  });

  expect(result).toEqual({ ok: false, code: "malformed_state" });
  expect(JSON.stringify(result)).not.toContain("ciphertext");
  expect(storage.entries()).toEqual(beforeClaim);
}

describe("Capability Durable Object persistence", () => {
  it("atomically records the activation event before creation succeeds", async () => {
    const storage = new MemoryDurableObjectStorage();

    expect(await createCapability(storage, baseCommand())).toEqual({ ok: true });

    const entries = storage.entries();
    expect(entries["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "ACTIVE", committedConsumptions: 0 }
    });
    expect(entries["capability:v1:outbox:op_create"]).toMatchObject({
      event: {
        type: "capability_activated",
        eventId: "op_create",
        fromState: "DRAFT",
        toState: "ACTIVE"
      },
      status: "pending",
      recordedAt: 1_000
    });
  });

  it("treats only an exact completion replay with its activation outbox as idempotent", async () => {
    const storage = new MemoryDurableObjectStorage();
    expect(await createCapability(storage, baseCommand())).toEqual({ ok: true });
    const created = structuredClone(storage.entries());

    expect(await createCapability(storage, { ...baseCommand(), now: 1_500 })).toEqual({ ok: true });
    expect(storage.entries()).toEqual(created);
    expect(
      await createCapability(storage, {
        ...baseCommand(),
        ciphertextEnvelope: {
          ...(baseCommand().ciphertextEnvelope as Record<string, unknown>),
          ciphertext: "AQAAAAAAAAAAAAAAAAAAAAA"
        }
      })
    ).toEqual({ ok: false, code: "already_exists" });
    expect(await createCapability(storage, { ...baseCommand(), operationId: "op_other" })).toEqual({
      ok: false,
      code: "already_exists"
    });
    expect(storage.entries()).toEqual(created);
  });

  it("does not overwrite an outbox record while creating", async () => {
    const storage = new MemoryDurableObjectStorage();
    const existing = { sentinel: "existing-event" };
    await storage.put("capability:v1:outbox:op_create", existing);

    expect(await createCapability(storage, baseCommand())).toEqual({
      ok: false,
      code: "event_conflict"
    });
    expect(storage.entries()["capability:v1:outbox:op_create"]).toEqual(existing);
    expect(storage.entries()["capability:v1:record"]).toBeUndefined();
  });

  it("creates and reloads versioned capability state without exposing bearer hashes", async () => {
    const storage = await populatedStorage();

    const result = await claimCapability(storage, {
      publicBearerSecret: PUBLIC_BEARER,
      operationId: "op_1",
      nonce: "nonce_1",
      now: 2_000
    });

    expect(result).toEqual({
      ok: true,
      outcome: "released",
      ciphertextEnvelope: baseCommand().ciphertextEnvelope
    });
    expect(JSON.stringify(result)).not.toContain(PUBLIC_HASH);
    expect(JSON.stringify(result)).not.toContain(OWNER_HASH);
  });

  it("authorizes public and owner bearer secrets inside the authoritative object", async () => {
    const storage = await populatedStorage();
    const beforeAuthorization = structuredClone(storage.entries());

    await expect(
      authorizeCapability(storage, { authority: "public", bearerSecret: PUBLIC_BEARER, now: 1_500 })
    ).resolves.toEqual({
      ok: true,
      authority: "public",
      capability: {
        kind: "secret",
        state: "ACTIVE",
        createdAt: "2026-07-13T00:00:00.000Z",
        expiresAt: null,
        isAvailable: true,
        policy: { maxConsumptions: 1 },
        accessCodeRequired: false
      }
    });
    await expect(
      authorizeCapability(storage, { authority: "owner", bearerSecret: OWNER_BEARER, now: 1_500 })
    ).resolves.toEqual({
      ok: true,
      authority: "owner",
      capability: {
        kind: "secret",
        state: "ACTIVE",
        createdAt: "2026-07-13T00:00:00.000Z",
        expiresAt: null,
        isAvailable: true,
        policy: { maxConsumptions: 1 },
        accessCodeRequired: false,
        events: [{ type: "created", occurredAt: 1_000 }]
      }
    });
    expect(storage.entries()["capability:v1:record"]).toEqual(
      beforeAuthorization["capability:v1:record"]
    );
  });

  it("returns owner-only coarse activation and consumption events without operation detail", async () => {
    const storage = await populatedStorage();
    await claimCapability(storage, {
      publicBearerSecret: PUBLIC_BEARER,
      operationId: "op_owner_status_claim",
      nonce: "nonce_owner_status_claim",
      now: 1_000
    });

    const owner = await authorizeCapability(storage, {
      authority: "owner",
      bearerSecret: OWNER_BEARER,
      now: 2_500
    });
    const publicResult = await authorizeCapability(storage, {
      authority: "public",
      bearerSecret: PUBLIC_BEARER,
      now: 2_500
    });

    expect(owner).toMatchObject({
      ok: true,
      capability: {
        state: "CONSUMED",
        isAvailable: false,
        events: [
          { type: "created", occurredAt: 1_000 },
          { type: "consumed", occurredAt: 1_000 }
        ]
      }
    });
    expect(publicResult).toMatchObject({
      ok: true,
      capability: { state: "CONSUMED", isAvailable: false }
    });
    expect(JSON.stringify(publicResult)).not.toContain("events");
    const ownerJson = JSON.stringify(owner);
    expect(ownerJson).not.toContain("op_owner_status_claim");
    expect(ownerJson).not.toContain("nonce_owner_status_claim");
    expect(ownerJson).not.toContain("ciphertext");
    expect(ownerJson).not.toContain(PUBLIC_HASH);
    expect(ownerJson).not.toContain(OWNER_HASH);
  });

  it("fails owner event inspection closed for a malformed outbox record", async () => {
    const storage = await populatedStorage();
    await storage.put("capability:v1:outbox:corrupt", {
      schemaVersion: 1,
      pending: true,
      event: { type: "capability_activated", eventId: "corrupt", occurredAt: -1 }
    });
    await expect(
      authorizeCapability(storage, {
        authority: "owner",
        bearerSecret: OWNER_BEARER,
        now: 1_500
      })
    ).resolves.toEqual({ ok: false, code: "malformed_state" });
  });

  it("rejects locator-only, wrong-authority and substituted bearer authorization", async () => {
    const storage = await populatedStorage();
    const beforeAuthorization = structuredClone(storage.entries());

    await expect(
      authorizeCapability(storage, { authority: "public", now: 1_500 })
    ).resolves.toEqual({
      ok: false,
      code: "invalid_command"
    });
    await expect(
      authorizeCapability(storage, { authority: "public", bearerSecret: OWNER_BEARER, now: 1_500 })
    ).resolves.toEqual({ ok: false, code: "invalid_command" });
    await expect(
      authorizeCapability(storage, {
        authority: "public",
        bearerSecret: OTHER_PUBLIC_BEARER,
        now: 1_500
      })
    ).resolves.toEqual({ ok: false, code: "unauthorized" });
    await expect(
      authorizeCapability(storage, {
        authority: "owner",
        bearerSecret: OTHER_OWNER_BEARER,
        now: 1_500
      })
    ).resolves.toEqual({ ok: false, code: "unauthorized" });
    expect(storage.entries()).toEqual(beforeAuthorization);
  });

  it("rejects non-public bearer authority without mutating state", async () => {
    const storage = await populatedStorage();
    const beforeClaim = structuredClone(storage.entries());

    const result = await claimCapability(storage, {
      publicBearerSecret: OWNER_BEARER,
      operationId: "op_wrong_authority",
      nonce: "nonce_wrong_authority",
      now: 2_000
    });

    expect(result).toEqual({ ok: false, code: "invalid_command" });
    expect(JSON.stringify(result)).not.toContain(OWNER_BEARER);
    expect(storage.entries()).toEqual(beforeClaim);
  });

  it("atomically records the consume transition and outbox before success", async () => {
    const storage = await populatedStorage();
    await claimCapability(storage, {
      publicBearerSecret: PUBLIC_BEARER,
      operationId: "op_atomic",
      nonce: "nonce_atomic",
      now: 2_000
    });

    const entries = storage.entries();
    expect(entries["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "CONSUMED", committedConsumptions: 1 },
      ciphertextEnvelope: null
    });
    expect(entries["capability:v1:outbox:op_atomic"]).toMatchObject({
      event: { type: "capability_consumption_committed", consumptionId: "nonce_atomic" },
      status: "pending"
    });
  });

  it("makes same operation and nonce retries deterministically unavailable", async () => {
    const storage = await populatedStorage();
    const command = {
      publicBearerSecret: PUBLIC_BEARER,
      operationId: "op_retry",
      nonce: "nonce_retry",
      now: 2_000
    };

    expect(await claimCapability(storage, command)).toMatchObject({
      ok: true,
      outcome: "released"
    });
    expect(await claimCapability(storage, command)).toEqual({ ok: false, code: "unavailable" });
    expect(JSON.stringify(storage.entries()["capability:v1:claim:op_retry"])).not.toContain(
      "ciphertextEnvelope"
    );
  });

  it("rejects a different replay for an existing operation", async () => {
    const storage = await populatedStorage();
    await claimCapability(storage, {
      publicBearerSecret: PUBLIC_BEARER,
      operationId: "op_conflict",
      nonce: "nonce_a",
      now: 2_000
    });

    expect(
      await claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_conflict",
        nonce: "nonce_b",
        now: 2_001
      })
    ).toEqual({ ok: false, code: "nonce_conflict" });
  });

  it("rejects an outbox event collision before changing authoritative state", async () => {
    const storage = await populatedStorage();
    const activationBefore = structuredClone(storage.entries()["capability:v1:outbox:op_create"]);

    expect(
      await claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_create",
        nonce: "nonce_collision",
        now: 2_000
      })
    ).toEqual({ ok: false, code: "event_conflict" });

    let entries = storage.entries();
    expect(entries["capability:v1:outbox:op_create"]).toEqual(activationBefore);
    expect(entries["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "ACTIVE", committedConsumptions: 0 },
      ciphertextEnvelope: baseCommand().ciphertextEnvelope
    });
    expect(entries["capability:v1:claim:op_create"]).toBeUndefined();

    expect(
      await claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_distinct",
        nonce: "nonce_distinct",
        now: 2_001
      })
    ).toMatchObject({ ok: true, outcome: "released" });

    entries = storage.entries();
    expect(entries["capability:v1:outbox:op_create"]).toEqual(activationBefore);
    expect(entries["capability:v1:outbox:op_distinct"]).toMatchObject({
      event: { type: "capability_consumption_committed", eventId: "op_distinct" },
      status: "pending"
    });
  });

  it("does not release expired capabilities", async () => {
    const storage = new MemoryDurableObjectStorage();
    expect(
      await createCapability(storage, {
        ...baseCommand(),
        policy: { ...policy, expiresAt: 1_500 }
      })
    ).toEqual({ ok: true });

    expect(
      await claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_expired",
        nonce: "nonce_expired",
        now: 1_500
      })
    ).toEqual({ ok: false, code: "unavailable" });
  });

  it("returns malformed_state for corrupted authoritative state", async () => {
    const storage = new MemoryDurableObjectStorage();
    await storage.put("capability:v1:record", { schemaVersion: 1, lifecycle: { state: "ACTIVE" } });

    expect(
      await claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_bad",
        nonce: "nonce_bad",
        now: 2_000
      })
    ).toEqual({ ok: false, code: "malformed_state" });
  });

  it("serializes concurrent claims so at most one payload is released", async () => {
    const storage = await populatedStorage();
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        claimCapability(storage, {
          publicBearerSecret: PUBLIC_BEARER,
          operationId: `op_concurrent_${index}`,
          nonce: `nonce_concurrent_${index}`,
          now: 2_000 + index
        })
      )
    );

    expect(results.filter((result) => result.ok && result.outcome === "released")).toHaveLength(1);
    expect(
      Object.keys(storage.entries()).filter((key) =>
        key.startsWith("capability:v1:outbox:op_concurrent_")
      )
    ).toHaveLength(1);
  });

  it("does not expose a passive method path that can consume", async () => {
    const source = await readFile(
      fileURLToPath(new URL("./capability-durable-object.ts", import.meta.url).href),
      "utf8"
    );

    expect(source).toContain('request.method !== "POST"');
    expect(source).not.toContain('request.method === "GET"');
    expect(source).not.toContain('request.method === "HEAD"');
  });

  it("enforces the exact per-capability passive rolling window after authorization", async () => {
    const storage = await populatedStorage();
    for (let attempt = 0; attempt < 60; attempt += 1) {
      await expect(
        authorizeCapability(storage, {
          authority: "public",
          bearerSecret: PUBLIC_BEARER,
          now: 1_000
        })
      ).resolves.toMatchObject({ ok: true });
    }
    await expect(
      authorizeCapability(storage, {
        authority: "public",
        bearerSecret: PUBLIC_BEARER,
        now: 1_000
      })
    ).resolves.toEqual({ ok: false, code: "rate_limited", retryAfter: 60 });
    await expect(
      authorizeCapability(storage, {
        authority: "public",
        bearerSecret: PUBLIC_BEARER,
        now: 61_000
      })
    ).resolves.toMatchObject({ ok: true });

    const unauthorizedStorage = await populatedStorage();
    for (let attempt = 0; attempt < 70; attempt += 1) {
      await expect(
        authorizeCapability(unauthorizedStorage, {
          authority: "public",
          bearerSecret: OTHER_PUBLIC_BEARER,
          now: 1_000
        })
      ).resolves.toEqual({ ok: false, code: "unauthorized" });
    }
    expect(unauthorizedStorage.entries()["capability:v1:rate:passive"]).toBeUndefined();
  });

  it("enforces the exact per-capability reveal rolling window without reopening content", async () => {
    const storage = await populatedStorage();
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const result = await claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: `op_reveal_quota_${attempt}`,
        nonce: `nonce_reveal_quota_${attempt}`,
        now: 2_000
      });
      expect(result.ok).toBe(attempt === 0);
    }
    await expect(
      claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_reveal_quota_limited",
        nonce: "nonce_reveal_quota_limited",
        now: 2_000
      })
    ).resolves.toEqual({ ok: false, code: "rate_limited", retryAfter: 60 });
  });

  it("serializes concurrent reveal quotas and access-code failures", async () => {
    const revealStorage = await populatedStorage();
    const revealResults = await Promise.all(
      Array.from({ length: 12 }, (_, attempt) =>
        claimCapability(revealStorage, {
          publicBearerSecret: PUBLIC_BEARER,
          operationId: `op_concurrent_quota_${attempt}`,
          nonce: `nonce_concurrent_quota_${attempt}`,
          now: 2_000
        })
      )
    );
    expect(revealResults.filter((result) => result.ok)).toHaveLength(1);
    expect(
      revealResults.filter((result) => !result.ok && result.code === "rate_limited")
    ).toHaveLength(2);

    const accessStorage = new MemoryDurableObjectStorage();
    expect(
      await createCapability(accessStorage, {
        ...baseCommand(),
        accessCodeVerifier: await accessCodeVerifier("correct horse")
      })
    ).toEqual({ ok: true });
    await Promise.all(
      Array.from({ length: 20 }, (_, attempt) =>
        claimCapability(accessStorage, {
          publicBearerSecret: PUBLIC_BEARER,
          operationId: `op_concurrent_wrong_${attempt}`,
          nonce: `nonce_concurrent_wrong_${attempt}`,
          accessCode: "wrong",
          challengeVerified: true,
          now: 2_000
        })
      )
    );
    expect(accessStorage.entries()["capability:v1:access-code"]).toMatchObject({
      failureCount: 4,
      challengeRequired: true,
      backoffUntil: 32_000
    });
    expect(accessStorage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "ACTIVE", committedConsumptions: 0 }
    });
  });

  it("applies access-code challenge, backoff, protective lock, and privileged release atomically", async () => {
    const verifier = await accessCodeVerifier("correct horse");
    const storage = new MemoryDurableObjectStorage();
    expect(
      await createCapability(storage, { ...baseCommand(), accessCodeVerifier: verifier })
    ).toEqual({ ok: true });
    await expect(
      authorizeCapability(storage, {
        authority: "public",
        bearerSecret: PUBLIC_BEARER,
        now: 1_500
      })
    ).resolves.toMatchObject({ ok: true, capability: { accessCodeRequired: true } });

    const wrongAttempt = (failure: number, now: number, challengeVerified = true) =>
      claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: `op_wrong_${failure}`,
        nonce: `nonce_wrong_${failure}`,
        accessCode: "wrong",
        challengeVerified,
        now
      });
    await expect(wrongAttempt(1, 2_000)).resolves.toEqual({
      ok: false,
      code: "verification_failed"
    });
    await expect(wrongAttempt(2, 2_001)).resolves.toEqual({
      ok: false,
      code: "verification_failed"
    });
    await expect(wrongAttempt(3, 2_002)).resolves.toEqual({
      ok: false,
      code: "verification_failed"
    });
    await expect(wrongAttempt(4, 2_003, false)).resolves.toEqual({
      ok: false,
      code: "challenge_required"
    });
    expect(storage.entries()["capability:v1:access-code"]).toMatchObject({ failureCount: 3 });

    await expect(wrongAttempt(4, 2_003)).resolves.toEqual({
      ok: false,
      code: "rate_limited",
      retryAfter: 30
    });
    await expect(wrongAttempt(5, 3_003)).resolves.toEqual({
      ok: false,
      code: "rate_limited",
      retryAfter: 29
    });
    expect(storage.entries()["capability:v1:access-code"]).toMatchObject({ failureCount: 4 });

    await expect(wrongAttempt(5, 32_003)).resolves.toMatchObject({
      ok: false,
      code: "rate_limited",
      retryAfter: 120
    });
    await expect(wrongAttempt(6, 152_003)).resolves.toMatchObject({ retryAfter: 600 });
    await expect(wrongAttempt(7, 752_003)).resolves.toMatchObject({ retryAfter: 3_600 });
    await expect(wrongAttempt(8, 4_352_003)).resolves.toMatchObject({ retryAfter: 3_600 });
    await expect(wrongAttempt(9, 7_952_003)).resolves.toMatchObject({ retryAfter: 3_600 });
    await expect(wrongAttempt(10, 11_552_003)).resolves.toEqual({
      ok: false,
      code: "unavailable"
    });
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "ABUSE_LOCKED", committedConsumptions: 0 },
      ciphertextEnvelope: baseCommand().ciphertextEnvelope
    });
    expect(storage.entries()["capability:v1:outbox:op_wrong_10"]).toMatchObject({
      event: { type: "capability_abuse_locked", toState: "ABUSE_LOCKED" }
    });
    expect(storage.entries()["capability:v1:access-code"]).toMatchObject({
      failureCount: 10,
      challengeRequired: true,
      backoffUntil: null,
      deleteAt: 270_752_003
    });

    const revealQuotaBeforeDecision = structuredClone(
      storage.entries()["capability:v1:rate:reveal"]
    );
    await expect(
      decideAbuseLock(storage, {
        operationId: "op_release_lock",
        privilegedDecisionId: "decision_release_lock",
        decision: "release",
        now: 11_552_004
      })
    ).resolves.toEqual({ ok: true });
    expect(storage.entries()["capability:v1:rate:reveal"]).toEqual(revealQuotaBeforeDecision);
    expect(storage.entries()["capability:v1:access-code"]).toEqual({
      schemaVersion: 1,
      failureCount: 0,
      challengeRequired: false,
      backoffUntil: null,
      deleteAt: null
    });
    await maintainCapability(storage, 270_752_003);
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "ACTIVE" },
      ciphertextEnvelope: baseCommand().ciphertextEnvelope
    });
    await expect(
      claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_after_release",
        nonce: "nonce_after_release",
        accessCode: "correct horse",
        now: 270_752_004
      })
    ).resolves.toMatchObject({ ok: true, outcome: "released" });
    expect(storage.entries()["capability:v1:access-code"]).toEqual({
      schemaVersion: 1,
      failureCount: 0,
      challengeRequired: false,
      backoffUntil: null,
      deleteAt: null
    });
  });

  it("does not increment access-code failures when the exact capability limiter rejects", async () => {
    const storage = new MemoryDurableObjectStorage();
    expect(
      await createCapability(storage, {
        ...baseCommand(),
        accessCodeVerifier: await accessCodeVerifier("correct horse")
      })
    ).toEqual({ ok: true });
    await storage.put("capability:v1:rate:reveal", {
      schemaVersion: 1,
      attempts: Array.from({ length: 10 }, (_, index) => 1_000 + index)
    });

    await expect(
      claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_limited_wrong_code",
        nonce: "nonce_limited_wrong_code",
        accessCode: "wrong",
        challengeVerified: true,
        now: 2_000
      })
    ).resolves.toEqual({ ok: false, code: "rate_limited", retryAfter: 59 });
    expect(storage.entries()["capability:v1:access-code"]).toBeUndefined();
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "ACTIVE", committedConsumptions: 0 }
    });
  });

  it.each([
    [
      "early challenge",
      { failureCount: 2, challengeRequired: true, backoffUntil: null, deleteAt: null }
    ],
    [
      "missing challenge",
      { failureCount: 3, challengeRequired: false, backoffUntil: null, deleteAt: null }
    ],
    [
      "early backoff",
      { failureCount: 3, challengeRequired: true, backoffUntil: 10, deleteAt: null }
    ],
    [
      "missing backoff",
      { failureCount: 4, challengeRequired: true, backoffUntil: null, deleteAt: null }
    ],
    [
      "unexpected deadline",
      { failureCount: 9, challengeRequired: true, backoffUntil: 10, deleteAt: 20 }
    ],
    [
      "missing deadline",
      { failureCount: 10, challengeRequired: true, backoffUntil: null, deleteAt: null }
    ],
    ["lock backoff", { failureCount: 10, challengeRequired: true, backoffUntil: 10, deleteAt: 20 }],
    [
      "non-positive deadline",
      { failureCount: 10, challengeRequired: true, backoffUntil: null, deleteAt: 0 }
    ]
  ] as const)("fails closed for malformed persisted access state: %s", async (_name, state) => {
    const storage = new MemoryDurableObjectStorage();
    expect(
      await createCapability(storage, {
        ...baseCommand(),
        accessCodeVerifier: await accessCodeVerifier("correct horse")
      })
    ).toEqual({ ok: true });
    await storage.put("capability:v1:access-code", { schemaVersion: 1, ...state });

    await expect(
      claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_malformed_access",
        nonce: "nonce_malformed_access",
        accessCode: "correct horse",
        challengeVerified: true,
        now: 30
      })
    ).resolves.toEqual({ ok: false, code: "malformed_state" });
    expect(storage.entries()["capability:v1:rate:reveal"]).toBeUndefined();
  });

  it("fails closed when access-code lock state and lifecycle disagree", async () => {
    const storage = new MemoryDurableObjectStorage();
    expect(
      await createCapability(storage, {
        ...baseCommand(),
        accessCodeVerifier: await accessCodeVerifier("correct horse")
      })
    ).toEqual({ ok: true });
    await storage.put("capability:v1:access-code", {
      schemaVersion: 1,
      failureCount: 10,
      challengeRequired: true,
      backoffUntil: null,
      deleteAt: 72_000
    });

    await expect(
      decideAbuseLock(storage, {
        operationId: "op_malformed_release",
        privilegedDecisionId: "decision_malformed_release",
        decision: "release",
        now: 40
      })
    ).resolves.toEqual({ ok: false, code: "malformed_state" });
  });

  it.each([
    ["empty public bearer hash", { publicBearerSecretHash: "" }],
    ["empty owner bearer hash", { ownerBearerSecretHash: "" }],
    ["identical public and owner bearer hashes", { ownerBearerSecretHash: PUBLIC_HASH }],
    ["empty operation ID", { operationId: "" }],
    ["blank policy hash", { policyHash: "   " }],
    ["oversized operation ID", { operationId: "x".repeat(513) }],
    ["invalid creation timestamp", { createdAt: "2026-07-13T00:00:00Z" }],
    ["invalid epoch milliseconds", { now: -1 }]
  ] as const)("rejects a create command with %s", async (_name, override) => {
    const storage = new MemoryDurableObjectStorage();

    expect(await createCapability(storage, { ...baseCommand(), ...override })).toEqual({
      ok: false,
      code: "invalid_command"
    });
    expect(storage.entries()).toEqual({});
  });

  it("rejects non-object create commands", async () => {
    const storage = new MemoryDurableObjectStorage();

    expect(await createCapability(storage, null)).toEqual({
      ok: false,
      code: "invalid_command"
    });
    expect(await createCapability(storage, [])).toEqual({
      ok: false,
      code: "invalid_command"
    });
    expect(storage.entries()).toEqual({});
  });

  it.each([
    ["empty public bearer", { publicBearerSecret: "" }],
    ["empty operation ID", { operationId: "" }],
    ["empty nonce", { nonce: "" }],
    ["oversized nonce", { nonce: "x".repeat(513) }],
    ["invalid epoch milliseconds", { now: 1.5 }]
  ] as const)("rejects a claim command with %s", async (_name, override) => {
    const storage = await populatedStorage();
    const beforeClaim = structuredClone(storage.entries());

    expect(
      await claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_invalid",
        nonce: "nonce_invalid",
        now: 2_000,
        ...override
      })
    ).toEqual({ ok: false, code: "invalid_command" });
    expect(storage.entries()).toEqual(beforeClaim);
  });

  it("bounds and validates the stored Phase 1A ciphertext envelope", async () => {
    const storage = new MemoryDurableObjectStorage();
    expect(
      await createCapability(storage, {
        ...baseCommand(),
        ciphertextEnvelope: {
          ...(baseCommand().ciphertextEnvelope as Record<string, unknown>),
          nonce: "not padded=="
        }
      })
    ).toEqual({ ok: false, code: "invalid_ciphertext" });
  });

  it("rejects non-canonical base64url pad-bit aliases", async () => {
    const storage = new MemoryDurableObjectStorage();
    expect(
      await createCapability(storage, {
        ...baseCommand(),
        ciphertextEnvelope: {
          ...(baseCommand().ciphertextEnvelope as Record<string, unknown>),
          ciphertext: "AAAAAAAAAAAAAAAAAAAAAAB"
        }
      })
    ).toEqual({ ok: false, code: "invalid_ciphertext" });
  });

  it("rejects an envelope with non-protocol associated-data keys", async () => {
    const storage = new MemoryDurableObjectStorage();
    const envelope = baseCommand().ciphertextEnvelope as Record<string, unknown>;

    expect(
      await createCapability(storage, {
        ...baseCommand(),
        ciphertextEnvelope: {
          ...envelope,
          ad: {
            ...(envelope.ad as Record<string, unknown>),
            unexpected: "not-canonical"
          }
        }
      })
    ).toEqual({ ok: false, code: "invalid_ciphertext" });
  });

  it("fails closed without consuming when stored envelope metadata is corrupted", async () => {
    const storage = await populatedStorage();
    const recordKey = "capability:v1:record";
    const record = storage.entries()[recordKey] as Record<string, unknown>;
    const envelope = record.ciphertextEnvelope as Record<string, unknown>;
    const associatedData = envelope.ad as Record<string, unknown>;
    await storage.put(recordKey, {
      ...record,
      ciphertextEnvelope: {
        ...envelope,
        ad: { ...associatedData, policyHash: "tampered_policy_hash" }
      }
    });

    expect(
      await claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_corrupt",
        nonce: "nonce_corrupt",
        now: 2_000
      })
    ).toEqual({ ok: false, code: "malformed_state" });

    const entries = storage.entries();
    expect(entries[recordKey]).toMatchObject({
      lifecycle: { state: "ACTIVE", committedConsumptions: 0 }
    });
    expect(entries["capability:v1:outbox:op_corrupt"]).toBeUndefined();
    expect(entries["capability:v1:claim:op_corrupt"]).toBeUndefined();
  });

  it("rejects unknown persisted lifecycle states", async () => {
    await expectMalformedPersistedRecord((record) => ({
      ...record,
      lifecycle: { state: "BROKEN", committedConsumptions: 0 }
    }));
  });

  it.each([-1, 1.5, Number.MAX_SAFE_INTEGER + 1])(
    "rejects invalid persisted consumption count %s",
    async (committedConsumptions) => {
      await expectMalformedPersistedRecord((record) => ({
        ...record,
        lifecycle: { state: "ACTIVE", committedConsumptions }
      }));
    }
  );

  it("rejects malformed persisted policies", async () => {
    await expectMalformedPersistedRecord((record) => ({
      ...record,
      policy: { kind: "secret" }
    }));
  });

  it("rejects the wrong persisted capability kind", async () => {
    await expectMalformedPersistedRecord((record) => ({
      ...record,
      policy: {
        ...policy,
        kind: "file_download"
      }
    }));
  });

  it.each(["capabilityId", "locator", "policyHash", "publicBearerSecretHash"] as const)(
    "rejects an empty persisted %s",
    async (field) => {
      await expectMalformedPersistedRecord((record) => ({ ...record, [field]: "" }));
    }
  );

  it("rejects missing and identical persisted authority hashes", async () => {
    await expectMalformedPersistedRecord((record) => {
      const withoutCapabilityId = { ...record };
      delete withoutCapabilityId.capabilityId;
      return withoutCapabilityId;
    });
    await expectMalformedPersistedRecord((record) => {
      const withoutOwnerHash = { ...record };
      delete withoutOwnerHash.ownerBearerSecretHash;
      return withoutOwnerHash;
    });
    await expectMalformedPersistedRecord((record) => ({
      ...record,
      ownerBearerSecretHash: record.publicBearerSecretHash
    }));
  });

  it("rejects invalid persisted creation timestamps", async () => {
    await expectMalformedPersistedRecord((record) => ({
      ...record,
      createdAt: "2026-07-13T00:00:00Z"
    }));
  });

  it("rejects internally inconsistent lifecycle and payload state", async () => {
    await expectMalformedPersistedRecord((record) => ({
      ...record,
      lifecycle: { state: "ACTIVE", committedConsumptions: 0 },
      ciphertextEnvelope: null
    }));
  });

  it("rejects unsupported persisted schema versions", async () => {
    await expectMalformedPersistedRecord((record) => ({ ...record, schemaVersion: 4 }));
  });
});

describe("Capability Durable Object delivery and deadlines", () => {
  it("submits only after commit and keeps authoritative state when Queue submission fails", async () => {
    const storage = new MemoryDurableObjectStorage();
    await expect(createCapability(storage, baseCommand())).resolves.toEqual({ ok: true });
    const recordBefore = structuredClone(storage.entries()["capability:v1:record"]);

    const summary = await deliverPendingOutbox(
      storage,
      {
        send: () => Promise.reject(new Error("injected Queue outage"))
      },
      1_000
    );

    expect(summary).toEqual({
      selected: 1,
      submitted: 0,
      failed: 1,
      pendingAgeBucket: "under_1m",
      retryStateBucket: "initial"
    });
    expect(storage.entries()["capability:v1:record"]).toEqual(recordBefore);
    expect(storage.entries()["capability:v1:outbox:op_create"]).toMatchObject({
      status: "pending",
      attemptCount: 1,
      lastAttemptedAt: 1_000,
      nextAttemptAt: 6_000
    });
  });

  it("redrives pending delivery without copying payload or authority material", async () => {
    const storage = await populatedStorage();
    const messages: unknown[] = [];
    const publisher = {
      send(message: unknown) {
        messages.push(message);
        return Promise.resolve();
      }
    };
    await deliverPendingOutbox(storage, publisher, 1_000);
    await deliverPendingOutbox(storage, publisher, 6_000);

    expect(messages).toHaveLength(2);
    const serialized = JSON.stringify(messages);
    expect(serialized).not.toContain("ciphertext");
    expect(serialized).not.toContain(PUBLIC_BEARER);
    expect(serialized).not.toContain(OWNER_BEARER);
    expect(serialized).not.toContain(PUBLIC_HASH);
    expect(serialized).not.toContain(OWNER_HASH);
    expect(serialized).not.toContain("accessCode");
  });

  it.each([
    ["current", false],
    ["legacy", true]
  ] as const)(
    "projects and acknowledges each pending %s outbox as its own committed fact",
    async (_schema, legacy) => {
      const storage = await populatedStorage();
      await claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_consume_before_delivery",
        nonce: "nonce_consume_before_delivery",
        now: 2_000
      });
      if (legacy) {
        for (const eventId of ["op_create", "op_consume_before_delivery"]) {
          const key = `capability:v1:outbox:${eventId}`;
          const stored = storage.entries()[key] as Record<string, unknown>;
          await storage.put(key, {
            schemaVersion: 1,
            eventId: stored.eventId,
            event: stored.event,
            pending: true,
            recordedAt: stored.recordedAt
          });
        }
      }

      const messages: CapabilityProjectionMessage[] = [];
      await deliverPendingOutbox(
        storage,
        {
          send(message) {
            messages.push(message);
            return Promise.resolve();
          }
        },
        2_000
      );

      expect(messages).toHaveLength(2);
      expect(messages[0]).toMatchObject({
        deliveryEventId: "op_create",
        event: { eventId: "op_create", type: "capability_activated", toState: "ACTIVE" },
        projection: { state: "ACTIVE", version: 1, updatedAt: 1_000 }
      });
      expect(messages[1]).toMatchObject({
        deliveryEventId: "op_consume_before_delivery",
        event: {
          eventId: "op_consume_before_delivery",
          type: "capability_consumption_committed",
          toState: "CONSUMED"
        },
        projection: { state: "CONSUMED", version: 2, updatedAt: 2_000 }
      });
      expect(
        parseCapabilityProjectionMessage({ ...messages[0], deliveryEventId: "different_event" })
      ).toBeNull();

      await expect(
        acknowledgeOutboxDelivery(storage, {
          eventId: "op_create",
          projectionVersion: 2,
          now: 2_100
        })
      ).resolves.toEqual({ ok: false, code: "malformed_state" });
      expect(storage.entries()["capability:v1:outbox:op_create"]).toMatchObject({
        status: "pending"
      });
      await acknowledgeOutboxDelivery(storage, {
        eventId: "op_create",
        projectionVersion: 1,
        now: 2_100
      });
      expect(storage.entries()["capability:v1:outbox:op_create"]).toMatchObject({
        status: "delivered"
      });
      expect(storage.entries()["capability:v1:outbox:op_consume_before_delivery"]).toMatchObject({
        status: "pending"
      });
    }
  );

  it("never restores consumed ciphertext when Queue delivery fails", async () => {
    const storage = await populatedStorage();
    await claimCapability(storage, {
      publicBearerSecret: PUBLIC_BEARER,
      operationId: "op_consume_queue_failure",
      nonce: "nonce_consume_queue_failure",
      now: 2_000
    });

    await deliverPendingOutbox(
      storage,
      { send: () => Promise.reject(new Error("injected Queue outage")) },
      2_000
    );

    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "CONSUMED", committedConsumptions: 1 },
      ciphertextEnvelope: null
    });
  });

  it("normalizes a genuine schema-v2 consumed record from its retained legacy outbox", async () => {
    const storage = await populatedStorage();
    const consumedAt = 1_000 + 2 * DAY_MS;
    await claimCapability(storage, {
      publicBearerSecret: PUBLIC_BEARER,
      operationId: "op_legacy_consume_reconcile",
      nonce: "nonce_legacy_consume_reconcile",
      now: consumedAt
    });
    await rewriteAsLegacySchema2(storage);

    await expect(
      reconcileCapability(storage, { now: consumedAt + DAY_MS + 1 })
    ).resolves.toMatchObject({
      ok: true,
      message: {
        deliveryEventId: null,
        event: {
          eventId: "op_legacy_consume_reconcile",
          type: "capability_consumption_committed",
          occurredAt: consumedAt,
          toState: "CONSUMED"
        },
        projection: {
          state: "CONSUMED",
          version: 2,
          updatedAt: consumedAt,
          consumedAt
        }
      }
    });
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      schemaVersion: 3,
      lifecycle: { state: "CONSUMED", committedConsumptions: 1 },
      projectionVersion: 2,
      lastTransition: {
        eventId: "op_legacy_consume_reconcile",
        occurredAt: consumedAt,
        toState: "CONSUMED"
      }
    });
  });

  it("fails legacy current-state reconciliation closed without an exact lifecycle outbox", async () => {
    const storage = await populatedStorage();
    await claimCapability(storage, {
      publicBearerSecret: PUBLIC_BEARER,
      operationId: "op_legacy_consume_missing",
      nonce: "nonce_legacy_consume_missing",
      now: 2_000
    });
    await rewriteAsLegacySchema2(storage);
    await storage.delete("capability:v1:outbox:op_legacy_consume_missing");

    await expect(reconcileCapability(storage, { now: 3_000 })).resolves.toEqual({
      ok: false,
      code: "malformed_state"
    });
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      schemaVersion: 2,
      lifecycle: { state: "CONSUMED" }
    });
  });

  it("normalizes a genuine schema-v2 protective lock from its retained legacy outbox", async () => {
    const lockedAt = 2_000;
    const deleteAt = lockedAt + 72 * 60 * 60 * 1_000;
    const storage = await lockedStorage(deleteAt);
    await storage.put("capability:v1:outbox:op_protective_lock", {
      schemaVersion: 1,
      eventId: "op_protective_lock",
      event: {
        type: "capability_abuse_locked",
        eventId: "op_protective_lock",
        occurredAt: lockedAt,
        fromState: "ACTIVE",
        toState: "ABUSE_LOCKED"
      },
      pending: true,
      recordedAt: lockedAt
    });
    await rewriteAsLegacySchema2(storage);

    await expect(reconcileCapability(storage, { now: 3_000 })).resolves.toMatchObject({
      ok: true,
      message: {
        event: {
          eventId: "op_protective_lock",
          type: "capability_abuse_locked",
          occurredAt: lockedAt,
          toState: "ABUSE_LOCKED"
        },
        projection: {
          state: "ABUSE_LOCKED",
          version: 2,
          updatedAt: lockedAt,
          automaticDeleteAt: deleteAt
        }
      }
    });
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      schemaVersion: 3,
      projectionVersion: 2,
      lastTransition: {
        eventId: "op_protective_lock",
        occurredAt: lockedAt,
        toState: "ABUSE_LOCKED"
      }
    });
  });

  it.each([
    ["release", "ACTIVE"],
    ["disable", "DISABLED"]
  ] as const)(
    "derives monotonic legacy versions through a protective-lock %s decision",
    async (decision, state) => {
      const storage = await legacyProtectedDecisionStorage(decision);
      const messages: CapabilityProjectionMessage[] = [];

      await deliverPendingOutbox(
        storage,
        {
          send(message) {
            messages.push(message);
            return Promise.resolve();
          }
        },
        3_000
      );

      expect(
        messages.map((message) => ({
          eventId: message.event.eventId,
          state: message.projection.state,
          version: message.projection.version
        }))
      ).toEqual([
        { eventId: "op_create", state: "ACTIVE", version: 1 },
        { eventId: "op_protective_lock", state: "ABUSE_LOCKED", version: 2 },
        { eventId: `op_legacy_${decision}`, state, version: 3 }
      ]);
      await expect(reconcileCapability(storage, { now: 3_001 })).resolves.toMatchObject({
        ok: true,
        message: {
          event: { eventId: `op_legacy_${decision}`, toState: state },
          projection: { state, version: 3, updatedAt: 3_000 }
        }
      });
      expect(storage.entries()["capability:v1:record"]).toMatchObject({
        schemaVersion: 3,
        lifecycle: { state },
        projectionVersion: 3,
        lastTransition: { eventId: `op_legacy_${decision}`, toState: state }
      });
    }
  );

  it("repairs an already-upgraded legacy history with duplicate retained versions", async () => {
    const storage = await legacyProtectedDecisionStorage("release");
    await deliverPendingOutbox(storage, { send: () => Promise.resolve() }, 3_000);

    const recordKey = "capability:v1:record";
    const record = storage.entries()[recordKey] as Record<string, unknown>;
    await storage.put(recordKey, { ...record, projectionVersion: 2 });
    const releaseKey = "capability:v1:outbox:op_legacy_release";
    const release = storage.entries()[releaseKey] as Record<string, unknown>;
    await storage.put(releaseKey, { ...release, projectionVersion: 2 });

    await expect(reconcileCapability(storage, { now: 3_001 })).resolves.toMatchObject({
      ok: true,
      message: {
        event: { eventId: "op_legacy_release", toState: "ACTIVE" },
        projection: { state: "ACTIVE", version: 3, updatedAt: 3_000 }
      }
    });
    expect(storage.entries()[recordKey]).toMatchObject({
      schemaVersion: 3,
      projectionVersion: 3,
      lastTransition: { eventId: "op_legacy_release", toState: "ACTIVE" }
    });
    expect(storage.entries()[releaseKey]).toMatchObject({ projectionVersion: 3 });
  });

  it("continues a normalized legacy release history with consume version 4", async () => {
    const storage = await legacyProtectedDecisionStorage("release");

    await expect(
      claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_consume_after_legacy_release",
        nonce: "nonce_consume_after_legacy_release",
        accessCode: "correct horse",
        now: 4_000
      })
    ).resolves.toMatchObject({ ok: true, outcome: "released" });

    const messages: CapabilityProjectionMessage[] = [];
    await deliverPendingOutbox(
      storage,
      {
        send(message) {
          messages.push(message);
          return Promise.resolve();
        }
      },
      4_000
    );
    expect(messages.map((message) => message.projection.version)).toEqual([1, 2, 3, 4]);
    expect(messages.at(-1)).toMatchObject({
      event: { eventId: "op_consume_after_legacy_release", toState: "CONSUMED" },
      projection: { state: "CONSUMED", version: 4, consumedAt: 4_000 }
    });
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      schemaVersion: 3,
      lifecycle: { state: "CONSUMED", committedConsumptions: 1 },
      projectionVersion: 4
    });
  });

  it("fails an ambiguous equal-time legacy transition history closed", async () => {
    const storage = await legacyProtectedDecisionStorage("release");
    const releaseKey = "capability:v1:outbox:op_legacy_release";
    const release = structuredClone(storage.entries()[releaseKey]) as Record<string, unknown>;
    const event = release.event as Record<string, unknown>;
    await storage.put(releaseKey, {
      ...release,
      event: { ...event, occurredAt: 2_000 },
      recordedAt: 2_000
    });

    await expect(
      deliverPendingOutbox(storage, { send: () => Promise.resolve() }, 3_000)
    ).rejects.toThrow("Malformed capability projection history");
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      schemaVersion: 2,
      lifecycle: { state: "ACTIVE" }
    });
  });

  it("keeps the earliest alarm across outbox, expiry, and retention duties", async () => {
    const storage = new MemoryDurableObjectStorage();
    await createCapability(storage, {
      ...baseCommand(),
      policy: { ...policy, expiresAt: 5_000 }
    });
    expect(storage.alarmTime()).toBe(1_000);

    await deliverPendingOutbox(storage, { send: () => Promise.resolve() }, 1_000);
    expect(storage.alarmTime()).toBe(5_000);

    await acknowledgeOutboxDelivery(storage, {
      eventId: "op_create",
      projectionVersion: 1,
      now: 1_100
    });
    expect(storage.alarmTime()).toBe(5_000);
  });

  it("expires exactly at the policy boundary and cleanup is idempotent", async () => {
    const storage = new MemoryDurableObjectStorage();
    await createCapability(storage, {
      ...baseCommand(),
      policy: { ...policy, expiresAt: 5_000 }
    });
    await expect(
      claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_at_expiry",
        nonce: "nonce_at_expiry",
        now: 5_000
      })
    ).resolves.toEqual({ ok: false, code: "unavailable" });

    await maintainCapability(storage, 5_000);
    const afterFirst = structuredClone(storage.entries());
    await maintainCapability(storage, 5_000);

    expect(storage.entries()).toEqual(afterFirst);
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "EXPIRED", committedConsumptions: 0 },
      ciphertextEnvelope: null
    });
  });

  it("destroys ciphertext in the owner-delete transaction", async () => {
    const storage = await populatedStorage();

    await expect(
      deleteCapability(storage, {
        ownerBearerSecret: OWNER_BEARER,
        operationId: "op_owner_delete",
        now: 2_000
      })
    ).resolves.toEqual({ ok: true });

    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "DELETED" },
      ciphertextEnvelope: null
    });
    expect(storage.entries()["capability:v1:outbox:op_owner_delete"]).toMatchObject({
      status: "pending",
      event: { type: "capability_deleted" }
    });
  });

  it("prunes delivered outbox state after seven days and unresolved state by thirty days", async () => {
    const delivered = await populatedStorage();
    await acknowledgeOutboxDelivery(delivered, {
      eventId: "op_create",
      projectionVersion: 1,
      now: 2_000
    });
    await maintainCapability(delivered, 2_000 + 7 * 24 * 60 * 60 * 1_000);
    expect(delivered.entries()["capability:v1:outbox:op_create"]).toBeUndefined();

    const unresolved = await populatedStorage();
    await markOutboxDeadLetter(unresolved, { eventId: "op_create", now: 2_000 });
    expect(unresolved.entries()["capability:v1:outbox:op_create"]).toMatchObject({
      status: "unresolved"
    });
    await maintainCapability(unresolved, 1_000 + 30 * 24 * 60 * 60 * 1_000);
    expect(unresolved.entries()["capability:v1:outbox:op_create"]).toBeUndefined();
  });

  it("automatically deletes an unresolved protective lock at its persisted deadline", async () => {
    const storage = new MemoryDurableObjectStorage();
    await createCapability(storage, {
      ...baseCommand(),
      accessCodeVerifier: await accessCodeVerifier("correct horse")
    });
    const record = structuredClone(storage.entries()["capability:v1:record"]) as Record<
      string,
      unknown
    >;
    await storage.put("capability:v1:record", {
      ...record,
      lifecycle: { state: "ABUSE_LOCKED", committedConsumptions: 0 },
      projectionVersion: 2,
      lastTransition: {
        eventId: "op_protective_lock",
        type: "capability_abuse_locked",
        occurredAt: 2_000,
        fromState: "ACTIVE",
        toState: "ABUSE_LOCKED"
      }
    });
    await storage.put("capability:v1:access-code", {
      schemaVersion: 1,
      failureCount: 10,
      challengeRequired: true,
      backoffUntil: null,
      deleteAt: 3_000
    });

    await maintainCapability(storage, 3_000);

    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "DELETED" },
      ciphertextEnvelope: null
    });
    expect(storage.entries()["capability:v1:outbox:automatic-delete:3000"]).toMatchObject({
      event: { type: "capability_abuse_lock_decided", decision: "delete" }
    });
  });

  it.each([
    ["release immediately before", "release", 2_999, true],
    ["release exactly at", "release", 3_000, false],
    ["disable exactly at", "disable", 3_000, false],
    ["release after", "release", 3_001, false]
  ] as const)(
    "%s the protective-lock deadline gives automatic deletion precedence",
    async (_boundary, decision, now, decisionAllowed) => {
      const storage = await lockedStorage();
      const operationId = `op_deadline_${decision}_${now}`;

      await expect(
        decideAbuseLock(storage, {
          operationId,
          privilegedDecisionId: `decision_deadline_${decision}_${now}`,
          decision,
          now
        })
      ).resolves.toEqual(decisionAllowed ? { ok: true } : { ok: false, code: "unavailable" });

      expect(storage.entries()["capability:v1:record"]).toMatchObject({
        lifecycle: { state: decisionAllowed ? "ACTIVE" : "DELETED" },
        ...(decisionAllowed ? {} : { ciphertextEnvelope: null })
      });
      if (decisionAllowed) {
        expect(storage.entries()[`capability:v1:outbox:${operationId}`]).toMatchObject({
          event: { decision, toState: "ACTIVE" }
        });
        expect(storage.entries()["capability:v1:outbox:automatic-delete:3000"]).toBeUndefined();
      } else {
        expect(storage.entries()[`capability:v1:outbox:${operationId}`]).toBeUndefined();
        expect(storage.entries()["capability:v1:outbox:automatic-delete:3000"]).toMatchObject({
          event: { decision: "delete", toState: "DELETED" }
        });
      }
    }
  );

  it("sets the protective-lock deadline to the earlier original expiry", async () => {
    const storage = new MemoryDurableObjectStorage();
    await createCapability(storage, {
      ...baseCommand(),
      policy: { ...policy, expiresAt: 3_000 },
      accessCodeVerifier: await accessCodeVerifier("correct horse")
    });
    await storage.put("capability:v1:access-code", {
      schemaVersion: 1,
      failureCount: 9,
      challengeRequired: true,
      backoffUntil: 1_000,
      deleteAt: null
    });

    await expect(
      claimCapability(storage, {
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op_lock_at_expiry",
        nonce: "nonce_lock_at_expiry",
        accessCode: "wrong",
        challengeVerified: true,
        now: 2_000
      })
    ).resolves.toEqual({ ok: false, code: "unavailable" });

    expect(storage.entries()["capability:v1:access-code"]).toMatchObject({
      failureCount: 10,
      deleteAt: 3_000
    });
  });

  it("retains disabled ciphertext only until the original expiry", async () => {
    const storage = new MemoryDurableObjectStorage();
    await createCapability(storage, {
      ...baseCommand(),
      policy: { ...policy, expiresAt: 3_000 },
      accessCodeVerifier: await accessCodeVerifier("correct horse")
    });
    const record = structuredClone(storage.entries()["capability:v1:record"]) as Record<
      string,
      unknown
    >;
    await storage.put("capability:v1:record", {
      ...record,
      lifecycle: { state: "ABUSE_LOCKED", committedConsumptions: 0 },
      projectionVersion: 2,
      lastTransition: {
        eventId: "op_lock_before_disable",
        type: "capability_abuse_locked",
        occurredAt: 2_000,
        fromState: "ACTIVE",
        toState: "ABUSE_LOCKED"
      }
    });
    await storage.put("capability:v1:access-code", {
      schemaVersion: 1,
      failureCount: 10,
      challengeRequired: true,
      backoffUntil: null,
      deleteAt: 3_000
    });
    await decideAbuseLock(storage, {
      operationId: "op_disable_lock",
      privilegedDecisionId: "decision_disable_lock",
      decision: "disable",
      now: 2_500
    });

    await maintainCapability(storage, 2_999);
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "DISABLED" },
      ciphertextEnvelope: baseCommand().ciphertextEnvelope
    });
    await maintainCapability(storage, 3_000);
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "EXPIRED" },
      ciphertextEnvelope: null
    });
  });

  it("re-deletes restored ciphertext from retained terminal evidence idempotently", async () => {
    const storage = await populatedStorage();
    const command = {
      now: 3_000,
      terminalEvidence: {
        capabilityId: baseCommand().capabilityId,
        locator: LOCATOR,
        eventId: "event_pre_restore_consume",
        state: "CONSUMED",
        version: 2,
        occurredAt: 2_000
      }
    };

    await expect(reconcileCapability(storage, command)).resolves.toMatchObject({
      ok: true,
      message: { projection: { state: "DELETED", version: 3 } }
    });
    const afterFirst = structuredClone(storage.entries());
    await expect(reconcileCapability(storage, command)).resolves.toMatchObject({
      ok: true,
      message: { projection: { state: "DELETED", version: 3 } }
    });

    expect(storage.entries()).toEqual(afterFirst);
    expect(storage.entries()["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "DELETED" },
      ciphertextEnvelope: null
    });
  });
});
