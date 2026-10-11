import { env } from "cloudflare:workers";
import { applyD1Migrations, runInDurableObject } from "cloudflare:test";
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { createTestApp } from "./app";
import {
  administerCapability,
  createCapability,
  claimCapability,
  maintainCapability,
  prepareCapabilityReport,
  submitCapabilityReport
} from "./capability-durable-object-core";
import {
  cleanupAbuseRetention,
  projectSecurityRecords,
  securityRecordSchema,
  SECURITY_RECORD_PREFIX
} from "./abuse-records";
import { securityDigest } from "./admin-auth";
import {
  createChallengeTicket,
  markChallengeVerified,
  consumeChallengeTicket,
  consumeExactIpQuota,
  deriveIpDigests
} from "./abuse-control";
import type {
  CapabilityObjectStorage,
  CapabilityObjectTransaction
} from "./capability-durable-object-core";
import {
  consumeAdminCsrf,
  consumeReportNonce,
  executeSecurityTicket,
  issueAdminCsrf,
  issueReportNonce
} from "./security-tickets";
import {
  adminTestAssertion,
  adminTestEnv,
  ADMIN_TEST_JWKS,
  ADMIN_TEST_OPERATOR
} from "./testing/admin";
import { createCommand, runtimeEnv, requiredDatabase } from "./testing/capability-delivery-runtime";
import type { WorkerEnv } from "./env";

const PUBLIC_BEARER = "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const DAY = 86_400_000;
const LOCATOR = `loc1_${"7".repeat(48)}`;
const SECOND_LOCATOR = `loc1_${"8".repeat(48)}`;
const reportId = `rep1_${"A".repeat(43)}`;
function namespace() {
  const binding = env.CAPABILITY_STATE;
  if (binding === undefined) throw new Error();
  return binding;
}
function testEnv(): WorkerEnv {
  return {
    ...adminTestEnv(),
    CAPABILITY_STATE: namespace(),
    ABUSE_CONTROL: env.ABUSE_CONTROL,
    DB: requiredDatabase()
  };
}
function observeNamespace<T extends object>(namespace: T, getByName: unknown): T {
  return new Proxy(namespace, {
    get(target, key) {
      if (key === "getByName") return getByName;
      const value: unknown = Reflect.get(target, key, target);
      const bound: unknown = typeof value === "function" ? value.bind(target) : value;
      return bound;
    }
  });
}
function observeReportDependencies(
  configuration: WorkerEnv,
  unavailable?: "ip:" | "challenge:" | "challenge-consume"
) {
  const abuse = configuration.ABUSE_CONTROL;
  const capabilities = configuration.CAPABILITY_STATE;
  if (abuse === undefined || capabilities === undefined) throw new Error("Missing test bindings");
  const abuseObjects = vi.fn((name: string) => {
    if (unavailable !== undefined && name.startsWith(unavailable))
      throw new Error("Unavailable test dependency");
    const stub = abuse.getByName(name);
    if (unavailable === "challenge-consume" && name.startsWith("challenge:"))
      return {
        fetch: async (request: Request) => {
          if (new URL(request.url).pathname === "/internal/challenge/consume")
            throw new Error("Unavailable test challenge consumption");
          return stub.fetch(request);
        }
      } as DurableObjectStub;
    return stub;
  });
  const capabilityObjects = vi.fn((name: string) => capabilities.getByName(name));
  return {
    abuseObjects,
    capabilityObjects,
    configuration: {
      ...configuration,
      ABUSE_CONTROL: observeNamespace(abuse, abuseObjects),
      CAPABILITY_STATE: observeNamespace(capabilities, capabilityObjects)
    }
  };
}
async function reportNonceState(configuration: WorkerEnv, nonce: string) {
  const abuse = configuration.ABUSE_CONTROL;
  if (abuse === undefined) throw new Error("Missing test abuse binding");
  return state(
    abuse.getByName(`ticket:${await securityDigest("onceurl.security-ticket.v1", nonce)}`)
  );
}
async function verifiedReportChallenge(configuration: WorkerEnv, now: number) {
  const challenge = await createChallengeTicket(configuration, "onceurl_report_submit", now);
  expect(await markChallengeVerified(configuration, challenge, "onceurl_report_submit", now)).toBe(
    true
  );
  return challenge;
}
function mutation(action: "disable" | "abuse_lock" | "delete" | "release" = "disable") {
  return {
    locator: LOCATOR,
    operation_id: crypto.randomUUID(),
    action,
    reason: "phishing" as const,
    confirm_abuse: false
  };
}
async function objectRequest(stub: DurableObjectStub, path: string, body: unknown) {
  const response = await stub.fetch(`https://capability.invalid/internal/capability/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  return { response, body: await response.json() };
}
async function initialize(
  now = Date.now(),
  code = false,
  expiresAt?: number,
  options: { locator?: string; native?: boolean } = {}
) {
  const locator = options.locator ?? LOCATOR;
  const stub = namespace().getByName(locator);
  const command = createCommand(now);
  const capabilityId = `mis28_${crypto.randomUUID()}`;
  const created = {
    ...command,
    operationId: `mis28-create-${crypto.randomUUID()}`,
    capabilityId,
    locator,
    ...(expiresAt === undefined ? {} : { policy: { ...command.policy, expiresAt } }),
    ciphertextEnvelope: {
      ...command.ciphertextEnvelope,
      ad: { ...command.ciphertextEnvelope.ad, locator, capabilityId }
    },
    ...(code
      ? {
          accessCodeVerifier: {
            version: "acv1",
            algorithm: "PBKDF2-SHA-256",
            iterations: 210000,
            salt: "AAAAAAAAAAAAAAAAAAAAAA",
            digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          }
        }
      : {})
  };
  const result = options.native
    ? await runInDurableObject(stub, async (_instance, context) =>
        createCapability(context.storage, created)
      )
    : (await objectRequest(stub, "create", created)).body;
  expect(result).toEqual({ ok: true });
  return stub;
}
async function state(stub: DurableObjectStub) {
  return runInDurableObject(stub, async (_instance, context) =>
    Object.fromEntries(await context.storage.list())
  );
}
beforeEach(async () => {
  await applyD1Migrations(requiredDatabase(), runtimeEnv.TEST_D1_MIGRATIONS);
  for (const locator of [LOCATOR, SECOND_LOCATOR]) {
    await runInDurableObject(namespace().getByName(locator), async (_instance, context) => {
      await context.storage.deleteAll();
      await context.storage.deleteAlarm();
    });
    await requiredDatabase().batch([
      requiredDatabase().prepare("DELETE FROM abuse_reports WHERE routing_locator=?").bind(locator),
      requiredDatabase().prepare("DELETE FROM admin_audit WHERE routing_locator=?").bind(locator),
      requiredDatabase().prepare("DELETE FROM capabilities WHERE routing_locator=?").bind(locator)
    ]);
  }
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("real SQLite administrative and report authority", () => {
  it("projects both real capability audits for the same request operation ID and acknowledges exact replay", async () => {
    const now = Date.now() + 60_000;
    const operationId = crypto.randomUUID();
    const first = await initialize(now, false, undefined, { native: true });
    const second = await initialize(now, false, undefined, {
      locator: SECOND_LOCATOR,
      native: true
    });
    const cases = [
      { stub: first, locator: LOCATOR, actor: ADMIN_TEST_OPERATOR, action: "disable" as const },
      {
        stub: second,
        locator: SECOND_LOCATOR,
        actor: "second-operator@onceurl.invalid",
        action: "abuse_lock" as const
      }
    ];
    const ids: string[] = [];
    for (const entry of cases) {
      await runInDurableObject(entry.stub, async (_instance, context) => {
        const command = {
          mutation: {
            ...mutation(entry.action),
            locator: entry.locator,
            operation_id: operationId
          },
          actor: entry.actor,
          now
        };
        expect(await administerCapability(context.storage, command)).toEqual({ ok: true });
        const records = [
          ...(await context.storage.list({ prefix: SECURITY_RECORD_PREFIX })).values()
        ].map((value) => securityRecordSchema.parse(value));
        expect(records).toHaveLength(1);
        const record = records[0];
        if (record?.kind !== "audit") throw new Error("Expected an authoritative audit");
        ids.push(record.id);
        expect(record.projectedVersion).toBe(0);
        await projectSecurityRecords(context.storage, requiredDatabase(), now);
        expect(await context.storage.get(SECURITY_RECORD_PREFIX + record.id)).toMatchObject({
          projectedVersion: 1,
          actor: entry.actor,
          action: entry.action
        });
        expect(await administerCapability(context.storage, { ...command, now: now + 1 })).toEqual({
          ok: true
        });
        expect(
          await administerCapability(context.storage, {
            ...command,
            actor: "changed-operator@onceurl.invalid",
            now: now + 1
          })
        ).toMatchObject({ ok: false, code: "event_conflict" });
        // Model a crash after D1 commit and before the local delivery acknowledgement.
        await context.storage.put(SECURITY_RECORD_PREFIX + record.id, record);
        await projectSecurityRecords(context.storage, requiredDatabase(), now + 1);
        expect(await context.storage.get(SECURITY_RECORD_PREFIX + record.id)).toMatchObject({
          projectedVersion: 1
        });
        expect((await context.storage.list({ prefix: SECURITY_RECORD_PREFIX })).size).toBe(1);
      });
    }
    expect(new Set(ids).size).toBe(2);
    const rows = await requiredDatabase()
      .prepare(
        "SELECT id,routing_locator,actor,action,reason,report_id,occurred_at,retain_until FROM admin_audit WHERE routing_locator IN (?,?) ORDER BY routing_locator"
      )
      .bind(LOCATOR, SECOND_LOCATOR)
      .all();
    expect(rows.results).toEqual(
      cases.map((entry, index) => ({
        id: ids[index],
        routing_locator: entry.locator,
        actor: entry.actor,
        action: entry.action,
        reason: "phishing",
        report_id: null,
        occurred_at: now,
        retain_until: now + 180 * DAY
      }))
    );
  });
  it.each(["locator", "actor", "action", "reason", "report", "time"] as const)(
    "keeps a mismatched D1 audit %s collision pending and retries after repair",
    async (mismatch) => {
      const now = Date.now() + 60_000;
      const stub = await initialize(now, false, undefined, { native: true });
      await runInDurableObject(stub, async (_instance, context) => {
        const command = { mutation: mutation(), actor: ADMIN_TEST_OPERATOR, now };
        expect(await administerCapability(context.storage, command)).toEqual({ ok: true });
        const record = securityRecordSchema.parse(
          [...(await context.storage.list({ prefix: SECURITY_RECORD_PREFIX })).values()][0]
        );
        if (record.kind !== "audit") throw new Error("Expected an authoritative audit");
        const fake = {
          ...record,
          ...(mismatch === "locator" ? { locator: SECOND_LOCATOR } : {}),
          ...(mismatch === "actor" ? { actor: "different-operator@onceurl.invalid" } : {}),
          ...(mismatch === "action" ? { action: "delete" as const } : {}),
          ...(mismatch === "reason" ? { reason: "spam" as const } : {}),
          ...(mismatch === "report" ? { reportId } : {}),
          ...(mismatch === "time" ? { createdAt: now + 1, retainUntil: now + 1 + 180 * DAY } : {})
        };
        await requiredDatabase()
          .prepare(
            "INSERT INTO admin_audit(id,routing_locator,actor,action,reason,report_id,occurred_at,retain_until) VALUES (?,?,?,?,?,?,?,?)"
          )
          .bind(
            fake.id,
            fake.locator,
            fake.actor,
            fake.action,
            fake.reason,
            fake.reportId,
            fake.createdAt,
            fake.retainUntil
          )
          .run();
        const before = await requiredDatabase()
          .prepare("SELECT * FROM admin_audit WHERE id=?")
          .bind(record.id)
          .first();
        const logs = vi.spyOn(console, "error").mockImplementation(() => undefined);
        await projectSecurityRecords(context.storage, requiredDatabase(), now);
        expect(await context.storage.get(SECURITY_RECORD_PREFIX + record.id)).toMatchObject({
          projectedVersion: 0,
          nextAttemptAt: now + 300_000
        });
        expect(
          await requiredDatabase()
            .prepare("SELECT * FROM admin_audit WHERE id=?")
            .bind(record.id)
            .first()
        ).toEqual(before);
        expect(logs).not.toHaveBeenCalled();
        expect(await administerCapability(context.storage, { ...command, now: now + 1 })).toEqual({
          ok: true
        });
        expect(await context.storage.get("capability:v1:record")).toMatchObject({
          lifecycle: { state: "DISABLED" }
        });
        await projectSecurityRecords(context.storage, requiredDatabase(), now + 300_000);
        expect(await context.storage.get(SECURITY_RECORD_PREFIX + record.id)).toMatchObject({
          projectedVersion: 0,
          nextAttemptAt: now + 600_000
        });
        await requiredDatabase()
          .prepare("DELETE FROM admin_audit WHERE id=?")
          .bind(record.id)
          .run();
        await projectSecurityRecords(context.storage, requiredDatabase(), now + 600_000);
        expect(await context.storage.get(SECURITY_RECORD_PREFIX + record.id)).toMatchObject({
          projectedVersion: 1
        });
        expect(
          await requiredDatabase()
            .prepare(
              "SELECT routing_locator,actor,action,reason,report_id,occurred_at,retain_until FROM admin_audit WHERE id=?"
            )
            .bind(record.id)
            .first()
        ).toEqual({
          routing_locator: record.locator,
          actor: record.actor,
          action: record.action,
          reason: record.reason,
          report_id: record.reportId,
          occurred_at: record.createdAt,
          retain_until: record.retainUntil
        });
      });
    }
  );
  it.each(["disable", "abuse_lock"] as const)(
    "applies %s immediately while the real D1 catalogue remains stale",
    async (action) => {
      const now = Date.now();
      const stub = await initialize(now);
      await runInDurableObject(stub, async (_instance, context) => {
        const record = await context.storage.get<{ capabilityId: string; locator: string }>(
          "capability:v1:record"
        );
        if (record === undefined) throw new Error();
        await requiredDatabase()
          .prepare(
            "INSERT INTO capabilities(id,kind,state,routing_locator,policy_json,created_at,updated_at,version) VALUES (?,'secret','ACTIVE',?,'{}',?,?,1) ON CONFLICT(id) DO UPDATE SET state='ACTIVE'"
          )
          .bind(record.capabilityId, record.locator, now, now)
          .run();
        expect(
          await administerCapability(context.storage, {
            mutation: mutation(action),
            actor: ADMIN_TEST_OPERATOR,
            now: now + 1
          })
        ).toEqual({ ok: true });
        expect(
          await requiredDatabase()
            .prepare("SELECT state FROM capabilities WHERE id=?")
            .bind(record.capabilityId)
            .first()
        ).toEqual({ state: "ACTIVE" });
        expect(
          await claimCapability(context.storage, {
            publicBearerSecret: PUBLIC_BEARER,
            operationId: "stale-catalogue-claim",
            nonce: "nonce",
            now: now + 2
          })
        ).toMatchObject({ ok: false });
        expect(await context.storage.get("capability:v1:record")).toMatchObject({
          lifecycle: { state: action === "disable" ? "DISABLED" : "ABUSE_LOCKED" }
        });
        expect((await context.storage.list({ prefix: SECURITY_RECORD_PREFIX })).size).toBe(1);
      });
    }
  );
  it("rolls back lifecycle, audit and outbox together when durable audit persistence fails", async () => {
    const now = Date.now();
    const stub = await initialize(now);
    const before = await state(stub);
    await runInDurableObject(stub, async (_instance, context) => {
      const failing = new Proxy(context.storage, {
        get(target, property) {
          if (property === "transaction")
            return <T>(closure: (transaction: CapabilityObjectTransaction) => Promise<T>) =>
              target.transaction((txn) =>
                closure(
                  new Proxy(txn, {
                    get(transaction, member) {
                      if (member === "put")
                        return (key: string, value: unknown) => {
                          if (key.startsWith(SECURITY_RECORD_PREFIX))
                            throw new Error("injected write failure");
                          return transaction.put(key, value);
                        };
                      const value: unknown = Reflect.get(transaction, member);
                      return typeof value === "function"
                        ? (value as (...args: unknown[]) => unknown).bind(transaction)
                        : value;
                    }
                  })
                )
              );
          const value: unknown = Reflect.get(target, property);
          return typeof value === "function"
            ? (value as (...args: unknown[]) => unknown).bind(target)
            : value;
        }
      }) as CapabilityObjectStorage;
      await expect(
        administerCapability(failing, { mutation: mutation(), actor: ADMIN_TEST_OPERATOR, now })
      ).rejects.toThrow("injected write failure");
    });
    expect(await state(stub)).toEqual(before);
  });
  it("releases an actual ten-failure protective lock with atomic code-state reset and preserves unrelated quota", async () => {
    const timing = {
      claimMs: [] as number[],
      pbkdf2Ms: [] as number[],
      transactionWaitMs: [] as number[],
      transactionBodyMs: [] as number[],
      storageWaitMs: [] as number[],
      maxTimerDelayMs: 0,
      timerSamples: 0
    };
    const caseStarted = performance.now();
    let timerAt = caseStarted;
    const timer = setInterval(() => {
      const at = performance.now();
      timing.maxTimerDelayMs = Math.max(timing.maxTimerDelayMs, at - timerAt - 100);
      timing.timerSamples++;
      timerAt = at;
    }, 100);
    const deriveBits = crypto.subtle.deriveBits.bind(crypto.subtle);
    const derivation = vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async (...args) => {
      const at = performance.now();
      try {
        return await deriveBits(...args);
      } finally {
        timing.pbkdf2Ms.push(performance.now() - at);
      }
    });
    const measureStorage = <T extends CapabilityObjectTransaction>(storage: T): T =>
      new Proxy(storage, {
        get(target, property) {
          const value: unknown = Reflect.get(target, property);
          if (typeof value !== "function") return value;
          return async (...args: unknown[]) => {
            const at = performance.now();
            try {
              return (await Reflect.apply(value, target, args)) as unknown;
            } finally {
              timing.storageWaitMs.push(performance.now() - at);
            }
          };
        }
      });
    try {
      const start = Date.now();
      const stub = await initialize(start, true);
      await runInDurableObject(stub, async (_instance, context) => {
        const measured = new Proxy(context.storage, {
          get(target, property) {
            if (property === "transaction") {
              return async <T>(closure: (txn: CapabilityObjectTransaction) => Promise<T>) => {
                const requested = performance.now();
                return target.transaction(async (txn) => {
                  const entered = performance.now();
                  timing.transactionWaitMs.push(entered - requested);
                  try {
                    return await closure(measureStorage(txn));
                  } finally {
                    timing.transactionBodyMs.push(performance.now() - entered);
                  }
                });
              };
            }
            const value: unknown = Reflect.get(target, property);
            return typeof value === "function"
              ? (...args: unknown[]) => Reflect.apply(value, target, args) as unknown
              : value;
          }
        }) as CapabilityObjectStorage;
        let now = start;
        for (let count = 1; count <= 10; count++) {
          const claimStarted = performance.now();
          const result = await claimCapability(measured, {
            publicBearerSecret: PUBLIC_BEARER,
            operationId: `bad-code-${count}`,
            nonce: `bad-${count}`,
            accessCode: "incorrect",
            challengeVerified: true,
            now
          });
          timing.claimMs.push(performance.now() - claimStarted);
          expect(result.ok).toBe(false);
          if (!result.ok && result.retryAfter !== undefined) now += result.retryAfter * 1000;
        }
        expect(await context.storage.get("capability:v1:record")).toMatchObject({
          lifecycle: { state: "ABUSE_LOCKED" }
        });
        const rateBefore = await context.storage.get("capability:v1:rate:reveal");
        const release = { mutation: mutation("release"), actor: ADMIN_TEST_OPERATOR, now: now + 1 };
        expect(await administerCapability(context.storage, release)).toEqual({ ok: true });
        expect(await administerCapability(context.storage, release)).toEqual({ ok: true });
        const audits = await context.storage.list<{ kind: string; action?: string }>({
          prefix: "capability:security:v1:"
        });
        expect(
          [...audits.values()].filter((row) => row.kind === "audit" && row.action === "release")
        ).toHaveLength(1);
        const metrics = await context.storage.list<{ category?: string }>({
          prefix: "capability:metrics:v1:"
        });
        expect([...metrics.values()].filter((row) => row.category === "enforcement")).toHaveLength(
          0
        );
        expect(await context.storage.get("capability:v1:access-code")).toEqual({
          schemaVersion: 1,
          failureCount: 0,
          challengeRequired: false,
          backoffUntil: null,
          deleteAt: null
        });
        expect(await context.storage.get("capability:v1:rate:reveal")).toEqual(rateBefore);
      });
      // Give the due timer a turn before sampling/clearing it. A crypto/storage
      // chain can otherwise finish without a timer callback, hiding scheduling delay.
      await new Promise((resolve) => setTimeout(resolve, 0));
    } finally {
      derivation.mockRestore();
      clearInterval(timer);
      // Only numeric durations/counts leave this synthetic test; never storage keys or values.
      console.info("protective_lock_execution_timing", {
        ...Object.fromEntries(
          Object.entries(timing).map(([name, value]) => [
            name,
            Array.isArray(value) ? value.map((duration) => Math.round(duration)) : Math.round(value)
          ])
        ),
        caseMs: Math.round(performance.now() - caseStarted)
      });
    }
  }, 20_000);
  it("missing/unavailable exact and challenge dependencies expose only 503/403 and leave capability/report state unchanged", async () => {
    const now = Date.now();
    const stub = await initialize(now);
    const configuration = testEnv();
    const app = createTestApp();
    const nonce = await issueReportNonce(configuration, LOCATOR, true, now);
    const before = await state(stub);
    const headers = { Origin: "http://localhost", "content-type": "application/json" };
    const body = JSON.stringify({ nonce, reason: "other", note: "private hostile note" });
    expect(
      (
        await app.request(
          "/api/v1/reports",
          { method: "POST", headers, body },
          { ...configuration, ABUSE_CONTROL: undefined }
        )
      ).status
    ).toBe(503);
    expect(
      (await app.request("/api/v1/reports", { method: "POST", headers, body }, configuration))
        .status
    ).toBe(403);
    const challenge = await createChallengeTicket(configuration, "onceurl_report_submit", now);
    await markChallengeVerified(configuration, challenge, "onceurl_report_submit", now);
    const logs = vi.spyOn(console, "error").mockImplementation(() => undefined);
    expect(
      (
        await app.request(
          "/api/v1/reports",
          { method: "POST", headers: { ...headers, "X-OnceURL-Challenge": challenge }, body },
          { ...configuration, CAPABILITY_STATE: undefined }
        )
      ).status
    ).toBe(503);
    expect(await state(stub)).toEqual(before);
    expect(JSON.stringify(logs.mock.calls)).not.toContain("private hostile note");
    expect(
      await consumeChallengeTicket(configuration, challenge, "onceurl_report_submit", now)
    ).toBe(false);
  });
  it("report challenge purpose cannot substitute for preparation/access-code and is single-use", async () => {
    const now = Date.now();
    const configuration = testEnv();
    const challenge = await createChallengeTicket(configuration, "onceurl_report_submit", now);
    expect(
      await markChallengeVerified(configuration, challenge, "onceurl_report_submit", now)
    ).toBe(true);
    expect(await consumeChallengeTicket(configuration, challenge, "onceurl_prepare", now)).toBe(
      false
    );
    expect(await consumeChallengeTicket(configuration, challenge, "onceurl_access_code", now)).toBe(
      false
    );
    expect(
      await consumeChallengeTicket(configuration, challenge, "onceurl_report_submit", now + 300_001)
    ).toBe(false);
    expect(
      await consumeChallengeTicket(configuration, challenge, "onceurl_report_submit", now)
    ).toBe(true);
    expect(
      await consumeChallengeTicket(configuration, challenge, "onceurl_report_submit", now)
    ).toBe(false);
  });
  it("denies cookies, unverified headers, absent configuration and unknown aliases without touching authority or assets", async () => {
    const assets = vi.fn();
    const configuration = { ...testEnv(), ASSETS: { fetch: assets } as unknown as Fetcher };
    for (const path of [
      "/internal/admin",
      "/internal/admin/action",
      "/internal/admin/unknown",
      "/internal/admin/client.js"
    ]) {
      const response = await createTestApp().request(
        path,
        {
          headers: {
            Cookie: "CF_Authorization=secret-cookie",
            "Cf-Access-Authenticated-User-Email": ADMIN_TEST_OPERATOR
          }
        },
        configuration
      );
      expect(response.status).toBe(403);
      expect(response.headers.get("cache-control")).toBe("private, no-store");
      expect(await response.text()).not.toContain("secret-cookie");
    }
    expect(
      (
        await createTestApp().request(
          "/internal/admin",
          {},
          { ...configuration, ADMIN_ACCESS_ISSUER: undefined }
        )
      ).status
    ).toBe(503);
    for (const path of [
      "/internal",
      "/Internal/admin",
      "/internal/ADMIN",
      "/internal/%61dmin",
      "/internal/adminish"
    ])
      expect((await createTestApp().request(path, {}, configuration)).status).toBe(404);
    expect(assets).not.toHaveBeenCalled();
  });
  it("protects every route and passive admin GET; requires exact Origin and action/session-bound CSRF, and rejects replay", async () => {
    const stub = await initialize();
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(Response.json(ADMIN_TEST_JWKS)))
    );
    const app = createTestApp();
    const configuration = testEnv();
    const jwt = await adminTestAssertion(Date.now());
    const headers = {
      "Cf-Access-Jwt-Assertion": jwt,
      Origin: "http://localhost",
      "content-type": "application/json"
    };
    const doc = await app.request("/internal/admin", { headers }, configuration);
    expect(doc.status).toBe(200);
    expect(doc.headers.get("content-security-policy")).not.toContain("cloudflare.com");
    expect(doc.headers.get("x-robots-tag")).toBe("noindex, nofollow, noarchive");
    expect((await state(stub))["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "ACTIVE" }
    });
    const command = mutation();
    for (const origin of [undefined, "http://localhost.attacker.invalid"]) {
      const response = await app.request(
        "/internal/admin/csrf",
        {
          method: "POST",
          headers: {
            "Cf-Access-Jwt-Assertion": jwt,
            ...(origin === undefined ? {} : { Origin: origin })
          },
          body: JSON.stringify(command)
        },
        configuration
      );
      expect(response.status).toBe(403);
    }
    expect(
      (
        await app.request(
          "/internal/admin/action",
          { method: "POST", headers, body: JSON.stringify(command) },
          configuration
        )
      ).status
    ).toBe(403);
    const control = await app.request(
      "/internal/admin/csrf",
      { method: "POST", headers, body: JSON.stringify(command) },
      configuration
    );
    expect(control.status, await control.clone().text()).toBe(200);
    const { csrf_token: token } = await control.json<{ csrf_token: string }>();
    expect(typeof token).toBe("string");
    expect(
      (
        await app.request(
          "/internal/admin/action",
          {
            method: "POST",
            headers: { ...headers, "X-OnceURL-CSRF": token },
            body: JSON.stringify({ ...command, action: "delete" })
          },
          configuration
        )
      ).status
    ).toBe(403);
    const action = await app.request(
      "/internal/admin/action",
      {
        method: "POST",
        headers: { ...headers, "X-OnceURL-CSRF": token },
        body: JSON.stringify(command)
      },
      configuration
    );
    expect(action.status).toBe(200);
    expect(await action.json()).toEqual({ recorded: true });
    expect(
      (
        await app.request(
          "/internal/admin/action",
          {
            method: "POST",
            headers: { ...headers, "X-OnceURL-CSRF": token },
            body: JSON.stringify(command)
          },
          configuration
        )
      ).status
    ).toBe(403);
    const stored = await state(stub);
    expect(stored["capability:v1:record"]).toMatchObject({ lifecycle: { state: "DISABLED" } });
    const auditId = `adm1_${await securityDigest("onceurl.admin-audit-id.v1", JSON.stringify({ locator: command.locator, operation_id: command.operation_id }))}`;
    expect(stored[SECURITY_RECORD_PREFIX + auditId]).toMatchObject({
      actor: ADMIN_TEST_OPERATOR,
      action: "disable",
      reason: "phishing"
    });
    const inspection = await app.request(
      "/internal/admin/inspect",
      { method: "POST", headers, body: JSON.stringify({ locator: LOCATOR }) },
      configuration
    );
    const output = await inspection.text();
    for (const secret of [PUBLIC_BEARER, "ciphertext", "Bearer", jwt, token, "accessCodeVerifier"])
      expect(output).not.toContain(secret);
    expect(
      (
        await app.request(
          "/internal/admin/csrf",
          {
            method: "POST",
            headers,
            body: JSON.stringify({ ...mutation(), action: "reactivate" })
          },
          configuration
        )
      ).status
    ).toBe(400);
    expect((await app.request("/internal/admin/unknown", { headers }, configuration)).status).toBe(
      404
    );
  });
  it("CSRF expires, binds the exact operator/session and remains one-time under racing consumes", async () => {
    const configuration = testEnv();
    const now = Date.now();
    const command = mutation();
    const operator = {
      actor: ADMIN_TEST_OPERATOR,
      session: "A".repeat(43),
      expiresAt: now + 900_000
    };
    const token = await issueAdminCsrf(configuration, operator, command, now);
    expect(
      await consumeAdminCsrf(
        configuration,
        { ...operator, session: "B".repeat(43) },
        command,
        token,
        now
      )
    ).toBe(false);
    expect(
      await consumeAdminCsrf(
        configuration,
        { ...operator, actor: "other@onceurl.invalid" },
        command,
        token,
        now
      )
    ).toBe(false);
    expect(await consumeAdminCsrf(configuration, operator, command, token, now + 300_000)).toBe(
      false
    );
    const results = await Promise.all(
      Array.from({ length: 10 }, () =>
        consumeAdminCsrf(configuration, operator, command, token, now)
      )
    );
    expect(results.filter(Boolean)).toHaveLength(1);
    await expect(
      consumeAdminCsrf(
        { ...configuration, ABUSE_CONTROL: undefined },
        operator,
        command,
        token,
        now
      )
    ).rejects.toMatchObject({ status: 503 });
  });
  it.each(["disable", "abuse_lock"] as const)(
    "%s immediately denies release with stale D1, serializes against claim and durably attributes retries",
    async (action) => {
      const now = Date.now();
      const stub = await initialize(now);
      const command = { mutation: mutation(action), actor: ADMIN_TEST_OPERATOR, now: now + 1 };
      const results = await runInDurableObject(stub, async (_instance, context) =>
        Promise.all([
          administerCapability(context.storage, command),
          claimCapability(context.storage, {
            publicBearerSecret: PUBLIC_BEARER,
            operationId: "competing-claim",
            nonce: "nonce",
            now: now + 1
          })
        ])
      );
      expect(results.filter((result) => result.ok)).toHaveLength(1);
      const stored = await state(stub);
      if (results[0]?.ok) {
        expect(stored["capability:v1:record"]).toMatchObject({
          lifecycle: { state: action === "disable" ? "DISABLED" : "ABUSE_LOCKED" }
        });
        expect(
          (
            await objectRequest(stub, "claim", {
              publicBearerSecret: PUBLIC_BEARER,
              operationId: "after-disable",
              nonce: "nonce",
              now: now + 2
            })
          ).body
        ).toMatchObject({ ok: false });
        expect(
          (await objectRequest(stub, "administer", { ...command, now: now + 3 })).body
        ).toEqual({ ok: true });
        expect(
          (await objectRequest(stub, "administer", { ...command, actor: "other@onceurl.invalid" }))
            .body
        ).toMatchObject({ ok: false, code: "event_conflict" });
        expect(
          Object.keys(await state(stub)).filter((key) => key.startsWith(SECURITY_RECORD_PREFIX))
        ).toHaveLength(1);
      } else
        expect(stored["capability:v1:record"]).toMatchObject({
          lifecycle: { state: "CONSUMED" },
          ciphertextEnvelope: null
        });
    }
  );
  it("releases operator locks on code-protected capabilities and preserves traffic windows", async () => {
    const now = Date.now();
    const stub = await initialize(now, true);
    await runInDurableObject(stub, async (_instance, context) => {
      await context.storage.put("capability:v1:rate:passive", {
        schemaVersion: 1,
        attempts: [now]
      });
      await context.storage.put("capability:v1:rate:reveal", { schemaVersion: 1, attempts: [now] });
      expect(
        await administerCapability(context.storage, {
          mutation: mutation("abuse_lock"),
          actor: ADMIN_TEST_OPERATOR,
          now
        })
      ).toEqual({ ok: true });
      expect(
        await administerCapability(context.storage, {
          mutation: mutation("release"),
          actor: ADMIN_TEST_OPERATOR,
          now: now + 1
        })
      ).toEqual({ ok: true });
      expect(await context.storage.get("capability:v1:access-code")).toEqual({
        schemaVersion: 1,
        failureCount: 0,
        challengeRequired: false,
        backoffUntil: null,
        deleteAt: null
      });
      for (const kind of ["passive", "reveal"])
        expect(await context.storage.get(`capability:v1:rate:${kind}`)).toEqual({
          schemaVersion: 1,
          attempts: [now]
        });
    });
  });
  it.each(["CONSUMED", "EXPIRED"] as const)(
    "never reopens %s authority or adds enforcement/audit evidence for a refused release",
    async (terminal) => {
      const now = Date.now();
      const stub =
        terminal === "EXPIRED"
          ? await initialize(now - 2000, false, now - 1000)
          : await initialize(now);
      await runInDurableObject(stub, async (_instance, context) => {
        if (terminal === "EXPIRED") await maintainCapability(context.storage, now);
        else
          expect(
            (
              await claimCapability(context.storage, {
                publicBearerSecret: PUBLIC_BEARER,
                operationId: "terminal-consume",
                nonce: "nonce",
                now
              })
            ).ok
          ).toBe(true);
        expect(await context.storage.get("capability:v1:record")).toMatchObject({
          lifecycle: { state: terminal },
          ciphertextEnvelope: null
        });
        const before = Object.fromEntries(await context.storage.list());
        for (const action of ["release", "abuse_lock", "disable"] as const)
          expect(
            (
              await administerCapability(context.storage, {
                mutation: mutation(action),
                actor: ADMIN_TEST_OPERATOR,
                now: now + 1
              })
            ).ok
          ).toBe(false);
        expect(Object.fromEntries(await context.storage.list())).toEqual(before);
      });
    }
  );
  it("never reopens terminal authority; deletion destroys ciphertext and persists its audit/outbox atomically", async () => {
    const now = Date.now();
    const stub = await initialize(now);
    expect(
      (
        await objectRequest(stub, "administer", {
          mutation: mutation("delete"),
          actor: ADMIN_TEST_OPERATOR,
          now
        })
      ).body
    ).toEqual({ ok: true });
    expect((await state(stub))["capability:v1:record"]).toMatchObject({
      lifecycle: { state: "DELETED" },
      ciphertextEnvelope: null
    });
    expect(
      (
        await objectRequest(stub, "administer", {
          mutation: mutation("release"),
          actor: ADMIN_TEST_OPERATOR,
          now: now + 1
        })
      ).body
    ).toMatchObject({ ok: false });
  });
  it("enforces capability issuance/submission rolling windows and single-use report identity without changing lifecycle", async () => {
    const now = Date.now();
    const stub = await initialize(now);
    await runInDurableObject(stub, async (_instance, context) => {
      for (let count = 0; count < 3; count++)
        expect(
          await prepareCapabilityReport(context.storage, { publicBearerSecret: PUBLIC_BEARER, now })
        ).toEqual({ ok: true, authorized: true });
      expect(
        await prepareCapabilityReport(context.storage, {
          publicBearerSecret: PUBLIC_BEARER,
          now: now + 1
        })
      ).toEqual({ ok: false, code: "rate_limited", retryAfter: 3600 });
      expect(
        await prepareCapabilityReport(context.storage, {
          publicBearerSecret: PUBLIC_BEARER,
          now: now + 3_600_000
        })
      ).toEqual({ ok: true, authorized: true });
      const command = {
        id: reportId,
        locator: LOCATOR,
        nonceCreatedAt: now,
        reason: "other",
        note: "<img src=x onerror=alert(1)>",
        now
      };
      const concurrent = await Promise.all(
        Array.from({ length: 10 }, () => submitCapabilityReport(context.storage, command))
      );
      expect(concurrent.every((result) => result.ok)).toBe(true);
      expect((await context.storage.list({ prefix: SECURITY_RECORD_PREFIX })).size).toBe(1);
      for (const character of ["B", "C"])
        expect(
          await submitCapabilityReport(context.storage, {
            ...command,
            id: `rep1_${character.repeat(43)}`
          })
        ).toEqual({ ok: true });
      expect(
        await submitCapabilityReport(context.storage, { ...command, id: `rep1_${"D".repeat(43)}` })
      ).toEqual({ ok: false, code: "rate_limited", retryAfter: 86400 });
      expect(
        await submitCapabilityReport(context.storage, {
          ...command,
          id: `rep1_${"E".repeat(43)}`,
          now: now + 600_000
        })
      ).toEqual({ ok: true });
      expect((await context.storage.list({ prefix: SECURITY_RECORD_PREFIX })).size).toBe(3);
      expect(
        await submitCapabilityReport(context.storage, {
          ...command,
          id: `rep1_${"F".repeat(43)}`,
          nonceCreatedAt: now + DAY,
          now: now + DAY,
          note: "😀".repeat(256)
        })
      ).toEqual({ ok: true });
      expect(
        await context.storage.get(SECURITY_RECORD_PREFIX + `rep1_${"F".repeat(43)}`)
      ).toMatchObject({ note: "😀".repeat(256) });
      expect((await context.storage.list({ prefix: SECURITY_RECORD_PREFIX })).size).toBe(4);
      expect(await context.storage.get("capability:v1:record")).toMatchObject({
        lifecycle: { state: "ACTIVE" }
      });
    });
  });
  it("report nonce is opaque, purpose/capability-bound and atomically consumed only once", async () => {
    const now = Date.now();
    const configuration = testEnv();
    const nonce = await issueReportNonce(configuration, LOCATOR, true, now);
    expect(nonce).not.toContain(LOCATOR);
    const results = await Promise.all(
      Array.from({ length: 8 }, () => consumeReportNonce(configuration, nonce, now))
    );
    expect(results.filter((result) => result !== null)).toEqual([
      expect.objectContaining({
        purpose: "report",
        consumedAt: now,
        binding: { locator: LOCATOR, authorized: true }
      })
    ]);
    expect(await consumeReportNonce(configuration, nonce, now)).toBeNull();
    const other = await issueReportNonce(configuration, SECOND_LOCATOR, false, now);
    expect(await consumeReportNonce(configuration, other, now)).toMatchObject({
      purpose: "report",
      binding: { locator: SECOND_LOCATOR, authorized: false }
    });
    const expiring = await issueReportNonce(configuration, LOCATOR, true, now);
    expect(await consumeReportNonce(configuration, expiring, now + 600_000)).toBeNull();
    expect(
      (await reportNonceState(configuration, expiring))["abuse:security-ticket:v1"]
    ).toMatchObject({
      consumedAt: null
    });
    expect(await consumeReportNonce(configuration, `rpt1_${"Z".repeat(43)}`, now)).toBeNull();
    const operator = {
      actor: ADMIN_TEST_OPERATOR,
      session: "A".repeat(43),
      expiresAt: now + 900_000
    };
    const command = mutation();
    const csrf = await issueAdminCsrf(configuration, operator, command, now);
    expect(await consumeReportNonce(configuration, csrf, now)).toBeNull();
    const abuse = configuration.ABUSE_CONTROL;
    if (abuse === undefined) throw new Error("Missing test abuse binding");
    const csrfStub = abuse.getByName(
      `ticket:${await securityDigest("onceurl.security-ticket.v1", csrf)}`
    );
    expect(
      await runInDurableObject(csrfStub, async (_instance, context) =>
        executeSecurityTicket(context.storage, { type: "consume-report", now })
      )
    ).toEqual({ ok: false });
    expect(await consumeAdminCsrf(configuration, operator, command, csrf, now)).toBe(true);
  });
  it.each(["report_issue", "report_submit"] as const)(
    "keeps exact %s IP accounting across rotation, concurrency and failures",
    async (kind) => {
      const configuration = testEnv();
      const now = Date.now();
      const ip = "192.0.2.17";
      for (let count = 0; count < 4; count++)
        expect(await consumeExactIpQuota(configuration, ip, kind, now)).toEqual({ allowed: true });
      const rotated = {
        ...configuration,
        ABUSE_IP_HMAC_PREVIOUS_KEY: configuration.ABUSE_IP_HMAC_KEY,
        ABUSE_IP_HMAC_KEY: adminTestEnv().ABUSE_IP_HMAC_KEY
      };
      const results = await Promise.all(
        Array.from({ length: 8 }, () => consumeExactIpQuota(rotated, ip, kind, now))
      );
      expect(results.filter((result) => result.allowed)).toHaveLength(1);
      expect(results.filter((result) => !result.allowed)).toEqual(
        Array.from({ length: 7 }, () => ({
          allowed: false,
          retryAfter: kind === "report_issue" ? 60 : 3600
        }))
      );
      const digest = (await deriveIpDigests(ip, rotated)).at(-1);
      const abuseControl = configuration.ABUSE_CONTROL;
      if (abuseControl === undefined) throw new Error("Missing test abuse binding");
      const serialized = await runInDurableObject(
        abuseControl.getByName(`ip:${digest}`),
        async (_instance, context) =>
          JSON.stringify(Object.fromEntries(await context.storage.list()))
      );
      expect(serialized).not.toContain(ip);
      await expect(
        consumeExactIpQuota({ ...configuration, ABUSE_CONTROL: undefined }, ip, kind, now)
      ).rejects.toThrow();
    }
  );
  it("generic intake acknowledgement covers valid/random/expired/consumed/unauthorized nonces without another capability mutation", async () => {
    const stub = await initialize();
    const configuration = testEnv();
    const app = createTestApp();
    const now = Date.now();
    const response = await app.request(
      "/api/v1/reports/nonce",
      {
        method: "POST",
        headers: { Origin: "http://localhost", "content-type": "application/json" },
        body: JSON.stringify({ locator: LOCATOR, public_bearer: PUBLIC_BEARER })
      },
      configuration
    );
    expect(response.status).toBe(200);
    const { nonce } = await response.json<{ nonce: string }>();
    const expired = await issueReportNonce(configuration, LOCATOR, true, now - 600_000);
    const unauthorized = await issueReportNonce(configuration, SECOND_LOCATOR, false, now);
    const observed = observeReportDependencies(configuration);
    let acceptedState: Awaited<ReturnType<typeof state>> | undefined;
    for (const value of [nonce, `rpt1_${"Z".repeat(43)}`, expired, nonce, unauthorized]) {
      const challenge = await verifiedReportChallenge(configuration, now);
      const submission = await app.request(
        "/api/v1/reports",
        {
          method: "POST",
          headers: {
            Origin: "http://localhost",
            "content-type": "application/json",
            "X-OnceURL-Challenge": challenge
          },
          body: JSON.stringify({
            nonce: value,
            reason: "other",
            note: "<script>hostile()</script>"
          })
        },
        observed.configuration
      );
      expect(submission.status).toBe(200);
      expect(await submission.json()).toEqual({ acknowledged: true });
      expect(submission.headers.get("Cache-Control")).toContain("no-store");
      if (acceptedState === undefined) acceptedState = await state(stub);
      else expect(await state(stub)).toEqual(acceptedState);
    }
    expect(observed.capabilityObjects.mock.calls).toEqual([[LOCATOR]]);
    expect(await consumeReportNonce(configuration, nonce, Date.now())).toBeNull();
    expect(
      Object.keys(await state(stub)).filter((key) => key.startsWith(SECURITY_RECORD_PREFIX))
    ).toHaveLength(1);
    const oversized = await app.request(
      "/api/v1/reports",
      {
        method: "POST",
        headers: { Origin: "http://localhost" },
        body: JSON.stringify({ nonce, reason: "other", note: "😀".repeat(257) })
      },
      configuration
    );
    expect(oversized.status).toBe(400);
    expect(
      (
        await app.request(
          "/internal/admin",
          { headers: { Cookie: `report=${nonce}` } },
          configuration
        )
      ).status
    ).toBe(403);
  });
  it("concurrent guarded submissions consume one nonce and invoke report authority at most once", async () => {
    const now = Date.now();
    const stub = await initialize(now);
    const configuration = testEnv();
    const nonce = await issueReportNonce(configuration, LOCATOR, true, now);
    const challenges = await Promise.all(
      Array.from({ length: 4 }, () => verifiedReportChallenge(configuration, now))
    );
    const observed = observeReportDependencies(configuration);
    const app = createTestApp();
    const submissions = await Promise.all(
      challenges.map(
        async (challenge, index) =>
          await app.request(
            "/api/v1/reports",
            {
              method: "POST",
              headers: {
                Origin: "http://localhost",
                "content-type": "application/json",
                "CF-Connecting-IP": `192.0.2.${60 + index}`,
                "X-OnceURL-Challenge": challenge
              },
              body: JSON.stringify({ nonce, reason: "other", note: `concurrent note ${index}` })
            },
            observed.configuration
          )
      )
    );
    for (const response of submissions) {
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ acknowledged: true });
    }
    expect(observed.capabilityObjects.mock.calls).toEqual([[LOCATOR]]);
    expect(
      observed.abuseObjects.mock.calls.filter(([name]) => name.startsWith("ticket:"))
    ).toHaveLength(4);
    expect(await consumeReportNonce(configuration, nonce, Date.now())).toBeNull();
    const source = await state(stub);
    expect(
      Object.keys(source).filter((key) => key.startsWith(SECURITY_RECORD_PREFIX))
    ).toHaveLength(1);
    expect(source["capability:security:rate:submit"]).toEqual([expect.any(Number)]);
    expect(
      await requiredDatabase().prepare("SELECT count(*) AS count FROM abuse_reports").first()
    ).toEqual({ count: 1 });
  });
  it.each([
    "origin",
    "body",
    "ip",
    "quota",
    "missing-challenge",
    "unverified-challenge",
    "wrong-purpose-challenge"
  ] as const)("rejects %s before any report-nonce lookup or consumption", async (rejection) => {
    const now = Date.now();
    const stub = await initialize(now);
    const configuration = testEnv();
    const nonce = await issueReportNonce(configuration, LOCATOR, true, now);
    const ip = "192.0.2.70";
    if (rejection === "quota")
      for (let count = 0; count < 5; count++)
        expect(await consumeExactIpQuota(configuration, ip, "report_submit", now)).toEqual({
          allowed: true
        });
    const action =
      rejection === "wrong-purpose-challenge" ? "onceurl_prepare" : "onceurl_report_submit";
    const challenge = await createChallengeTicket(configuration, action, now);
    if (rejection !== "unverified-challenge")
      expect(await markChallengeVerified(configuration, challenge, action, now)).toBe(true);
    const observed = observeReportDependencies(configuration);
    const before = await state(stub);
    const nonceBefore = await reportNonceState(configuration, nonce);
    const response = await createTestApp().request(
      "/api/v1/reports",
      {
        method: "POST",
        headers: {
          Origin: rejection === "origin" ? "https://untrusted.invalid" : "http://localhost",
          "content-type": "application/json",
          "CF-Connecting-IP": rejection === "ip" ? "not-an-ip" : ip,
          ...(rejection === "missing-challenge" ? {} : { "X-OnceURL-Challenge": challenge })
        },
        body: JSON.stringify({ nonce, reason: rejection === "body" ? "invalid" : "other" })
      },
      observed.configuration
    );
    expect(response.status).toBe(
      rejection === "body" ? 400 : rejection === "ip" ? 503 : rejection === "quota" ? 429 : 403
    );
    expect(observed.abuseObjects.mock.calls.filter(([name]) => name.startsWith("ticket:"))).toEqual(
      []
    );
    expect(observed.capabilityObjects).not.toHaveBeenCalled();
    expect(await reportNonceState(configuration, nonce)).toEqual(nonceBefore);
    expect(await state(stub)).toEqual(before);
    expect(
      await requiredDatabase().prepare("SELECT count(*) AS count FROM abuse_reports").first()
    ).toEqual({ count: 0 });
    if (["origin", "body", "ip", "quota"].includes(rejection)) {
      expect(
        observed.abuseObjects.mock.calls.filter(([name]) => name.startsWith("challenge:"))
      ).toEqual([]);
      expect(await consumeChallengeTicket(configuration, challenge, action, now)).toBe(true);
    }
    expect(await consumeReportNonce(configuration, nonce, now)).not.toBeNull();
  });
  it.each(["ip:", "challenge:", "challenge-consume"] as const)(
    "unavailable %s dependency fails closed before nonce consumption",
    async (dependency) => {
      const now = Date.now();
      const stub = await initialize(now);
      const configuration = testEnv();
      const nonce = await issueReportNonce(configuration, LOCATOR, true, now);
      const challenge = await verifiedReportChallenge(configuration, now);
      const observed = observeReportDependencies(configuration, dependency);
      const before = await state(stub);
      const nonceBefore = await reportNonceState(configuration, nonce);
      const response = await createTestApp().request(
        "/api/v1/reports",
        {
          method: "POST",
          headers: {
            Origin: "http://localhost",
            "content-type": "application/json",
            "CF-Connecting-IP": "192.0.2.80",
            "X-OnceURL-Challenge": challenge
          },
          body: JSON.stringify({ nonce, reason: "other" })
        },
        observed.configuration
      );
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({ error: "service_unavailable" });
      expect(
        observed.abuseObjects.mock.calls.some(([name]) =>
          name.startsWith(dependency === "challenge-consume" ? "challenge:" : dependency)
        )
      ).toBe(true);
      expect(
        observed.abuseObjects.mock.calls.filter(([name]) => name.startsWith("ticket:"))
      ).toEqual([]);
      expect(observed.capabilityObjects).not.toHaveBeenCalled();
      expect(await reportNonceState(configuration, nonce)).toEqual(nonceBefore);
      expect(await state(stub)).toEqual(before);
      expect(
        await requiredDatabase().prepare("SELECT count(*) AS count FROM abuse_reports").first()
      ).toEqual({ count: 0 });
      expect(
        await consumeChallengeTicket(configuration, challenge, "onceurl_report_submit", now)
      ).toBe(true);
      expect(await consumeReportNonce(configuration, nonce, now)).not.toBeNull();
    }
  );
  it("retains confirmed structured evidence 180 days, redacts all original notes at 30 days and applies idempotent cleanup", async () => {
    const now = Date.now();
    const stub = await initialize(now);
    const submitted = await objectRequest(stub, "report-submit", {
      id: reportId,
      locator: LOCATOR,
      reason: "phishing",
      note: "hostile-note",
      nonceCreatedAt: now,
      now
    });
    expect(submitted.body).toEqual({ ok: true });
    const command = { ...mutation(), report_id: reportId, confirm_abuse: true };
    expect(
      (
        await objectRequest(stub, "administer", {
          mutation: command,
          actor: ADMIN_TEST_OPERATOR,
          now: now + 1
        })
      ).body
    ).toEqual({ ok: true });
    await runInDurableObject(stub, async (_instance, context) => {
      await maintainCapability(context.storage, now + 30 * DAY);
      expect(await context.storage.get(SECURITY_RECORD_PREFIX + reportId)).toMatchObject({
        note: null,
        confirmedAt: now + 1,
        retainUntil: now + 1 + 180 * DAY
      });
      await maintainCapability(context.storage, now + 1 + 180 * DAY);
      expect((await context.storage.list({ prefix: SECURITY_RECORD_PREFIX })).size).toBe(0);
    });
    await cleanupAbuseRetention(requiredDatabase(), now + 30 * DAY);
    expect(
      await requiredDatabase()
        .prepare("SELECT note FROM abuse_reports WHERE id=?")
        .bind(reportId)
        .first()
    ).toEqual({ note: null });
    await cleanupAbuseRetention(requiredDatabase(), now + 1 + 180 * DAY);
    await cleanupAbuseRetention(requiredDatabase(), now + 1 + 180 * DAY);
    expect(
      await requiredDatabase().prepare("SELECT count(*) AS count FROM abuse_reports").first()
    ).toEqual({ count: 0 });
    expect(
      await requiredDatabase().prepare("SELECT count(*) AS count FROM admin_audit").first()
    ).toEqual({ count: 0 });
  });
});
