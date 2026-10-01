import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { WorkerEnv } from "./env";

type QuotaKind = "preparation" | "passive" | "reveal";

function abuseNamespace(): DurableObjectNamespace {
  const namespace = (env as unknown as WorkerEnv).ABUSE_CONTROL;
  if (!namespace) throw new Error("Runtime test requires the ABUSE_CONTROL binding");
  return namespace;
}

function abuseStub(name: string): DurableObjectStub {
  return abuseNamespace().getByName(`${name}-${crypto.randomUUID()}`);
}

function ipObject(): { readonly name: string; readonly stub: DurableObjectStub } {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  bytes.fill(0);
  const digest = btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  const name = `ip:ipd1_${digest}`;
  return { name, stub: abuseNamespace().getByName(name) };
}

async function quota(stub: DurableObjectStub, kind: QuotaKind, now: number) {
  const response = await stub.fetch("https://abuse.invalid/internal/abuse/quota", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ kind, now })
  });
  return { status: response.status, body: await response.json() };
}

async function handoff(source: DurableObjectStub, targetObjectName: string, now: number) {
  const response = await source.fetch("https://abuse.invalid/internal/abuse/handoff", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ targetObjectName, now })
  });
  return { status: response.status, body: await response.json() };
}

describe("AbuseControlDurableObject exact state", () => {
  it.each([
    ["passive", 120],
    ["reveal", 30]
  ] as const)(
    "enforces the exact %s one-minute window",
    async (kind, limit) => {
      const stub = abuseStub(kind);
      const now = Date.now();
      for (let attempt = 0; attempt < limit; attempt += 1) {
        await expect(quota(stub, kind, now)).resolves.toMatchObject({
          status: 200,
          body: { ok: true }
        });
      }
      await expect(quota(stub, kind, now)).resolves.toEqual({
        status: 429,
        body: { ok: false, code: "rate_limited", retryAfter: 60 }
      });
      await expect(quota(stub, kind, now + 60_000)).resolves.toMatchObject({ status: 200 });
    },
    20_000
  );

  it("enforces both preparation rolling windows", async () => {
    const tenMinuteStub = abuseStub("prepare-ten-minute");
    const now = Date.now();
    for (let attempt = 0; attempt < 10; attempt += 1) {
      await expect(quota(tenMinuteStub, "preparation", now)).resolves.toMatchObject({
        status: 200
      });
    }
    await expect(quota(tenMinuteStub, "preparation", now)).resolves.toEqual({
      status: 429,
      body: { ok: false, code: "rate_limited", retryAfter: 600 }
    });

    const dailyStub = abuseStub("prepare-daily");
    for (let attempt = 0; attempt < 60; attempt += 1) {
      await expect(quota(dailyStub, "preparation", now + attempt * 600_001)).resolves.toMatchObject(
        { status: 200 }
      );
    }
    const limited = await quota(dailyStub, "preparation", now + 59 * 600_001);
    expect(limited).toMatchObject({ status: 429, body: { ok: false, code: "rate_limited" } });
  });

  it("serializes concurrent exact-IP quota requests", async () => {
    const stub = abuseStub("concurrent-reveal");
    const now = Date.now();
    const results = await Promise.all(Array.from({ length: 35 }, () => quota(stub, "reveal", now)));
    expect(results.filter((result) => result.status === 200)).toHaveLength(30);
    expect(results.filter((result) => result.status === 429)).toHaveLength(5);
    expect(
      results
        .filter((result) => result.status === 429)
        .every(
          (result) =>
            JSON.stringify(result.body) ===
            JSON.stringify({ ok: false, code: "rate_limited", retryAfter: 60 })
        )
    ).toBe(true);
  });

  it("moves a preparation bucket at its ten-minute limit without admitting or poisoning denials", async () => {
    const previous = ipObject();
    const current = ipObject();
    const now = Date.now();
    for (let attempt = 0; attempt < 10; attempt += 1) {
      await expect(quota(previous.stub, "preparation", now)).resolves.toMatchObject({
        status: 200
      });
    }

    await expect(handoff(previous.stub, current.name, now)).resolves.toEqual({
      status: 200,
      body: { ok: true }
    });
    for (const stub of [current.stub, previous.stub, current.stub]) {
      await expect(quota(stub, "preparation", now)).resolves.toEqual({
        status: 429,
        body: { ok: false, code: "rate_limited", retryAfter: 600 }
      });
    }
    await expect(quota(current.stub, "preparation", now + 600_000)).resolves.toMatchObject({
      status: 200,
      body: { ok: true }
    });
  });

  it("carries the combined preparation ten-minute and 24-hour history across handoff", async () => {
    const previous = ipObject();
    const current = ipObject();
    const first = Date.now() - 23 * 60 * 60_000;
    const spacing = 23 * 60_000;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      await expect(
        quota(previous.stub, "preparation", first + attempt * spacing)
      ).resolves.toMatchObject({ status: 200 });
    }
    const now = first + 59 * spacing;

    await expect(handoff(previous.stub, current.name, now)).resolves.toMatchObject({ status: 200 });
    await expect(quota(current.stub, "preparation", now)).resolves.toMatchObject({
      status: 429,
      body: { ok: false, code: "rate_limited" }
    });
    await expect(
      quota(current.stub, "preparation", first + 24 * 60 * 60_000)
    ).resolves.toMatchObject({
      status: 200,
      body: { ok: true }
    });
  });

  it("carries passive and reveal histories to the one current authority", async () => {
    const previous = ipObject();
    const current = ipObject();
    const now = Date.now();
    for (let attempt = 0; attempt < 120; attempt += 1) {
      await quota(previous.stub, "passive", now);
    }
    for (let attempt = 0; attempt < 30; attempt += 1) {
      await quota(previous.stub, "reveal", now);
    }

    await expect(handoff(previous.stub, current.name, now)).resolves.toMatchObject({ status: 200 });
    await expect(quota(current.stub, "passive", now)).resolves.toEqual({
      status: 429,
      body: { ok: false, code: "rate_limited", retryAfter: 60 }
    });
    await expect(quota(previous.stub, "reveal", now)).resolves.toEqual({
      status: 429,
      body: { ok: false, code: "rate_limited", retryAfter: 60 }
    });
    await expect(quota(current.stub, "passive", now + 60_000)).resolves.toMatchObject({
      status: 200
    });
    await expect(quota(previous.stub, "reveal", now + 60_000)).resolves.toMatchObject({
      status: 200
    });
  });

  it("serializes concurrent old-name forwarding and current-name requests after handoff", async () => {
    const previous = ipObject();
    const current = ipObject();
    const now = Date.now();
    for (let attempt = 0; attempt < 20; attempt += 1) {
      await quota(previous.stub, "reveal", now);
    }
    await expect(handoff(previous.stub, current.name, now)).resolves.toMatchObject({ status: 200 });

    const results = await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        quota(index % 2 === 0 ? previous.stub : current.stub, "reveal", now)
      )
    );
    expect(results.filter((result) => result.status === 200)).toHaveLength(10);
    expect(results.filter((result) => result.status === 429)).toHaveLength(10);
  });

  it("makes five-minute challenge tickets action-bound and single-use", async () => {
    const stub = abuseStub("challenge");
    const now = Date.now();
    const command = (path: string, body: unknown) =>
      stub.fetch(`https://abuse.invalid${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body)
      });
    await expect(
      command("/internal/challenge/status", {
        action: "onceurl_prepare",
        now
      }).then((r) => r.json())
    ).resolves.toEqual({ ok: false, code: "unavailable" });
    await expect(
      command("/internal/challenge/create-verified", {
        action: "onceurl_prepare",
        createdAt: now,
        now: now + 1
      }).then((r) => r.json())
    ).resolves.toEqual({ ok: true });
    await expect(
      command("/internal/challenge/status", {
        action: "onceurl_access_code",
        now: now + 1
      }).then((r) => r.json())
    ).resolves.toEqual({ ok: false, code: "unavailable" });
    await expect(
      command("/internal/challenge/consume", { action: "onceurl_prepare", now: now + 2 }).then(
        (r) => r.json()
      )
    ).resolves.toEqual({ ok: true });
    await expect(
      command("/internal/challenge/consume", { action: "onceurl_prepare", now: now + 3 }).then(
        (r) => r.json()
      )
    ).resolves.toEqual({ ok: false, code: "unavailable" });
  });
});
