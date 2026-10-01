import { describe, expect, it, vi } from "vitest";
import {
  AbuseControlDependencyError,
  canonicalizeClientIp,
  consumeExactIpQuota,
  createChallengeTicket,
  deriveIpDigests,
  readChallengeStatus
} from "./abuse-control";
import type { WorkerEnv } from "./env";
import { createTestPreparationHmacKey, createTestWorkerEnv } from "./testing/env";

describe("abuse-control identifiers and IP privacy", () => {
  it.each([
    ["192.0.2.1", "192.0.2.1"],
    ["2001:0db8:0:0:0:0:0:1", "[2001:db8::1]"],
    ["::1", "[::1]"]
  ])("canonicalizes %s", (input, expected) => {
    expect(canonicalizeClientIp(input)).toBe(expected.replaceAll("[", "").replaceAll("]", ""));
  });

  it.each(["", " 192.0.2.1", "192.168.001.1", "256.0.0.1", "fe80::1%eth0", "[::1]"])(
    "rejects non-canonical or unsafe IP input %s",
    (input) => expect(canonicalizeClientIp(input)).toBeNull()
  );

  it("hands the previous keyed digest to the current authority without storing raw IPs", async () => {
    const current = createTestPreparationHmacKey();
    const previous = createTestPreparationHmacKey();
    const fetch = vi.fn(() => Promise.resolve(Response.json({ ok: true })));
    const getByName = vi.fn(() => ({ fetch }));
    const env = createTestWorkerEnv({
      ABUSE_IP_HMAC_KEY: current,
      ABUSE_IP_HMAC_PREVIOUS_KEY: previous,
      ABUSE_CONTROL: { getByName } as unknown as WorkerEnv["ABUSE_CONTROL"]
    });

    const digests = await deriveIpDigests("192.0.2.10", env);
    expect(digests).toHaveLength(2);
    expect(digests[0]).not.toBe(digests[1]);
    expect(digests.every((digest) => /^ipd1_[A-Za-z0-9_-]{43}$/u.test(digest))).toBe(true);
    await expect(consumeExactIpQuota(env, "192.0.2.10", "passive", 1_000)).resolves.toEqual({
      allowed: true
    });
    expect(getByName).toHaveBeenCalledTimes(2);
    const serializedCalls = JSON.stringify([getByName.mock.calls, fetch.mock.calls]);
    expect(serializedCalls).not.toContain("192.0.2.10");
  });

  it("returns the current authority decision only after a successful rotation handoff", async () => {
    const paths: string[] = [];
    const fetch = vi.fn((request: Request) => {
      paths.push(new URL(request.url).pathname);
      return Promise.resolve(
        paths.length === 1
          ? Response.json({ ok: true })
          : Response.json({ ok: false, code: "rate_limited", retryAfter: 29 })
      );
    });
    const env = createTestWorkerEnv({
      ABUSE_IP_HMAC_PREVIOUS_KEY: createTestPreparationHmacKey(),
      ABUSE_CONTROL: {
        getByName: () => ({ fetch })
      } as unknown as WorkerEnv["ABUSE_CONTROL"]
    });
    await expect(consumeExactIpQuota(env, "198.51.100.7", "reveal", 2_000)).resolves.toEqual({
      allowed: false,
      retryAfter: 29
    });
    expect(paths).toEqual(["/internal/abuse/handoff", "/internal/abuse/quota"]);
  });

  it("fails closed without touching the current bucket when handoff is unavailable", async () => {
    const fetch = vi.fn((request: Request) => {
      void request;
      return Promise.resolve(Response.json({ ok: false, code: "unavailable" }, { status: 409 }));
    });
    const env = createTestWorkerEnv({
      ABUSE_IP_HMAC_PREVIOUS_KEY: createTestPreparationHmacKey(),
      ABUSE_CONTROL: {
        getByName: () => ({ fetch })
      } as unknown as WorkerEnv["ABUSE_CONTROL"]
    });

    await expect(
      consumeExactIpQuota(env, "203.0.113.9", "preparation", 3_000)
    ).rejects.toBeInstanceOf(AbuseControlDependencyError);
    expect(fetch).toHaveBeenCalledOnce();
    expect(new URL(fetch.mock.calls[0]?.[0].url ?? "https://invalid").pathname).toBe(
      "/internal/abuse/handoff"
    );
  });

  it("authenticates stateless challenge tickets across rotation before object access", async () => {
    const previousKey = createTestPreparationHmacKey();
    const issuedEnvironment = createTestWorkerEnv({ ABUSE_IP_HMAC_KEY: previousKey });
    const now = Date.now();
    const ticket = await createChallengeTicket(issuedEnvironment, "onceurl_prepare", now);
    const fetch = vi.fn((request: Request) => {
      void request;
      return Promise.resolve(Response.json({ ok: false, code: "unavailable" }, { status: 409 }));
    });
    const rotatedEnvironment = createTestWorkerEnv({
      ABUSE_IP_HMAC_PREVIOUS_KEY: previousKey,
      ABUSE_CONTROL: {
        getByName: () => ({ fetch })
      } as unknown as WorkerEnv["ABUSE_CONTROL"]
    });

    await expect(
      readChallengeStatus(rotatedEnvironment, ticket, "onceurl_prepare", now + 1)
    ).resolves.toBe(false);
    expect(fetch).toHaveBeenCalledTimes(2);

    fetch.mockClear();
    await expect(
      readChallengeStatus(rotatedEnvironment, ticket, "onceurl_access_code", now + 1)
    ).resolves.toBeNull();
    await expect(
      readChallengeStatus(
        rotatedEnvironment,
        `${ticket.slice(0, -1)}${ticket.endsWith("A") ? "B" : "A"}`,
        "onceurl_prepare",
        now + 1
      )
    ).resolves.toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });
});
