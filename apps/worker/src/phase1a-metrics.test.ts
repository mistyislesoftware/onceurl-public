import { describe, expect, it, vi } from "vitest";
import {
  metricEvent,
  metricEventSchema,
  metricLag,
  metricLatency,
  sendMetric
} from "./phase1a-metrics";
import { observedRoute, observeResponse } from "./metrics-observations";
import type { WorkerEnv } from "./env";

describe("privacy-safe metric schema", () => {
  const event = metricEvent("local", 1000, {
    family: "reveal",
    category: "committed",
    routeTemplate: "claim"
  });
  it("rejects unknown schema, identity, payload and raw route fields rather than stripping them", () => {
    expect(event).not.toBeNull();
    for (const key of [
      "plaintext",
      "ciphertext",
      "fragmentKey",
      "bearer",
      "locator",
      "capabilityId",
      "accessCode",
      "accessCodeHash",
      "ip",
      "ipDigest",
      "userAgent",
      "creatorId",
      "recipientId",
      "cookie",
      "referrer",
      "turnstile",
      "url",
      "body",
      "operator"
    ]) {
      expect(metricEventSchema.safeParse({ ...event, [key]: "sensitive" }).success, key).toBe(
        false
      );
      expect(
        metricEventSchema.safeParse({
          ...event,
          dimensions: { ...event?.dimensions, [key]: "sensitive" }
        }).success,
        key
      ).toBe(false);
    }
    expect(metricEventSchema.safeParse({ ...event, schemaVersion: "future" }).success).toBe(false);
    expect(
      metricEventSchema.safeParse({ ...event, eventId: "capability-tracking-id" }).success
    ).toBe(false);
    expect(
      metricEvent("unconfigured", 1000, {
        family: "reveal",
        category: "committed",
        routeTemplate: "claim"
      })
    ).toBeNull();
  });
  it("normalizes routes before a sink and uses explicit bucket boundaries", () => {
    expect(observedRoute("/s/locator/bearer/claim", "POST")).toBe("claim");
    expect(observedRoute("/s/locator/bearer/claim/extra", "POST")).toBeNull();
    expect(observedRoute("/unknown/sensitive", "POST")).toBeNull();
    expect(observedRoute("/s/locator/bearer", "GET")).toBe("passive");
    expect(observedRoute("/s/locator/bearer", "HEAD")).toBe("passive");
    expect(observedRoute("/s/locator/bearer/claim", "GET")).toBeNull();
    expect(observedRoute("/api/v1/secrets", "HEAD")).toBeNull();
    expect(observedRoute("/s/locator/bearer", "POST")).toBeNull();
    expect(metricLatency(99)).toBe("under_100ms");
    expect(metricLatency(100)).toBe("100ms_to_1s");
    expect(metricLag(60_000)).toBe("1m_to_15m");
    expect(metricLag(86_400_000)).toBe("over_24h");
  });
  it("does not turn an observation outage into an authorization or response failure", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const env = {
      DEPLOYMENT_ENVIRONMENT: "local",
      ASYNC_JOBS: { send: vi.fn().mockRejectedValue(new Error("secret-raw-error")) }
    } as unknown as WorkerEnv;
    await expect(sendMetric(env, event)).resolves.toBeUndefined();
    await expect(observeResponse(env, "claim", 503, 1000, 2000)).resolves.toBeUndefined();
    expect(JSON.stringify(warn.mock.calls)).not.toContain("secret-raw-error");
    warn.mockRestore();
  });
  it("distinguishes response observation from committed release and never captures a response body", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const env = { DEPLOYMENT_ENVIRONMENT: "local", ASYNC_JOBS: { send } } as unknown as WorkerEnv;
    await observeResponse(env, "claim", 200, 1000, 1200);
    expect(send.mock.calls[0]?.[0]).toMatchObject({
      dimensions: { family: "reveal", category: "accepted_response", lifecycleTransition: "none" }
    });
    expect(send.mock.calls[1]?.[0]).toMatchObject({
      dimensions: { family: "cost", category: "worker_request" }
    });
  });
});
