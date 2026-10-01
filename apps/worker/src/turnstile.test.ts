import { describe, expect, it, vi } from "vitest";
import {
  TURNSTILE_CHALLENGE_CLIENT,
  TurnstileDependencyError,
  turnstileChallengeDocument,
  verifyTurnstileToken
} from "./turnstile";

describe("isolated Turnstile verification", () => {
  it("validates exact action, hostname and five-minute freshness without sending an IP", async () => {
    const now = Date.parse("2026-08-28T12:00:00.000Z");
    const fetcher = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        Response.json({
          success: true,
          challenge_ts: "2026-08-28T11:59:59.000Z",
          hostname: "functional.example",
          action: "onceurl_prepare"
        })
      )
    );
    await expect(
      verifyTurnstileToken(
        "test-token",
        "onceurl_prepare",
        "functional.example",
        "test-secret",
        now,
        fetcher
      )
    ).resolves.toBe("verified");
    const request = fetcher.mock.calls[0];
    const init = request?.[1];
    expect(request?.[0]).toBe("https://challenges.cloudflare.com/turnstile/v0/siteverify");
    expect(typeof init?.body).toBe("string");
    const requestBody = typeof init?.body === "string" ? init.body : "";
    const parsedRequestBody: unknown = JSON.parse(requestBody);
    if (
      typeof parsedRequestBody !== "object" ||
      parsedRequestBody === null ||
      Array.isArray(parsedRequestBody)
    ) {
      throw new Error("Expected an object Siteverify request");
    }
    expect(parsedRequestBody).toMatchObject({
      secret: "test-secret",
      response: "test-token"
    });
    expect(typeof (parsedRequestBody as Record<string, unknown>).idempotency_key).toBe("string");
    expect(requestBody).not.toContain("remoteip");
  });

  it.each([
    ["wrong.example", "onceurl_prepare", "2026-08-28T11:59:59.000Z"],
    ["functional.example", "wrong_action", "2026-08-28T11:59:59.000Z"],
    ["functional.example", "onceurl_prepare", "2026-08-28T11:54:59.000Z"]
  ])("rejects a mismatched or stale success assertion", async (hostname, action, challengeTs) => {
    const fetcher = () =>
      Promise.resolve(
        Response.json({ success: true, challenge_ts: challengeTs, hostname, action })
      );
    await expect(
      verifyTurnstileToken(
        "test-token",
        "onceurl_prepare",
        "functional.example",
        "test-secret",
        Date.parse("2026-08-28T12:00:00.000Z"),
        fetcher
      )
    ).resolves.toBe("rejected");
  });

  it("fails closed for provider or configuration dependency errors", async () => {
    await expect(
      verifyTurnstileToken(
        "test-token",
        "onceurl_prepare",
        "functional.example",
        "test-secret",
        1_000,
        () => Promise.resolve(Response.json({ success: false, "error-codes": ["internal-error"] }))
      )
    ).rejects.toBeInstanceOf(TurnstileDependencyError);
  });

  it("rejects a provider-reported expired or reused single-use token", async () => {
    await expect(
      verifyTurnstileToken(
        "spent-token",
        "onceurl_prepare",
        "functional.example",
        "test-secret",
        Date.parse("2026-08-28T12:00:00.000Z"),
        () =>
          Promise.resolve(
            Response.json({ success: false, "error-codes": ["timeout-or-duplicate"] })
          )
      )
    ).resolves.toBe("rejected");
  });

  it("keeps challenge correlation in a fragment and removes it before provider execution", () => {
    const document = turnstileChallengeDocument("1x00000000000000000000AA");
    expect(document).toContain('src="/challenge/client.js"');
    expect(document).toContain("https://challenges.cloudflare.com/turnstile/v0/api.js");
    expect(TURNSTILE_CHALLENGE_CLIENT).toContain("window.location.hash.slice(1)");
    expect(TURNSTILE_CHALLENGE_CLIENT).toContain(
      'window.history.replaceState(null, "", window.location.pathname)'
    );
    expect(TURNSTILE_CHALLENGE_CLIENT).toContain('fetch("/api/v1/challenges/verify"');
    for (const forbidden of ["localStorage", "sessionStorage", "postMessage", "/s/", "/m/"]) {
      expect(`${document}\n${TURNSTILE_CHALLENGE_CLIENT}`).not.toContain(forbidden);
    }
  });
});
