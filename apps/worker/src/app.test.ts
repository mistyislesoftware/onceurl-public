import { describe, expect, it, vi } from "vitest";
import { app, createTestApp } from "./app";
import { createChallengeTicket } from "./abuse-control";
import type { WorkerEnv } from "./env";
import { readOriginConfiguration } from "./origins";
import { createTestWorkerEnv } from "./testing/env";

const env = createTestWorkerEnv({
  ASSETS: {
    fetch: (request) => {
      const url = new URL(request instanceof Request ? request.url : String(request));
      if (url.pathname === "/static.txt") {
        return Promise.resolve(
          new Response("static asset", {
            headers: { "set-cookie": "session=test; Domain=example.test" },
            status: 200
          })
        );
      }
      if (url.pathname === "/assets/app.js") {
        return Promise.resolve(
          new Response("export {};", {
            headers: {
              "access-control-allow-origin": "*",
              "content-type": "text/javascript",
              "service-worker-allowed": "/"
            }
          })
        );
      }
      if (url.pathname === "/") {
        return Promise.resolve(
          new Response('<!doctype html><div id="root"></div>', {
            headers: { "content-type": "text/html" }
          })
        );
      }
      if (url.pathname === "/test/asset-error") {
        throw new Error("sensitive asset exception detail");
      }
      return Promise.resolve(new Response("not found", { status: 404 }));
    },
    connect: () => {
      throw new Error("Unexpected ASSETS.connect call");
    }
  }
});

const LOCATOR = `loc1_${"c".repeat(48)}`;
const PUBLIC_BEARER = "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OWNER_BEARER = "own1_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
async function preparationRequestBody(workerEnv: WorkerEnv): Promise<string> {
  return JSON.stringify({
    expires_in_seconds: 86_400,
    challenge_id: await createChallengeTicket(workerEnv, "onceurl_prepare", Date.now())
  });
}

interface PreparedApiSecret {
  readonly creation: {
    readonly operation_id: string;
    readonly capability_id: string;
    readonly locator: string;
    readonly created_at: string;
    readonly policy_hash: string;
    readonly public_bearer: string;
    readonly owner_bearer: string;
  };
  readonly policy: Record<string, unknown> & {
    readonly expires_at: string;
    readonly post_consumption: {
      readonly behavior: "retain_capability";
      readonly retention: { readonly mode: "until_expiry" };
    };
  };
  readonly complete_by: string;
  readonly preparation_proof: string;
}

function capabilityRouteEnv(responseForRequest: (request: Request) => unknown): {
  readonly workerEnv: WorkerEnv;
  readonly getByName: ReturnType<typeof vi.fn>;
  readonly fetch: ReturnType<typeof vi.fn>;
} {
  const fetch = vi.fn(async (request: Request) =>
    Response.json(await responseForRequest(request), {
      headers: { "cache-control": "no-store" }
    })
  );
  const getByName = vi.fn(() => ({ fetch }));
  const capabilityState = { getByName } as unknown as NonNullable<WorkerEnv["CAPABILITY_STATE"]>;
  return {
    workerEnv: createTestWorkerEnv({ CAPABILITY_STATE: capabilityState }),
    getByName,
    fetch
  };
}

function completionBodyForPrepared(prepared: PreparedApiSecret) {
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

describe("worker health endpoints", () => {
  it("returns a small healthy JSON response from the canonical API route with a request ID", async () => {
    const response = await app.request("/api/v1/health", undefined, env);

    await expect(response.json()).resolves.toEqual({ ok: true, service: "onceurl-worker" });
    expect(response.status).toBe(200);
    expect(response.headers.get("X-Request-ID")).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(response.headers.get("X-Robots-Tag")).toBe("noindex, nofollow, noarchive");
    expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
    expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
  });

  it("generates separate request IDs for separate API requests", async () => {
    const first = await app.request("/api/v1/health", undefined, env);
    const second = await app.request("/api/v1/health", undefined, env);

    expect(first.headers.get("X-Request-ID")).toBeTruthy();
    expect(second.headers.get("X-Request-ID")).toBeTruthy();
    expect(first.headers.get("X-Request-ID")).not.toBe(second.headers.get("X-Request-ID"));
  });

  it("keeps the compatibility health alias functional without API request ID middleware", async () => {
    const response = await app.request("/health", undefined, env);

    await expect(response.json()).resolves.toEqual({ ok: true, service: "onceurl-worker" });
    expect(response.status).toBe(200);
    expect(response.headers.has("X-Request-ID")).toBe(false);
  });
});

describe("isolated security challenge boundary", () => {
  it("serves only the provider-scoped challenge document and fixed client", async () => {
    const document = await app.request("/challenge", undefined, env);
    const html = await document.text();
    expect(document.status).toBe(200);
    expect(document.headers.get("Content-Security-Policy")).toContain(
      "https://challenges.cloudflare.com"
    );
    expect(document.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(document.headers.get("Cache-Control")).toBe("no-store, private");
    expect(html).toContain("This separate page cannot see the secret");
    expect(html).not.toContain(LOCATOR);
    expect(html).not.toContain(PUBLIC_BEARER);

    const client = await app.request("/challenge/client.js", undefined, env);
    const source = await client.text();
    expect(client.headers.get("content-type")).toContain("text/javascript");
    expect(source).toContain('fetch("/api/v1/challenges/verify"');
    expect(source).not.toContain("localStorage");
    expect(source).not.toContain("postMessage");
  });

  it("mints preparation tickets without Durable Object state or public access-code minting", async () => {
    const getByName = vi.fn(() => ({
      fetch: () =>
        Promise.resolve(Response.json({ ok: false, code: "unavailable" }, { status: 409 }))
    }));
    const challengeEnv = createTestWorkerEnv({
      ABUSE_CONTROL: { getByName } as unknown as WorkerEnv["ABUSE_CONTROL"]
    });
    const created = await app.request(
      "/api/v1/challenges",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "onceurl_prepare" })
      },
      challengeEnv
    );
    expect(created.status).toBe(200);
    const ticket = await created.json<{ challenge_id: string; expires_in_seconds: number }>();
    expect(ticket).toMatchObject({ expires_in_seconds: 300 });
    expect(ticket.challenge_id).toMatch(/^chl2_p_\d{1,16}_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}$/u);
    expect(getByName).not.toHaveBeenCalled();
    const status = await app.request(
      "/api/v1/challenges/status",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          challenge_id: ticket.challenge_id,
          action: "onceurl_prepare"
        })
      },
      challengeEnv
    );
    await expect(status.json()).resolves.toEqual({ verified: false });

    const accessMint = await app.request(
      "/api/v1/challenges",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "onceurl_access_code" })
      },
      challengeEnv
    );
    expect(accessMint.status).toBe(400);
  });

  it("uses the native limiter only as a pre-Siteverify coarse preparation shedder", async () => {
    const nativeLimit = vi.fn(() => Promise.resolve({ success: false }));
    const providerFetch = vi.spyOn(globalThis, "fetch").mockImplementation(() => {
      throw new Error("Siteverify must not run after the coarse shedder rejects");
    });
    const abuseControl = {
      getByName: () => ({
        fetch: (request: Request) =>
          Promise.resolve(
            Response.json(
              new URL(request.url).pathname === "/internal/challenge/status"
                ? { ok: true, verified: false }
                : { ok: true }
            )
          )
      })
    } as unknown as WorkerEnv["ABUSE_CONTROL"];

    const challengeEnv = {
      ...env,
      ABUSE_CONTROL: abuseControl,
      PREPARATION_FLOOD_LIMITER: { limit: nativeLimit } as unknown as RateLimit
    };
    const response = await app.request(
      "/api/v1/challenges/verify",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "CF-Connecting-IP": "192.0.2.44"
        },
        body: JSON.stringify({
          challenge_id: await createChallengeTicket(challengeEnv, "onceurl_prepare", Date.now()),
          action: "onceurl_prepare",
          token: "provider-token"
        })
      },
      challengeEnv
    );

    providerFetch.mockRestore();
    expect(response.status).toBe(429);
    expect(response.headers.get("Retry-After")).toBe("60");
    expect(nativeLimit).toHaveBeenCalledOnce();
    expect(JSON.stringify(nativeLimit.mock.calls)).not.toContain("192.0.2.44");
    expect(providerFetch).not.toHaveBeenCalled();
  });

  it("creates verified challenge state only after the shedder and Siteverify, without double-counting", async () => {
    const events: string[] = [];
    let verified = false;
    const abuseControl = {
      getByName: () => ({
        fetch: (request: Request) => {
          const path = new URL(request.url).pathname;
          if (path === "/internal/challenge/status") {
            events.push("status");
            return Promise.resolve(
              verified
                ? Response.json({ ok: true, verified: true })
                : Response.json({ ok: false, code: "unavailable" }, { status: 409 })
            );
          }
          expect(path).toBe("/internal/challenge/create-verified");
          events.push("create-verified");
          verified = true;
          return Promise.resolve(Response.json({ ok: true }));
        }
      })
    } as unknown as WorkerEnv["ABUSE_CONTROL"];
    const nativeLimit = vi.fn(() => {
      events.push("shedder");
      return Promise.resolve({ success: true });
    });
    const challengeEnv = {
      ...env,
      ABUSE_CONTROL: abuseControl,
      PREPARATION_FLOOD_LIMITER: { limit: nativeLimit } as unknown as RateLimit
    };
    const now = Date.now();
    const challengeId = await createChallengeTicket(challengeEnv, "onceurl_prepare", now);
    const providerFetch = vi.spyOn(globalThis, "fetch").mockImplementation(() => {
      events.push("siteverify");
      return Promise.resolve(
        Response.json({
          success: true,
          challenge_ts: new Date(now).toISOString(),
          hostname: "localhost",
          action: "onceurl_prepare"
        })
      );
    });
    const verifyRequest = {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "CF-Connecting-IP": "192.0.2.45"
      },
      body: JSON.stringify({
        challenge_id: challengeId,
        action: "onceurl_prepare",
        token: "provider-token"
      })
    };

    try {
      const first = await app.request("/api/v1/challenges/verify", verifyRequest, challengeEnv);
      expect(first.status).toBe(200);
      await expect(first.json()).resolves.toEqual({ verified: true });
      expect(events).toEqual(["status", "shedder", "siteverify", "create-verified"]);

      events.length = 0;
      const repeated = await app.request("/api/v1/challenges/verify", verifyRequest, challengeEnv);
      expect(repeated.status).toBe(200);
      await expect(repeated.json()).resolves.toEqual({ verified: true });
      expect(events).toEqual(["status"]);
      expect(nativeLimit).toHaveBeenCalledOnce();
      expect(providerFetch).toHaveBeenCalledOnce();
    } finally {
      providerFetch.mockRestore();
    }
  });
});

describe("API error envelope", () => {
  it("returns the standard JSON error envelope for the exact /api boundary", async () => {
    const response = await app.request("/api", undefined, env);
    const requestId = response.headers.get("X-Request-ID");

    expect(response.status).toBe(404);
    expect(response.headers.get("content-type")).toContain("application/json");
    await expect(response.json()).resolves.toEqual({
      error: {
        code: "not_found",
        message: "The requested API resource was not found.",
        request_id: requestId,
        details: {}
      }
    });
  });

  it("returns the standard JSON error envelope for unknown /api/* routes", async () => {
    const response = await app.request("/api/v1/missing", undefined, env);
    const body = await response.json();

    expect(response.status).toBe(404);
    expect(body).toEqual({
      error: {
        code: "not_found",
        message: "The requested API resource was not found.",
        request_id: response.headers.get("X-Request-ID"),
        details: {}
      }
    });
  });

  it("sanitizes unexpected API exceptions", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await createTestApp().request("/api/v1/test/unhandled-error", undefined, env);
    const bodyText = await response.text();
    const loggedArguments = consoleError.mock.calls;
    const loggedText = JSON.stringify(loggedArguments);
    consoleError.mockRestore();

    expect(response.status).toBe(500);
    expect(JSON.parse(bodyText)).toEqual({
      error: {
        code: "internal_error",
        message: "An unexpected error occurred. Please try again later.",
        request_id: response.headers.get("X-Request-ID"),
        details: {}
      }
    });
    expect(bodyText).not.toContain("sensitive internal exception detail");
    expect(bodyText).not.toContain("Error:");
    expect(loggedText).not.toContain("sensitive internal exception detail");
    expect(loggedText).not.toContain("Error:");
    expect(loggedText).toContain(String(response.headers.get("X-Request-ID")));
    expect(loggedArguments).toEqual([
      [
        "Unhandled functional route error",
        {
          requestId: response.headers.get("X-Request-ID"),
          routeClass: "api",
          routeTemplate: "/api/*"
        }
      ]
    ]);
  });
});

describe("zero-knowledge secret creation API", () => {
  it("requires a verified challenge and exact successful-preparation IP quota", async () => {
    const routed = capabilityRouteEnv(() => {
      throw new Error("Capability object must not be reached during preparation");
    });
    const missingChallenge = await app.request(
      "/api/v1/secrets/prepare",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ expires_in_seconds: 86_400 })
      },
      routed.workerEnv
    );
    expect(missingChallenge.status).toBe(400);

    const abuseControl = {
      getByName: () => ({
        fetch: (request: Request) => {
          const path = new URL(request.url).pathname;
          return Promise.resolve(
            Response.json(
              path === "/internal/abuse/quota"
                ? { ok: false, code: "rate_limited", retryAfter: 23 }
                : path === "/internal/challenge/status"
                  ? { ok: true, verified: true }
                  : { ok: true }
            )
          );
        }
      })
    } as unknown as WorkerEnv["ABUSE_CONTROL"];
    const limited = await app.request(
      "/api/v1/secrets/prepare",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "CF-Connecting-IP": "198.51.100.22"
        },
        body: await preparationRequestBody(routed.workerEnv)
      },
      { ...routed.workerEnv, ABUSE_CONTROL: abuseControl }
    );
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBe("23");
    expect(routed.getByName).not.toHaveBeenCalled();
  });

  it("prepares without persistence and completes with hashes and ciphertext only", async () => {
    const routed = capabilityRouteEnv(async (request) => {
      expect(new URL(request.url).pathname).toBe("/internal/capability/create");
      const command = await request.json<Record<string, unknown>>();
      const commandText = JSON.stringify(command);
      expect(command.operationId).toBeTypeOf("string");
      expect(command.operationId).toMatch(/^op1_/u);
      expect(command.capabilityId).toBeTypeOf("string");
      expect(command.capabilityId).toMatch(/^cap1_/u);
      expect(command.locator).toBeTypeOf("string");
      expect(command.locator).toMatch(/^loc1_/u);
      expect(command.publicBearerSecretHash).toBeTypeOf("string");
      expect(command.publicBearerSecretHash).toMatch(/^bh1_/u);
      expect(command.ownerBearerSecretHash).toBeTypeOf("string");
      expect(command.ownerBearerSecretHash).toMatch(/^bh1_/u);
      expect(command.ciphertextEnvelope).toMatchObject({ version: "ouzk-v1" });
      expect(commandText).not.toContain(PUBLIC_BEARER);
      expect(commandText).not.toContain(OWNER_BEARER);
      expect(commandText).not.toContain("plaintext-never-sent");
      expect(commandText).not.toContain("#k=");
      return { ok: true };
    });
    const preparedResponse = await app.request(
      "/api/v1/secrets/prepare",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: await preparationRequestBody(routed.workerEnv)
      },
      routed.workerEnv
    );
    expect(preparedResponse.status).toBe(200);
    const prepared = await preparedResponse.json<{
      creation: {
        operation_id: string;
        capability_id: string;
        locator: string;
        created_at: string;
        policy_hash: string;
        public_bearer: string;
        owner_bearer: string;
      };
      policy: Record<string, unknown> & { expires_at: string };
      complete_by: string;
      preparation_proof: string;
    }>();
    expect(routed.getByName).not.toHaveBeenCalled();
    const envelope = {
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
    };
    const completionBody = {
      creation: prepared.creation,
      policy: prepared.policy,
      complete_by: prepared.complete_by,
      preparation_proof: prepared.preparation_proof,
      ciphertext_envelope: envelope
    };
    const completionResponse = await app.request(
      "/api/v1/secrets",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": prepared.creation.operation_id
        },
        body: JSON.stringify(completionBody)
      },
      routed.workerEnv
    );

    expect(completionResponse.status).toBe(200);
    const completed = await completionResponse.json<Record<string, string>>();
    expect(completed).toEqual({
      recipient_path: `/s/${prepared.creation.locator}/${prepared.creation.public_bearer}`,
      owner_path: `/m/${prepared.creation.locator}/${prepared.creation.owner_bearer}`,
      expires_at: prepared.policy.expires_at
    });
    expect(JSON.stringify(completed)).not.toContain("#k=");
    expect(routed.getByName).toHaveBeenCalledOnce();
    expect(routed.getByName).toHaveBeenCalledWith(prepared.creation.locator);
  });

  it("rejects missing idempotency, plaintext/extra fields, and oversized completion before object access", async () => {
    const routed = capabilityRouteEnv(() => {
      throw new Error("Capability object must not be called");
    });
    const invalid = {
      creation: {},
      policy: {},
      ciphertext_envelope: {},
      plaintext: "must not be accepted"
    };
    const responses = await Promise.all([
      app.request(
        "/api/v1/secrets",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(invalid)
        },
        routed.workerEnv
      ),
      app.request(
        "/api/v1/secrets",
        {
          method: "POST",
          headers: { "content-type": "application/json", "idempotency-key": "op_invalid" },
          body: JSON.stringify({ padding: "x".repeat(110 * 1024) })
        },
        routed.workerEnv
      )
    ]);
    expect(responses.map((response) => response.status)).toEqual([400, 400]);
    for (const response of responses) {
      expect(await response.text()).not.toContain("must not be accepted");
    }
    expect(routed.getByName).not.toHaveBeenCalled();
  });

  it("fails closed without exposing missing or malformed preparation signing configuration", async () => {
    for (const signingKey of [undefined, "", "malformed-configuration"]) {
      const routed = capabilityRouteEnv(() => {
        throw new Error("Capability object must not be called");
      });
      const response = await app.request(
        "/api/v1/secrets/prepare",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: await preparationRequestBody(routed.workerEnv)
        },
        {
          ...routed.workerEnv,
          SECRET_PREPARATION_HMAC_KEY: signingKey as unknown as string
        }
      );
      const body = await response.text();
      expect(response.status).toBe(503);
      expect(JSON.parse(body)).toMatchObject({ error: { code: "internal_error", details: {} } });
      expect(body).not.toContain("SECRET_PREPARATION_HMAC_KEY");
      expect(body).not.toContain("configuration");
      expect(routed.getByName).not.toHaveBeenCalled();
    }
  });

  it("fails preparation and completion closed for malformed previous-key configuration", async () => {
    const routed = capabilityRouteEnv(() => {
      throw new Error("Capability object must not be called");
    });
    const malformedPreviousEnvironment = {
      ...routed.workerEnv,
      SECRET_PREPARATION_HMAC_PREVIOUS_KEY: "malformed-configuration"
    };
    const preparedResponse = await app.request(
      "/api/v1/secrets/prepare",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: await preparationRequestBody(routed.workerEnv)
      },
      routed.workerEnv
    );
    expect(preparedResponse.status).toBe(200);
    const prepared = await preparedResponse.json<PreparedApiSecret>();
    const rejectedPreparation = await app.request(
      "/api/v1/secrets/prepare",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: await preparationRequestBody(malformedPreviousEnvironment)
      },
      malformedPreviousEnvironment
    );
    expect(rejectedPreparation.status).toBe(503);
    await expect(rejectedPreparation.json()).resolves.toMatchObject({
      error: { code: "internal_error", details: {} }
    });
    const response = await app.request(
      "/api/v1/secrets",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": prepared.creation.operation_id
        },
        body: JSON.stringify(completionBodyForPrepared(prepared))
      },
      malformedPreviousEnvironment
    );
    const responseBody = await response.text();
    expect(response.status).toBe(503);
    expect(JSON.parse(responseBody)).toMatchObject({
      error: { code: "internal_error", details: {} }
    });
    expect(responseBody).not.toContain("SECRET_PREPARATION_HMAC_PREVIOUS_KEY");
    expect(responseBody).not.toContain("configuration");
    expect(routed.getByName).not.toHaveBeenCalled();
  });

  it("rejects a forged preparation proof before Durable Object routing", async () => {
    const routed = capabilityRouteEnv(() => {
      throw new Error("Capability object must not be called");
    });
    const preparedResponse = await app.request(
      "/api/v1/secrets/prepare",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: await preparationRequestBody(routed.workerEnv)
      },
      routed.workerEnv
    );
    const prepared = await preparedResponse.json<PreparedApiSecret>();
    const body = completionBodyForPrepared(prepared);
    const proofPayload = prepared.preparation_proof.slice("prep1_".length);
    const replacement = proofPayload[0] === "A" ? "C" : "A";
    const response = await app.request(
      "/api/v1/secrets",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": prepared.creation.operation_id
        },
        body: JSON.stringify({
          ...body,
          preparation_proof: `prep1_${replacement}${proofPayload.slice(1)}`
        })
      },
      routed.workerEnv
    );
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "invalid_request", details: {} }
    });
    expect(routed.getByName).not.toHaveBeenCalled();
  });

  it("keeps existing capability routes independent of preparation-signing configuration", async () => {
    const routed = capabilityRouteEnv(async (request) => {
      const path = new URL(request.url).pathname;
      if (path === "/internal/capability/create") return { ok: true };
      if (path === "/internal/capability/authorize") {
        const command = await request.json<{ authority: "public" | "owner" }>();
        return {
          ok: true,
          authority: command.authority,
          capability: {
            kind: "secret",
            state: "ACTIVE",
            createdAt: "2026-08-01T00:00:00.000Z",
            expiresAt: null,
            isAvailable: true,
            policy: { maxConsumptions: 1 },
            accessCodeRequired: false,
            ...(command.authority === "owner"
              ? { events: [{ type: "created", occurredAt: 1_754_006_400_000 }] }
              : {})
          }
        };
      }
      throw new Error("Unexpected capability command");
    });
    const preparedResponse = await app.request(
      "/api/v1/secrets/prepare",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: await preparationRequestBody(routed.workerEnv)
      },
      routed.workerEnv
    );
    const prepared = await preparedResponse.json<PreparedApiSecret>();
    const completion = await app.request(
      "/api/v1/secrets",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": prepared.creation.operation_id
        },
        body: JSON.stringify(completionBodyForPrepared(prepared))
      },
      routed.workerEnv
    );
    expect(completion.status).toBe(200);

    const unrelatedMalformedEnvironment = {
      ...routed.workerEnv,
      SECRET_PREPARATION_HMAC_KEY: "malformed-current",
      SECRET_PREPARATION_HMAC_PREVIOUS_KEY: "malformed-previous"
    };
    const inspection = await app.request(
      `/s/${prepared.creation.locator}/${prepared.creation.public_bearer}`,
      { headers: { accept: "application/json" } },
      unrelatedMalformedEnvironment
    );
    expect(inspection.status).toBe(200);
    await expect(inspection.json()).resolves.toMatchObject({
      capability: { state: "ACTIVE", is_available: true }
    });

    const ownerInspection = await app.request(
      `/m/${prepared.creation.locator}/${prepared.creation.owner_bearer}`,
      { headers: { accept: "application/json" } },
      unrelatedMalformedEnvironment
    );
    expect(ownerInspection.status).toBe(200);
    await expect(ownerInspection.json()).resolves.toMatchObject({
      capability: {
        state: "ACTIVE",
        is_available: true,
        events: [{ type: "created", occurred_at: "2025-08-01T00:00:00.000Z" }]
      }
    });
  });
});

describe("direct capability routing", () => {
  it("fails passive requests closed when exact IP accounting is limited or unavailable", async () => {
    const capability = capabilityRouteEnv(() => {
      throw new Error("Capability object must not be reached after an IP quota failure");
    });
    const abuseBinding = (result: unknown) =>
      ({
        getByName: () => ({ fetch: () => Promise.resolve(Response.json(result)) })
      }) as unknown as WorkerEnv["ABUSE_CONTROL"];
    const limited = await app.request(
      `/s/${LOCATOR}/${PUBLIC_BEARER}`,
      { headers: { "CF-Connecting-IP": "192.0.2.20" } },
      {
        ...capability.workerEnv,
        ABUSE_CONTROL: abuseBinding({ ok: false, code: "rate_limited", retryAfter: 17 })
      }
    );
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBe("17");
    await expect(limited.json()).resolves.toMatchObject({ error: { code: "rate_limited" } });

    const unavailable = await app.request(
      `/s/${LOCATOR}/${PUBLIC_BEARER}`,
      { headers: { "CF-Connecting-IP": "192.0.2.20" } },
      {
        ...capability.workerEnv,
        ABUSE_CONTROL: {
          getByName: () => ({ fetch: () => Promise.reject(new Error("dependency down")) })
        } as unknown as WorkerEnv["ABUSE_CONTROL"]
      }
    );
    expect(unavailable.status).toBe(503);
    expect(capability.getByName).not.toHaveBeenCalled();
  });

  it("requires the trusted connecting-IP header outside local development", async () => {
    const capability = capabilityRouteEnv(() => {
      throw new Error("Capability object must not be reached without a trusted client IP");
    });
    const response = await app.request(
      `https://functional.staging.invalid/s/${LOCATOR}/${PUBLIC_BEARER}`,
      undefined,
      {
        ...capability.workerEnv,
        DEPLOYMENT_ENVIRONMENT: "staging",
        MARKETING_ORIGIN: "https://marketing.staging.invalid",
        FUNCTIONAL_ORIGIN: "https://functional.staging.invalid"
      }
    );
    expect(response.status).toBe(503);
    expect(capability.getByName).not.toHaveBeenCalled();
  });

  it.each([
    ["public", `/s/${LOCATOR}/${PUBLIC_BEARER}`],
    ["owner", `/m/${LOCATOR}/${OWNER_BEARER}`]
  ] as const)("routes valid %s authority directly by locator", async (authority, path) => {
    const routed = capabilityRouteEnv(async (request) => {
      expect(new URL(request.url).pathname).toBe("/internal/capability/authorize");
      expect(request.method).toBe("POST");
      const command = await request.json<Record<string, unknown>>();
      expect(command.authority).toBe(authority);
      expect(command.bearerSecret).toBe(authority === "public" ? PUBLIC_BEARER : OWNER_BEARER);
      expect(command.now).toBeTypeOf("number");
      return {
        ok: true,
        authority,
        capability: {
          kind: "secret",
          state: "ACTIVE",
          createdAt: "2026-08-01T00:00:00.000Z",
          expiresAt: null,
          isAvailable: true,
          policy: { maxConsumptions: 1 },
          accessCodeRequired: false,
          ...(authority === "owner"
            ? { events: [{ type: "created", occurredAt: 1_754_006_400_000 }] }
            : {})
        }
      };
    });

    const response = await app.request(path, undefined, routed.workerEnv);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(JSON.parse(body)).toEqual({
      capability: {
        kind: "secret",
        state: "ACTIVE",
        created_at: "2026-08-01T00:00:00.000Z",
        expires_at: null,
        is_available: true,
        policy: { max_consumptions: 1 },
        access_code_required: false,
        ...(authority === "owner"
          ? { events: [{ type: "created", occurred_at: "2025-08-01T00:00:00.000Z" }] }
          : {})
      }
    });
    expect(routed.getByName).toHaveBeenCalledOnce();
    expect(routed.getByName).toHaveBeenCalledWith(LOCATOR);
    expect(body).not.toContain(LOCATOR);
    expect(body).not.toContain(PUBLIC_BEARER);
    expect(body).not.toContain(OWNER_BEARER);
    expect(response.headers.get("Cache-Control")).toBe("no-store, private");
    expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
  });

  it("keeps public HEAD passive and body-free", async () => {
    const routed = capabilityRouteEnv(() => ({
      ok: true,
      authority: "public",
      capability: {
        kind: "secret",
        state: "ACTIVE",
        createdAt: "2026-08-01T00:00:00.000Z",
        expiresAt: null,
        isAvailable: true,
        policy: { maxConsumptions: 1 },
        accessCodeRequired: false
      }
    }));

    const response = await app.request(
      `/s/${LOCATOR}/${PUBLIC_BEARER}`,
      { method: "HEAD" },
      routed.workerEnv
    );

    expect(response.status).toBe(200);
    expect(await response.text()).toBe("");
    expect(routed.fetch).toHaveBeenCalledOnce();
    expect(new URL((routed.fetch.mock.calls[0]?.[0] as Request).url).pathname).toBe(
      "/internal/capability/authorize"
    );
  });

  it("authorizes passive browser HTML without claiming or exposing metadata", async () => {
    const routed = capabilityRouteEnv(() => ({
      ok: true,
      authority: "public",
      capability: {
        kind: "secret",
        state: "ACTIVE",
        createdAt: "2026-08-01T00:00:00.000Z",
        expiresAt: null,
        isAvailable: true,
        policy: { maxConsumptions: 1 },
        accessCodeRequired: false
      }
    }));
    const response = await app.request(
      `/s/${LOCATOR}/${PUBLIC_BEARER}`,
      { headers: { accept: "text/html,application/xhtml+xml" } },
      { ...routed.workerEnv, ASSETS: env.ASSETS }
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(await response.text()).toContain('id="root"');
    expect(routed.getByName).toHaveBeenCalledOnce();
    expect(new URL((routed.fetch.mock.calls[0]?.[0] as Request).url).pathname).toBe(
      "/internal/capability/authorize"
    );
    expect(response.headers.get("Cache-Control")).toBe("no-store, private");
    expect(response.headers.get("Pragma")).toBe("no-cache");
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(response.headers.get("X-Robots-Tag")).toBe("noindex, nofollow, noarchive");
    expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
  });

  it("makes unknown, wrong and cross-authority bearers externally indistinguishable", async () => {
    const routed = capabilityRouteEnv(async (request) => {
      const command: unknown = await request.json();
      const bearerSecret =
        typeof command === "object" && command !== null && "bearerSecret" in command
          ? command.bearerSecret
          : undefined;
      return {
        ok: false,
        code: bearerSecret === PUBLIC_BEARER ? "not_found" : "unauthorized"
      };
    });
    const otherPublic = "pub1_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    const otherOwner = "own1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    const unknown = await app.request(
      `/s/${LOCATOR}/${PUBLIC_BEARER}`,
      undefined,
      routed.workerEnv
    );
    const wrong = await app.request(`/s/${LOCATOR}/${otherPublic}`, undefined, routed.workerEnv);
    const substituted = await app.request(
      `/s/${LOCATOR}/${OWNER_BEARER}`,
      undefined,
      routed.workerEnv
    );
    const wrongOwner = await app.request(
      `/m/${LOCATOR}/${otherOwner}`,
      undefined,
      routed.workerEnv
    );
    const publicAsOwner = await app.request(
      `/m/${LOCATOR}/${PUBLIC_BEARER}`,
      undefined,
      routed.workerEnv
    );
    const malformedLocator = await app.request(
      `/s/not-a-locator/${PUBLIC_BEARER}`,
      undefined,
      routed.workerEnv
    );
    const locatorOnly = await app.request(`/s/${LOCATOR}`, undefined, routed.workerEnv);
    const bodies = await Promise.all([
      unknown.json(),
      wrong.json(),
      substituted.json(),
      wrongOwner.json(),
      publicAsOwner.json(),
      malformedLocator.json()
    ]);

    expect([
      unknown.status,
      wrong.status,
      substituted.status,
      wrongOwner.status,
      publicAsOwner.status,
      malformedLocator.status,
      locatorOnly.status
    ]).toEqual([404, 404, 404, 404, 404, 404, 404]);
    for (const body of bodies) {
      expect(body).toMatchObject({ error: { code: "not_found", details: {} } });
      expect(JSON.stringify(body)).not.toContain("unauthorized");
    }
    expect(await locatorOnly.text()).toBe("Not found");
    expect(routed.getByName).toHaveBeenCalledTimes(3);
  });

  it("redacts the route and bearer when object access throws", async () => {
    const routed = capabilityRouteEnv(() => {
      throw new Error(`sensitive ${LOCATOR} ${PUBLIC_BEARER}`);
    });
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);

    const response = await app.request(
      `/s/${LOCATOR}/${PUBLIC_BEARER}`,
      undefined,
      routed.workerEnv
    );
    const responseText = await response.text();
    const loggedText = JSON.stringify(consoleError.mock.calls);
    consoleError.mockRestore();

    const requestId = response.headers.get("X-Request-ID");
    expect(response.status).toBe(503);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(JSON.parse(responseText)).toEqual({
      error: {
        code: "internal_error",
        message: "An unexpected error occurred. Please try again later.",
        request_id: requestId,
        details: {}
      }
    });
    expect(requestId).toBeTruthy();
    expect(responseText).not.toContain(LOCATOR);
    expect(responseText).not.toContain(PUBLIC_BEARER);
    expect(loggedText).not.toContain(LOCATOR);
    expect(loggedText).not.toContain(PUBLIC_BEARER);
    expect(loggedText).toContain('"routeTemplate":"/:capability/*"');
  });

  it("claims through the same named object without a D1 lookup", async () => {
    const routed = capabilityRouteEnv(async (request) => {
      expect(new URL(request.url).pathname).toBe("/internal/capability/claim");
      const command: unknown = await request.json();
      expect(command).toMatchObject({
        publicBearerSecret: PUBLIC_BEARER,
        operationId: "op-route-claim",
        nonce: "nonce-route-claim"
      });
      expect(
        typeof command === "object" &&
          command !== null &&
          "now" in command &&
          typeof command.now === "number"
      ).toBe(true);
      return {
        ok: true,
        outcome: "released",
        ciphertextEnvelope: { version: "ouzk-v1", ciphertext: "synthetic" }
      };
    });

    const response = await app.request(
      `/s/${LOCATOR}/${PUBLIC_BEARER}/claim`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ operation_id: "op-route-claim", nonce: "nonce-route-claim" })
      },
      routed.workerEnv
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      outcome: "released",
      ciphertext_envelope: { version: "ouzk-v1", ciphertext: "synthetic" }
    });
    expect(routed.getByName).toHaveBeenCalledWith(LOCATOR);
  });

  it("mints an access-code ticket only after the capability requires a challenge", async () => {
    const routed = capabilityRouteEnv(() => ({ ok: false, code: "challenge_required" }));
    const abuseFetch = vi.fn((request: Request) => {
      expect(new URL(request.url).pathname).toBe("/internal/abuse/quota");
      return Promise.resolve(Response.json({ ok: true }));
    });
    const abuseGetByName = vi.fn(() => ({ fetch: abuseFetch }));
    const workerEnv = {
      ...routed.workerEnv,
      ABUSE_CONTROL: { getByName: abuseGetByName } as unknown as WorkerEnv["ABUSE_CONTROL"]
    };

    const response = await app.request(
      `/s/${LOCATOR}/${PUBLIC_BEARER}/claim`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          operation_id: "op-access-challenge",
          nonce: "nonce-access-challenge",
          access_code: "wrong"
        })
      },
      workerEnv
    );

    expect(response.status).toBe(403);
    const body = await response.json<{
      error: {
        code: string;
        details: { challenge_id: string; expires_in_seconds: number };
      };
    }>();
    expect(body).toMatchObject({
      error: {
        code: "verification_required",
        details: {
          expires_in_seconds: 300
        }
      }
    });
    expect(body.error.details.challenge_id).toMatch(
      /^chl2_a_\d{1,16}_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}$/u
    );
    expect(abuseGetByName).toHaveBeenCalledOnce();
    expect(abuseFetch).toHaveBeenCalledOnce();
    expect(routed.getByName).toHaveBeenCalledWith(LOCATOR);
  });

  it("fails reveal closed before capability state when exact IP accounting is unavailable", async () => {
    const routed = capabilityRouteEnv(() => {
      throw new Error("Capability object must not be reached after an IP limiter failure");
    });
    const response = await app.request(
      `/s/${LOCATOR}/${PUBLIC_BEARER}/claim`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "CF-Connecting-IP": "192.0.2.30"
        },
        body: JSON.stringify({ operation_id: "op-limited", nonce: "nonce-limited" })
      },
      {
        ...routed.workerEnv,
        ABUSE_CONTROL: {
          getByName: () => ({ fetch: () => Promise.reject(new Error("dependency down")) })
        } as unknown as WorkerEnv["ABUSE_CONTROL"]
      }
    );

    expect(response.status).toBe(503);
    expect(routed.getByName).not.toHaveBeenCalled();
  });

  it("rejects malformed and oversized claim bodies before object access", async () => {
    const routed = capabilityRouteEnv(() => {
      throw new Error("Capability object must not be called");
    });
    const malformed = await app.request(
      `/s/${LOCATOR}/${PUBLIC_BEARER}/claim`,
      { method: "POST", headers: { "content-type": "application/json" }, body: "{" },
      routed.workerEnv
    );
    const oversized = await app.request(
      `/s/${LOCATOR}/${PUBLIC_BEARER}/claim`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ operation_id: "x".repeat(2_100), nonce: "n" })
      },
      routed.workerEnv
    );
    const oversizedUtf8Code = await app.request(
      `/s/${LOCATOR}/${PUBLIC_BEARER}/claim`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          operation_id: "op-oversized-code",
          nonce: "nonce-oversized-code",
          access_code: "🔐".repeat(33)
        })
      },
      routed.workerEnv
    );

    expect(malformed.status).toBe(400);
    expect(oversized.status).toBe(400);
    expect(oversizedUtf8Code.status).toBe(400);
    expect(routed.getByName).not.toHaveBeenCalled();
  });
});

describe("non-API error boundary", () => {
  it("returns a sanitized application-policy response when asset lookup throws", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await app.request("/test/asset-error", undefined, env);
    const body = await response.text();
    const loggedText = JSON.stringify(consoleError.mock.calls);
    consoleError.mockRestore();

    expect(response.status).toBe(500);
    expect(body).toBe("Internal server error");
    expect(body).not.toContain("sensitive asset exception detail");
    expect(response.headers.get("X-Request-ID")).toBeTruthy();
    expect(response.headers.get("Cache-Control")).toBe("private, no-store");
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(response.headers.get("X-Robots-Tag")).toBe("noindex, nofollow");
    expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'self'");
    expect(response.headers.has("Set-Cookie")).toBe(false);
    expect(loggedText).not.toContain("sensitive asset exception detail");
    expect(loggedText).not.toContain("/test/asset-error");
    expect(loggedText).toContain('"routeTemplate":"/application/*"');
  });

  it("returns the documented sanitized capability 503 when a future handler throws", async () => {
    const assetsFetch = vi.fn(() => Promise.resolve(new Response("unexpected")));
    const capabilityEnv = createTestWorkerEnv({
      ASSETS: {
        fetch: assetsFetch,
        connect: () => {
          throw new Error("Unexpected ASSETS.connect call");
        }
      }
    });
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await createTestApp().request(
      `/s/${LOCATOR}/${PUBLIC_BEARER}/test/unhandled-error`,
      undefined,
      capabilityEnv
    );
    const bodyText = await response.text();
    const loggedText = JSON.stringify(consoleError.mock.calls);
    consoleError.mockRestore();

    const requestId = response.headers.get("X-Request-ID");
    expect(response.status).toBe(503);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(JSON.parse(bodyText)).toEqual({
      error: {
        code: "internal_error",
        message: "An unexpected error occurred. Please try again later.",
        request_id: requestId,
        details: {}
      }
    });
    expect(requestId).toBeTruthy();
    expect(bodyText).not.toContain(LOCATOR);
    expect(bodyText).not.toContain(PUBLIC_BEARER);
    expect(bodyText).not.toContain("sensitive capability exception detail");
    expect(response.headers.get("Cache-Control")).toBe("no-store, private");
    expect(response.headers.get("Pragma")).toBe("no-cache");
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(response.headers.get("X-Robots-Tag")).toBe("noindex, nofollow, noarchive");
    expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
    expect(response.headers.has("Set-Cookie")).toBe(false);
    expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
    expect(loggedText).not.toContain(LOCATOR);
    expect(loggedText).not.toContain(PUBLIC_BEARER);
    expect(loggedText).not.toContain("sensitive capability exception detail");
    expect(loggedText).toContain('"routeTemplate":"/:capability/*"');
    expect(assetsFetch).not.toHaveBeenCalled();
  });
});

describe("non-API routing", () => {
  it("serves static assets before SPA fallback", async () => {
    const response = await app.request("/static.txt", undefined, env);

    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe("static asset");
    expect(response.headers.get("Cache-Control")).toBe("private, no-store");
    expect(response.headers.has("Set-Cookie")).toBe(false);
  });

  it("keeps SPA fallback for non-API client routes", async () => {
    const response = await app.request("/dashboard/future-route", undefined, env);

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.get("Cache-Control")).toBe("private, no-store");
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(response.headers.get("X-Robots-Tag")).toBe("noindex, nofollow");
    expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'self'");
    await expect(response.text()).resolves.toContain('id="root"');
  });

  it("applies immutable same-origin policy to functional static assets", async () => {
    const response = await app.request("/assets/app.js", undefined, env);

    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable");
    expect(response.headers.get("Cross-Origin-Resource-Policy")).toBe("same-origin");
    expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
    expect(response.headers.has("Service-Worker-Allowed")).toBe(false);
  });

  it("keeps capability documents no-store, no-referrer, noindex, cookie-free and self-only", async () => {
    const assetsFetch = vi.fn(() => Promise.resolve(new Response("unexpected")));
    const capabilityEnv = createTestWorkerEnv({
      ASSETS: {
        fetch: assetsFetch,
        connect: () => {
          throw new Error("Unexpected ASSETS.connect call");
        }
      }
    });
    const response = await app.request("/s/locator/public-bearer", undefined, capabilityEnv);
    const csp = response.headers.get("Content-Security-Policy") ?? "";

    expect(response.status).toBe(404);
    expect(response.headers.get("Cache-Control")).toBe("no-store, private");
    expect(response.headers.get("Pragma")).toBe("no-cache");
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(response.headers.get("X-Robots-Tag")).toBe("noindex, nofollow, noarchive");
    expect(response.headers.has("Set-Cookie")).toBe(false);
    expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
    expect(response.headers.has("Service-Worker-Allowed")).toBe(false);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("worker-src 'none'");
    expect(csp).not.toContain("challenges.cloudflare.com");
    expect(csp).not.toContain("staging.invalid");
    expect(assetsFetch).not.toHaveBeenCalled();
  });

  it.each(["/%73/locator/public-bearer", "/s%2Flocator/public-bearer", "/S/locator/public-bearer"])(
    "rejects non-canonical reserved path %s before asset lookup",
    async (path) => {
      const assetsFetch = vi.fn(() => Promise.resolve(new Response("unexpected")));
      const invalidPathEnv = createTestWorkerEnv({
        ASSETS: {
          fetch: assetsFetch,
          connect: () => {
            throw new Error("Unexpected ASSETS.connect call");
          }
        }
      });
      const response = await app.request(path, undefined, invalidPathEnv);

      expect(response.status).toBe(404);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
      expect(response.headers.get("X-Robots-Tag")).toBe("noindex, nofollow, noarchive");
      expect(response.headers.has("Set-Cookie")).toBe(false);
      expect(assetsFetch).not.toHaveBeenCalled();
    }
  );

  it.each(["/_marketing/health", "/marketing-assets/site.css", "/robots.txt", "/sitemap.xml"])(
    "does not serve marketing-owned path %s",
    async (path) => {
      const response = await app.request(path, undefined, env);
      const body = await response.text();

      expect(response.status).toBe(404);
      expect(body).not.toContain('id="root"');
      expect(response.headers.get("Cache-Control")).toBe("no-store");
    }
  );
});

describe("exact functional-origin routing", () => {
  it.each([
    "http://127.attacker.example",
    "http://127.0.0.256",
    "http://127.1",
    "http://127.0.0.1.",
    "http://localhost.",
    "http://[::ffff:127.0.0.1]",
    "http://0177.0.0.1"
  ])("rejects non-canonical or non-loopback local HTTP origin %s", (functionalOrigin) => {
    expect(
      readOriginConfiguration({
        DEPLOYMENT_ENVIRONMENT: "local",
        MARKETING_ORIGIN: "http://127.0.0.2",
        FUNCTIONAL_ORIGIN: functionalOrigin
      })
    ).toBeNull();
  });

  it("accepts only canonical loopback HTTP variants in local configuration", () => {
    expect(
      readOriginConfiguration({
        DEPLOYMENT_ENVIRONMENT: "local",
        MARKETING_ORIGIN: "http://127.255.255.254",
        FUNCTIONAL_ORIGIN: "http://localhost"
      })
    ).toEqual({
      deploymentEnvironment: "local",
      marketingOrigin: "http://127.255.255.254",
      functionalOrigin: "http://localhost"
    });
    expect(
      readOriginConfiguration({
        DEPLOYMENT_ENVIRONMENT: "local",
        MARKETING_ORIGIN: "http://[::1]",
        FUNCTIONAL_ORIGIN: "http://127.1.2.3"
      })
    ).toEqual({
      deploymentEnvironment: "local",
      marketingOrigin: "http://[::1]",
      functionalOrigin: "http://127.1.2.3"
    });
  });

  it("fails closed for a request received on the wrong origin", async () => {
    const response = await app.request(
      "https://unexpected.example.test/api/v1/health",
      undefined,
      env
    );

    expect(response.status).toBe(421);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("fails closed when marketing and functional origins share a hostname", async () => {
    const invalidEnv = createTestWorkerEnv({
      MARKETING_ORIGIN: "https://same.example.test",
      FUNCTIONAL_ORIGIN: "https://same.example.test:8443",
      DEPLOYMENT_ENVIRONMENT: "staging"
    });
    const response = await app.request(
      "https://same.example.test/api/v1/health",
      undefined,
      invalidEnv
    );

    expect(response.status).toBe(503);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("fails closed for an unknown deployment environment", async () => {
    const invalidEnv = createTestWorkerEnv({ DEPLOYMENT_ENVIRONMENT: "stagin" });
    const response = await app.request("/api/v1/health", undefined, invalidEnv);

    expect(response.status).toBe(503);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });
});
