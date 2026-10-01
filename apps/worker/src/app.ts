import { Hono, type Context, type Next } from "hono";
import { bodyLimit } from "hono/body-limit";
import {
  createApiErrorBody,
  healthResponse,
  type ApiErrorCode,
  type JsonObject
} from "@onceurl/shared";
import { z } from "zod";
import type { WorkerEnv } from "./env";
import {
  AbuseControlConfigurationError,
  AbuseControlDependencyError,
  canonicalizeClientIp,
  coarsePreparationAllowed,
  consumeChallengeTicket,
  consumeExactIpQuota,
  createChallengeTicket,
  deriveIpDigests,
  markChallengeVerified,
  readChallengeStatus
} from "./abuse-control";
import {
  parseBearerSecret,
  parseCapabilityLocator,
  type CapabilityAuthority
} from "./capability-authority";
import { ACCESS_CODE_MAX_BYTES } from "./access-code";
import { readOriginConfiguration } from "./origins";
import {
  applyFunctionalRoutePolicy,
  classifyFunctionalRoute,
  type FunctionalRouteClass
} from "./route-policies";
import {
  parseSecretPreparationRequest,
  prepareSecretCreation,
  SecretPreparationConfigurationError,
  validateSecretCompletion
} from "./secret-creation";
import {
  TURNSTILE_CHALLENGE_CLIENT,
  TurnstileDependencyError,
  turnstileChallengeDocument,
  verifyTurnstileToken
} from "./turnstile";

type Variables = {
  requestId: string;
};

type WorkerContext = Context<{ Bindings: WorkerEnv; Variables: Variables }>;

const claimRequestSchema = z.strictObject({
  operation_id: z.string().min(1).max(512),
  nonce: z.string().min(1).max(512),
  access_code: z
    .string()
    .min(1)
    .max(ACCESS_CODE_MAX_BYTES)
    .refine((value) => new TextEncoder().encode(value).byteLength <= ACCESS_CODE_MAX_BYTES)
    .optional(),
  challenge_id: z
    .string()
    .regex(/^chl2_[pa]_\d{1,16}_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}$/u)
    .optional()
});

const turnstileActionSchema = z.enum(["onceurl_prepare", "onceurl_access_code"]);
const challengeIdSchema = z
  .string()
  .regex(/^chl2_[pa]_\d{1,16}_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}$/u);
const challengeCreateSchema = z.strictObject({ action: z.literal("onceurl_prepare") });
const challengeStateSchema = z.strictObject({
  challenge_id: challengeIdSchema,
  action: turnstileActionSchema
});
const challengeVerifySchema = z.strictObject({
  challenge_id: challengeIdSchema,
  action: turnstileActionSchema,
  token: z.string().min(1).max(2_048)
});

const internalFailureSchema = z.strictObject({
  ok: z.literal(false),
  code: z.string()
});

const internalAuthorizationSchema = z.union([
  z.strictObject({
    ok: z.literal(true),
    authority: z.enum(["public", "owner"]),
    capability: z.strictObject({
      kind: z.literal("secret"),
      state: z.enum([
        "DRAFT",
        "ACTIVE",
        "CONSUMED",
        "EXPIRED",
        "DISABLED",
        "ABUSE_LOCKED",
        "DELETED"
      ]),
      createdAt: z.string(),
      expiresAt: z.number().nullable(),
      isAvailable: z.boolean(),
      policy: z.strictObject({ maxConsumptions: z.literal(1) }),
      accessCodeRequired: z.boolean(),
      events: z
        .array(
          z.strictObject({
            type: z.enum([
              "created",
              "consumed",
              "expired",
              "disabled",
              "abuse_locked",
              "reactivated",
              "abuse_lock_decided",
              "deleted"
            ]),
            occurredAt: z.number().int().nonnegative()
          })
        )
        .max(64)
        .optional()
    })
  }),
  z.strictObject({
    ok: z.literal(false),
    code: z.string(),
    retryAfter: z.number().int().positive().optional()
  })
]);

const internalClaimSchema = z.union([
  z.strictObject({
    ok: z.literal(true),
    outcome: z.literal("released"),
    ciphertextEnvelope: z.unknown()
  }),
  z.strictObject({
    ok: z.literal(false),
    code: z.string(),
    retryAfter: z.number().int().positive().optional()
  })
]);

const internalCreateSchema = z.union([
  z.strictObject({ ok: z.literal(true) }),
  internalFailureSchema
]);

function createApp(options: { includeTestRoutes?: boolean } = {}) {
  const app = new Hono<{ Bindings: WorkerEnv; Variables: Variables }>();

  function getRequestId(context: { get: (key: "requestId") => string | undefined }): string {
    return context.get("requestId") ?? crypto.randomUUID();
  }

  function apiErrorResponse(
    context: { get: (key: "requestId") => string | undefined; json: HonoJsonResponse },
    code: ApiErrorCode,
    status: 400 | 403 | 404 | 409 | 429 | 500 | 503,
    details: JsonObject = {}
  ): Response {
    const requestId = getRequestId(context);
    return context.json(createApiErrorBody(code, requestId, details), status);
  }

  type HonoJsonResponse = (object: unknown, status?: number) => Response;

  function rateLimitedResponse(
    context: { get: (key: "requestId") => string | undefined; json: HonoJsonResponse },
    retryAfter: number
  ): Response {
    const response = apiErrorResponse(context, "rate_limited", 429);
    response.headers.set("Retry-After", String(retryAfter));
    return response;
  }

  function normalizedRouteTemplate(routeClass: FunctionalRouteClass): string {
    switch (routeClass) {
      case "api":
        return "/api/*";
      case "asset":
        return "/assets/*";
      case "boundary":
        return "/boundary/*";
      case "challenge":
        return "/challenge/*";
      case "capability":
        return "/:capability/*";
      case "application":
        return "/application/*";
    }
  }

  app.use("*", async (context, next) => {
    await next();
    context.res = new Response(context.res.body, context.res);
    applyFunctionalRoutePolicy(
      context.res,
      classifyFunctionalRoute(new URL(context.req.url).pathname)
    );
  });

  app.use("*", async (context, next) => {
    const origins = readOriginConfiguration(context.env);
    if (origins === null) {
      return new Response("Service unavailable", { status: 503 });
    }

    if (new URL(context.req.url).origin !== origins.functionalOrigin) {
      return new Response("Misdirected request", { status: 421 });
    }

    await next();
  });

  async function requestIdMiddleware(
    context: Context<{ Bindings: WorkerEnv; Variables: Variables }>,
    next: Next
  ) {
    const requestId = context.get("requestId") ?? crypto.randomUUID();
    context.set("requestId", requestId);
    await next();
    context.header("X-Request-ID", requestId);
  }

  app.use("/api", requestIdMiddleware);
  app.use("/api/*", requestIdMiddleware);
  app.use("/s/*", requestIdMiddleware);
  app.use("/m/*", requestIdMiddleware);
  app.use("/challenge", requestIdMiddleware);
  app.use("/challenge/*", requestIdMiddleware);
  app.use(
    "/api/v1/challenges/*",
    bodyLimit({
      maxSize: 4 * 1024,
      onError: (context) => apiErrorResponse(context, "invalid_request", 400)
    })
  );
  app.use(
    "/s/*",
    bodyLimit({
      maxSize: 2 * 1024,
      onError: (context) => apiErrorResponse(context, "invalid_request", 400)
    })
  );
  app.use(
    "/api/v1/secrets/prepare",
    bodyLimit({
      maxSize: 2 * 1024,
      onError: (context) => apiErrorResponse(context, "invalid_request", 400)
    })
  );
  app.use(
    "/api/v1/secrets",
    bodyLimit({
      maxSize: 104 * 1024,
      onError: (context) => apiErrorResponse(context, "invalid_request", 400)
    })
  );

  app.get("/health", (context) => {
    return context.json(healthResponse);
  });

  app.get("/api/v1/health", (context) => {
    return context.json(healthResponse);
  });

  app.get("/challenge", (context) => {
    const document = turnstileChallengeDocument(context.env.TURNSTILE_SITE_KEY);
    return document === null
      ? new Response("Service unavailable", { status: 503 })
      : new Response(document, { headers: { "content-type": "text/html; charset=utf-8" } });
  });

  app.get(
    "/challenge/client.js",
    () =>
      new Response(TURNSTILE_CHALLENGE_CLIENT, {
        headers: { "content-type": "text/javascript; charset=utf-8" }
      })
  );

  app.post("/api/v1/challenges", async (context) => {
    const request = challengeCreateSchema.safeParse(await readJson(context));
    if (!request.success) return apiErrorResponse(context, "invalid_request", 400);
    try {
      const challengeId = await createChallengeTicket(context.env, request.data.action, Date.now());
      return context.json({ challenge_id: challengeId, expires_in_seconds: 300 });
    } catch (error) {
      if (isAbuseControlError(error)) return apiErrorResponse(context, "internal_error", 503);
      throw error;
    }
  });

  app.post("/api/v1/challenges/status", async (context) => {
    const request = challengeStateSchema.safeParse(await readJson(context));
    if (!request.success) return apiErrorResponse(context, "invalid_request", 400);
    try {
      const verified = await readChallengeStatus(
        context.env,
        request.data.challenge_id,
        request.data.action,
        Date.now()
      );
      return verified === null
        ? apiErrorResponse(context, "verification_failed", 403)
        : context.json({ verified });
    } catch (error) {
      if (isAbuseControlError(error)) return apiErrorResponse(context, "internal_error", 503);
      throw error;
    }
  });

  app.post("/api/v1/challenges/verify", async (context) => {
    const request = challengeVerifySchema.safeParse(await readJson(context));
    if (!request.success) return apiErrorResponse(context, "invalid_request", 400);
    const now = Date.now();
    try {
      const status = await readChallengeStatus(
        context.env,
        request.data.challenge_id,
        request.data.action,
        now
      );
      if (status === null) return apiErrorResponse(context, "verification_failed", 403);
      if (status) return context.json({ verified: true });

      if (request.data.action === "onceurl_prepare") {
        const clientIp = readClientIp(context);
        if (clientIp === null) return apiErrorResponse(context, "internal_error", 503);
        const digests = await deriveIpDigests(clientIp, context.env);
        const currentDigest = digests[digests.length - 1];
        if (currentDigest === undefined) return apiErrorResponse(context, "internal_error", 503);
        if (!(await coarsePreparationAllowed(context.env, currentDigest))) {
          return rateLimitedResponse(context, 60);
        }
      }

      const verification = await verifyTurnstileToken(
        request.data.token,
        request.data.action,
        new URL(context.env.FUNCTIONAL_ORIGIN).hostname,
        context.env.TURNSTILE_SECRET_KEY,
        now
      );
      if (verification !== "verified") {
        return apiErrorResponse(context, "verification_failed", 403);
      }
      const marked = await markChallengeVerified(
        context.env,
        request.data.challenge_id,
        request.data.action,
        now
      );
      return marked
        ? context.json({ verified: true })
        : apiErrorResponse(context, "verification_failed", 403);
    } catch (error) {
      if (isAbuseControlError(error) || error instanceof TurnstileDependencyError) {
        return apiErrorResponse(context, "internal_error", 503);
      }
      throw error;
    }
  });

  app.post("/api/v1/secrets/prepare", async (context) => {
    const request = parseSecretPreparationRequest(await readJson(context));
    if (request === null) {
      return apiErrorResponse(context, "invalid_request", 400);
    }
    const now = Date.now();
    try {
      if (
        !(await consumeChallengeTicket(context.env, request.challenge_id, "onceurl_prepare", now))
      ) {
        return apiErrorResponse(context, "verification_failed", 403);
      }
      const preparation = await prepareSecretCreation(
        request.expires_in_seconds,
        now,
        {
          current: context.env.SECRET_PREPARATION_HMAC_KEY,
          previous: context.env.SECRET_PREPARATION_HMAC_PREVIOUS_KEY
        },
        undefined,
        request.access_code_verifier
      );
      const clientIp = readClientIp(context);
      if (clientIp === null) return apiErrorResponse(context, "internal_error", 503);
      const quota = await consumeExactIpQuota(context.env, clientIp, "preparation", now);
      if (!quota.allowed) return rateLimitedResponse(context, quota.retryAfter);
      return context.json(preparation);
    } catch (error) {
      if (error instanceof SecretPreparationConfigurationError || isAbuseControlError(error)) {
        return apiErrorResponse(context, "internal_error", 503);
      }
      throw error;
    }
  });

  app.post("/api/v1/secrets", async (context) => {
    let body: unknown;
    try {
      body = await context.req.json();
    } catch {
      return apiErrorResponse(context, "invalid_request", 400);
    }
    let completion: Awaited<ReturnType<typeof validateSecretCompletion>>;
    try {
      completion = await validateSecretCompletion(
        body,
        context.req.header("Idempotency-Key"),
        Date.now(),
        {
          current: context.env.SECRET_PREPARATION_HMAC_KEY,
          previous: context.env.SECRET_PREPARATION_HMAC_PREVIOUS_KEY
        }
      );
    } catch (error) {
      if (error instanceof SecretPreparationConfigurationError) {
        return apiErrorResponse(context, "internal_error", 503);
      }
      throw error;
    }
    if (completion === null) {
      return apiErrorResponse(context, "invalid_request", 400);
    }
    const result = internalCreateSchema.parse(
      await capabilityObjectCommand(context, completion.locator, "/internal/capability/create", {
        operationId: completion.operationId,
        capabilityId: completion.capabilityId,
        locator: completion.locator,
        createdAt: completion.createdAt,
        policy: completion.policy,
        policyHash: completion.policyHash,
        publicBearerSecretHash: completion.publicBearerSecretHash,
        ownerBearerSecretHash: completion.ownerBearerSecretHash,
        ciphertextEnvelope: completion.ciphertextEnvelope,
        accessCodeVerifier: completion.accessCodeVerifier,
        now: Date.now()
      })
    );
    if (!result.ok) {
      return result.code === "already_exists" || result.code === "event_conflict"
        ? apiErrorResponse(context, "capability_unavailable", 409)
        : result.code === "invalid_command" ||
            result.code === "invalid_policy" ||
            result.code === "invalid_ciphertext"
          ? apiErrorResponse(context, "invalid_request", 400)
          : apiErrorResponse(context, "internal_error", 503);
    }
    return context.json({
      recipient_path: completion.recipientPath,
      owner_path: completion.ownerPath,
      expires_at: completion.expiresAt
    });
  });

  async function inspectCapability(context: WorkerContext, authority: CapabilityAuthority) {
    const locator = parseCapabilityLocator(context.req.param("locator"));
    const bearerSecret = parseBearerSecret(authority, context.req.param("bearer"));
    if (locator === null || bearerSecret === null) {
      return apiErrorResponse(context, "not_found", 404);
    }

    const clientIp = readClientIp(context);
    if (clientIp === null) return apiErrorResponse(context, "internal_error", 503);
    try {
      const quota = await consumeExactIpQuota(context.env, clientIp, "passive", Date.now());
      if (!quota.allowed) return rateLimitedResponse(context, quota.retryAfter);
    } catch (error) {
      if (isAbuseControlError(error)) return apiErrorResponse(context, "internal_error", 503);
      throw error;
    }

    const result = internalAuthorizationSchema.parse(
      await capabilityObjectCommand(context, locator, "/internal/capability/authorize", {
        authority,
        bearerSecret,
        now: Date.now()
      })
    );
    if (!result.ok) {
      if (result.code === "rate_limited" && result.retryAfter !== undefined) {
        return rateLimitedResponse(context, result.retryAfter);
      }
      return publicCapabilityFailure(context, result.code);
    }

    if (context.req.method === "GET" && context.req.header("Accept")?.includes("text/html")) {
      return capabilityDocument(context);
    }

    if (context.req.method === "HEAD") {
      return new Response(null, { status: 200 });
    }
    return context.json({
      capability: {
        kind: result.capability.kind,
        state: result.capability.state,
        created_at: result.capability.createdAt,
        expires_at:
          result.capability.expiresAt === null
            ? null
            : new Date(result.capability.expiresAt).toISOString(),
        is_available: result.capability.isAvailable,
        policy: { max_consumptions: result.capability.policy.maxConsumptions },
        access_code_required: result.capability.accessCodeRequired,
        ...(authority === "owner"
          ? {
              events: (result.capability.events ?? []).map((event) => ({
                type: event.type,
                occurred_at: new Date(event.occurredAt).toISOString()
              }))
            }
          : {})
      }
    });
  }

  async function capabilityDocument(context: WorkerContext): Promise<Response> {
    const indexUrl = new URL("/", new URL(context.req.url).origin);
    return context.env.ASSETS.fetch(new Request(indexUrl, context.req.raw));
  }

  app.on(["GET", "HEAD"], "/s/:locator/:bearer", (context) => inspectCapability(context, "public"));
  app.on(["GET", "HEAD"], "/m/:locator/:bearer", (context) => inspectCapability(context, "owner"));

  app.post("/s/:locator/:bearer/claim", async (context) => {
    const locator = parseCapabilityLocator(context.req.param("locator"));
    const publicBearerSecret = parseBearerSecret("public", context.req.param("bearer"));
    if (locator === null || publicBearerSecret === null) {
      return apiErrorResponse(context, "not_found", 404);
    }

    let body: unknown;
    try {
      body = await context.req.json();
    } catch {
      return apiErrorResponse(context, "invalid_request", 400);
    }
    const command = claimRequestSchema.safeParse(body);
    if (!command.success) {
      return apiErrorResponse(context, "invalid_request", 400);
    }

    const now = Date.now();
    const clientIp = readClientIp(context);
    if (clientIp === null) return apiErrorResponse(context, "internal_error", 503);
    let challengeVerified = false;
    try {
      const quota = await consumeExactIpQuota(context.env, clientIp, "reveal", now);
      if (!quota.allowed) return rateLimitedResponse(context, quota.retryAfter);
      if (command.data.challenge_id !== undefined) {
        challengeVerified = await consumeChallengeTicket(
          context.env,
          command.data.challenge_id,
          "onceurl_access_code",
          now
        );
        if (!challengeVerified) {
          return apiErrorResponse(context, "verification_failed", 403);
        }
      }
    } catch (error) {
      if (isAbuseControlError(error)) return apiErrorResponse(context, "internal_error", 503);
      throw error;
    }

    const result = internalClaimSchema.parse(
      await capabilityObjectCommand(context, locator, "/internal/capability/claim", {
        publicBearerSecret,
        operationId: command.data.operation_id,
        nonce: command.data.nonce,
        accessCode: command.data.access_code,
        challengeVerified,
        now
      })
    );
    if (!result.ok) {
      if (result.code === "rate_limited" && result.retryAfter !== undefined) {
        return rateLimitedResponse(context, result.retryAfter);
      }
      if (result.code === "challenge_required") {
        try {
          const challengeId = await createChallengeTicket(context.env, "onceurl_access_code", now);
          return apiErrorResponse(context, "verification_required", 403, {
            challenge_id: challengeId,
            expires_in_seconds: 300
          });
        } catch (error) {
          if (isAbuseControlError(error)) {
            return apiErrorResponse(context, "internal_error", 503);
          }
          throw error;
        }
      }
      if (result.code === "verification_failed") {
        return apiErrorResponse(context, "verification_failed", 403);
      }
      return publicCapabilityFailure(context, result.code);
    }

    return context.json({
      outcome: result.outcome,
      ciphertext_envelope: result.ciphertextEnvelope
    });
  });

  if (options.includeTestRoutes === true) {
    app.get("/api/v1/test/unhandled-error", () => {
      throw new Error("sensitive internal exception detail");
    });

    app.get("/s/:locator/:bearer/test/unhandled-error", () => {
      throw new Error("sensitive capability exception detail");
    });
  }

  app.onError((_error, context) => {
    const routeClass = classifyFunctionalRoute(new URL(context.req.url).pathname);
    const requestId = getRequestId(context);
    console.error("Unhandled functional route error", {
      requestId,
      routeClass,
      routeTemplate: normalizedRouteTemplate(routeClass)
    });

    const response =
      routeClass === "api"
        ? apiErrorResponse(context, "internal_error", 500)
        : routeClass === "capability"
          ? apiErrorResponse(context, "internal_error", 503)
          : new Response("Internal server error", { status: 500 });
    response.headers.set("X-Request-ID", requestId);
    return response;
  });

  app.notFound(async (context) => {
    const url = new URL(context.req.url);
    const routeClass = classifyFunctionalRoute(url.pathname);

    if (routeClass === "api") {
      return apiErrorResponse(context, "not_found", 404);
    }

    if (routeClass === "boundary" || routeClass === "capability" || routeClass === "challenge") {
      return new Response("Not found", { status: 404 });
    }

    const assetResponse = await context.env.ASSETS.fetch(context.req.raw);

    if (assetResponse.status !== 404 || routeClass === "asset") {
      return assetResponse;
    }

    const indexUrl = new URL("/", url.origin);
    return context.env.ASSETS.fetch(new Request(indexUrl, context.req.raw));
  });

  async function capabilityObjectCommand(
    context: WorkerContext,
    locator: string,
    path: string,
    command: unknown
  ): Promise<unknown> {
    const namespace = context.env.CAPABILITY_STATE;
    if (namespace === undefined) {
      return { ok: false, code: "service_unavailable" };
    }

    const stub = namespace.getByName(locator);
    const response = await stub.fetch(
      new Request(`https://capability.internal${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(command)
      })
    );
    return response.json();
  }

  async function readJson(context: WorkerContext): Promise<unknown> {
    try {
      return await context.req.json();
    } catch {
      return null;
    }
  }

  function readClientIp(context: WorkerContext): string | null {
    const header = context.req.header("CF-Connecting-IP");
    return canonicalizeClientIp(
      header ?? (context.env.DEPLOYMENT_ENVIRONMENT === "local" ? "127.0.0.1" : undefined)
    );
  }

  function isAbuseControlError(error: unknown): boolean {
    return (
      error instanceof AbuseControlConfigurationError ||
      error instanceof AbuseControlDependencyError
    );
  }

  function publicCapabilityFailure(context: WorkerContext, internalCode: string): Response {
    switch (internalCode) {
      case "not_found":
      case "unauthorized":
      case "invalid_command":
        return apiErrorResponse(context, "not_found", 404);
      case "unavailable":
      case "nonce_conflict":
      case "event_conflict":
        return apiErrorResponse(context, "capability_unavailable", 409);
      case "rate_limited":
        return rateLimitedResponse(context, 60);
      case "challenge_required":
        return apiErrorResponse(context, "verification_required", 403);
      case "verification_failed":
        return apiErrorResponse(context, "verification_failed", 403);
      default:
        return apiErrorResponse(context, "internal_error", 503);
    }
  }

  return app;
}

export const app = createApp();
export const createTestApp = () => createApp({ includeTestRoutes: true });
