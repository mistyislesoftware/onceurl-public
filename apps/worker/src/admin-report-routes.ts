import type { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { z } from "zod";
import { canonicalizeClientIp, consumeChallengeTicket, consumeExactIpQuota } from "./abuse-control";
import {
  adminMutationSchema,
  locatorSchema,
  reportSubmissionSchema,
  epochSchema
} from "./abuse-records";
import {
  AdminBoundaryError,
  createAdminVerifier,
  securityDigest,
  type AuthorizedOperator
} from "./admin-auth";
import { ADMIN_CLIENT, ADMIN_DOCUMENT } from "./admin-ui";
import { parseBearerSecret } from "./capability-authority";
import type { WorkerEnv } from "./env";
import { readMetrics } from "./phase1a-metrics";
import {
  consumeAdminCsrf,
  consumeReportNonce,
  issueAdminCsrf,
  issueReportNonce
} from "./security-tickets";

const resultSchema = z.union([
  z.strictObject({
    ok: z.literal(true),
    authorized: z.boolean().optional(),
    metadata: z.unknown().optional()
  }),
  z.strictObject({
    ok: z.literal(false),
    code: z.string(),
    retryAfter: z.number().int().positive().optional()
  })
]);
const nonceRequestSchema = z.strictObject({
  locator: locatorSchema,
  public_bearer: z.string().refine((value) => parseBearerSecret("public", value) !== null)
});
const safeMetadata = z.strictObject({
  kind: z.literal("secret"),
  state: z.enum(["DRAFT", "ACTIVE", "CONSUMED", "EXPIRED", "DISABLED", "ABUSE_LOCKED", "DELETED"]),
  created_at: z.string(),
  expires_at: epochSchema.nullable(),
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
        occurredAt: epochSchema
      })
    )
    .max(64)
});
const safeReports = z
  .array(
    z.strictObject({
      id: z.string(),
      routing_locator: locatorSchema,
      reason: z.enum(["phishing", "malware", "harassment", "spam", "other"]),
      created_at: epochSchema,
      confirmed_at: epochSchema.nullable()
    })
  )
  .max(50);

async function objectCommand(env: WorkerEnv, locator: string, path: string, command: unknown) {
  if (env.CAPABILITY_STATE === undefined) throw new AdminBoundaryError(503);
  try {
    const response = await env.CAPABILITY_STATE.getByName(locator).fetch(
      new Request(`https://capability.internal/internal/capability/${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(command)
      })
    );
    const result = resultSchema.parse(await response.json());
    if (
      !result.ok &&
      ["malformed_state", "internal_error", "service_unavailable"].includes(result.code)
    )
      throw new Error();
    return result;
  } catch {
    throw new AdminBoundaryError(503);
  }
}

function failed(status: number): Response {
  return Response.json(
    {
      error:
        status === 503
          ? "service_unavailable"
          : status === 429
            ? "rate_limited"
            : "request_unavailable"
    },
    { status }
  );
}
function quotaDenied(retryAfter: number): Response {
  const response = failed(429);
  response.headers.set("Retry-After", String(retryAfter));
  return response;
}

export function mountAdminReportRoutes(
  app: Hono<{ Bindings: WorkerEnv; Variables: { requestId: string } }>
) {
  const verify = createAdminVerifier();
  const operators = new WeakMap<object, AuthorizedOperator>();
  app.use("/internal/*", async (context, next) => {
    const url = new URL(context.req.url);
    if (url.pathname !== "/internal/admin" && !url.pathname.startsWith("/internal/admin/"))
      return failed(404);
    try {
      operators.set(context, await verify(context.req.raw, context.env));
      if (url.search !== "") return failed(400);
      if (
        context.req.method !== "GET" &&
        context.req.method !== "HEAD" &&
        context.req.header("Origin") !== context.env.FUNCTIONAL_ORIGIN
      )
        return failed(403);
      await next();
    } catch (error) {
      return failed(error instanceof AdminBoundaryError ? error.status : 503);
    }
  });
  app.use("/internal/*", bodyLimit({ maxSize: 4096, onError: () => failed(400) }));
  app.get("/internal/admin/metrics", async (context) => {
    if (context.env.DB === undefined) return failed(503);
    try {
      return context.json(await readMetrics(context.env.DB, Date.now()));
    } catch {
      return failed(503);
    }
  });
  app.get(
    "/internal/admin",
    () => new Response(ADMIN_DOCUMENT, { headers: { "content-type": "text/html; charset=utf-8" } })
  );
  app.get(
    "/internal/admin/client.js",
    () =>
      new Response(ADMIN_CLIENT, { headers: { "content-type": "text/javascript; charset=utf-8" } })
  );
  app.post("/internal/admin/reports", async (context) => {
    if (!z.strictObject({}).safeParse(await context.req.json().catch(() => null)).success)
      return failed(400);
    if (context.env.DB === undefined) return failed(503);
    const result = await context.env.DB.prepare(
      "SELECT id,routing_locator,reason,created_at,confirmed_at FROM abuse_reports WHERE retain_until>? ORDER BY created_at DESC,id DESC LIMIT 50"
    )
      .bind(Date.now())
      .all();
    return context.json({ reports: safeReports.parse(result.results) });
  });
  app.post("/internal/admin/inspect", async (context) => {
    const input = z
      .strictObject({ locator: locatorSchema })
      .safeParse(await context.req.json().catch(() => null));
    if (!input.success) return failed(400);
    const result = await objectCommand(context.env, input.data.locator, "admin-inspect", {
      now: Date.now()
    });
    return result.ok
      ? context.json({ capability: safeMetadata.parse(result.metadata) })
      : failed(404);
  });
  app.post("/internal/admin/csrf", async (context) => {
    const input = adminMutationSchema.safeParse(await context.req.json().catch(() => null));
    const operator = operators.get(context);
    if (!input.success) return failed(400);
    if (operator === undefined) return failed(403);
    // Dedicated security-control exchange; tokens never enter ordinary metadata/views/audits.
    return context.json({
      csrf_token: await issueAdminCsrf(context.env, operator, input.data, Date.now())
    });
  });
  app.post("/internal/admin/action", async (context) => {
    const input = adminMutationSchema.safeParse(await context.req.json().catch(() => null));
    const operator = operators.get(context);
    if (!input.success) return failed(400);
    if (operator === undefined) return failed(403);
    const now = Date.now();
    if (
      !(await consumeAdminCsrf(
        context.env,
        operator,
        input.data,
        context.req.header("X-OnceURL-CSRF") ?? null,
        now
      ))
    )
      return failed(403);
    const result = await objectCommand(context.env, input.data.locator, "administer", {
      mutation: input.data,
      actor: operator.actor,
      now
    });
    return result.ok ? context.json({ recorded: true }) : failed(409);
  });
  app.all("/internal/admin/*", () => failed(404));

  app.use("/api/v1/reports/*", bodyLimit({ maxSize: 8192, onError: () => failed(400) }));
  app.use("/api/v1/reports", bodyLimit({ maxSize: 8192, onError: () => failed(400) }));
  for (const path of ["/api/v1/reports/nonce", "/api/v1/reports"]) {
    app.use(path, async (context, next) => {
      if (
        context.req.method !== "POST" ||
        context.req.header("Origin") !== context.env.FUNCTIONAL_ORIGIN ||
        new URL(context.req.url).search !== ""
      )
        return failed(403);
      try {
        await next();
      } catch {
        return failed(503);
      }
    });
  }
  app.post("/api/v1/reports/nonce", async (context) => {
    const input = nonceRequestSchema.safeParse(await context.req.json().catch(() => null));
    if (!input.success) return failed(400);
    const now = Date.now();
    const ip = canonicalizeClientIp(
      context.req.header("CF-Connecting-IP") ??
        (context.env.DEPLOYMENT_ENVIRONMENT === "local" ? "127.0.0.1" : undefined)
    );
    if (ip === null) return failed(503);
    const quota = await consumeExactIpQuota(context.env, ip, "report_issue", now);
    if (!quota.allowed) return quotaDenied(quota.retryAfter);
    const result = await objectCommand(context.env, input.data.locator, "report-prepare", {
      publicBearerSecret: input.data.public_bearer,
      now
    });
    if (!result.ok)
      return result.code === "rate_limited" && result.retryAfter !== undefined
        ? quotaDenied(result.retryAfter)
        : failed(503);
    const nonce = await issueReportNonce(
      context.env,
      input.data.locator,
      result.authorized === true,
      now
    );
    return context.json({ nonce, expires_in_seconds: 600 });
  });
  app.post("/api/v1/reports", async (context) => {
    const input = reportSubmissionSchema.safeParse(await context.req.json().catch(() => null));
    if (!input.success) return failed(400);
    const now = Date.now();
    const ip = canonicalizeClientIp(
      context.req.header("CF-Connecting-IP") ??
        (context.env.DEPLOYMENT_ENVIRONMENT === "local" ? "127.0.0.1" : undefined)
    );
    if (ip === null) return failed(503);
    const quota = await consumeExactIpQuota(context.env, ip, "report_submit", now);
    if (!quota.allowed) return quotaDenied(quota.retryAfter);
    const challenge = context.req.header("X-OnceURL-Challenge");
    if (
      challenge === undefined ||
      !(await consumeChallengeTicket(context.env, challenge, "onceurl_report_submit", now))
    )
      return failed(403);
    const nonce = await consumeReportNonce(context.env, input.data.nonce, now);
    if (nonce !== null && nonce.binding.authorized) {
      const result = await objectCommand(context.env, nonce.binding.locator, "report-submit", {
        id: `rep1_${await securityDigest("onceurl.report-id.v1", input.data.nonce)}`,
        locator: nonce.binding.locator,
        nonceCreatedAt: nonce.createdAt,
        reason: input.data.reason,
        ...(input.data.note === undefined ? {} : { note: input.data.note }),
        now
      });
      if (!result.ok)
        return result.code === "rate_limited" && result.retryAfter !== undefined
          ? quotaDenied(result.retryAfter)
          : failed(503);
    }
    return context.json({ acknowledged: true });
  });
}
