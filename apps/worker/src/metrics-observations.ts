import type { MetricDimensions } from "./phase1a-metrics";
import { metricEvent, metricLatency, sendMetric } from "./phase1a-metrics";
import type { WorkerEnv } from "./env";

export function observedRoute(
  path: string,
  method: string
): MetricDimensions["routeTemplate"] | null {
  if (method === "GET" || method === "HEAD")
    return /^\/[sm]\/[^/]+\/[^/]+$/u.test(path) ? "passive" : null;
  if (method !== "POST") return null;
  if (path === "/api/v1/secrets/prepare") return "prepare";
  if (path === "/api/v1/secrets") return "complete";
  if (/^\/s\/[^/]+\/[^/]+\/claim$/u.test(path)) return "claim";
  if (
    ["/api/v1/challenges", "/api/v1/challenges/status", "/api/v1/challenges/verify"].includes(path)
  )
    return "challenge";
  if (["/api/v1/reports", "/api/v1/reports/nonce"].includes(path)) return "report";
  if (path === "/internal/admin/action") return "admin";
  return null;
}

export async function observeResponse(
  env: WorkerEnv,
  route: MetricDimensions["routeTemplate"],
  status: number,
  startedAt: number,
  endedAt: number
): Promise<void> {
  const category =
    status >= 500
      ? "platform_error"
      : status === 429
        ? "rate_limited"
        : status === 403
          ? "verification_rejected"
          : status === 400
            ? "invalid_request"
            : status >= 400
              ? "policy_rejected"
              : "accepted_response";
  const family =
    route === "prepare"
      ? "preparation"
      : route === "complete"
        ? "creation"
        : route === "claim"
          ? "reveal"
          : route === "report" || route === "admin"
            ? "abuse"
            : "control";
  const controlStage =
    category === "rate_limited"
      ? "rate"
      : route === "challenge"
        ? "turnstile"
        : route === "claim" && status === 403
          ? "access_code"
          : route === "report"
            ? "report"
            : route === "admin"
              ? "operator"
              : "none";
  await sendMetric(
    env,
    metricEvent(env.DEPLOYMENT_ENVIRONMENT, startedAt, {
      family,
      category,
      routeTemplate: route,
      controlStage,
      latencyBucket: metricLatency(endedAt - startedAt)
    })
  );
  await sendMetric(
    env,
    metricEvent(env.DEPLOYMENT_ENVIRONMENT, startedAt, {
      family: "cost",
      category: "worker_request",
      routeTemplate: route
    })
  );
}
