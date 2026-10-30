import { DurableObject } from "cloudflare:workers";
import {
  authorizeCapability,
  acknowledgeOutboxDelivery,
  claimCapability,
  createCapability,
  decideAbuseLock,
  deleteCapability,
  deliverPendingOutbox,
  failClosedUncertainRestore,
  maintainCapability,
  markOutboxDeadLetter,
  reconcileCapability,
  administerCapability,
  inspectAdministrativeCapability,
  prepareCapabilityReport,
  submitCapabilityReport,
  type AbuseCommandResult,
  type AuthorizeCapabilityResult,
  type ClaimCapabilityResult,
  type CreateCapabilityResult,
  type DecideAbuseLockResult,
  type DeleteCapabilityResult,
  type FailClosedUncertainRestoreResult,
  type OutboxDeliveryResult,
  type ReconcileCapabilityResult
} from "./capability-durable-object-core";
import type { WorkerEnv } from "./env";
import { projectSecurityRecords } from "./abuse-records";
import { projectMetricOutbox } from "./security-metrics-outbox";
import { metricEvent, sendMetric, type MetricDimensions } from "./phase1a-metrics";

export class CapabilityDurableObject extends DurableObject<WorkerEnv> {
  private metricProjection: Promise<void> | null = null;
  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (
      url.pathname !== "/internal/capability/create" &&
      url.pathname !== "/internal/capability/claim" &&
      url.pathname !== "/internal/capability/authorize" &&
      url.pathname !== "/internal/capability/decide-abuse-lock" &&
      url.pathname !== "/internal/capability/delete" &&
      url.pathname !== "/internal/capability/projection-ack" &&
      url.pathname !== "/internal/capability/dead-letter" &&
      url.pathname !== "/internal/capability/reconcile" &&
      url.pathname !== "/internal/capability/administer" &&
      url.pathname !== "/internal/capability/admin-inspect" &&
      url.pathname !== "/internal/capability/report-prepare" &&
      url.pathname !== "/internal/capability/report-submit" &&
      url.pathname !== "/internal/capability/fail-closed-uncertain-restore"
    ) {
      return jsonResponse({ ok: false, code: "not_found" }, 404);
    }
    if (request.method !== "POST") {
      return jsonResponse({ ok: false, code: "method_not_allowed" }, 405, {
        allow: "POST"
      });
    }

    let command: unknown;
    try {
      command = await request.json();
    } catch {
      return jsonResponse({ ok: false, code: "invalid_json" }, 400);
    }

    try {
      const result = await executeCommand(url.pathname, this.ctx.storage, command);
      this.ctx.waitUntil(
        sendMetric(
          this.env,
          metricEvent(this.env.DEPLOYMENT_ENVIRONMENT, Date.now(), {
            family: "cost",
            category: "do_command",
            routeTemplate: "outbox"
          })
        )
      );
      await this.recoverAfterActivity(commandTime(command));
      return jsonResponse(result, statusForResult(result));
    } catch {
      return jsonResponse({ ok: false, code: "internal_error" }, 500);
    }
  }

  override async alarm(): Promise<void> {
    try {
      await runCapabilityAlarmDuties(
        () => maintainCapability(this.ctx.storage, Date.now()),
        () => this.deliverPending(Date.now(), false)
      );
    } finally {
      // Requests do not await measurements. Alarms await the shared bounded
      // attempt so an immediate retry alarm cannot fan out slow D1 work.
      await this.projectMetrics(Date.now());
    }
  }

  private async recoverAfterActivity(now: number): Promise<void> {
    try {
      await maintainCapability(this.ctx.storage, now);
    } catch {
      console.error("capability_activity_recovery_failed", { category: "maintenance" });
    }
    try {
      await this.deliverPending(now);
    } catch {
      console.error("capability_activity_recovery_failed", { category: "outbox" });
    }
  }

  private async deliverPending(now = Date.now(), metricsInBackground = true): Promise<void> {
    if (metricsInBackground) this.ctx.waitUntil(this.projectMetrics(now));
    await projectSecurityRecords(this.ctx.storage, this.env.DB, now);
    if (this.env.ASYNC_JOBS === undefined) return;
    const summary = await deliverPendingOutbox(this.ctx.storage, this.env.ASYNC_JOBS, now);
    if (summary.selected === 0) return;
    await sendMetric(
      this.env,
      metricEvent(this.env.DEPLOYMENT_ENVIRONMENT, now, {
        family: "delivery",
        category: summary.failed > 0 ? "platform_error" : "queue_send",
        routeTemplate: "outbox",
        lagBucket: summary.pendingAgeBucket as MetricDimensions["lagBucket"],
        retryBucket: summary.retryStateBucket === "initial" ? "initial" : "retry"
      })
    );
    const evidence = {
      category: summary.failed > 0 ? "queue_send_failed" : "queue_send_accepted",
      pendingAgeBucket: summary.pendingAgeBucket,
      retryStateBucket: summary.retryStateBucket,
      selected: summary.selected,
      failed: summary.failed
    };
    if (summary.failed > 0) console.warn("capability_outbox_delivery", evidence);
    else console.info("capability_outbox_delivery", evidence);
  }

  private projectMetrics(now: number): Promise<void> {
    if (this.metricProjection !== null) return this.metricProjection;
    this.metricProjection = this.projectMetricAttempt(now).finally(() => {
      this.metricProjection = null;
    });
    return this.metricProjection;
  }

  private async projectMetricAttempt(now: number): Promise<void> {
    try {
      await projectMetricOutbox(
        this.ctx.storage,
        this.env.DB,
        this.env.DEPLOYMENT_ENVIRONMENT,
        now
      );
    } catch {
      console.error("metrics_source_projection_failed", { category: "storage" });
    }
  }
}

export async function runCapabilityAlarmDuties(
  maintenanceDuty: () => Promise<void>,
  outboxDuty: () => Promise<void>
): Promise<void> {
  const failures: Error[] = [];
  try {
    await maintenanceDuty();
  } catch (cause) {
    const failure = sanitizedAlarmFailure("maintenance", cause);
    failures.push(failure);
    console.error("capability_alarm_duty_failed", {
      category: "maintenance",
      failure: failure.message
    });
  }
  try {
    await outboxDuty();
  } catch (cause) {
    const failure = sanitizedAlarmFailure("outbox", cause);
    failures.push(failure);
    console.error("capability_alarm_duty_failed", { category: "outbox", failure: failure.message });
  }
  if (failures.length > 0) {
    // Native runtime stderr may bypass Vitest's console reporter. Preserve both
    // duties' safe provenance in its top-level message as well as the cause chain.
    throw new AggregateError(
      failures,
      `One or more capability alarm duties failed (${failures.map((failure) => failure.message).join("; ")})`,
      { cause: failures[0] }
    );
  }
}

function sanitizedAlarmFailure(duty: "maintenance" | "outbox", cause: unknown): Error {
  // Error messages, Zod issues and native exceptions can contain stored values.
  // Never attach the raw cause: only fixed reasons and trusted source coordinates
  // are safe for native exception formatting and application log sinks.
  const knownReasons: Readonly<Record<string, string>> = {
    "Invalid maintenance time": "invalid_maintenance_time",
    "Malformed capability state": "malformed_capability_state",
    "Malformed capability access state": "malformed_access_state",
    "Malformed capability projection history": "malformed_projection_history",
    "Terminal evidence does not identify this capability": "terminal_identity_mismatch",
    "Automatic lock deletion transition failed": "lock_transition_failed",
    "Automatic expiry transition failed": "expiry_transition_failed",
    "Invalid security record": "invalid_security_record"
  };
  let reason = "unknown_error";
  let source = "unavailable";
  try {
    if (cause instanceof Error) {
      const message = cause.message;
      const name = cause.name;
      const stack = cause.stack;
      reason =
        typeof message === "string" && Object.hasOwn(knownReasons, message)
          ? (knownReasons[message] ?? "unknown_error")
          : name === "ZodError"
            ? "schema_validation_failed"
            : "unknown_error";
      if (reason === "unknown_error" && typeof message === "string") {
        if (/storage.*(?:disconnected|shut down)|actor.*shut down/iu.test(message)) {
          reason = "storage_disconnected";
        } else if (/cannot perform i\/o.*different (?:request|durable object)/iu.test(message)) {
          reason = "runtime_io_scope_mismatch";
        } else if (/(?:input|output) gate.*broken/iu.test(message)) {
          reason = "storage_gate_broken";
        } else if (/sqlite/iu.test(message)) {
          reason = "sqlite_failure";
        }
      }
      const location =
        typeof stack === "string"
          ? stack.match(
              /^\s*at [^\r\n]*(?:\/|\\)(capability-durable-object-core|abuse-records)\.ts:(\d{1,6}):(\d{1,6})(?=\s|\)|$)/mu
            )
          : null;
      if (location !== undefined && location !== null) {
        source = `${location[1]}.ts:${location[2]}:${location[3]}`;
      }
    }
  } catch {
    // Provenance must never interrupt the second duty, including for exotic
    // thrown objects with unreadable Error properties.
    reason = "uninspectable_error";
    source = "unavailable";
  }
  return new Error(`${duty}:${reason} source=${source}`);
}

function commandTime(value: unknown): number {
  if (
    typeof value === "object" &&
    value !== null &&
    "now" in value &&
    typeof value.now === "number" &&
    Number.isSafeInteger(value.now) &&
    value.now >= 0
  ) {
    return value.now;
  }
  return Date.now();
}

function executeCommand(
  path: string,
  storage: DurableObjectStorage,
  command: unknown
): Promise<
  | CreateCapabilityResult
  | ClaimCapabilityResult
  | AuthorizeCapabilityResult
  | DecideAbuseLockResult
  | DeleteCapabilityResult
  | FailClosedUncertainRestoreResult
  | OutboxDeliveryResult
  | ReconcileCapabilityResult
  | AbuseCommandResult
> {
  switch (path) {
    case "/internal/capability/administer":
      return administerCapability(storage, command);
    case "/internal/capability/admin-inspect":
      return inspectAdministrativeCapability(storage, command);
    case "/internal/capability/report-prepare":
      return prepareCapabilityReport(storage, command);
    case "/internal/capability/report-submit":
      return submitCapabilityReport(storage, command);
    case "/internal/capability/create":
      return createCapability(storage, command);
    case "/internal/capability/claim":
      return claimCapability(storage, command);
    case "/internal/capability/authorize":
      return authorizeCapability(storage, command);
    case "/internal/capability/decide-abuse-lock":
      return decideAbuseLock(storage, command);
    case "/internal/capability/delete":
      return deleteCapability(storage, command);
    case "/internal/capability/projection-ack":
      return acknowledgeOutboxDelivery(storage, command);
    case "/internal/capability/dead-letter":
      return markOutboxDeadLetter(storage, command);
    case "/internal/capability/reconcile":
      return reconcileCapability(storage, command);
    case "/internal/capability/fail-closed-uncertain-restore":
      return failClosedUncertainRestore(storage, command);
    default:
      return Promise.resolve({ ok: false, code: "not_found" });
  }
}

function statusForResult(
  result:
    | CreateCapabilityResult
    | ClaimCapabilityResult
    | AuthorizeCapabilityResult
    | DecideAbuseLockResult
    | DeleteCapabilityResult
    | FailClosedUncertainRestoreResult
    | OutboxDeliveryResult
    | ReconcileCapabilityResult
    | AbuseCommandResult
): number {
  if (result.ok) {
    return 200;
  }

  switch (result.code) {
    case "invalid_command":
    case "invalid_policy":
    case "invalid_ciphertext":
      return 400;
    case "not_found":
      return 404;
    case "unauthorized":
    case "challenge_required":
    case "verification_failed":
      return 403;
    case "rate_limited":
      return 429;
    case "already_exists":
    case "nonce_conflict":
    case "event_conflict":
    case "unavailable":
      return 409;
    case "malformed_state":
      return 500;
  }
}

function jsonResponse(
  body: unknown,
  status: number,
  extraHeaders: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json",
      ...extraHeaders
    }
  });
}
