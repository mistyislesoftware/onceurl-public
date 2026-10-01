import { DurableObject } from "cloudflare:workers";
import {
  authorizeCapability,
  acknowledgeOutboxDelivery,
  claimCapability,
  createCapability,
  decideAbuseLock,
  deleteCapability,
  deliverPendingOutbox,
  maintainCapability,
  markOutboxDeadLetter,
  reconcileCapability,
  type AuthorizeCapabilityResult,
  type ClaimCapabilityResult,
  type CreateCapabilityResult,
  type DecideAbuseLockResult,
  type DeleteCapabilityResult,
  type OutboxDeliveryResult,
  type ReconcileCapabilityResult
} from "./capability-durable-object-core";
import type { WorkerEnv } from "./env";

export class CapabilityDurableObject extends DurableObject<WorkerEnv> {
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
      url.pathname !== "/internal/capability/reconcile"
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
      await this.recoverAfterActivity(commandTime(command));
      return jsonResponse(result, statusForResult(result));
    } catch {
      return jsonResponse({ ok: false, code: "internal_error" }, 500);
    }
  }

  override async alarm(): Promise<void> {
    await runCapabilityAlarmDuties(
      () => maintainCapability(this.ctx.storage, Date.now()),
      () => this.deliverPending()
    );
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

  private async deliverPending(now = Date.now()): Promise<void> {
    if (this.env.ASYNC_JOBS === undefined) return;
    const summary = await deliverPendingOutbox(this.ctx.storage, this.env.ASYNC_JOBS, now);
    if (summary.selected === 0) return;
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
}

export async function runCapabilityAlarmDuties(
  maintenanceDuty: () => Promise<void>,
  outboxDuty: () => Promise<void>
): Promise<void> {
  let failed = false;
  try {
    await maintenanceDuty();
  } catch {
    failed = true;
    console.error("capability_alarm_duty_failed", { category: "maintenance" });
  }
  try {
    await outboxDuty();
  } catch {
    failed = true;
    console.error("capability_alarm_duty_failed", { category: "outbox" });
  }
  if (failed) throw new Error("One or more capability alarm duties failed");
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
  | OutboxDeliveryResult
  | ReconcileCapabilityResult
> {
  switch (path) {
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
    | OutboxDeliveryResult
    | ReconcileCapabilityResult
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
