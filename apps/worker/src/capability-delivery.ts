import {
  parseCapabilityProjectionMessage,
  type CapabilityProjectionMessage
} from "./capability-durable-object-core";
import {
  applyCapabilityProjection,
  cleanupProjectionRetention,
  completeProjectionReconciliation,
  deferReconciliationCandidate,
  listDueReconciliationCandidates,
  markTerminalVerified,
  type ReconciliationCandidate
} from "./capability-projection";
import type { WorkerEnv } from "./env";

const QUEUE_RETRY_DELAY_SECONDS = 60;

export async function handleCapabilityQueue(
  batch: MessageBatch<unknown>,
  env: WorkerEnv
): Promise<void> {
  if (env.DB === undefined || env.CAPABILITY_STATE === undefined) {
    for (const message of batch.messages)
      message.retry({ delaySeconds: QUEUE_RETRY_DELAY_SECONDS });
    return;
  }
  const deadLetterDelivery = batch.queue.endsWith("-dead-letter");
  await Promise.all(
    batch.messages.map((message) =>
      processQueueMessage(message, env.DB as D1Database, env, deadLetterDelivery)
    )
  );
}

export async function handleCapabilityReconciliation(env: WorkerEnv, now: number): Promise<void> {
  if (env.DB === undefined || env.CAPABILITY_STATE === undefined) return;
  try {
    await cleanupProjectionRetention(env.DB, now);
  } catch {
    console.error("capability_retention_cleanup_failed", { category: "d1" });
  }

  let candidates: readonly ReconciliationCandidate[];
  try {
    candidates = await listDueReconciliationCandidates(env.DB, now);
  } catch {
    console.error("capability_reconciliation_sweep_failed", { category: "candidate_query" });
    return;
  }

  await Promise.all(
    candidates.map((candidate) => reconcileCandidate(env.DB as D1Database, env, candidate, now))
  );
}

async function processQueueMessage(
  queueMessage: Message<unknown>,
  database: D1Database,
  env: WorkerEnv,
  deadLetterDelivery: boolean
): Promise<void> {
  const message = parseCapabilityProjectionMessage(queueMessage.body);
  if (message === null || message.deliveryEventId === null) {
    console.warn("capability_queue_poison", {
      category: deadLetterDelivery ? "dead_letter_unparseable" : "unparseable"
    });
    if (deadLetterDelivery) queueMessage.ack();
    else queueMessage.retry({ delaySeconds: QUEUE_RETRY_DELAY_SECONDS });
    return;
  }

  try {
    if (deadLetterDelivery) {
      await invokeCapabilityObject(env, message, "/internal/capability/dead-letter", {
        eventId: message.deliveryEventId,
        now: Date.now()
      });
      console.warn("capability_queue_dead_letter", {
        category: "projection",
        pendingAgeBucket: ageBucket(Date.now() - message.event.occurredAt)
      });
      queueMessage.ack();
      return;
    }

    const now = Date.now();
    const projectionResult = await applyCapabilityProjection(database, message, now);
    await invokeCapabilityObject(env, message, "/internal/capability/projection-ack", {
      eventId: message.deliveryEventId,
      projectionVersion: message.projection.version,
      now
    });
    if (projectionResult === "applied") {
      await completeProjectionReconciliation(database, message, now);
    }
    queueMessage.ack();
  } catch {
    console.error("capability_queue_processing_failed", {
      category: "retryable",
      projectionLagBucket: ageBucket(Date.now() - message.event.occurredAt)
    });
    queueMessage.retry({ delaySeconds: QUEUE_RETRY_DELAY_SECONDS });
  }
}

async function reconcileCandidate(
  database: D1Database,
  env: WorkerEnv,
  candidate: ReconciliationCandidate,
  now: number
): Promise<void> {
  try {
    const terminalEvidence =
      candidate.terminalEvidence === null
        ? null
        : {
            capabilityId: candidate.capabilityId,
            locator: candidate.routingLocator,
            ...candidate.terminalEvidence
          };
    const response = await env.CAPABILITY_STATE?.getByName(candidate.routingLocator).fetch(
      new Request("https://capability.invalid/internal/capability/reconcile", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ now, terminalEvidence })
      })
    );
    if (response === undefined || !response.ok) throw new Error("Capability reconciliation failed");
    const body: unknown = await response.json();
    const message = reconciliationMessage(body);
    if (message === null) throw new Error("Malformed capability reconciliation response");
    await applyCapabilityProjection(database, message, now);
    if (candidate.terminalEvidence !== null) {
      await markTerminalVerified(database, candidate.capabilityId, now);
    }
    await completeProjectionReconciliation(database, message, now);
    console.info("capability_reconciliation_result", {
      category: candidate.terminalEvidence === null ? "verified" : "terminal_reapplied",
      pendingAgeBucket: ageBucket(now - message.event.occurredAt),
      expiryLatenessBucket: expiryLatenessBucket(message, now)
    });
  } catch {
    console.error("capability_reconciliation_result", { category: "retry_scheduled" });
    try {
      await deferReconciliationCandidate(database, candidate, now);
    } catch {
      console.error("capability_reconciliation_result", { category: "checkpoint_failed" });
    }
  }
}

async function invokeCapabilityObject(
  env: WorkerEnv,
  message: CapabilityProjectionMessage,
  path: string,
  body: unknown
): Promise<void> {
  const namespace = env.CAPABILITY_STATE;
  if (namespace === undefined) throw new Error("Capability namespace unavailable");
  const response = await namespace.getByName(message.projection.locator).fetch(
    new Request(`https://capability.invalid${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    })
  );
  if (!response.ok) throw new Error("Capability object operation failed");
  const result: unknown = await response.json();
  if (!isSuccessfulResult(result)) throw new Error("Capability object rejected operation");
}

function reconciliationMessage(value: unknown): CapabilityProjectionMessage | null {
  if (
    typeof value !== "object" ||
    value === null ||
    !("ok" in value) ||
    value.ok !== true ||
    !("message" in value)
  ) {
    return null;
  }
  const message = parseCapabilityProjectionMessage(value.message);
  return message?.deliveryEventId === null ? message : null;
}

function isSuccessfulResult(value: unknown): value is { readonly ok: true } {
  return typeof value === "object" && value !== null && "ok" in value && value.ok === true;
}

function ageBucket(ageMilliseconds: number): string {
  if (ageMilliseconds < 60_000) return "under_1m";
  if (ageMilliseconds < 15 * 60_000) return "1m_to_15m";
  if (ageMilliseconds < 60 * 60_000) return "15m_to_1h";
  if (ageMilliseconds < 24 * 60 * 60_000) return "1h_to_24h";
  return "over_24h";
}

function expiryLatenessBucket(message: CapabilityProjectionMessage, now: number): string {
  const expiresAt = message.projection.expiresAt;
  if (expiresAt === null || now < expiresAt) return "not_overdue";
  return ageBucket(now - expiresAt);
}
