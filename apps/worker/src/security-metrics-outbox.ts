import { z } from "zod";
import type {
  CapabilityObjectTransaction,
  CapabilityProjectionMessage
} from "./capability-durable-object-core";
import {
  aggregateMetric,
  metricEvent,
  dimensionsSchema,
  metricLag,
  type MetricDimensions,
  METRIC_EVENT_RETENTION,
  METRIC_HOUR
} from "./phase1a-metrics";

export const SECURITY_METRIC_PREFIX = "capability:metrics:v1:";
const securityRecordSchema = z.strictObject({
  eventId: z.uuid(),
  timeBucket: z.number().int().nonnegative(),
  category: z.enum(["report_received", "report_confirmed", "enforcement"]),
  nextAttemptAt: z.number().int().nonnegative()
});

const recordSchema = z.union([
  securityRecordSchema,
  z.strictObject({
    eventId: z.uuid(),
    timeBucket: z.number().int().nonnegative(),
    dimensions: dimensionsSchema.omit({ environment: true }),
    nextAttemptAt: z.number().int().nonnegative()
  })
]);

// Transfer the committed fact in the operational acknowledgement transaction.
// Its retry and retention no longer depend on the seven-day delivered outbox.
export async function storeLifecycleMetric(
  txn: CapabilityObjectTransaction,
  message: CapabilityProjectionMessage,
  now: number
) {
  if (message.metricEventId === undefined) return;
  const event = lifecycleMetric(message, "local", now);
  if (event === null || event.timeBucket + METRIC_EVENT_RETENTION <= now) return;
  const dimensions = dimensionsSchema.omit({ environment: true }).strip().parse(event.dimensions);
  await txn.put(
    SECURITY_METRIC_PREFIX + event.eventId,
    recordSchema.parse({
      eventId: event.eventId,
      timeBucket: event.timeBucket,
      dimensions,
      nextAttemptAt: now
    })
  );
}

export async function storeSecurityMetric(
  txn: CapabilityObjectTransaction,
  category: z.infer<typeof securityRecordSchema>["category"],
  now: number
) {
  const eventId = crypto.randomUUID();
  await txn.put(SECURITY_METRIC_PREFIX + eventId, {
    eventId,
    timeBucket: Math.floor(now / METRIC_HOUR) * METRIC_HOUR,
    category,
    nextAttemptAt: now
  });
}

export async function maintainMetricOutbox(
  txn: CapabilityObjectTransaction,
  now: number
): Promise<number | null> {
  let next: number | null = null;
  for (const [key, raw] of await txn.list({ prefix: SECURITY_METRIC_PREFIX })) {
    const record = recordSchema.parse(raw);
    if (key !== SECURITY_METRIC_PREFIX + record.eventId || record.timeBucket % METRIC_HOUR !== 0)
      throw new Error("Invalid metric outbox");
    const deadline = record.timeBucket + METRIC_EVENT_RETENTION;
    if (deadline <= now) {
      await txn.delete(key);
      continue;
    }
    const due = Math.min(deadline, Math.max(now, record.nextAttemptAt));
    next = next === null ? due : Math.min(next, due);
  }
  return next;
}

export async function projectMetricOutbox(
  storage: CapabilityObjectTransaction,
  database: D1Database | undefined,
  environment: string,
  now: number
) {
  if (database === undefined) return;
  const records = [...(await storage.list({ prefix: SECURITY_METRIC_PREFIX })).entries()]
    .map(([key, raw]) => ({ key, record: recordSchema.parse(raw) }))
    .filter(({ record }) => record.nextAttemptAt <= now)
    .sort((left, right) => left.record.nextAttemptAt - right.record.nextAttemptAt)
    .slice(0, 16);
  for (const { key, record } of records) {
    const event = metricEvent(
      environment,
      record.timeBucket,
      "dimensions" in record
        ? record.dimensions
        : {
            family: "abuse",
            category: record.category,
            routeTemplate: record.category === "enforcement" ? "admin" : "report",
            controlStage: record.category === "enforcement" ? "operator" : "report"
          },
      record.eventId
    );
    if (event === null) {
      await storage.put(key, { ...record, nextAttemptAt: now + 300_000 });
      continue;
    }
    try {
      await aggregateMetric(database, event, now);
      await storage.delete(key);
    } catch {
      await storage.put(key, { ...record, nextAttemptAt: now + 300_000 });
    }
  }
}

function lifecycleMetric(message: CapabilityProjectionMessage, environment: string, now: number) {
  const transition: MetricDimensions["lifecycleTransition"] =
    message.event.type === "capability_activated"
      ? "activated"
      : message.event.type === "capability_consumption_committed"
        ? "consumed"
        : message.event.type === "capability_expired"
          ? "expired"
          : message.event.type === "capability_deleted"
            ? "deleted"
            : message.event.type === "capability_disabled"
              ? "disabled"
              : message.event.type === "capability_abuse_locked"
                ? "locked"
                : message.event.type === "capability_reactivated"
                  ? "reactivated"
                  : "lock_decided";
  const duration =
    message.projection.expiresAt === null
      ? null
      : message.projection.expiresAt - message.projection.createdAt;
  const expiryPolicy: MetricDimensions["expiryPolicy"] =
    duration === 3_600_000
      ? "1h"
      : duration === 86_400_000
        ? "24h"
        : duration === 604_800_000
          ? "7d"
          : duration === 2_592_000_000
            ? "30d"
            : "other";
  return metricEvent(
    environment,
    message.event.occurredAt,
    {
      family:
        transition === "activated"
          ? "creation"
          : transition === "consumed"
            ? "reveal"
            : "lifecycle",
      category: "committed",
      routeTemplate:
        transition === "activated" ? "complete" : transition === "consumed" ? "claim" : "outbox",
      expiryPolicy,
      lifecycleTransition: transition,
      lagBucket: metricLag(now - message.event.occurredAt)
    },
    message.metricEventId
  );
}
