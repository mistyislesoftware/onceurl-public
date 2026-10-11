import { z } from "zod";
import type { WorkerEnv } from "./env";

export const METRIC_HOUR = 3_600_000;
export const METRIC_DAY = 24 * METRIC_HOUR;
export const METRIC_EVENT_RETENTION = 30 * METRIC_DAY;
export const METRIC_AGGREGATE_RETENTION = 180 * METRIC_DAY;
// Even one 1,000-row cleanup batch per five-minute cron drains 12,000/hour
// per table. Bound each expiry cohort below that capacity, including quiet traffic.
export const METRIC_HOURLY_ADMISSION_LIMIT = 8_000;
const epoch = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER - METRIC_AGGREGATE_RETENTION);
export const dimensionsSchema = z.strictObject({
  family: z.enum([
    "preparation",
    "creation",
    "reveal",
    "lifecycle",
    "delivery",
    "control",
    "abuse",
    "cost"
  ]),
  environment: z.enum(["local", "preview", "staging", "production"]),
  kind: z.literal("secret"),
  expiryPolicy: z.enum(["1h", "24h", "7d", "30d", "other", "unknown"]),
  routeTemplate: z.enum([
    "prepare",
    "complete",
    "claim",
    "passive",
    "challenge",
    "report",
    "admin",
    "outbox",
    "reconciliation"
  ]),
  category: z.enum([
    "committed",
    "accepted_response",
    "policy_rejected",
    "rate_limited",
    "verification_rejected",
    "platform_error",
    "invalid_request",
    "projected",
    "reconciled",
    "queue_send",
    "worker_request",
    "do_command",
    "d1_batch",
    "queue_delivery",
    "report_received",
    "report_confirmed",
    "enforcement"
  ]),
  latencyBucket: z.enum(["under_100ms", "100ms_to_1s", "1s_to_5s", "over_5s", "unknown"]),
  lagBucket: z.enum(["under_1m", "1m_to_15m", "15m_to_1h", "1h_to_24h", "over_24h", "unknown"]),
  retryBucket: z.enum(["initial", "retry", "unknown"]),
  lifecycleTransition: z.enum([
    "none",
    "activated",
    "consumed",
    "expired",
    "deleted",
    "disabled",
    "locked",
    "lock_decided",
    "reactivated"
  ]),
  controlStage: z.enum(["none", "rate", "turnstile", "access_code", "report", "operator"])
});
export const metricEventSchema = z.strictObject({
  schemaVersion: z.literal("phase1a-metrics-v1"),
  job: z.literal("phase1a_metrics"),
  eventId: z.uuid(),
  timeBucket: epoch.refine((value) => value % METRIC_HOUR === 0),
  dimensions: dimensionsSchema
});
export type MetricEvent = z.infer<typeof metricEventSchema>;
export type MetricDimensions = z.infer<typeof dimensionsSchema>;

export function metricEvent(
  environment: string,
  now: number,
  dimensions: Partial<MetricDimensions> &
    Pick<MetricDimensions, "family" | "category" | "routeTemplate">,
  eventId = crypto.randomUUID()
): MetricEvent | null {
  const result = metricEventSchema.safeParse({
    schemaVersion: "phase1a-metrics-v1",
    job: "phase1a_metrics",
    eventId,
    timeBucket: Math.floor(now / METRIC_HOUR) * METRIC_HOUR,
    dimensions: {
      environment,
      kind: "secret",
      expiryPolicy: "unknown",
      latencyBucket: "unknown",
      lagBucket: "unknown",
      retryBucket: "unknown",
      lifecycleTransition: "none",
      controlStage: "none",
      ...dimensions
    }
  });
  return result.success ? result.data : null;
}

export function metricLag(milliseconds: number): MetricDimensions["lagBucket"] {
  if (milliseconds < 60_000) return "under_1m";
  if (milliseconds < 15 * 60_000) return "1m_to_15m";
  if (milliseconds < METRIC_HOUR) return "15m_to_1h";
  if (milliseconds < METRIC_DAY) return "1h_to_24h";
  return "over_24h";
}

export function metricLatency(milliseconds: number): MetricDimensions["latencyBucket"] {
  if (milliseconds < 100) return "under_100ms";
  if (milliseconds < 1000) return "100ms_to_1s";
  if (milliseconds < 5000) return "1s_to_5s";
  return "over_5s";
}

export async function sendMetric(env: WorkerEnv, event: MetricEvent | null): Promise<void> {
  if (event === null || env.ASYNC_JOBS === undefined) return;
  // Observational loss cannot alter authorization, lifecycle or a response.
  try {
    await env.ASYNC_JOBS.send(metricEventSchema.parse(event));
  } catch {
    console.warn("metrics_observation_unavailable", { category: "queue" });
  }
}

function clockStatements(database: D1Database, now: number): D1PreparedStatement[] {
  epoch.parse(now);
  return [
    database
      .prepare(
        `INSERT INTO phase1a_metrics_clock (id, processed_at) VALUES (1, ?)
    ON CONFLICT(id) DO UPDATE SET processed_at = max(processed_at, excluded.processed_at)`
      )
      .bind(now)
  ];
}

function expiryBacklog(database: D1Database) {
  return database.prepare(`SELECT
    EXISTS(SELECT 1 FROM phase1a_metric_receipts WHERE retain_until <= (SELECT processed_at FROM phase1a_metrics_clock WHERE id = 1)) OR
    EXISTS(SELECT 1 FROM phase1a_metric_aggregates WHERE retain_until <= (SELECT processed_at FROM phase1a_metrics_clock WHERE id = 1)) AS pending`);
}

function deleteExpired(database: D1Database, limit: number) {
  return ["phase1a_metric_receipts", "phase1a_metric_aggregates"].map((table) =>
    database
      .prepare(
        `DELETE FROM ${table} WHERE rowid IN (SELECT rowid FROM ${table}
     WHERE retain_until <= (SELECT processed_at FROM phase1a_metrics_clock WHERE id = 1)
     ORDER BY retain_until LIMIT ?)`
      )
      .bind(limit)
  );
}

export async function aggregateMetric(
  database: D1Database,
  input: unknown,
  now: number
): Promise<void> {
  const event = metricEventSchema.parse(input);
  const dimensions = JSON.stringify(event.dimensions);
  const retainUntil = event.timeBucket + METRIC_EVENT_RETENTION;
  // D1 batch is a transaction. Eligibility and cleanup use the same monotonic clock.
  const results = await database.batch([
    ...clockStatements(database, now),
    ...deleteExpired(database, 100),
    database
      .prepare(
        `INSERT INTO phase1a_metric_receipts
      (event_id, time_bucket, dimensions, processed_at, retain_until, applied)
      SELECT ?, ?, ?, processed_at, ?, 0 FROM phase1a_metrics_clock
      WHERE id = 1 AND processed_at < ? AND ? <= ?
        AND (SELECT coalesce(sum(count), 0) FROM phase1a_metric_aggregates WHERE time_bucket = ?) < ?
        AND NOT EXISTS(SELECT 1 FROM phase1a_metric_receipts WHERE retain_until <= (SELECT processed_at FROM phase1a_metrics_clock WHERE id = 1))
        AND NOT EXISTS(SELECT 1 FROM phase1a_metric_aggregates WHERE retain_until <= (SELECT processed_at FROM phase1a_metrics_clock WHERE id = 1))
      ON CONFLICT(event_id) DO NOTHING`
      )
      .bind(
        event.eventId,
        event.timeBucket,
        dimensions,
        retainUntil,
        retainUntil,
        event.timeBucket,
        now,
        event.timeBucket,
        METRIC_HOURLY_ADMISSION_LIMIT
      ),
    database
      .prepare(
        `INSERT INTO phase1a_metric_aggregates
      (time_bucket, dimensions, count, processed_at, retain_until)
      SELECT time_bucket, dimensions, 1, processed_at, time_bucket + ?
      FROM phase1a_metric_receipts WHERE event_id = ? AND dimensions = ? AND applied = 0
        AND retain_until > (SELECT processed_at FROM phase1a_metrics_clock WHERE id = 1)
      ON CONFLICT(time_bucket, dimensions) DO UPDATE SET
        count = count + 1, processed_at = max(processed_at, excluded.processed_at)`
      )
      .bind(METRIC_AGGREGATE_RETENTION, event.eventId, dimensions),
    database
      .prepare(
        `UPDATE phase1a_metric_receipts SET applied = 1
      WHERE event_id = ? AND dimensions = ? AND applied = 0
        AND retain_until > (SELECT processed_at FROM phase1a_metrics_clock WHERE id = 1)`
      )
      .bind(event.eventId, dimensions),
    database
      .prepare(
        `SELECT
      (processed_at < ? AND ? <= ?) AS eligible,
      EXISTS(SELECT 1 FROM phase1a_metric_receipts WHERE event_id = ?) AS retained,
      (SELECT coalesce(sum(count), 0) FROM phase1a_metric_aggregates WHERE time_bucket = ?) >= ? AS saturated
      FROM phase1a_metrics_clock WHERE id = 1`
      )
      .bind(
        retainUntil,
        event.timeBucket,
        now,
        event.eventId,
        event.timeBucket,
        METRIC_HOURLY_ADMISSION_LIMIT
      ),
    expiryBacklog(database)
  ]);
  const admission = results.at(-2)?.results[0] as
    { eligible: number; retained: number; saturated: number } | undefined;
  const backlog = results.at(-1)?.results[0] as { pending: number } | undefined;
  // Commit cleanup progress before requesting an independent measurement retry.
  if (admission?.eligible === 1 && admission.retained === 0) {
    if (backlog?.pending === 1) throw new Error("Metric retention backlog; retry measurement");
    if (admission.saturated === 1)
      throw new Error("Metric hourly admission limit; retry measurement");
  }
}

export async function cleanupMetrics(
  database: D1Database,
  now: number,
  elapsedClock: () => number = () => performance.now()
) {
  const started = elapsedClock();
  let removedReceipts = 0;
  let removedAggregates = 0;
  // At most 32 statements and 16,000 deletions. Five seconds bounds new batch
  // starts; the last in-flight D1 batch remains subject to its service limit.
  for (let batch = 0; batch < 8; batch++) {
    if (batch > 0 && elapsedClock() - started >= 5_000) break;
    const results = await database.batch([
      ...clockStatements(database, now),
      ...deleteExpired(database, 1_000),
      expiryBacklog(database)
    ]);
    removedReceipts += results[1]?.meta.changes ?? 0;
    removedAggregates += results[2]?.meta.changes ?? 0;
    if ((results[3]?.results[0] as { pending: number } | undefined)?.pending === 0)
      return { removedReceipts, removedAggregates, complete: true, budgetExhausted: false };
  }
  return { removedReceipts, removedAggregates, complete: false, budgetExhausted: true };
}

const aggregateRowSchema = z.strictObject({
  time_bucket: epoch,
  dimensions: z.string(),
  count: z.number().int().positive(),
  processed_at: epoch
});
export async function readMetrics(database: D1Database, now: number) {
  epoch.parse(now);
  const checkpoint = await database
    .prepare("SELECT processed_at FROM phase1a_metrics_clock WHERE id = 1")
    .first<{ processed_at: number }>();
  const asOf = Math.max(now, checkpoint === null ? 0 : epoch.parse(checkpoint.processed_at));
  const saturation = await database
    .prepare(
      `SELECT time_bucket FROM phase1a_metric_aggregates
    WHERE retain_until > ? GROUP BY time_bucket HAVING sum(count) >= ?
    ORDER BY time_bucket DESC LIMIT 501`
    )
    .bind(asOf, METRIC_HOURLY_ADMISSION_LIMIT)
    .all<{ time_bucket: number }>();
  const admissionLimited = saturation.results.length > 0;
  const rows = await database
    .prepare(
      `SELECT time_bucket, dimensions, count, processed_at
    FROM phase1a_metric_aggregates WHERE retain_until > ? ORDER BY time_bucket DESC, dimensions LIMIT 501`
    )
    .bind(asOf)
    .all();
  const aggregates = rows.results.slice(0, 500).map((raw) => {
    const row = aggregateRowSchema.parse(raw);
    return {
      timeBucket: row.time_bucket,
      dimensions: dimensionsSchema.parse(JSON.parse(row.dimensions)),
      count: row.count,
      processedAt: row.processed_at
    };
  });
  // One-way grouped reconciliation. Never return or select event IDs for reporting.
  const source = await database
    .prepare(
      `SELECT time_bucket, dimensions, count(*) AS count
    FROM phase1a_metric_receipts WHERE applied = 1 AND retain_until > ?
    GROUP BY time_bucket, dimensions ORDER BY time_bucket DESC, dimensions LIMIT 501`
    )
    .bind(asOf)
    .all<{ time_bucket: number; dimensions: string; count: number }>();
  const grouped = new Map(
    source.results.map((row) => [JSON.stringify([row.time_bucket, row.dimensions]), row.count])
  );
  const recent = aggregates.filter((row) => row.timeBucket + METRIC_EVENT_RETENTION > asOf);
  const mismatch =
    recent.some(
      (row) =>
        grouped.get(JSON.stringify([row.timeBucket, JSON.stringify(row.dimensions)])) !== row.count
    ) ||
    source.results.some(
      (row) =>
        !recent.some(
          (aggregate) =>
            aggregate.timeBucket === row.time_bucket &&
            JSON.stringify(aggregate.dimensions) === row.dimensions &&
            aggregate.count === row.count
        )
    );
  return {
    schemaVersion: "phase1a-metrics-v1",
    asOf,
    processingClockAheadOfNow: asOf > now,
    aggregates,
    summaries: ["local", "preview", "staging", "production"].map((environment) => {
      const selected = aggregates.filter((row) => row.dimensions.environment === environment);
      const count = (family: MetricDimensions["family"], category: MetricDimensions["category"]) =>
        selected
          .filter((row) => row.dimensions.family === family && row.dimensions.category === category)
          .reduce((total, row) => total + row.count, 0);
      const created = count("creation", "committed");
      const released = count("reveal", "committed");
      const accepted =
        count("creation", "accepted_response") + count("reveal", "accepted_response");
      const failures = count("creation", "platform_error") + count("reveal", "platform_error");
      const eligibleAttempts = accepted + failures;
      return {
        environment,
        created,
        released,
        eligibleAttempts,
        observedTechnicalSuccess:
          eligibleAttempts === 0 || rows.results.length > 500 || admissionLimited
            ? null
            : accepted / eligibleAttempts,
        confirmedReportsPer1000Creations:
          created === 0 || rows.results.length > 500 || admissionLimited
            ? null
            : (count("abuse", "report_confirmed") * 1000) / created,
        driverCounts: {
          workerRequests: count("cost", "worker_request"),
          doCommands: count("cost", "do_command"),
          queueDeliveries: count("cost", "queue_delivery"),
          d1ProjectionBatches: count("cost", "d1_batch")
        },
        driverDenominator: released,
        lastProcessedAt:
          selected.length === 0 ? null : Math.max(...selected.map((row) => row.processedAt)),
        partial: rows.results.length > 500 || admissionLimited
      };
    }),
    admission: {
      perSourceHourLimit: METRIC_HOURLY_ADMISSION_LIMIT,
      saturatedHours: saturation.results.slice(0, 500).map((row) => row.time_bucket),
      truncated: saturation.results.length > 500
    },
    truncated: rows.results.length > 500,
    reconciliation: {
      since: asOf - METRIC_EVENT_RETENTION,
      complete: rows.results.length <= 500 && source.results.length <= 500,
      matches: !mismatch,
      olderHistory: "source_expired_unverified"
    },
    coverage:
      "committed_outbox_plus_best_effort_observations; admission_limits_can_defer_or_expire_measurements; no_recipient_identity_or_delivery_guarantee"
  };
}
