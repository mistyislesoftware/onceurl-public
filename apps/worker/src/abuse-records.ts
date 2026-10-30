import { z } from "zod";
import { storeSecurityMetric, maintainMetricOutbox } from "./security-metrics-outbox";
import type {
  CapabilityObjectStorage,
  CapabilityObjectTransaction
} from "./capability-durable-object-core";

export const REPORT_REASONS = ["phishing", "malware", "harassment", "spam", "other"] as const;
export const ADMIN_ACTIONS = ["disable", "abuse_lock", "delete", "release"] as const;
export const epochSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
export const locatorSchema = z.string().regex(/^loc1_[0-9a-f]{48}$/u);
export const reportIdSchema = z.string().regex(/^rep1_[A-Za-z0-9_-]{43}$/u);
export const adminMutationSchema = z
  .strictObject({
    locator: locatorSchema,
    operation_id: z.string().uuid(),
    action: z.enum(ADMIN_ACTIONS),
    reason: z.enum(REPORT_REASONS),
    report_id: reportIdSchema.optional(),
    confirm_abuse: z.boolean().default(false)
  })
  .refine(
    (value) => !value.confirm_abuse || (value.report_id !== undefined && value.action !== "release")
  );
export const reportSubmissionSchema = z.strictObject({
  nonce: z.string().regex(/^rpt1_[A-Za-z0-9_-]{43}$/u),
  reason: z.enum(REPORT_REASONS),
  note: z
    .string()
    .max(1024)
    .refine((value) => new TextEncoder().encode(value).byteLength <= 1024)
    .optional()
});
const DAY = 86_400_000;
export const SECURITY_RECORD_PREFIX = "capability:security:v1:";
const shared = {
  id: z.string().min(1).max(64),
  locator: locatorSchema,
  createdAt: epochSchema,
  retainUntil: epochSchema,
  version: z.number().int().positive(),
  projectedVersion: z.number().int().nonnegative(),
  nextAttemptAt: epochSchema
};
export const securityRecordSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    ...shared,
    kind: z.literal("report"),
    reason: z.enum(REPORT_REASONS),
    note: z.string().max(1024).nullable(),
    noteDeleteAt: epochSchema,
    confirmedAt: epochSchema.nullable()
  }),
  z.strictObject({
    ...shared,
    kind: z.literal("audit"),
    actor: z.string().min(1).max(254),
    action: z.enum(ADMIN_ACTIONS),
    reason: z.enum(REPORT_REASONS),
    reportId: reportIdSchema.nullable(),
    binding: z.string().length(43)
  })
]);
export type SecurityRecord = z.infer<typeof securityRecordSchema>;

export async function storeReport(
  txn: CapabilityObjectTransaction,
  input: {
    id: string;
    locator: string;
    reason: (typeof REPORT_REASONS)[number];
    note?: string;
    now: number;
  }
) {
  const { now, note } = input;
  const record: SecurityRecord = {
    id: input.id,
    locator: input.locator,
    reason: input.reason,
    kind: "report",
    createdAt: now,
    note: note ?? null,
    noteDeleteAt: now + 30 * DAY,
    retainUntil: now + 30 * DAY,
    confirmedAt: null,
    version: 1,
    projectedVersion: 0,
    nextAttemptAt: now
  };
  await txn.put(SECURITY_RECORD_PREFIX + record.id, record);
  await storeSecurityMetric(txn, "report_received", now);
}

export async function storeAudit(
  txn: CapabilityObjectTransaction,
  input: {
    id: string;
    locator: string;
    actor: string;
    action: (typeof ADMIN_ACTIONS)[number];
    reason: (typeof REPORT_REASONS)[number];
    reportId: string | null;
    binding: string;
    now: number;
  }
) {
  const { now, ...fields } = input;
  const record: SecurityRecord = {
    ...fields,
    kind: "audit",
    createdAt: now,
    retainUntil: now + 180 * DAY,
    version: 1,
    projectedVersion: 0,
    nextAttemptAt: now
  };
  await txn.put(SECURITY_RECORD_PREFIX + record.id, record);
  if (input.action !== "release") await storeSecurityMetric(txn, "enforcement", now);
}

export async function confirmReport(
  txn: CapabilityObjectTransaction,
  id: string,
  now: number
): Promise<boolean> {
  const stored = await txn.get(SECURITY_RECORD_PREFIX + id);
  if (stored === undefined) return false;
  const record = securityRecordSchema.parse(stored);
  if (record.kind !== "report" || now >= record.retainUntil) return false;
  if (record.confirmedAt !== null) return true;
  await storeSecurityMetric(txn, "report_confirmed", now);
  await txn.put(SECURITY_RECORD_PREFIX + id, {
    ...record,
    confirmedAt: now,
    retainUntil: now + 180 * DAY,
    version: record.version + 1,
    nextAttemptAt: now
  });
  return true;
}

export async function maintainSecurityRecords(
  txn: CapabilityObjectTransaction,
  now: number
): Promise<number | null> {
  const deadlines: number[] = [];
  const metricsDue = await maintainMetricOutbox(txn, now);
  if (metricsDue !== null) deadlines.push(metricsDue);
  for (const [kind, window] of [
    ["issue", 3_600_000],
    ["submit", 86_400_000]
  ] as const) {
    const key = `capability:security:rate:${kind}`;
    const stored = await txn.get(key);
    if (stored === undefined) continue;
    const values = z.array(epochSchema).max(3).parse(stored);
    if (values.some((at, index) => at > now || (index > 0 && at < (values[index - 1] ?? 0))))
      throw new Error("Invalid report quota state");
    const retained = values.filter((at) => at > now - window);
    if (retained.length === 0) await txn.delete(key);
    else {
      if (retained.length !== values.length) await txn.put(key, retained);
      deadlines.push((retained[0] ?? now) + window);
    }
  }
  for (const [key, stored] of await txn.list({ prefix: SECURITY_RECORD_PREFIX })) {
    let record = securityRecordSchema.parse(stored);
    if (key !== SECURITY_RECORD_PREFIX + record.id) throw new Error("Invalid security record");
    if (now >= record.retainUntil) {
      await txn.delete(key);
      continue;
    }
    if (record.kind === "report" && now >= record.noteDeleteAt && record.note !== null) {
      record = { ...record, note: null, version: record.version + 1, nextAttemptAt: now };
      await txn.put(key, record);
    }
    deadlines.push(record.retainUntil);
    if (record.kind === "report" && record.note !== null) deadlines.push(record.noteDeleteAt);
    if (record.projectedVersion < record.version)
      deadlines.push(Math.max(now, record.nextAttemptAt));
  }
  return deadlines.length === 0 ? null : Math.min(...deadlines);
}

/** D1 is a projection only. The source journal commits in the same DO transaction as enforcement. */
export async function projectSecurityRecords(
  storage: CapabilityObjectStorage,
  database: D1Database | undefined,
  now: number
): Promise<void> {
  const records = [...(await storage.list({ prefix: SECURITY_RECORD_PREFIX })).values()]
    .map((value) => securityRecordSchema.parse(value))
    .filter(
      (record) =>
        record.retainUntil > now &&
        record.projectedVersion < record.version &&
        record.nextAttemptAt <= now
    )
    .slice(0, 16);
  for (const record of records) {
    let delivered = false;
    try {
      if (database === undefined) throw new Error();
      if (record.kind === "report") {
        await database
          .prepare(
            `INSERT INTO abuse_reports (id, routing_locator, reason, note, created_at, note_delete_at, confirmed_at, retain_until, version)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET note=excluded.note, confirmed_at=excluded.confirmed_at, retain_until=excluded.retain_until, version=excluded.version
          WHERE abuse_reports.routing_locator=excluded.routing_locator AND abuse_reports.version<excluded.version`
          )
          .bind(
            record.id,
            record.locator,
            record.reason,
            now >= record.noteDeleteAt ? null : record.note,
            record.createdAt,
            record.noteDeleteAt,
            record.confirmedAt,
            record.retainUntil,
            record.version
          )
          .run();
      } else {
        const result = await database.batch([
          database
            .prepare(
              `INSERT INTO admin_audit (id, routing_locator, actor, action, reason, report_id, occurred_at, retain_until)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`
            )
            .bind(
              record.id,
              record.locator,
              record.actor,
              record.action,
              record.reason,
              record.reportId,
              record.createdAt,
              record.retainUntil
            ),
          // An immutable conflicting row is delivery only if every audit field matches.
          database
            .prepare(
              `SELECT 1 AS matched FROM admin_audit
          WHERE id=? AND routing_locator=? AND actor=? AND action=? AND reason=?
          AND report_id IS ? AND occurred_at=? AND retain_until=?`
            )
            .bind(
              record.id,
              record.locator,
              record.actor,
              record.action,
              record.reason,
              record.reportId,
              record.createdAt,
              record.retainUntil
            )
        ]);
        if (
          result.length !== 2 ||
          result.some((entry) => !entry.success) ||
          !z.tuple([z.strictObject({ matched: z.literal(1) })]).safeParse(result[1]?.results)
            .success
        )
          throw new Error("Audit projection conflict");
      }
      delivered = true;
    } catch {
      /* No provider/database error or report body enters a log sink. */
    }
    await storage.transaction(async (txn) => {
      const stored = await txn.get(SECURITY_RECORD_PREFIX + record.id);
      if (stored === undefined) return;
      const latest = securityRecordSchema.parse(stored);
      await txn.put(SECURITY_RECORD_PREFIX + record.id, {
        ...latest,
        projectedVersion: delivered
          ? Math.max(latest.projectedVersion, record.version)
          : latest.projectedVersion,
        nextAttemptAt: now + 300_000
      });
    });
  }
}

export async function cleanupAbuseRetention(database: D1Database, now: number): Promise<void> {
  await database.batch([
    database
      .prepare(
        "UPDATE abuse_reports SET note=NULL WHERE id IN (SELECT id FROM abuse_reports WHERE note_delete_at<=? AND note IS NOT NULL ORDER BY note_delete_at,id LIMIT 100)"
      )
      .bind(now),
    database
      .prepare(
        "DELETE FROM abuse_reports WHERE id IN (SELECT id FROM abuse_reports WHERE retain_until<=? ORDER BY retain_until,id LIMIT 100)"
      )
      .bind(now),
    database
      .prepare(
        "DELETE FROM admin_audit WHERE id IN (SELECT id FROM admin_audit WHERE retain_until<=? ORDER BY retain_until,id LIMIT 100)"
      )
      .bind(now)
  ]);
}
