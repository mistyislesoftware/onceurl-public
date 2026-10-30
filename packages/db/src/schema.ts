import type { CapabilityKind, CapabilityState } from "@onceurl/domain";
import { sql } from "drizzle-orm";
import {
  check,
  index,
  integer,
  primaryKey,
  sqliteTable,
  text,
  uniqueIndex
} from "drizzle-orm/sqlite-core";

// Purpose-limited event receipts, never capability/recipient identity.
export const phase1aMetricReceipts = sqliteTable(
  "phase1a_metric_receipts",
  {
    eventId: text("event_id").primaryKey(),
    timeBucket: integer("time_bucket").notNull(),
    dimensions: text("dimensions").notNull(),
    processedAt: integer("processed_at").notNull(),
    retainUntil: integer("retain_until").notNull(),
    applied: integer("applied").notNull().default(0)
  },
  (table) => [
    index("phase1a_metric_receipts_retention_idx").on(table.retainUntil),
    check(
      "phase1a_metric_receipts_dimensions",
      sql`json_valid(${table.dimensions}) AND json_type(${table.dimensions}) = 'object'`
    ),
    check(
      "phase1a_metric_receipts_window",
      sql`${table.timeBucket} >= 0 AND ${table.timeBucket} % 3600000 = 0 AND ${table.retainUntil} = ${table.timeBucket} + 2592000000`
    ),
    check("phase1a_metric_receipts_applied", sql`${table.applied} IN (0, 1)`)
  ]
);

// Aggregate keys contain only bounded approved dimensions; no dedupe IDs.
export const phase1aMetricAggregates = sqliteTable(
  "phase1a_metric_aggregates",
  {
    timeBucket: integer("time_bucket").notNull(),
    dimensions: text("dimensions").notNull(),
    count: integer("count").notNull(),
    processedAt: integer("processed_at").notNull(),
    retainUntil: integer("retain_until").notNull()
  },
  (table) => [
    primaryKey({ columns: [table.timeBucket, table.dimensions] }),
    index("phase1a_metric_aggregates_retention_idx").on(table.retainUntil),
    check(
      "phase1a_metric_aggregates_dimensions",
      sql`json_valid(${table.dimensions}) AND json_type(${table.dimensions}) = 'object'`
    ),
    check(
      "phase1a_metric_aggregates_window",
      sql`${table.timeBucket} >= 0 AND ${table.timeBucket} % 3600000 = 0 AND ${table.retainUntil} = ${table.timeBucket} + 15552000000`
    ),
    check(
      "phase1a_metric_aggregates_count",
      sql`typeof(${table.count}) = 'integer' AND ${table.count} > 0`
    )
  ]
);

export const phase1aMetricsClock = sqliteTable(
  "phase1a_metrics_clock",
  {
    id: integer("id").primaryKey(),
    processedAt: integer("processed_at").notNull()
  },
  (table) => [
    check("phase1a_metrics_clock_singleton", sql`${table.id} = 1 AND ${table.processedAt} >= 0`)
  ]
);

export const capabilities = sqliteTable(
  "capabilities",
  {
    id: text("id").primaryKey(),
    workspaceId: text("workspace_id"),
    createdByUserId: text("created_by_user_id"),
    kind: text("kind").$type<CapabilityKind>().notNull(),
    state: text("state").$type<CapabilityState>().notNull(),
    routingLocator: text("routing_locator").notNull(),
    publicAlias: text("public_alias"),
    policyJson: text("policy_json", { mode: "json" }).$type<Record<string, unknown>>().notNull(),
    expiresAt: integer("expires_at", { mode: "timestamp_ms" }),
    consumedAt: integer("consumed_at", { mode: "timestamp_ms" }),
    disabledAt: integer("disabled_at", { mode: "timestamp_ms" }),
    deletedAt: integer("deleted_at", { mode: "timestamp_ms" }),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
    updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
    version: integer("version").notNull().default(1)
  },
  (table) => [
    uniqueIndex("capabilities_routing_locator_unique").on(table.routingLocator),
    index("capabilities_state_expires_at_idx").on(table.state, table.expiresAt),
    index("capabilities_workspace_id_created_at_idx").on(table.workspaceId, table.createdAt),
    check(
      "capabilities_routing_locator_format",
      sql`length(${table.routingLocator}) = 53 and substr(${table.routingLocator}, 1, 5) = 'loc1_' and substr(${table.routingLocator}, 6) not glob '*[^0-9a-f]*'`
    ),
    check(
      "capabilities_policy_json_object",
      sql`json_valid(${table.policyJson}) = 1 and case when json_valid(${table.policyJson}) = 1 then json_type(${table.policyJson}) = 'object' else 0 end`
    ),
    check(
      "capabilities_version_positive_integer",
      sql`typeof(${table.version}) = 'integer' and ${table.version} > 0`
    )
  ]
);

export const capabilityCounters = sqliteTable(
  "capability_counters",
  {
    capabilityId: text("capability_id")
      .primaryKey()
      .references(() => capabilities.id, { onDelete: "cascade" }),
    viewCount: integer("view_count").notNull().default(0),
    consumptionCount: integer("consumption_count").notNull().default(0),
    downloadCount: integer("download_count").notNull().default(0),
    uploadCount: integer("upload_count").notNull().default(0),
    clickCount: integer("click_count").notNull().default(0),
    updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull()
  },
  (table) => [
    check(
      "capability_counters_view_count_non_negative",
      sql`typeof(${table.viewCount}) = 'integer' and ${table.viewCount} >= 0`
    ),
    check(
      "capability_counters_consumption_count_non_negative",
      sql`typeof(${table.consumptionCount}) = 'integer' and ${table.consumptionCount} >= 0`
    ),
    check(
      "capability_counters_download_count_non_negative",
      sql`typeof(${table.downloadCount}) = 'integer' and ${table.downloadCount} >= 0`
    ),
    check(
      "capability_counters_upload_count_non_negative",
      sql`typeof(${table.uploadCount}) = 'integer' and ${table.uploadCount} >= 0`
    ),
    check(
      "capability_counters_click_count_non_negative",
      sql`typeof(${table.clickCount}) = 'integer' and ${table.clickCount} >= 0`
    )
  ]
);

export const capabilityProjectionEvents = sqliteTable(
  "capability_projection_events",
  {
    capabilityId: text("capability_id").notNull(),
    eventId: text("event_id").notNull(),
    eventType: text("event_type").notNull(),
    projectionVersion: integer("projection_version").notNull(),
    occurredAt: integer("occurred_at", { mode: "timestamp_ms" }).notNull(),
    processedAt: integer("processed_at", { mode: "timestamp_ms" }).notNull(),
    retainUntil: integer("retain_until", { mode: "timestamp_ms" }).notNull()
  },
  (table) => [
    primaryKey({ columns: [table.capabilityId, table.eventId] }),
    index("capability_projection_events_retention_idx").on(table.retainUntil),
    check(
      "capability_projection_events_version_positive",
      sql`typeof(${table.projectionVersion}) = 'integer' and ${table.projectionVersion} > 0`
    ),
    check(
      "capability_projection_events_retention_order",
      sql`${table.retainUntil} >= ${table.occurredAt}`
    )
  ]
);

export const capabilityTerminalTombstones = sqliteTable(
  "capability_terminal_tombstones",
  {
    capabilityId: text("capability_id").primaryKey(),
    routingLocator: text("routing_locator").notNull(),
    terminalState: text("terminal_state").$type<"CONSUMED" | "EXPIRED" | "DELETED">().notNull(),
    projectionVersion: integer("projection_version").notNull(),
    terminalEventId: text("terminal_event_id").notNull(),
    terminalAt: integer("terminal_at", { mode: "timestamp_ms" }).notNull(),
    catalogueDeleteAt: integer("catalogue_delete_at", { mode: "timestamp_ms" }).notNull(),
    retainUntil: integer("retain_until", { mode: "timestamp_ms" }).notNull(),
    lastVerifiedAt: integer("last_verified_at", { mode: "timestamp_ms" })
  },
  (table) => [
    uniqueIndex("capability_terminal_tombstones_locator_unique").on(table.routingLocator),
    index("capability_terminal_tombstones_catalogue_cleanup_idx").on(table.catalogueDeleteAt),
    index("capability_terminal_tombstones_retention_idx").on(table.retainUntil),
    check(
      "capability_terminal_tombstones_state",
      sql`${table.terminalState} in ('CONSUMED', 'EXPIRED', 'DELETED')`
    ),
    check(
      "capability_terminal_tombstones_version_positive",
      sql`typeof(${table.projectionVersion}) = 'integer' and ${table.projectionVersion} > 0`
    ),
    check(
      "capability_terminal_tombstones_retention_order",
      sql`${table.retainUntil} >= ${table.terminalAt} and ${table.catalogueDeleteAt} <= ${table.retainUntil}`
    )
  ]
);

export const capabilityReconciliationCandidates = sqliteTable(
  "capability_reconciliation_candidates",
  {
    capabilityId: text("capability_id").primaryKey(),
    routingLocator: text("routing_locator").notNull(),
    reason: text("reason").notNull(),
    nextAttemptAt: integer("next_attempt_at", { mode: "timestamp_ms" }).notNull(),
    attemptCount: integer("attempt_count").notNull().default(0),
    lastAttemptAt: integer("last_attempt_at", { mode: "timestamp_ms" }),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
    retainUntil: integer("retain_until", { mode: "timestamp_ms" })
  },
  (table) => [
    uniqueIndex("capability_reconciliation_candidates_locator_unique").on(table.routingLocator),
    index("capability_reconciliation_candidates_due_idx").on(
      table.nextAttemptAt,
      table.capabilityId
    ),
    index("capability_reconciliation_candidates_retention_idx").on(table.retainUntil),
    check(
      "capability_reconciliation_candidates_attempts_non_negative",
      sql`typeof(${table.attemptCount}) = 'integer' and ${table.attemptCount} >= 0`
    )
  ]
);

export const abuseReports = sqliteTable(
  "abuse_reports",
  {
    id: text("id").primaryKey(),
    routingLocator: text("routing_locator").notNull(),
    reason: text("reason").notNull(),
    note: text("note"),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
    noteDeleteAt: integer("note_delete_at", { mode: "timestamp_ms" }).notNull(),
    confirmedAt: integer("confirmed_at", { mode: "timestamp_ms" }),
    retainUntil: integer("retain_until", { mode: "timestamp_ms" }).notNull(),
    version: integer("version").notNull()
  },
  (table) => [
    index("abuse_reports_retention_idx").on(table.retainUntil),
    index("abuse_reports_note_cleanup_idx").on(table.noteDeleteAt),
    index("abuse_reports_created_idx").on(table.createdAt, table.id),
    check(
      "abuse_reports_note_bytes",
      sql`${table.note} is null or length(cast(${table.note} as blob)) <= 1024`
    ),
    check(
      "abuse_reports_reason",
      sql`${table.reason} in ('phishing','malware','harassment','spam','other')`
    ),
    check(
      "abuse_reports_retention",
      sql`${table.noteDeleteAt} = ${table.createdAt} + 2592000000 and ((${table.confirmedAt} is null and ${table.retainUntil} = ${table.createdAt} + 2592000000) or (${table.confirmedAt} >= ${table.createdAt} and ${table.retainUntil} = ${table.confirmedAt} + 15552000000))`
    ),
    check(
      "abuse_reports_version",
      sql`typeof(${table.version}) = 'integer' and ${table.version} > 0`
    )
  ]
);

export const adminAudit = sqliteTable(
  "admin_audit",
  {
    id: text("id").primaryKey(),
    routingLocator: text("routing_locator").notNull(),
    actor: text("actor").notNull(),
    action: text("action").notNull(),
    reason: text("reason").notNull(),
    reportId: text("report_id"),
    occurredAt: integer("occurred_at", { mode: "timestamp_ms" }).notNull(),
    retainUntil: integer("retain_until", { mode: "timestamp_ms" }).notNull()
  },
  (table) => [
    index("admin_audit_retention_idx").on(table.retainUntil),
    check(
      "admin_audit_action",
      sql`${table.action} in ('disable','abuse_lock','delete','release')`
    ),
    check(
      "admin_audit_reason",
      sql`${table.reason} in ('phishing','malware','harassment','spam','other')`
    ),
    check("admin_audit_retention", sql`${table.retainUntil} = ${table.occurredAt} + 15552000000`)
  ]
);

export const schema = {
  phase1aMetricReceipts,
  phase1aMetricAggregates,
  phase1aMetricsClock,
  capabilities,
  capabilityCounters,
  capabilityProjectionEvents,
  capabilityTerminalTombstones,
  capabilityReconciliationCandidates,
  abuseReports,
  adminAudit
};

export type CapabilitySelect = typeof capabilities.$inferSelect;
export type CapabilityInsert = typeof capabilities.$inferInsert;
export type CapabilityCounterSelect = typeof capabilityCounters.$inferSelect;
export type CapabilityCounterInsert = typeof capabilityCounters.$inferInsert;
export type CapabilityProjectionEventSelect = typeof capabilityProjectionEvents.$inferSelect;
export type CapabilityTerminalTombstoneSelect = typeof capabilityTerminalTombstones.$inferSelect;
export type CapabilityReconciliationCandidateSelect =
  typeof capabilityReconciliationCandidates.$inferSelect;
