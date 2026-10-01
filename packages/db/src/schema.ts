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

export const schema = {
  capabilities,
  capabilityCounters,
  capabilityProjectionEvents,
  capabilityTerminalTombstones,
  capabilityReconciliationCandidates
};

export type CapabilitySelect = typeof capabilities.$inferSelect;
export type CapabilityInsert = typeof capabilities.$inferInsert;
export type CapabilityCounterSelect = typeof capabilityCounters.$inferSelect;
export type CapabilityCounterInsert = typeof capabilityCounters.$inferInsert;
export type CapabilityProjectionEventSelect = typeof capabilityProjectionEvents.$inferSelect;
export type CapabilityTerminalTombstoneSelect = typeof capabilityTerminalTombstones.$inferSelect;
export type CapabilityReconciliationCandidateSelect =
  typeof capabilityReconciliationCandidates.$inferSelect;
