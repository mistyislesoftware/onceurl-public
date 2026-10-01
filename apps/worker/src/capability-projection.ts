import type { CapabilityState } from "@onceurl/domain";
import type { CapabilityProjectionMessage } from "./capability-durable-object-core";

const DAY_MS = 24 * 60 * 60 * 1_000;
const TERMINAL_RETENTION_MS = 30 * DAY_MS;
const RECONCILIATION_CADENCE_MS = DAY_MS;
const RECONCILIATION_RETRY_MS = 5 * 60 * 1_000;
export const RECONCILIATION_BATCH_LIMIT = 50;
export const RETENTION_CLEANUP_LIMIT = 100;

const TERMINAL_STATES = ["CONSUMED", "EXPIRED", "DELETED"] as const;
type TerminalState = (typeof TERMINAL_STATES)[number];

export interface ReconciliationCandidate {
  readonly capabilityId: string;
  readonly routingLocator: string;
  readonly attemptCount: number;
  readonly retainUntil: number | null;
  readonly terminalEvidence: {
    readonly eventId: string;
    readonly state: TerminalState;
    readonly version: number;
    readonly occurredAt: number;
  } | null;
}

export type CapabilityProjectionApplyResult = "applied" | "expired_queue_event";

export async function applyCapabilityProjection(
  database: D1Database,
  message: CapabilityProjectionMessage,
  processedAt: number
): Promise<CapabilityProjectionApplyResult> {
  const projection = message.projection;
  const eventRetainUntil = message.event.occurredAt + TERMINAL_RETENTION_MS;
  if (message.deliveryEventId !== null && eventRetainUntil <= processedAt) {
    return "expired_queue_event";
  }
  const statements: D1PreparedStatement[] = [
    database
      .prepare(
        `INSERT INTO capability_projection_events (
          capability_id, event_id, event_type, projection_version,
          occurred_at, processed_at, retain_until
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(capability_id, event_id) DO NOTHING`
      )
      .bind(
        projection.capabilityId,
        message.event.eventId,
        message.event.type,
        projection.version,
        message.event.occurredAt,
        processedAt,
        eventRetainUntil
      )
  ];

  const terminalState = asTerminalState(projection.state);
  if (terminalState !== null) {
    const terminalAt = terminalTimestamp(message);
    const catalogueDeleteAt =
      terminalState === "DELETED" ? terminalAt : terminalAt + TERMINAL_RETENTION_MS;
    const retainUntil = terminalAt + TERMINAL_RETENTION_MS;
    statements.push(
      database
        .prepare(
          `INSERT INTO capability_terminal_tombstones (
            capability_id, routing_locator, terminal_state, projection_version,
            terminal_event_id, terminal_at, catalogue_delete_at, retain_until, last_verified_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
          ON CONFLICT(capability_id) DO UPDATE SET
            routing_locator = excluded.routing_locator,
            terminal_state = excluded.terminal_state,
            projection_version = excluded.projection_version,
            terminal_event_id = excluded.terminal_event_id,
            terminal_at = excluded.terminal_at,
            catalogue_delete_at = excluded.catalogue_delete_at,
            retain_until = excluded.retain_until
          WHERE capability_terminal_tombstones.routing_locator = excluded.routing_locator
            AND capability_terminal_tombstones.projection_version < excluded.projection_version`
        )
        .bind(
          projection.capabilityId,
          projection.locator,
          terminalState,
          projection.version,
          message.event.eventId,
          terminalAt,
          catalogueDeleteAt,
          retainUntil
        )
    );
  }

  if (projection.state === "DELETED") {
    statements.push(
      database
        .prepare(
          `DELETE FROM capabilities
          WHERE id = ? AND routing_locator = ? AND version <= ?`
        )
        .bind(projection.capabilityId, projection.locator, projection.version)
    );
  } else {
    statements.push(buildCatalogueUpsert(database, message));
  }

  const candidateRetainUntil =
    terminalState === null ? null : terminalTimestamp(message) + TERMINAL_RETENTION_MS;
  statements.push(
    database
      .prepare(
        `INSERT INTO capability_reconciliation_candidates (
          capability_id, routing_locator, reason, next_attempt_at, attempt_count,
          last_attempt_at, created_at, retain_until
        ) VALUES (?, ?, 'projection_ack', ?, 0, NULL, ?, ?)
        ON CONFLICT(capability_id) DO UPDATE SET
          routing_locator = excluded.routing_locator,
          reason = 'projection_ack',
          next_attempt_at = min(
            capability_reconciliation_candidates.next_attempt_at,
            excluded.next_attempt_at
          ),
          retain_until = CASE
            WHEN capability_reconciliation_candidates.retain_until IS NULL THEN excluded.retain_until
            WHEN excluded.retain_until IS NULL THEN capability_reconciliation_candidates.retain_until
            ELSE max(capability_reconciliation_candidates.retain_until, excluded.retain_until)
          END
        WHERE capability_reconciliation_candidates.routing_locator = excluded.routing_locator`
      )
      .bind(
        projection.capabilityId,
        projection.locator,
        processedAt,
        processedAt,
        candidateRetainUntil
      )
  );

  await database.batch(statements);
  return "applied";
}

export async function completeProjectionReconciliation(
  database: D1Database,
  message: CapabilityProjectionMessage,
  now: number
): Promise<void> {
  const nextAttemptAt = nextReconciliationAt(message, now);
  const terminalState = asTerminalState(message.projection.state);
  const retainUntil =
    terminalState === null ? null : terminalTimestamp(message) + TERMINAL_RETENTION_MS;
  if (retainUntil !== null && retainUntil <= now) {
    await database
      .prepare("DELETE FROM capability_reconciliation_candidates WHERE capability_id = ?")
      .bind(message.projection.capabilityId)
      .run();
    return;
  }
  await database
    .prepare(
      `UPDATE capability_reconciliation_candidates
      SET reason = CASE
            WHEN EXISTS (
              SELECT 1 FROM capability_terminal_tombstones
              WHERE capability_id = capability_reconciliation_candidates.capability_id
            ) THEN 'terminal_verification'
            ELSE ?
          END,
          next_attempt_at = ?, attempt_count = 0,
          last_attempt_at = ?,
          retain_until = COALESCE(
            (
              SELECT retain_until FROM capability_terminal_tombstones
              WHERE capability_id = capability_reconciliation_candidates.capability_id
            ),
            ?
          )
      WHERE capability_id = ? AND routing_locator = ?`
    )
    .bind(
      reconciliationReason(message.projection.state),
      nextAttemptAt,
      now,
      retainUntil,
      message.projection.capabilityId,
      message.projection.locator
    )
    .run();
}

export async function deferReconciliationCandidate(
  database: D1Database,
  candidate: ReconciliationCandidate,
  now: number
): Promise<void> {
  const nextAttemptAt = Math.min(
    now + RECONCILIATION_RETRY_MS,
    candidate.retainUntil ?? Number.MAX_SAFE_INTEGER
  );
  await database
    .prepare(
      `UPDATE capability_reconciliation_candidates
      SET reason = 'retry', next_attempt_at = ?, attempt_count = attempt_count + 1,
          last_attempt_at = ?
      WHERE capability_id = ? AND routing_locator = ?`
    )
    .bind(nextAttemptAt, now, candidate.capabilityId, candidate.routingLocator)
    .run();
}

export async function listDueReconciliationCandidates(
  database: D1Database,
  now: number
): Promise<readonly ReconciliationCandidate[]> {
  const result = await database
    .prepare(
      `SELECT
        candidate.capability_id AS capability_id,
        candidate.routing_locator AS routing_locator,
        candidate.attempt_count AS attempt_count,
        candidate.retain_until AS candidate_retain_until,
        tombstone.terminal_event_id AS terminal_event_id,
        tombstone.terminal_state AS terminal_state,
        tombstone.projection_version AS terminal_version,
        tombstone.terminal_at AS terminal_at
      FROM capability_reconciliation_candidates AS candidate
      LEFT JOIN capability_terminal_tombstones AS tombstone
        ON tombstone.capability_id = candidate.capability_id
       AND tombstone.routing_locator = candidate.routing_locator
      WHERE candidate.next_attempt_at <= ?
        AND (candidate.retain_until IS NULL OR candidate.retain_until > ?)
      ORDER BY candidate.next_attempt_at, candidate.capability_id
      LIMIT ?`
    )
    .bind(now, now, RECONCILIATION_BATCH_LIMIT)
    .all<{
      capability_id: string;
      routing_locator: string;
      attempt_count: number;
      candidate_retain_until: number | null;
      terminal_event_id: string | null;
      terminal_state: string | null;
      terminal_version: number | null;
      terminal_at: number | null;
    }>();
  return result.results.map((row) => ({
    capabilityId: row.capability_id,
    routingLocator: row.routing_locator,
    attemptCount: row.attempt_count,
    retainUntil: row.candidate_retain_until,
    terminalEvidence:
      isTerminalState(row.terminal_state) &&
      row.terminal_event_id !== null &&
      row.terminal_version !== null &&
      row.terminal_at !== null
        ? {
            eventId: row.terminal_event_id,
            state: row.terminal_state,
            version: row.terminal_version,
            occurredAt: row.terminal_at
          }
        : null
  }));
}

export async function cleanupProjectionRetention(database: D1Database, now: number): Promise<void> {
  await database.batch([
    database
      .prepare(
        `DELETE FROM capabilities
        WHERE id IN (
          SELECT capability.id
          FROM capabilities AS capability
          INNER JOIN capability_terminal_tombstones AS tombstone
            ON tombstone.capability_id = capability.id
          WHERE tombstone.catalogue_delete_at <= ?
            AND capability.version <= tombstone.projection_version
          ORDER BY tombstone.catalogue_delete_at, capability.id
          LIMIT ?
        )`
      )
      .bind(now, RETENTION_CLEANUP_LIMIT),
    database
      .prepare(
        `DELETE FROM capability_projection_events
        WHERE rowid IN (
          SELECT rowid FROM capability_projection_events
          WHERE retain_until <= ?
          ORDER BY retain_until, capability_id, event_id
          LIMIT ?
        )`
      )
      .bind(now, RETENTION_CLEANUP_LIMIT),
    database
      .prepare(
        `DELETE FROM capability_reconciliation_candidates
        WHERE capability_id IN (
          SELECT capability_id FROM capability_reconciliation_candidates
          WHERE retain_until IS NOT NULL AND retain_until <= ?
          ORDER BY retain_until, capability_id
          LIMIT ?
        )`
      )
      .bind(now, RETENTION_CLEANUP_LIMIT),
    database
      .prepare(
        `DELETE FROM capability_terminal_tombstones
        WHERE capability_id IN (
          SELECT capability_id FROM capability_terminal_tombstones
          WHERE retain_until <= ?
          ORDER BY retain_until, capability_id
          LIMIT ?
        )`
      )
      .bind(now, RETENTION_CLEANUP_LIMIT)
  ]);
}

async function markTerminalVerified(
  database: D1Database,
  capabilityId: string,
  now: number
): Promise<void> {
  await database
    .prepare(
      "UPDATE capability_terminal_tombstones SET last_verified_at = ? WHERE capability_id = ?"
    )
    .bind(now, capabilityId)
    .run();
}

export { markTerminalVerified };

function buildCatalogueUpsert(
  database: D1Database,
  message: CapabilityProjectionMessage
): D1PreparedStatement {
  const projection = message.projection;
  return database
    .prepare(
      `INSERT INTO capabilities (
        id, workspace_id, created_by_user_id, kind, state, routing_locator,
        public_alias, policy_json, expires_at, consumed_at, disabled_at,
        deleted_at, created_at, updated_at, version
      )
      SELECT ?, NULL, NULL, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?
      WHERE NOT EXISTS (
        SELECT 1 FROM capability_terminal_tombstones
        WHERE capability_id = ?
          AND (projection_version > ? OR (projection_version = ? AND terminal_state = 'DELETED'))
      )
      ON CONFLICT(id) DO UPDATE SET
        workspace_id = excluded.workspace_id,
        created_by_user_id = excluded.created_by_user_id,
        kind = excluded.kind,
        state = excluded.state,
        public_alias = excluded.public_alias,
        policy_json = excluded.policy_json,
        expires_at = excluded.expires_at,
        consumed_at = excluded.consumed_at,
        disabled_at = excluded.disabled_at,
        deleted_at = excluded.deleted_at,
        updated_at = excluded.updated_at,
        version = excluded.version
      WHERE capabilities.routing_locator = excluded.routing_locator
        AND capabilities.version < excluded.version
        AND NOT EXISTS (
          SELECT 1 FROM capability_terminal_tombstones
          WHERE capability_id = excluded.id
            AND (
              projection_version > excluded.version
              OR (projection_version = excluded.version AND terminal_state = 'DELETED')
            )
        )`
    )
    .bind(
      projection.capabilityId,
      projection.kind,
      projection.state,
      projection.locator,
      JSON.stringify(projection.policy),
      projection.expiresAt,
      projection.consumedAt,
      projection.disabledAt,
      projection.deletedAt,
      projection.createdAt,
      projection.updatedAt,
      projection.version,
      projection.capabilityId,
      projection.version,
      projection.version
    );
}

function nextReconciliationAt(message: CapabilityProjectionMessage, now: number): number {
  const candidates = [now + RECONCILIATION_CADENCE_MS];
  if (
    (message.projection.state === "ACTIVE" || message.projection.state === "DISABLED") &&
    message.projection.expiresAt !== null
  ) {
    candidates.push(message.projection.expiresAt);
  }
  if (
    message.projection.state === "ABUSE_LOCKED" &&
    message.projection.automaticDeleteAt !== null
  ) {
    candidates.push(message.projection.automaticDeleteAt);
  }
  const terminalState = asTerminalState(message.projection.state);
  if (terminalState !== null) {
    candidates.push(terminalTimestamp(message) + TERMINAL_RETENTION_MS);
  }
  return Math.min(...candidates);
}

function reconciliationReason(state: CapabilityState): string {
  if (state === "ABUSE_LOCKED") return "abuse_lock_deadline";
  if (state === "ACTIVE" || state === "DISABLED") return "lifecycle_check";
  return asTerminalState(state) === null ? "lifecycle_check" : "terminal_verification";
}

function terminalTimestamp(message: CapabilityProjectionMessage): number {
  return (
    message.projection.consumedAt ??
    message.projection.deletedAt ??
    (message.projection.state === "EXPIRED"
      ? message.projection.updatedAt
      : message.projection.updatedAt)
  );
}

function asTerminalState(state: CapabilityState): TerminalState | null {
  return isTerminalState(state) ? state : null;
}

function isTerminalState(value: unknown): value is TerminalState {
  return TERMINAL_STATES.includes(value as TerminalState);
}
