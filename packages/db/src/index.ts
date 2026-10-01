import type { D1Database } from "@cloudflare/workers-types";
import { sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/d1";
import { capabilities, schema, type CapabilitySelect } from "./schema.js";

export * from "./schema.js";

export type D1Binding = D1Database;

export function createDatabase(d1Binding: D1Binding) {
  return drizzle(d1Binding, { schema });
}

export type Database = ReturnType<typeof createDatabase>;

export type CapabilityProjectionRecord = Pick<
  CapabilitySelect,
  | "id"
  | "workspaceId"
  | "createdByUserId"
  | "kind"
  | "state"
  | "routingLocator"
  | "publicAlias"
  | "policyJson"
  | "expiresAt"
  | "consumedAt"
  | "disabledAt"
  | "deletedAt"
  | "createdAt"
  | "updatedAt"
  | "version"
>;

export function buildCapabilityProjectionUpsert(
  database: Database,
  projection: CapabilityProjectionRecord
) {
  // The later Queue consumer may replay or reorder projection records. Existing
  // rows therefore advance only for the same immutable locator and a strictly
  // newer authoritative version. Stale, duplicate, same-version conflicting,
  // and locator-conflicting records are deliberate no-ops.
  return database
    .insert(capabilities)
    .values(projection)
    .onConflictDoUpdate({
      target: capabilities.id,
      set: {
        workspaceId: projection.workspaceId,
        createdByUserId: projection.createdByUserId,
        kind: projection.kind,
        state: projection.state,
        publicAlias: projection.publicAlias,
        policyJson: projection.policyJson,
        expiresAt: projection.expiresAt,
        consumedAt: projection.consumedAt,
        disabledAt: projection.disabledAt,
        deletedAt: projection.deletedAt,
        updatedAt: projection.updatedAt,
        version: projection.version
      },
      where: sql`${capabilities.routingLocator} = excluded.routing_locator and ${capabilities.version} < excluded.version`
    });
}

export async function upsertCapabilityProjection(
  database: Database,
  projection: CapabilityProjectionRecord
): Promise<void> {
  await buildCapabilityProjectionUpsert(database, projection).run();
}
