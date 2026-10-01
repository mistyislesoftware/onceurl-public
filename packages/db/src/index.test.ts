import { describe, expect, it, vi } from "vitest";
import { buildCapabilityProjectionUpsert, createDatabase } from "./index.js";
import type { CapabilityProjectionRecord, D1Binding } from "./index.js";

const completeProjection = {
  id: "cap_projection_nonsequential",
  workspaceId: null,
  createdByUserId: null,
  kind: "secret",
  state: "ACTIVE",
  routingLocator: `loc1_${"a".repeat(48)}`,
  publicAlias: null,
  policyJson: { kind: "secret", synthetic: true },
  expiresAt: null,
  consumedAt: null,
  disabledAt: null,
  deletedAt: null,
  createdAt: new Date("2026-08-01T00:00:00.000Z"),
  updatedAt: new Date("2026-08-01T00:00:00.000Z"),
  version: 1
} satisfies CapabilityProjectionRecord;

describe("createDatabase", () => {
  it("creates independent clients without calling the D1 binding", () => {
    const unexpectedCall = () => {
      throw new Error("A D1 method was called during database construction");
    };
    const bindingMethods = {
      prepare: vi.fn(unexpectedCall),
      batch: vi.fn(unexpectedCall),
      exec: vi.fn(unexpectedCall),
      withSession: vi.fn(unexpectedCall),
      dump: vi.fn(unexpectedCall)
    };
    const binding = bindingMethods as unknown as D1Binding;

    const firstDatabase = createDatabase(binding);
    const secondDatabase = createDatabase(binding);

    expect(firstDatabase).not.toBe(secondDatabase);
    for (const method of Object.values(bindingMethods)) {
      expect(method).not.toHaveBeenCalled();
    }
  });

  it("builds a monotonic locator-immutable catalogue projection upsert", () => {
    const binding = {} as D1Binding;
    const database = createDatabase(binding);
    const query = buildCapabilityProjectionUpsert(database, completeProjection).toSQL();
    const updateClause = query.sql.split(" do update set ")[1];
    const updateSetClause = updateClause?.split(" where ")[0];

    expect(query.sql).toContain('insert into "capabilities"');
    expect(query.sql).toContain('on conflict ("capabilities"."id") do update');
    expect(query.sql).toContain('"routing_locator"');
    expect(query.sql).toContain(
      'where "capabilities"."routing_locator" = excluded.routing_locator and "capabilities"."version" < excluded.version'
    );
    expect(updateClause).toBeDefined();
    expect(updateSetClause).not.toContain('"routing_locator"');
    expect(query.sql).not.toContain("token_hash");
    expect(JSON.stringify(query.params)).not.toContain("bearer");
    expect(JSON.stringify(query.params)).not.toContain("authorization");
  });

  it("rejects incomplete authoritative projection snapshots at compile time", () => {
    const { version: omittedVersion, ...withoutVersion } = completeProjection;
    const { workspaceId: omittedWorkspaceId, ...withoutWorkspaceId } = completeProjection;
    const { expiresAt: omittedExpiresAt, ...withoutExpiresAt } = completeProjection;

    void omittedVersion;
    void omittedWorkspaceId;
    void omittedExpiresAt;

    // @ts-expect-error Projection versions must always be explicit.
    const missingVersion: CapabilityProjectionRecord = withoutVersion;
    // @ts-expect-error Nullable snapshot fields must be present even when null.
    const missingWorkspaceId: CapabilityProjectionRecord = withoutWorkspaceId;
    // @ts-expect-error Nullable lifecycle fields must be present even when null.
    const missingExpiresAt: CapabilityProjectionRecord = withoutExpiresAt;

    expect([missingVersion, missingWorkspaceId, missingExpiresAt]).toHaveLength(3);
  });
});
