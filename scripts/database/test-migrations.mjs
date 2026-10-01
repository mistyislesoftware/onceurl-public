import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  assert,
  calculateMigrationChecksums,
  databaseBinding,
  isRecord,
  migrationDirectory,
  rootDirectory,
  runWranglerLocal,
  wranglerConfigArgument
} from "./helpers.mjs";

const smokeStateDirectory = join(rootDirectory, ".tmp", "database-migration-smoke");
const upgradeRootDirectory = join(rootDirectory, ".tmp", "database-migration-upgrade");
const upgradeStateDirectory = join(upgradeRootDirectory, "state");
const upgradeMigrationDirectory = join(upgradeRootDirectory, "migrations");
const upgradeConfigPath = join(upgradeRootDirectory, "wrangler.jsonc");
const migrationFiles = Object.keys(await calculateMigrationChecksums()).sort();
assert(migrationFiles.length > 0, "Migration smoke test requires committed SQL migrations");

/**
 * @param {string} value
 */
function quoteSql(value) {
  return "'" + value.replaceAll("'", "''") + "'";
}

/**
 * @param {{
 *   id: string;
 *   routingLocator: string;
 *   policyJson?: string;
 *   version?: number;
 *   workspaceId?: string | null;
 *   createdByUserId?: string | null;
 * }} options
 */
function capabilityInsert(options) {
  const columns = [
    "id",
    "workspace_id",
    "created_by_user_id",
    "kind",
    "state",
    "routing_locator",
    "public_alias",
    "policy_json",
    "expires_at",
    "consumed_at",
    "disabled_at",
    "deleted_at",
    "created_at",
    "updated_at"
  ];
  const values = [
    quoteSql(options.id),
    options.workspaceId === null || options.workspaceId === undefined
      ? "NULL"
      : quoteSql(options.workspaceId),
    options.createdByUserId === null || options.createdByUserId === undefined
      ? "NULL"
      : quoteSql(options.createdByUserId),
    quoteSql("secret"),
    quoteSql("ACTIVE"),
    quoteSql(options.routingLocator),
    "NULL",
    quoteSql(options.policyJson ?? "{}"),
    "NULL",
    "NULL",
    "NULL",
    "NULL",
    "1700000000000",
    "1700000000000"
  ];

  if (options.version !== undefined) {
    columns.push("version");
    values.push(String(options.version));
  }

  return (
    "INSERT INTO capabilities (" + columns.join(", ") + ") VALUES (" + values.join(", ") + ");"
  );
}

/**
 * @param {string} output
 * @returns {unknown}
 */
function parseJsonOutput(output) {
  const trimmed = output.trim();

  for (let index = 0; index < trimmed.length; index += 1) {
    if (trimmed[index] !== "[" && trimmed[index] !== "{") {
      continue;
    }

    try {
      return /** @type {unknown} */ (JSON.parse(trimmed.slice(index)));
    } catch {
      continue;
    }
  }

  throw new Error("Wrangler did not return valid JSON");
}

/**
 * @param {string} sql
 * @param {boolean} [allowFailure]
 * @param {string} [stateDirectory]
 * @param {string} [configArgument]
 */
function executeSqlRaw(
  sql,
  allowFailure = false,
  stateDirectory = smokeStateDirectory,
  configArgument = wranglerConfigArgument
) {
  return runWranglerLocal(
    [
      "d1",
      "execute",
      databaseBinding,
      "--config",
      configArgument,
      "--local",
      "--persist-to",
      stateDirectory,
      "--command",
      sql,
      "--json"
    ],
    { allowFailure, quiet: true }
  );
}

/**
 * @param {string} sql
 * @param {string} [stateDirectory]
 * @param {string} [configArgument]
 * @returns {Record<string, unknown>[]}
 */
function executeSql(
  sql,
  stateDirectory = smokeStateDirectory,
  configArgument = wranglerConfigArgument
) {
  const result = executeSqlRaw(sql, false, stateDirectory, configArgument);
  const parsed = parseJsonOutput(result.stdout);
  assert(Array.isArray(parsed), "Wrangler JSON response must be an array");

  const rows = [];
  for (const response of parsed) {
    assert(isRecord(response), "Wrangler JSON entries must be objects");
    assert(response.success !== false, "Wrangler reported a failed local D1 query");

    if (Array.isArray(response.results)) {
      for (const row of response.results) {
        assert(isRecord(row), "D1 result rows must be objects");
        rows.push(row);
      }
    }
  }

  return rows;
}

/**
 * @param {string} sql
 * @param {string} description
 */
function expectConstraintFailure(sql, description) {
  const result = executeSqlRaw(sql, true);
  const output = result.stdout + "\n" + result.stderr;

  assert(result.status !== 0, description + " unexpectedly succeeded");
  assert(
    /SQLITE_CONSTRAINT|constraint failed|UNIQUE constraint|CHECK constraint/i.test(output),
    description + " failed for a reason other than a database constraint"
  );
}

/**
 * @param {Record<string, unknown>[]} rows
 * @param {string} field
 */
function stringFieldValues(rows, field) {
  return rows.map((row) => {
    const value = row[field];
    assert(typeof value === "string", "Expected string field " + field);
    return value;
  });
}

/**
 * @param {Record<string, unknown>[]} rows
 */
function onlyRow(rows) {
  assert(rows.length === 1, "Expected exactly one D1 result row");
  const row = rows[0];
  assert(row, "Expected a D1 result row");
  return row;
}

/**
 * @param {string[]} actual
 * @param {string[]} expected
 * @param {string} description
 */
function assertStringSet(actual, expected, description) {
  const actualSorted = [...actual].sort();
  const expectedSorted = [...expected].sort();
  assert(JSON.stringify(actualSorted) === JSON.stringify(expectedSorted), description);
}

/**
 * @param {string[]} actual
 * @param {string[]} expected
 * @param {string} description
 */
function assertStringSequence(actual, expected, description) {
  assert(JSON.stringify(actual) === JSON.stringify(expected), description);
}

async function testUpgradeFromInitialMigration() {
  await rm(upgradeRootDirectory, { recursive: true, force: true });
  await mkdir(upgradeMigrationDirectory, { recursive: true });
  await cp(
    join(migrationDirectory, "0000_initial_capability_catalogue.sql"),
    join(upgradeMigrationDirectory, "0000_initial_capability_catalogue.sql")
  );
  await writeFile(
    upgradeConfigPath,
    JSON.stringify(
      {
        name: "onceurl-migration-upgrade-test",
        compatibility_date: "2026-07-12",
        d1_databases: [
          {
            binding: databaseBinding,
            database_name: "onceurl-migration-upgrade-test",
            database_id: "local-migration-upgrade-test",
            migrations_dir: "./migrations",
            migrations_pattern: "./migrations/*.sql",
            migrations_table: "d1_migrations"
          }
        ]
      },
      null,
      2
    ) + "\n",
    "utf8"
  );

  const upgradeArguments = [
    databaseBinding,
    "--config",
    upgradeConfigPath,
    "--local",
    "--persist-to",
    upgradeStateDirectory
  ];
  runWranglerLocal(["d1", "migrations", "apply", ...upgradeArguments]);
  executeSql(
    "INSERT INTO capabilities (" +
      "id, kind, state, public_token_hash, owner_token_hash, policy_json, created_at, updated_at" +
      ") VALUES (" +
      "'legacy-catalogue-row', 'secret', 'ACTIVE', " +
      "'legacy-synthetic-public-hash', 'legacy-synthetic-owner-hash', '{}', " +
      "1700000000000, 1700000000000);",
    upgradeStateDirectory,
    upgradeConfigPath
  );
  executeSql(
    "INSERT INTO capability_counters (" +
      "capability_id, view_count, consumption_count, download_count, upload_count, " +
      "click_count, updated_at" +
      ") VALUES (" +
      "'legacy-catalogue-row', 11, 7, 5, 3, 2, 1700000001234);",
    upgradeStateDirectory,
    upgradeConfigPath
  );

  for (const migrationFile of migrationFiles.slice(1)) {
    await cp(
      join(migrationDirectory, migrationFile),
      join(upgradeMigrationDirectory, migrationFile)
    );
  }
  runWranglerLocal(["d1", "migrations", "apply", ...upgradeArguments]);

  const upgradedColumns = stringFieldValues(
    executeSql("PRAGMA table_info(capabilities);", upgradeStateDirectory, upgradeConfigPath),
    "name"
  );
  assert(upgradedColumns.includes("routing_locator"), "Upgrade did not add routing_locator");
  assert(!upgradedColumns.includes("public_token_hash"), "Upgrade retained public_token_hash");
  assert(!upgradedColumns.includes("owner_token_hash"), "Upgrade retained owner_token_hash");

  const upgradedLegacy = onlyRow(
    executeSql(
      "SELECT id, routing_locator FROM capabilities WHERE id = 'legacy-catalogue-row';",
      upgradeStateDirectory,
      upgradeConfigPath
    )
  );
  assert(upgradedLegacy.id === "legacy-catalogue-row", "Upgrade lost the existing catalogue row");
  assert(
    typeof upgradedLegacy.routing_locator === "string" &&
      /^loc1_[0-9a-f]{48}$/u.test(upgradedLegacy.routing_locator),
    "Upgrade did not backfill a valid random locator"
  );

  const upgradedCounters = onlyRow(
    executeSql(
      "SELECT capability_id, view_count, consumption_count, download_count, upload_count, " +
        "click_count, updated_at FROM capability_counters " +
        "WHERE capability_id = 'legacy-catalogue-row';",
      upgradeStateDirectory,
      upgradeConfigPath
    )
  );
  assert(
    JSON.stringify(upgradedCounters) ===
      JSON.stringify({
        capability_id: "legacy-catalogue-row",
        view_count: 11,
        consumption_count: 7,
        download_count: 5,
        upload_count: 3,
        click_count: 2,
        updated_at: 1700000001234
      }),
    "Upgrade did not preserve the exact legacy reporting counters"
  );

  const tracked = stringFieldValues(
    executeSql(
      "SELECT name FROM d1_migrations ORDER BY id;",
      upgradeStateDirectory,
      upgradeConfigPath
    ),
    "name"
  );
  assertStringSequence(
    tracked,
    migrationFiles,
    "Upgrade did not record the complete migration chain"
  );
}

const migrationArguments = [
  databaseBinding,
  "--config",
  wranglerConfigArgument,
  "--local",
  "--persist-to",
  smokeStateDirectory
];

await rm(smokeStateDirectory, { recursive: true, force: true });
await rm(upgradeRootDirectory, { recursive: true, force: true });

try {
  await testUpgradeFromInitialMigration();

  const pendingBefore = runWranglerLocal(["d1", "migrations", "list", ...migrationArguments]);
  for (const migrationFile of migrationFiles) {
    assert(
      pendingBefore.stdout.includes(migrationFile),
      "Fresh local D1 state did not list pending migration " + migrationFile
    );
  }

  const firstApply = runWranglerLocal(["d1", "migrations", "apply", ...migrationArguments]);
  for (const migrationFile of migrationFiles) {
    assert(
      firstApply.stdout.includes(migrationFile),
      "Local D1 migration apply did not report " + migrationFile
    );
  }

  const pendingAfterFirstApply = runWranglerLocal([
    "d1",
    "migrations",
    "list",
    ...migrationArguments
  ]);
  for (const migrationFile of migrationFiles) {
    assert(
      !pendingAfterFirstApply.stdout.includes(migrationFile),
      "Migration remained pending after apply: " + migrationFile
    );
  }

  const tableRows = executeSql(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN " +
      "('capabilities', 'capability_counters', 'capability_projection_events', " +
      "'capability_terminal_tombstones', 'capability_reconciliation_candidates') " +
      "ORDER BY name;"
  );
  assertStringSet(
    stringFieldValues(tableRows, "name"),
    [
      "capabilities",
      "capability_counters",
      "capability_projection_events",
      "capability_terminal_tombstones",
      "capability_reconciliation_candidates"
    ],
    "Required capability tables are missing"
  );

  assertStringSet(
    stringFieldValues(executeSql("PRAGMA table_info(capabilities);"), "name"),
    [
      "id",
      "workspace_id",
      "created_by_user_id",
      "kind",
      "state",
      "routing_locator",
      "public_alias",
      "policy_json",
      "expires_at",
      "consumed_at",
      "disabled_at",
      "deleted_at",
      "created_at",
      "updated_at",
      "version"
    ],
    "capabilities columns do not match the canonical schema"
  );
  assertStringSet(
    stringFieldValues(executeSql("PRAGMA table_info(capability_counters);"), "name"),
    [
      "capability_id",
      "view_count",
      "consumption_count",
      "download_count",
      "upload_count",
      "click_count",
      "updated_at"
    ],
    "capability_counters columns do not match the canonical schema"
  );
  assertStringSet(
    stringFieldValues(executeSql("PRAGMA table_info(capability_projection_events);"), "name"),
    [
      "capability_id",
      "event_id",
      "event_type",
      "projection_version",
      "occurred_at",
      "processed_at",
      "retain_until"
    ],
    "capability_projection_events columns do not match the canonical schema"
  );
  assertStringSet(
    stringFieldValues(executeSql("PRAGMA table_info(capability_terminal_tombstones);"), "name"),
    [
      "capability_id",
      "routing_locator",
      "terminal_state",
      "projection_version",
      "terminal_event_id",
      "terminal_at",
      "catalogue_delete_at",
      "retain_until",
      "last_verified_at"
    ],
    "capability_terminal_tombstones columns do not match the canonical schema"
  );
  assertStringSet(
    stringFieldValues(
      executeSql("PRAGMA table_info(capability_reconciliation_candidates);"),
      "name"
    ),
    [
      "capability_id",
      "routing_locator",
      "reason",
      "next_attempt_at",
      "attempt_count",
      "last_attempt_at",
      "created_at",
      "retain_until"
    ],
    "capability_reconciliation_candidates columns do not match the canonical schema"
  );

  const capabilityTableSql = onlyRow(
    executeSql("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'capabilities';")
  ).sql;
  assert(typeof capabilityTableSql === "string", "capabilities table SQL was not available");
  for (const constraint of [
    "capabilities_routing_locator_format",
    "capabilities_policy_json_object",
    "capabilities_version_positive_integer"
  ]) {
    assert(capabilityTableSql.includes(constraint), "Missing capability constraint " + constraint);
  }

  const counterTableSql = onlyRow(
    executeSql(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'capability_counters';"
    )
  ).sql;
  assert(typeof counterTableSql === "string", "capability_counters table SQL was not available");
  for (const constraint of [
    "capability_counters_view_count_non_negative",
    "capability_counters_consumption_count_non_negative",
    "capability_counters_download_count_non_negative",
    "capability_counters_upload_count_non_negative",
    "capability_counters_click_count_non_negative"
  ]) {
    assert(counterTableSql.includes(constraint), "Missing counter constraint " + constraint);
  }

  const indexRows = executeSql("PRAGMA index_list(capabilities);");
  const indexesByName = new Map(
    indexRows.map((row) => {
      assert(typeof row.name === "string", "Capability index name must be a string");
      return [row.name, row];
    })
  );
  for (const indexName of [
    "capabilities_routing_locator_unique",
    "capabilities_state_expires_at_idx",
    "capabilities_workspace_id_created_at_idx"
  ]) {
    assert(indexesByName.has(indexName), "Missing capability index " + indexName);
  }
  assert(
    indexesByName.get("capabilities_routing_locator_unique")?.unique === 1,
    "routing_locator index must be unique"
  );

  /** @type {Array<[string, string[]]>} */
  const compositeIndexes = [
    ["capabilities_state_expires_at_idx", ["state", "expires_at"]],
    ["capabilities_workspace_id_created_at_idx", ["workspace_id", "created_at"]]
  ];
  for (const [indexName, expectedColumns] of compositeIndexes) {
    assertStringSequence(
      stringFieldValues(executeSql("PRAGMA index_info(" + quoteSql(indexName) + ");"), "name"),
      expectedColumns,
      indexName + " columns do not match the canonical index"
    );
  }

  const foreignKey = onlyRow(executeSql("PRAGMA foreign_key_list(capability_counters);"));
  assert(foreignKey.table === "capabilities", "Counter foreign key must target capabilities");
  assert(foreignKey.from === "capability_id", "Counter foreign key must use capability_id");
  assert(foreignKey.to === "id", "Counter foreign key must target capabilities.id");
  assert(foreignKey.on_delete === "CASCADE", "Counter foreign key must cascade deletes");

  executeSql(
    [
      capabilityInsert({
        id: "capability-synthetic-valid",
        routingLocator: `loc1_${"a".repeat(48)}`,
        workspaceId: "workspace-synthetic",
        createdByUserId: "user-synthetic"
      }),
      "INSERT INTO capability_counters (capability_id, updated_at) VALUES " +
        "('capability-synthetic-valid', 1700000000000);",
      capabilityInsert({
        id: "capability-synthetic-second",
        routingLocator: `loc1_${"b".repeat(48)}`
      }),
      capabilityInsert({
        id: "capability-synthetic-third",
        routingLocator: `loc1_${"c".repeat(48)}`
      })
    ].join("\n")
  );

  const defaults = onlyRow(
    executeSql(
      "SELECT c.version, r.view_count, r.consumption_count, r.download_count, " +
        "r.upload_count, r.click_count FROM capabilities c " +
        "JOIN capability_counters r ON r.capability_id = c.id " +
        "WHERE c.id = 'capability-synthetic-valid';"
    )
  );
  assert(defaults.version === 1, "Capability version must default to 1");
  for (const field of [
    "view_count",
    "consumption_count",
    "download_count",
    "upload_count",
    "click_count"
  ]) {
    assert(defaults[field] === 0, field + " must default to zero");
  }

  executeSql(
    "INSERT INTO capabilities " +
      "(id, kind, state, routing_locator, policy_json, created_at, updated_at, version) VALUES " +
      `('capability-synthetic-valid', 'secret', 'CONSUMED', 'loc1_${"a".repeat(48)}', ` +
      "'{}', 1700000000000, 1700000001000, 2) " +
      "ON CONFLICT(id) DO UPDATE SET state = excluded.state, " +
      "updated_at = excluded.updated_at, version = excluded.version " +
      "WHERE capabilities.routing_locator = excluded.routing_locator " +
      "AND capabilities.version < excluded.version;"
  );
  const upsertedProjection = onlyRow(
    executeSql(
      "SELECT state, routing_locator, updated_at, version FROM capabilities " +
        "WHERE id = 'capability-synthetic-valid';"
    )
  );
  assert(upsertedProjection.state === "CONSUMED", "Projection upsert did not update state");
  assert(upsertedProjection.version === 2, "Projection upsert did not update version");
  assert(
    upsertedProjection.routing_locator === `loc1_${"a".repeat(48)}`,
    "Projection upsert did not preserve the routing locator"
  );

  for (const ignoredProjection of [
    {
      description: "stale projection",
      state: "ACTIVE",
      routingLocator: `loc1_${"a".repeat(48)}`,
      updatedAt: 1700000002000,
      version: 1
    },
    {
      description: "identical replay",
      state: "CONSUMED",
      routingLocator: `loc1_${"a".repeat(48)}`,
      updatedAt: 1700000001000,
      version: 2
    },
    {
      description: "same-version conflicting projection",
      state: "ABUSE_LOCKED",
      routingLocator: `loc1_${"a".repeat(48)}`,
      updatedAt: 1700000003000,
      version: 2
    },
    {
      description: "newer projection with a conflicting locator",
      state: "DISABLED",
      routingLocator: `loc1_${"d".repeat(48)}`,
      updatedAt: 1700000004000,
      version: 3
    }
  ]) {
    executeSql(
      "INSERT INTO capabilities " +
        "(id, kind, state, routing_locator, policy_json, created_at, updated_at, version) VALUES " +
        "('capability-synthetic-valid', 'secret', " +
        quoteSql(ignoredProjection.state) +
        ", " +
        quoteSql(ignoredProjection.routingLocator) +
        ", '{}', 1700000000000, " +
        ignoredProjection.updatedAt +
        ", " +
        ignoredProjection.version +
        ") ON CONFLICT(id) DO UPDATE SET state = excluded.state, " +
        "updated_at = excluded.updated_at, version = excluded.version " +
        "WHERE capabilities.routing_locator = excluded.routing_locator " +
        "AND capabilities.version < excluded.version;"
    );
    const retainedProjection = onlyRow(
      executeSql(
        "SELECT state, routing_locator, updated_at, version FROM capabilities " +
          "WHERE id = 'capability-synthetic-valid';"
      )
    );
    assert(
      JSON.stringify(retainedProjection) === JSON.stringify(upsertedProjection),
      "Projection upsert mutated state for " + ignoredProjection.description
    );
  }

  expectConstraintFailure(
    capabilityInsert({
      id: "capability-synthetic-duplicate-locator",
      routingLocator: `loc1_${"a".repeat(48)}`
    }),
    "Duplicate routing_locator"
  );
  expectConstraintFailure(
    capabilityInsert({
      id: "capability-synthetic-empty-locator",
      routingLocator: ""
    }),
    "Empty routing_locator"
  );
  expectConstraintFailure(
    capabilityInsert({
      id: "capability-synthetic-malformed-locator",
      routingLocator: `loc1_${"g".repeat(48)}`
    }),
    "Malformed routing_locator"
  );
  expectConstraintFailure(
    capabilityInsert({
      id: "capability-synthetic-invalid-json",
      routingLocator: `loc1_${"d".repeat(48)}`,
      policyJson: "not-json"
    }),
    "Invalid policy_json"
  );
  expectConstraintFailure(
    capabilityInsert({
      id: "capability-synthetic-array-json",
      routingLocator: `loc1_${"e".repeat(48)}`,
      policyJson: "[]"
    }),
    "Non-object policy_json"
  );
  expectConstraintFailure(
    capabilityInsert({
      id: "capability-synthetic-version-zero",
      routingLocator: `loc1_${"f".repeat(48)}`,
      version: 0
    }),
    "Non-positive capability version"
  );
  expectConstraintFailure(
    "INSERT INTO capability_counters (capability_id, view_count, updated_at) VALUES " +
      "('capability-synthetic-second', -1, 1700000000000);",
    "Negative reporting counter"
  );

  executeSql("DELETE FROM capabilities WHERE id = 'capability-synthetic-valid';");
  const cascadedCounterCount = onlyRow(
    executeSql(
      "SELECT COUNT(*) AS count FROM capability_counters " +
        "WHERE capability_id = 'capability-synthetic-valid';"
    )
  ).count;
  assert(cascadedCounterCount === 0, "Deleting a capability must cascade to its counter row");

  const trackedMigrations = stringFieldValues(
    executeSql("SELECT name FROM d1_migrations ORDER BY id;"),
    "name"
  );
  assertStringSet(
    trackedMigrations,
    migrationFiles,
    "D1 migration tracking table does not record every committed migration"
  );

  const schemaFingerprintBefore = JSON.stringify(
    executeSql(
      "SELECT type, name, tbl_name, sql FROM sqlite_master " +
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name;"
    )
  );
  const secondApply = runWranglerLocal(["d1", "migrations", "apply", ...migrationArguments]);
  assert(
    /No migrations to apply/i.test(secondApply.stdout + secondApply.stderr),
    "Reapplying migrations must be a no-op"
  );
  const schemaFingerprintAfter = JSON.stringify(
    executeSql(
      "SELECT type, name, tbl_name, sql FROM sqlite_master " +
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name;"
    )
  );
  assert(
    schemaFingerprintAfter === schemaFingerprintBefore,
    "Reapplying migrations changed the local schema"
  );

  const pendingAfterSecondApply = runWranglerLocal([
    "d1",
    "migrations",
    "list",
    ...migrationArguments
  ]);
  for (const migrationFile of migrationFiles) {
    assert(
      !pendingAfterSecondApply.stdout.includes(migrationFile),
      "Migration was pending after the no-op reapply: " + migrationFile
    );
  }

  process.stdout.write(
    "Legacy upgrade plus fresh local D1 migration application, constraints, indexes, projection upsert, tracking, and no-op reapply passed.\n"
  );
} finally {
  await rm(smokeStateDirectory, { recursive: true, force: true });
  await rm(upgradeRootDirectory, { recursive: true, force: true });
}
