import { cp, mkdir, readFile, rm } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import {
  assert,
  assertHashRecordsEqual,
  calculateMigrationChecksums,
  databasePackageDirectory,
  hashDirectory,
  isRecord,
  migrationDirectory,
  readChecksumManifest,
  rootDirectory,
  runPnpm,
  wranglerConfigPath
} from "./helpers.mjs";

const committedBefore = await hashDirectory(migrationDirectory);
const sqlChecksums = await calculateMigrationChecksums();
assert(Object.keys(sqlChecksums).length > 0, "No committed SQL migrations were found");

const manifest = await readChecksumManifest();
assert(manifest, "Committed SQL migrations require a checksum manifest");
assertHashRecordsEqual(
  manifest.files,
  sqlChecksums,
  "A committed SQL migration was added, removed, or modified without updating history"
);

const configValue = /** @type {unknown} */ (JSON.parse(await readFile(wranglerConfigPath, "utf8")));
assert(isRecord(configValue), "Wrangler configuration must be a JSON object");

const databaseConfigsValue = configValue.d1_databases;
assert(Array.isArray(databaseConfigsValue), "Wrangler must declare D1 databases");
const databaseConfigs = /** @type {unknown[]} */ (databaseConfigsValue);
const databaseConfig = databaseConfigs.find((entry) => isRecord(entry) && entry.binding === "DB");
assert(isRecord(databaseConfig), "Wrangler must declare the canonical DB binding");
assert(
  typeof databaseConfig.migrations_dir === "string",
  "DB must explicitly declare migrations_dir"
);
assert(
  typeof databaseConfig.migrations_pattern === "string",
  "DB must explicitly declare migrations_pattern"
);
assert(
  typeof databaseConfig.migrations_table === "string" && databaseConfig.migrations_table.length > 0,
  "DB must explicitly declare migrations_table"
);

const configuredDirectory = resolve(dirname(wranglerConfigPath), databaseConfig.migrations_dir);
assert(
  configuredDirectory === resolve(migrationDirectory),
  "Wrangler migrations_dir does not point to the committed Drizzle migration directory"
);
assert(
  databaseConfig.migrations_pattern === databaseConfig.migrations_dir + "/*.sql",
  "Wrangler migrations_pattern must discover the installed Drizzle top-level SQL layout"
);
assert(
  Object.keys(sqlChecksums).every((path) => !path.includes("/")),
  "Committed SQL layout is nested but Wrangler is configured for top-level SQL files"
);

runPnpm(["--filter", "@onceurl/db", "db:history:check"]);

const temporaryRoot = join(rootDirectory, ".tmp", "database-migration-drift");
const temporaryMigrations = join(temporaryRoot, "migrations");
const temporaryMigrationsArgument = relative(databasePackageDirectory, temporaryMigrations)
  .split(sep)
  .join("/");
await rm(temporaryRoot, { recursive: true, force: true });
await mkdir(temporaryRoot, { recursive: true });
await cp(migrationDirectory, temporaryMigrations, { recursive: true });

try {
  const isolatedBefore = await hashDirectory(temporaryMigrations);
  const generation = runPnpm([
    "--filter",
    "@onceurl/db",
    "exec",
    "drizzle-kit",
    "generate",
    "--dialect",
    "sqlite",
    "--schema",
    "./src/schema.ts",
    "--out",
    temporaryMigrationsArgument,
    "--breakpoints"
  ]);
  assert(
    !/(^|\\n)Error:/.test(generation.stdout + "\\n" + generation.stderr),
    "Drizzle reported an error while checking isolated schema drift"
  );
  const isolatedAfter = await hashDirectory(temporaryMigrations);
  assertHashRecordsEqual(
    isolatedAfter,
    isolatedBefore,
    "Current Drizzle schema would add or modify migration artifacts"
  );
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

const committedAfter = await hashDirectory(migrationDirectory);
assertHashRecordsEqual(
  committedAfter,
  committedBefore,
  "Migration drift check modified the committed migration directory"
);

process.stdout.write(
  "Migration history, checksums, Wrangler discovery, and schema drift are valid.\n"
);
