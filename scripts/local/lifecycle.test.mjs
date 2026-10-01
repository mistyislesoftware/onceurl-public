import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { databaseBinding, runWranglerLocal, wranglerConfigArgument } from "../database/helpers.mjs";
import { rootDirectory } from "./config.mjs";
import { resetLocalState } from "./reset.mjs";
import { seedLocalDatabase } from "./seed.mjs";

const isolatedRepository = join(rootDirectory, ".tmp", "local-lifecycle-test");
const isolatedState = join(isolatedRepository, ".wrangler", "state");

function migrate() {
  return runWranglerLocal([
    "d1",
    "migrations",
    "apply",
    databaseBinding,
    "--config",
    wranglerConfigArgument,
    "--local",
    "--persist-to",
    isolatedState
  ]);
}

function querySeedSnapshot() {
  const result = runWranglerLocal(
    [
      "d1",
      "execute",
      databaseBinding,
      "--config",
      wranglerConfigArgument,
      "--local",
      "--persist-to",
      isolatedState,
      "--command",
      "SELECT c.id, c.state, c.routing_locator, c.policy_json, c.created_at, r.view_count " +
        "FROM capabilities c JOIN capability_counters r ON r.capability_id = c.id " +
        "WHERE c.id LIKE 'local-synthetic-%' ORDER BY c.id;",
      "--json"
    ],
    { quiet: true }
  );
  const jsonStart = result.stdout.indexOf("[");
  expect(jsonStart).toBeGreaterThanOrEqual(0);
  return JSON.parse(result.stdout.slice(jsonStart)).flatMap((response) => response.results ?? []);
}

beforeAll(async () => {
  await rm(isolatedRepository, { recursive: true, force: true });
});

afterAll(async () => {
  await rm(isolatedRepository, { recursive: true, force: true });
});

describe("local migrate, seed, and reset lifecycle", () => {
  it("is repeatable and recreates the same deterministic snapshot after reset", async () => {
    migrate();
    migrate();
    seedLocalDatabase(isolatedState);
    const firstSnapshot = querySeedSnapshot();

    await resetLocalState(isolatedRepository, isolatedState);
    await expect(readFile(join(isolatedState, "sentinel"), "utf8")).rejects.toMatchObject({
      code: "ENOENT"
    });

    migrate();
    seedLocalDatabase(isolatedState);
    const secondSnapshot = querySeedSnapshot();

    expect(secondSnapshot).toEqual(firstSnapshot);
    expect(JSON.stringify(secondSnapshot)).toContain("local-synthetic-alpha");
    expect(JSON.stringify(secondSnapshot)).toContain("local-synthetic-beta");
    expect(secondSnapshot.map((row) => row.routing_locator)).toEqual([
      `loc1_${"a".repeat(48)}`,
      `loc1_${"b".repeat(48)}`
    ]);
  }, 60_000);
});
