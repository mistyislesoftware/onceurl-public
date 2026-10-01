import { join } from "node:path";
import {
  databaseBinding,
  localStateDirectory,
  runWranglerLocal,
  wranglerConfigArgument
} from "../database/helpers.mjs";
import { rootDirectory } from "./config.mjs";

export function seedLocalDatabase(stateDirectory = localStateDirectory) {
  return runWranglerLocal([
    "d1",
    "execute",
    databaseBinding,
    "--config",
    wranglerConfigArgument,
    "--local",
    "--persist-to",
    stateDirectory,
    "--file",
    join(rootDirectory, "scripts", "local", "seed.sql"),
    "--yes"
  ]);
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  if (process.argv.length !== 2) {
    throw new Error("Local seed does not accept arguments");
  }
  try {
    seedLocalDatabase();
  } catch (error) {
    throw new Error(
      "Local seed failed. Run pnpm db:migrate:local first.\n" +
        (error instanceof Error ? error.message : String(error)),
      { cause: error }
    );
  }
  process.stdout.write("Deterministic synthetic local seed applied.\n");
}
