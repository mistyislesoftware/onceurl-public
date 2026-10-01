import {
  assert,
  databaseBinding,
  localStateDirectory,
  runWranglerLocal,
  wranglerConfigArgument
} from "./helpers.mjs";

const action = process.argv[2];
assert(process.argv.length === 3, "Local migration commands do not accept additional arguments");
assert(action === "apply" || action === "list", "Expected migration action apply or list");

runWranglerLocal([
  "d1",
  "migrations",
  action,
  databaseBinding,
  "--config",
  wranglerConfigArgument,
  "--local",
  "--persist-to",
  localStateDirectory
]);
