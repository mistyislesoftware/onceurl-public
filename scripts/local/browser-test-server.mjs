import { rm } from "node:fs/promises";
import { join } from "node:path";
import { rootDirectory } from "./config.mjs";
import { runLocalDevelopment } from "./start.mjs";

const testRoot = join(rootDirectory, ".tmp", "local-browser-tests");
const stateDirectory = join(testRoot, "state");
const browserTestPreparationKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

await rm(testRoot, { recursive: true, force: true });
try {
  await runLocalDevelopment({
    ephemeralPreparationKey: browserTestPreparationKey,
    quiet: true,
    stateDirectory
  });
} finally {
  await rm(testRoot, { recursive: true, force: true });
}
