import { mkdir, writeFile } from "node:fs/promises";
import {
  assert,
  calculateMigrationChecksums,
  checksumManifestPath,
  parentDirectory,
  readChecksumManifest,
  runPnpm
} from "./helpers.mjs";

const existingChecksums = await calculateMigrationChecksums();
const existingManifest = await readChecksumManifest();

if (Object.keys(existingChecksums).length > 0) {
  assert(existingManifest, "Existing SQL migrations require a checksum manifest");
  assert(
    JSON.stringify(existingManifest.files) === JSON.stringify(existingChecksums),
    "A historical SQL migration differs from the committed checksum manifest"
  );
} else {
  assert(
    existingManifest === null || Object.keys(existingManifest.files).length === 0,
    "Checksum manifest references SQL migrations that do not exist"
  );
}

const forwardedArguments = process.argv.slice(2).filter((argument) => argument !== "--");
runPnpm([
  "--filter",
  "@onceurl/db",
  "exec",
  "drizzle-kit",
  "generate",
  "--config",
  "drizzle.config.ts",
  ...forwardedArguments
]);

const generatedChecksums = await calculateMigrationChecksums();
assert(Object.keys(generatedChecksums).length > 0, "Drizzle did not generate any SQL migrations");

if (existingManifest) {
  for (const [path, checksum] of Object.entries(existingManifest.files)) {
    assert(
      generatedChecksums[path] === checksum,
      "Generation changed historical SQL migration " + path
    );
  }
}

await mkdir(parentDirectory(checksumManifestPath), { recursive: true });
await writeFile(
  checksumManifestPath,
  JSON.stringify({ algorithm: "sha256", files: generatedChecksums }, null, 2) + "\n",
  "utf8"
);

process.stdout.write(
  "Updated SHA-256 checksums for " + Object.keys(generatedChecksums).length + " SQL migration(s).\n"
);
