import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { access, readFile, readdir } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const rootDirectory = fileURLToPath(new URL("../..", import.meta.url));
export const databasePackageDirectory = join(rootDirectory, "packages", "db");
export const migrationDirectory = join(databasePackageDirectory, "drizzle", "migrations");
export const checksumManifestPath = join(
  databasePackageDirectory,
  "drizzle",
  "migration-checksums.json"
);
export const wranglerConfigPath = join(rootDirectory, "apps", "worker", "wrangler.jsonc");
export const wranglerConfigArgument = "apps/worker/wrangler.jsonc";
export const databaseBinding = "DB";
export const localStateDirectory = join(rootDirectory, ".wrangler", "state");

/**
 * @param {unknown} condition
 * @param {string} message
 * @returns {asserts condition}
 */
export function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
export function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * @param {string} path
 */
export async function pathExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * @param {string} directory
 * @param {(path: string) => boolean} [predicate]
 * @returns {Promise<string[]>}
 */
export async function listFiles(directory, predicate = () => true) {
  if (!(await pathExists(directory))) {
    return [];
  }

  const files = [];
  const entries = await readdir(directory, { withFileTypes: true });

  for (const entry of entries) {
    const entryPath = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFiles(entryPath, predicate)));
    } else if (entry.isFile() && predicate(entryPath)) {
      files.push(entryPath);
    }
  }

  return files.sort();
}

/**
 * @param {string} path
 */
export async function sha256File(path) {
  const contents = await readFile(path);
  return createHash("sha256").update(contents).digest("hex");
}

/**
 * @param {string} directory
 * @param {(path: string) => boolean} [predicate]
 * @returns {Promise<Record<string, string>>}
 */
export async function hashDirectory(directory, predicate = () => true) {
  const files = await listFiles(directory, predicate);
  /** @type {Array<[string, string]>} */
  const entries = await Promise.all(
    files.map(async (path) => {
      const relativePath = relative(directory, path).split(sep).join("/");
      return /** @type {[string, string]} */ ([relativePath, await sha256File(path)]);
    })
  );
  return Object.fromEntries(entries);
}

/**
 * @returns {Promise<Record<string, string>>}
 */
export async function calculateMigrationChecksums() {
  return hashDirectory(migrationDirectory, (path) => path.endsWith(".sql"));
}

/**
 * @returns {Promise<{algorithm: "sha256", files: Record<string, string>} | null>}
 */
export async function readChecksumManifest() {
  if (!(await pathExists(checksumManifestPath))) {
    return null;
  }

  const parsed = /** @type {unknown} */ (JSON.parse(await readFile(checksumManifestPath, "utf8")));
  assert(isRecord(parsed), "Migration checksum manifest must be a JSON object");
  assert(parsed.algorithm === "sha256", "Migration checksum manifest must use sha256");
  assert(isRecord(parsed.files), "Migration checksum manifest must contain a files object");

  /** @type {Record<string, string>} */
  const files = {};
  for (const [path, checksum] of Object.entries(parsed.files)) {
    assert(typeof checksum === "string", "Migration checksum entries must be strings");
    files[path] = checksum;
  }

  return {
    algorithm: "sha256",
    files: Object.fromEntries(
      Object.entries(files).sort(([left], [right]) => left.localeCompare(right))
    )
  };
}

/**
 * @param {Record<string, string>} actual
 * @param {Record<string, string>} expected
 * @param {string} message
 */
export function assertHashRecordsEqual(actual, expected, message) {
  assert(JSON.stringify(actual) === JSON.stringify(expected), message);
}

/**
 * @param {string} command
 * @param {string[]} args
 * @param {{
 *   cwd?: string;
 *   env?: NodeJS.ProcessEnv;
 *   allowFailure?: boolean;
 *   quiet?: boolean;
 * }} [options]
 * @returns {{status: number, stdout: string, stderr: string}}
 */
export function runProcess(command, args, options = {}) {
  const cwd = options.cwd ?? rootDirectory;
  const env = options.env ?? process.env;
  const allowFailure = options.allowFailure ?? false;
  const quiet = options.quiet ?? false;
  const commandDescription = [command, ...args].join(" ");

  if (!quiet) {
    process.stdout.write("> " + commandDescription + "\n");
  }

  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    env,
    stdio: ["ignore", "pipe", "pipe"]
  });

  if (result.error) {
    throw result.error;
  }

  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  const status = result.status ?? 1;

  if (!quiet) {
    process.stdout.write(stdout);
    process.stderr.write(stderr);
  }

  if (!allowFailure && status !== 0) {
    const details = [stdout, stderr].filter(Boolean).join("\n");
    throw new Error(
      "Command failed with exit code " +
        status +
        ": " +
        commandDescription +
        (details ? "\n" + details : "")
    );
  }

  return { status, stdout, stderr };
}

/**
 * @param {string[]} args
 * @param {Parameters<typeof runProcess>[2]} [options]
 * @returns {ReturnType<typeof runProcess>}
 */
export function runPnpm(args, options = {}) {
  const pnpmEntryPoint = process.env.npm_execpath;
  assert(pnpmEntryPoint, "pnpm scripts must provide npm_execpath");
  return runProcess(process.execPath, [pnpmEntryPoint, ...args], options);
}

export function localCloudflareEnvironment() {
  const env = {
    ...process.env,
    CI: "true",
    WRANGLER_LOG_PATH: join(rootDirectory, ".tmp", "wrangler-logs")
  };

  for (const key of Object.keys(env)) {
    if (
      key.startsWith("CLOUDFLARE_") ||
      key === "CF_API_TOKEN" ||
      key === "CF_API_KEY" ||
      key === "CF_ACCOUNT_ID"
    ) {
      delete env[key];
    }
  }

  return env;
}

/**
 * @param {string[]} args
 * @param {Parameters<typeof runPnpm>[1]} [options]
 * @returns {ReturnType<typeof runPnpm>}
 */
export function runWranglerLocal(args, options = {}) {
  assert(args[0] === "d1", "Only D1 commands are permitted by the local Wrangler wrapper");
  assert(args.includes("--local"), "Local Wrangler commands must include --local");
  assert(!args.includes("--remote"), "Remote Wrangler access is prohibited");
  assert(
    !args.some((argument) => argument === "--env" || argument.startsWith("--env=")),
    "Local Wrangler commands cannot override the top-level environment"
  );

  return runPnpm(["exec", "wrangler", ...args, "--env="], {
    ...options,
    env: localCloudflareEnvironment()
  });
}

/**
 * @param {string} path
 */
export function repositoryRelativePath(path) {
  return relative(rootDirectory, resolve(path)).split(sep).join("/");
}

/**
 * @param {string} path
 */
export function parentDirectory(path) {
  return dirname(path);
}
