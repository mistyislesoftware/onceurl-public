import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { developmentEnvironment, rootDirectory } from "./config.mjs";

function assertCondition(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

export function parseVersion(value, label) {
  const match = /^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+].*)?$/u.exec(value);
  assertCondition(match !== null, `${label} must be a semantic version`);
  return match.slice(1, 4).map(Number);
}

function compareVersions(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) {
      return left[index] - right[index];
    }
  }
  return 0;
}

export function validateNodeVersion(value) {
  const actual = parseVersion(value, "Node version");
  const minimum = parseVersion(developmentEnvironment.node.minimum, "Minimum Node version");
  assertCondition(
    actual[0] === developmentEnvironment.node.major,
    `OnceURL requires Node ${developmentEnvironment.node.major}.x; found ${value}`
  );
  assertCondition(
    compareVersions(actual, minimum) >= 0,
    `OnceURL requires Node ${developmentEnvironment.node.minimum} or newer; found ${value}`
  );
  return value.replace(/^v/u, "");
}

export function readPnpmVersion(userAgent) {
  const match = /(?:^|\s)pnpm\/([^\s]+)/u.exec(userAgent ?? "");
  assertCondition(match !== null, "Run this check through the repository-pinned pnpm command");
  return match[1];
}

export async function validateToolchain(environment = process.env) {
  const packageJson = JSON.parse(await readFile(join(rootDirectory, "package.json"), "utf8"));
  const nvmVersion = (await readFile(join(rootDirectory, ".nvmrc"), "utf8")).trim();
  const wranglerPackage = JSON.parse(
    await readFile(join(rootDirectory, "node_modules", "wrangler", "package.json"), "utf8")
  );
  const nodeVersion = validateNodeVersion(process.version);
  const pnpmVersion = readPnpmVersion(environment.npm_config_user_agent);
  const wranglerVersion = parseVersion(wranglerPackage.version, "Wrangler version");

  assertCondition(
    nvmVersion === String(developmentEnvironment.node.major),
    ".nvmrc must match the development environment contract"
  );
  assertCondition(
    packageJson.packageManager === `pnpm@${developmentEnvironment.pnpm}`,
    "packageManager must match the development environment contract"
  );
  assertCondition(
    pnpmVersion === developmentEnvironment.pnpm,
    `OnceURL requires pnpm ${developmentEnvironment.pnpm}; found ${pnpmVersion}`
  );
  assertCondition(
    wranglerVersion[0] >= developmentEnvironment.wrangler.minimumMajor,
    `OnceURL requires Wrangler ${developmentEnvironment.wrangler.minimumMajor}.x or newer`
  );

  return { nodeVersion, pnpmVersion, wranglerVersion: wranglerPackage.version };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const versions = await validateToolchain();
  process.stdout.write(
    `Toolchain verified: Node ${versions.nodeVersion}, pnpm ${versions.pnpmVersion}, ` +
      `Wrangler ${versions.wranglerVersion}.\n`
  );
}
