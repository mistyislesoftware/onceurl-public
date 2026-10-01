import { readFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const rootDirectory = fileURLToPath(new URL("../..", import.meta.url));
export const contractPath = join(rootDirectory, "config", "development-environment.json");

const parsedContract = JSON.parse(await readFile(contractPath, "utf8"));

export function assertCondition(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function positiveInteger(value, label) {
  assertCondition(Number.isSafeInteger(value) && value > 0, `${label} must be a positive integer`);
  return value;
}

function validHostname(value, label) {
  assertCondition(
    typeof value === "string" &&
      value === value.toLowerCase() &&
      value.length <= 253 &&
      value.split(".").every((part) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(part)),
    `${label} must be a canonical lowercase hostname`
  );
  return value;
}

function isLoopbackHostname(hostname) {
  if (hostname === "localhost" || hostname === "[::1]") {
    return true;
  }

  const octets = hostname.split(".");
  return (
    octets.length === 4 &&
    octets[0] === "127" &&
    octets.every((octet) => /^(?:0|[1-9][0-9]{0,2})$/u.test(octet) && Number(octet) <= 255)
  );
}

export function parseExactDevelopmentOrigin(value, label) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }

  const allowedProtocol =
    url.protocol === "https:" || (url.protocol === "http:" && isLoopbackHostname(url.hostname));
  assertCondition(allowedProtocol, `${label} must use HTTPS or loopback HTTP`);
  assertCondition(value === url.origin, `${label} must be an exact origin without a path`);
  assertCondition(
    url.username === "" && url.password === "",
    `${label} must not contain credentials`
  );
  assertCondition(!url.hostname.endsWith("."), `${label} must use a canonical hostname`);
  return url.origin;
}

function readContract(value) {
  assertCondition(isRecord(value), "Development environment contract must be an object");
  assertCondition(value.schemaVersion === 1, "Unsupported development environment schema version");
  assertCondition(isRecord(value.node), "Development environment contract must define Node");
  assertCondition(
    isRecord(value.wrangler),
    "Development environment contract must define Wrangler"
  );
  assertCondition(
    isRecord(value.local),
    "Development environment contract must define local runtime"
  );
  assertCondition(isRecord(value.local.functional), "Local functional runtime must be defined");
  assertCondition(isRecord(value.local.marketing), "Local marketing runtime must be defined");
  assertCondition(typeof value.pnpm === "string", "Development environment must define pnpm");
  assertCondition(
    typeof value.local.persistenceDirectory === "string" &&
      value.local.persistenceDirectory === ".wrangler/state",
    "Local persistence must remain in .wrangler/state"
  );

  const functional = {
    hostname: validHostname(value.local.functional.hostname, "Functional hostname"),
    port: positiveInteger(value.local.functional.port, "Functional port"),
    inspectorPort: positiveInteger(
      value.local.functional.inspectorPort,
      "Functional inspector port"
    )
  };
  const marketing = {
    hostname: validHostname(value.local.marketing.hostname, "Marketing hostname"),
    port: positiveInteger(value.local.marketing.port, "Marketing port"),
    inspectorPort: positiveInteger(value.local.marketing.inspectorPort, "Marketing inspector port")
  };
  assertCondition(
    functional.hostname !== marketing.hostname,
    "Local marketing and functional hostnames must differ"
  );
  assertCondition(functional.port !== marketing.port, "Local Worker ports must differ");
  assertCondition(
    Array.isArray(value.forwardedPorts) &&
      JSON.stringify(value.forwardedPorts) === JSON.stringify([functional.port, marketing.port]),
    "Forwarded ports must match the functional and marketing ports"
  );
  assertCondition(
    value.forwardedProtocol === "https",
    "Forwarded ports must preserve HTTPS into Wrangler"
  );

  return {
    schemaVersion: 1,
    node: {
      major: positiveInteger(value.node.major, "Node major version"),
      minimum: String(value.node.minimum)
    },
    pnpm: value.pnpm,
    wrangler: {
      source: String(value.wrangler.source),
      minimumMajor: positiveInteger(value.wrangler.minimumMajor, "Wrangler minimum major")
    },
    local: {
      persistenceDirectory: value.local.persistenceDirectory,
      functional,
      marketing
    },
    forwardedPorts: [...value.forwardedPorts],
    forwardedProtocol: value.forwardedProtocol
  };
}

export const developmentEnvironment = readContract(parsedContract);
export const localStateDirectory = resolve(
  rootDirectory,
  developmentEnvironment.local.persistenceDirectory
);

export function validateDevelopmentOriginPair(marketingOriginValue, functionalOriginValue) {
  const marketingOrigin = parseExactDevelopmentOrigin(marketingOriginValue, "Marketing origin");
  const functionalOrigin = parseExactDevelopmentOrigin(functionalOriginValue, "Functional origin");
  assertCondition(
    new URL(marketingOrigin).hostname !== new URL(functionalOrigin).hostname,
    "Marketing and functional origins must use different hostnames"
  );
  return { functionalOrigin, marketingOrigin };
}

function codespacesOrigins(environment) {
  const codespaceName = environment.CODESPACE_NAME ?? "";
  const forwardingDomain = environment.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN ?? "";
  assertCondition(
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(codespaceName),
    "CODESPACE_NAME must be a canonical DNS label"
  );
  validHostname(forwardingDomain, "GitHub Codespaces port forwarding domain");

  const functionalOrigin =
    `https://${codespaceName}-${developmentEnvironment.local.functional.port}.` + forwardingDomain;
  const marketingOrigin =
    `https://${codespaceName}-${developmentEnvironment.local.marketing.port}.` + forwardingDomain;
  return validateDevelopmentOriginPair(marketingOrigin, functionalOrigin);
}

export function resolveDevelopmentRuntime(environment = process.env) {
  const hasFunctionalOverride = Boolean(environment.ONCEURL_FUNCTIONAL_ORIGIN);
  const hasMarketingOverride = Boolean(environment.ONCEURL_MARKETING_ORIGIN);
  assertCondition(
    hasFunctionalOverride === hasMarketingOverride,
    "Set ONCEURL_FUNCTIONAL_ORIGIN and ONCEURL_MARKETING_ORIGIN together"
  );

  if (hasFunctionalOverride && hasMarketingOverride) {
    const origins = validateDevelopmentOriginPair(
      environment.ONCEURL_MARKETING_ORIGIN,
      environment.ONCEURL_FUNCTIONAL_ORIGIN
    );
    return {
      kind: "forwarded",
      listenIp: "0.0.0.0",
      listenProtocol: developmentEnvironment.forwardedProtocol,
      readinessHeaders: {},
      ...origins
    };
  }

  if (environment.CODESPACES === "true") {
    const origins = codespacesOrigins(environment);
    const readinessHeaders = environment.GITHUB_TOKEN
      ? { "X-Github-Token": environment.GITHUB_TOKEN }
      : {};
    return {
      kind: "codespaces",
      listenIp: "0.0.0.0",
      listenProtocol: developmentEnvironment.forwardedProtocol,
      readinessHeaders,
      ...origins
    };
  }

  const functional = developmentEnvironment.local.functional;
  const marketing = developmentEnvironment.local.marketing;
  return {
    kind: "loopback",
    listenIp: null,
    listenProtocol: "http",
    readinessHeaders: {},
    ...validateDevelopmentOriginPair(
      `http://${marketing.hostname}:${marketing.port}`,
      `http://${functional.hostname}:${functional.port}`
    )
  };
}

export function assertExactResetTarget(repositoryDirectory, candidateDirectory) {
  const repository = resolve(repositoryDirectory);
  const expected = resolve(repository, developmentEnvironment.local.persistenceDirectory);
  const candidate = resolve(candidateDirectory);
  const relativeCandidate = relative(repository, candidate);

  assertCondition(!isAbsolute(relativeCandidate), "Reset target must be repository-owned");
  assertCondition(
    relativeCandidate !== ".." && !relativeCandidate.startsWith(`..${sep}`),
    "Reset target must remain inside the repository"
  );
  assertCondition(candidate === expected, "Reset target must be exactly .wrangler/state");
  return candidate;
}
