import { appendFileSync } from "node:fs";

const WORKER_NAME_PREFIX = "onceurl-pr-";

export function assertCondition(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

export function parsePullRequestNumber(value) {
  assertCondition(/^[1-9][0-9]*$/u.test(value), "Pull request number must be a positive integer");
  const number = Number(value);
  assertCondition(Number.isSafeInteger(number), "Pull request number is outside the safe range");
  return number;
}

export function previewWorkerNames(pullRequestNumber) {
  const number = parsePullRequestNumber(String(pullRequestNumber));
  const functionalName = `${WORKER_NAME_PREFIX}${number}-functional`;
  const marketingName = `${WORKER_NAME_PREFIX}${number}-marketing`;

  for (const name of [functionalName, marketingName]) {
    assertCondition(
      /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(name),
      "Generated preview Worker name is not a valid workers.dev DNS label"
    );
  }

  return { functionalName, marketingName, pullRequestNumber: number };
}

export function parseWorkersDevSubdomain(value) {
  assertCondition(value === value.toLowerCase(), "Workers.dev subdomain must be lowercase");
  assertCondition(
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.workers\.dev$/u.test(value),
    "Workers.dev subdomain must be one account label followed by .workers.dev"
  );
  return value;
}

export function parseExactHttpsOrigin(value, label) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }

  assertCondition(url.protocol === "https:", `${label} must use HTTPS`);
  assertCondition(value === url.origin, `${label} must be an exact origin without a path`);
  assertCondition(
    url.username === "" && url.password === "",
    `${label} must not contain credentials`
  );
  assertCondition(url.hostname.endsWith(".") === false, `${label} must use a canonical hostname`);
  assertCondition(
    url.hostname.endsWith(".invalid") === false,
    `${label} must replace the fail-closed .invalid sentinel`
  );
  return url.origin;
}

export function validateOriginPair(marketingOriginValue, functionalOriginValue) {
  const marketingOrigin = parseExactHttpsOrigin(marketingOriginValue, "Marketing origin");
  const functionalOrigin = parseExactHttpsOrigin(functionalOriginValue, "Functional origin");
  const marketing = new URL(marketingOrigin);
  const functional = new URL(functionalOrigin);

  assertCondition(
    marketing.hostname !== functional.hostname,
    "Marketing and functional origins must use different hostnames"
  );

  return { functionalOrigin, marketingOrigin };
}

export function previewMetadata(pullRequestNumber, workersDevSubdomain) {
  const names = previewWorkerNames(pullRequestNumber);
  const subdomain = parseWorkersDevSubdomain(workersDevSubdomain);
  const origins = validateOriginPair(
    `https://${names.marketingName}.${subdomain}`,
    `https://${names.functionalName}.${subdomain}`
  );

  return { ...names, ...origins, workersDevSubdomain: subdomain };
}

export function parseCloudflareAccountId(value) {
  assertCondition(
    /^[a-f0-9]{32}$/u.test(value),
    "Cloudflare account ID must be a 32-character lowercase hexadecimal identifier"
  );
  return value;
}

function writeGithubOutputs(outputs) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (outputPath) {
    appendFileSync(
      outputPath,
      Object.entries(outputs)
        .map(([key, value]) => `${key}=${String(value)}\n`)
        .join(""),
      "utf8"
    );
    return;
  }

  process.stdout.write(`${JSON.stringify(outputs, null, 2)}\n`);
}

function runCli() {
  const command = process.argv[2];

  if (command === "preview") {
    const metadata = previewMetadata(
      process.env.PR_NUMBER ?? "",
      process.env.PREVIEW_WORKERS_SUBDOMAIN ?? ""
    );
    writeGithubOutputs({
      functional_name: metadata.functionalName,
      functional_origin: metadata.functionalOrigin,
      marketing_name: metadata.marketingName,
      marketing_origin: metadata.marketingOrigin,
      pr_number: metadata.pullRequestNumber
    });
    return;
  }

  if (command === "origins") {
    const origins = validateOriginPair(
      process.env.MARKETING_ORIGIN ?? "",
      process.env.FUNCTIONAL_ORIGIN ?? ""
    );
    writeGithubOutputs({
      functional_origin: origins.functionalOrigin,
      marketing_origin: origins.marketingOrigin
    });
    return;
  }

  throw new Error("Expected delivery config command: preview or origins");
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  runCli();
}
