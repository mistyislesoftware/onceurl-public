import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { z } from "zod";
import { assert, digest, encode, DIGEST } from "../publication/contract.mjs";
import {
  campaignIdentity,
  campaignIdentitySchema,
  workerVersionsSchema,
  validateAssertion,
  verifyEvidence
} from "../publication/staging-contract.mjs";
import { stagingConfiguration } from "./public-staging.mjs";
import { runDeliverySmoke } from "./smoke.mjs";

export const contract = "onceurl.staging.provider.v2";
const UUID = z.string().uuid();
const timestamp = z.string().datetime({ offset: false });
const bindings = {
  canonicalSourceSha: "STAGING_CANONICAL_SOURCE_SHA",
  publicSourceSha: "STAGING_PUBLIC_SOURCE_SHA",
  exportDigest: "STAGING_EXPORT_DIGEST",
  publicationSequence: "STAGING_PUBLICATION_SEQUENCE",
  acceptedRecordDigest: "STAGING_ACCEPTED_RECORD_DIGEST",
  publicCiWorkflowRunId: "STAGING_PUBLIC_CI_RUN_ID",
  publicCiWorkflowRunAttempt: "STAGING_PUBLIC_CI_RUN_ATTEMPT",
  publicCiJobId: "STAGING_PUBLIC_CI_JOB_ID",
  workflowRunId: "STAGING_WORKFLOW_RUN_ID",
  workflowRunAttempt: "STAGING_WORKFLOW_RUN_ATTEMPT",
  campaignId: "STAGING_CAMPAIGN_ID",
  configurationDigest: "STAGING_CONFIGURATION_DIGEST"
};
const operationStarts = new Set();
const preparedBuilds = new Map();
const STEP = "record sanitized acceptance evidence";
const now = (options) => (options.now ?? (() => Math.floor(Date.now() / 1000)))();

function context(options) {
  const identity = campaignIdentity(options.identity),
    config = stagingConfiguration(options.config);
  assert(
    identity.configurationDigest === digest(encode(config)),
    "Provider configuration mismatch"
  );
  assert(
    typeof options.apiToken === "string" &&
      options.apiToken.length >= 20 &&
      !/\s/u.test(options.apiToken),
    "Provider reader unavailable"
  );
  return { ...options, root: resolve(options.root), identity, config };
}
function fail() {
  throw new Error("Staging provider operation failed closed; preserve recovery evidence");
}
async function api(options, path, method = "GET", body, allowMissing = false) {
  try {
    assert(path.startsWith("/") && !path.includes(".."), "Invalid provider path");
    const response = await (options.transport ?? fetch)(
      `https://api.cloudflare.com/client/v4/accounts/${options.config.accountId}${path}`,
      {
        method,
        headers: {
          Authorization: `Bearer ${options.apiToken}`,
          "Content-Type": "application/json"
        },
        redirect: "error",
        signal: AbortSignal.timeout(30_000),
        ...(body === undefined ? {} : { body: encode(body) })
      }
    );
    if (allowMissing && response.status === 404) return null;
    if (!response.ok) fail();
    const bytes = await response.arrayBuffer();
    if (bytes.byteLength > 2_000_000) fail();
    const value = JSON.parse(Buffer.from(bytes).toString("utf8"));
    if (value.success !== true || (value.errors?.length ?? 0) !== 0 || value.result === undefined)
      fail();
    return value;
  } catch {
    fail();
  }
}
function command(options, executable, args, mutation = false) {
  // Only explicit staging identity enters a provider subprocess. Output and errors
  // are captured and discarded: Wrangler/provider bodies are not sanitized evidence.
  const env = Object.fromEntries(
    ["PATH", "Path", "SystemRoot", "TEMP", "TMP", "TMPDIR", "HOME"]
      .filter((k) => process.env[k] !== undefined)
      .map((k) => [k, process.env[k]])
  );
  Object.assign(env, { CI: "true", WRANGLER_SEND_METRICS: "false" });
  if (mutation)
    Object.assign(env, {
      CLOUDFLARE_API_TOKEN: options.apiToken,
      CLOUDFLARE_ACCOUNT_ID: options.config.accountId
    });
  try {
    const result = (
      options.execute ??
      ((program, argumentsList, configuration) => spawnSync(program, argumentsList, configuration))
    )(executable, args, {
      cwd: options.root,
      env,
      encoding: "utf8",
      timeout: 600_000,
      maxBuffer: 16_000_000,
      stdio: "pipe"
    });
    if (result.status !== 0 || result.error) fail();
  } catch {
    fail();
  }
}
function checkout(options) {
  const result = spawnSync("git", ["rev-parse", "HEAD"], { cwd: options.root, encoding: "utf8" });
  assert(
    result.status === 0 && result.stdout.trim() === options.identity.publicSourceSha,
    "Provider requires exact public checkout"
  );
  const status = spawnSync("git", ["status", "--porcelain", "--untracked-files=no"], {
    cwd: options.root,
    encoding: "utf8"
  });
  assert(
    status.status === 0 && status.stdout.trim() === "",
    "Provider requires unchanged accepted checkout"
  );
  const manifest = JSON.parse(
    readFileSync(resolve(options.root, "publication/manifest.json"), "utf8")
  );
  assert(
    manifest.canonicalSourceSha === options.identity.canonicalSourceSha &&
      manifest.exportDigest === options.identity.exportDigest &&
      manifest.publication?.publicationSequence === options.identity.publicationSequence,
    "Provider export identity mismatch"
  );
}
function localConfigurations(options) {
  const functional = JSON.parse(
    readFileSync(resolve(options.root, "apps/worker/wrangler.jsonc"), "utf8")
  );
  const marketing = JSON.parse(
    readFileSync(resolve(options.root, "apps/marketing/wrangler.jsonc"), "utf8")
  );
  const staging = functional.env.staging;
  assert(
    staging.name === options.config.functionalWorker &&
      marketing.env.staging.name === options.config.marketingWorker &&
      staging.d1_databases.length === 1 &&
      staging.d1_databases[0].binding === "DB" &&
      staging.d1_databases[0].database_name === "onceurl-staging" &&
      staging.r2_buckets.length === 1 &&
      staging.r2_buckets[0].binding === "FILES" &&
      staging.workflows.length === 1 &&
      staging.workflows[0].name === options.config.providerWorkflow &&
      staging.workflows[0].class_name === "StagingReliabilityWorkflow" &&
      staging.version_metadata.binding === "CF_VERSION_METADATA" &&
      staging.queues.producers.length === 1 &&
      staging.queues.producers[0].queue === "onceurl-staging-async-jobs" &&
      staging.queues.consumers.length === 2 &&
      staging.queues.consumers[0].dead_letter_queue === "onceurl-staging-async-jobs-dead-letter" &&
      staging.queues.consumers[0].queue === "onceurl-staging-async-jobs" &&
      staging.queues.consumers[1].queue === "onceurl-staging-async-jobs-dead-letter" &&
      staging.queues.producers[0].binding === "ASYNC_JOBS" &&
      staging.workflows[0].binding === "STAGING_RELIABILITY" &&
      staging.durable_objects.bindings.length === 2 &&
      [
        ["CAPABILITY_STATE", "CapabilityDurableObject"],
        ["ABUSE_CONTROL", "AbuseControlDurableObject"]
      ].every(
        ([name, klass]) =>
          staging.durable_objects.bindings.filter(
            (b) => b.name === name && b.class_name === klass && !b.script_name
          ).length === 1
      ) &&
      functional.workflows.length === 0 &&
      functional.env.preview.workflows.length === 0,
    "Staging resource surface mismatch"
  );
  return { functional, marketing };
}
async function resourcePreflight(options) {
  const database = (await api(options, `/d1/database/${options.config.databaseId}`)).result;
  assert(
    database.uuid === options.config.databaseId && database.name === "onceurl-staging",
    "Wrong staging database"
  );
  const bucket = (await api(options, `/r2/buckets/${options.config.bucketName}`)).result;
  assert(bucket.name === options.config.bucketName, "Wrong staging bucket");
  const settings = (
    await api(options, `/workers/scripts/${options.config.functionalWorker}/settings`)
  ).result;
  const list = z
    .array(z.looseObject({ name: z.string(), type: z.string() }))
    .parse(settings.bindings);
  await resourceBindings(options, list);
  const workflow = await workflowConfiguration(options);
  assert(workflow.script_name === options.config.functionalWorker, "Wrong Workflow script");
}
async function resourceBindings(options, list) {
  assert(new Set(list.map((b) => b.name)).size === list.length, "Duplicate provider binding");
  assert(
    list.filter((b) => b.name === "DB" && b.type === "d1" && b.id === options.config.databaseId)
      .length === 1 &&
      list.filter(
        (b) =>
          b.name === "FILES" &&
          b.type === "r2_bucket" &&
          b.bucket_name === options.config.bucketName
      ).length === 1 &&
      list.filter((b) => b.name === "STAGING_RELIABILITY_HMAC_KEY" && b.type === "secret_text")
        .length === 1 &&
      list.filter(
        (b) =>
          b.name === "STAGING_RELIABILITY" &&
          b.type === "workflow" &&
          b.workflow_name === options.config.providerWorkflow &&
          b.class_name === "StagingReliabilityWorkflow" &&
          !b.script_name
      ).length === 1 &&
      list.filter((b) => b.name === "CF_VERSION_METADATA" && b.type === "version_metadata")
        .length === 1,
    "Missing existing staging bindings"
  );
  const queues = (await api(options, "/queues?per_page=100&page=1")).result;
  assert(Array.isArray(queues), "Missing staging queues");
  const queue = queues.filter((q) => q.queue_name === "onceurl-staging-async-jobs");
  assert(
    queue.length === 1 &&
      queues.filter((q) => q.queue_name === "onceurl-staging-async-jobs-dead-letter").length ===
        1 &&
      list.filter(
        (b) => b.name === "ASYNC_JOBS" && b.type === "queue" && b.queue_id === queue[0].queue_id
      ).length === 1,
    "Wrong staging Queue"
  );
  const namespaces = (await api(options, "/workers/durable_objects/namespaces?per_page=100&page=1"))
    .result;
  assert(Array.isArray(namespaces), "Missing staging namespaces");
  for (const [name, klass] of [
    ["CAPABILITY_STATE", "CapabilityDurableObject"],
    ["ABUSE_CONTROL", "AbuseControlDurableObject"]
  ]) {
    const binding = list.filter((b) => b.name === name && b.type === "durable_object_namespace");
    assert(binding.length === 1 && !binding[0].script_name, "Foreign staging object binding");
    const namespace = namespaces.filter(
      (n) =>
        n.id ===
        z
          .string()
          .regex(/^[a-f0-9]{32}$/u)
          .parse(binding[0].namespace_id)
    );
    assert(
      namespace.length === 1 &&
        namespace[0].script === options.config.functionalWorker &&
        namespace[0].class === klass &&
        namespace[0].use_sqlite === true,
      "Wrong staging object namespace"
    );
  }
}
async function workflowConfiguration(options) {
  const value = (await api(options, `/workflows/${options.config.providerWorkflow}`)).result;
  assert(
    value.name === options.config.providerWorkflow &&
      value.script_name === options.config.functionalWorker &&
      value.class_name === "StagingReliabilityWorkflow" &&
      value.script_deleted !== true,
    "Wrong staging Workflow"
  );
  UUID.parse(value.id);
  return value;
}
export async function preflight(value) {
  try {
    const options = context(value);
    checkout(options);
    localConfigurations(options);
    await resourcePreflight(options);
    return { passed: true };
  } catch {
    fail();
  }
}
export async function build(value) {
  try {
    const options = context(value);
    checkout(options);
    localConfigurations(options);
    for (const name of ["build:functional", "build:marketing"]) command(options, "pnpm", [name]);
    // Build bookkeeping is local only. No credential or provider state is persisted.
    preparedBuilds.set(options.root, digest(encode(options.identity)));
    return { passed: true };
  } catch {
    fail();
  }
}
function authorization(options, purpose, deployment) {
  const assertion = validateAssertion(
    options.assertion,
    {
      ...options.identity,
      purpose,
      nonce: options.assertion?.nonce,
      releaseAssertionDigest:
        purpose === "onceurl.staging.release.v1" ? null : options.releaseAssertionDigest,
      deployment
    },
    now(options)
  );
  DIGEST.parse(options.releaseAssertionDigest);
  if (deployment) DIGEST.parse(options.campaignAssertionDigest);
  assert(typeof options.beforeMutation === "function", "Missing first-write boundary");
  return assertion;
}
function reserve(options, purpose) {
  const key = `${options.root}:${options.identity.campaignId}:${purpose}`;
  assert(!operationStarts.has(key), "Operation already started");
  operationStarts.add(key);
  const directory = resolve(options.root, ".tmp/public-staging");
  mkdirSync(directory, { recursive: true });
  const marker = resolve(directory, `${options.identity.campaignId}-${purpose}.started`);
  // A failed/ambiguous start remains reserved, including across process restart.
  writeFileSync(marker, encode({ identity: options.identity, purpose }), {
    flag: "wx",
    mode: 0o600
  });
}
async function firstWrite(options, assertion) {
  await options.beforeMutation();
  assert(
    now(options) >= assertion.issuedAt && now(options) < assertion.expiresAt,
    "Provider authorization expired before first write"
  );
}
function generatedConfiguration(options) {
  const configs = localConfigurations(options),
    paths = {};
  mkdirSync(resolve(options.root, ".tmp/public-staging"), { recursive: true });
  for (const surface of ["functional", "marketing"]) {
    const original = configs[surface],
      base = resolve(options.root, surface === "functional" ? "apps/worker" : "apps/marketing");
    const selected = { ...original, ...original.env.staging };
    delete selected.env;
    selected.account_id = options.config.accountId;
    selected.main = resolve(base, original.main);
    selected.assets = { ...original.assets, directory: resolve(base, original.assets.directory) };
    selected.vars = {
      ...selected.vars,
      FUNCTIONAL_ORIGIN: options.config.functionalOrigin,
      MARKETING_ORIGIN: options.config.marketingOrigin,
      ...Object.fromEntries(
        Object.entries(bindings).map(([field, binding]) => [
          binding,
          String(options.identity[field])
        ])
      )
    };
    // No routes, DNS, custom domains, new namespace or migration declarations.
    delete selected.routes;
    delete selected.route;
    delete selected.migrations;
    if (surface === "functional") {
      selected.d1_databases = [
        {
          ...selected.d1_databases[0],
          database_id: options.config.databaseId,
          migrations_dir: resolve(options.root, "packages/db/drizzle/migrations"),
          migrations_pattern: resolve(options.root, "packages/db/drizzle/migrations/*.sql")
        }
      ];
      selected.r2_buckets = [{ binding: "FILES", bucket_name: options.config.bucketName }];
    }
    const path = resolve(
      options.root,
      `.tmp/public-staging/${options.identity.campaignId}-${surface}.json`
    );
    writeFileSync(path, JSON.stringify(selected, null, 2) + "\n", { flag: "wx", mode: 0o600 });
    paths[surface] = path;
  }
  return paths;
}
export async function release(value) {
  try {
    const options = context(value),
      assertion = authorization(options, "onceurl.staging.release.v1", null);
    checkout(options);
    assert(
      preparedBuilds.get(options.root) === digest(encode(options.identity)),
      "Release requires completed build"
    );
    const paths = generatedConfiguration(options);
    reserve(options, "release");
    const wrangler = resolve(options.root, "node_modules/wrangler/bin/wrangler.js");
    await firstWrite(options, assertion);
    command(
      options,
      process.execPath,
      [wrangler, "d1", "migrations", "apply", "DB", "--config", paths.functional, "--remote"],
      true
    );
    const tag = `staging-${options.identity.publicSourceSha.slice(0, 12)}`,
      message = deploymentMessage(options.identity);
    // Once started, finish the coherent pair; later freshness belongs to campaign.
    for (const surface of ["functional", "marketing"])
      command(
        options,
        process.execPath,
        [wrangler, "deploy", "--config", paths[surface], "--tag", tag, "--message", message],
        true
      );
    return await readRelease(options);
  } catch {
    fail();
  }
}
function deploymentMessage(identity) {
  return `onceurl.public-staging.v2 ${digest(encode(identity))}`;
}
async function activeVersion(options, worker) {
  const data = (await api(options, `/workers/scripts/${worker}/deployments`)).result;
  const deployments = z
    .array(
      z.looseObject({
        id: UUID,
        created_on: timestamp,
        versions: z.array(z.looseObject({ version_id: UUID, percentage: z.number() }))
      })
    )
    .parse(data.deployments);
  assert(deployments.length > 0, "Missing active deployment");
  deployments.sort((a, b) => Date.parse(b.created_on) - Date.parse(a.created_on));
  assert(
    deployments.length === 1 || deployments[0].created_on !== deployments[1].created_on,
    "Ambiguous active deployment"
  );
  const versions = deployments[0].versions;
  assert(versions.length === 1 && versions[0].percentage === 100, "Split Worker deployment");
  const version = (
    await api(options, `/workers/scripts/${worker}/versions/${versions[0].version_id}`)
  ).result;
  assert(
    version.id === versions[0].version_id &&
      version.metadata?.annotations?.["workers/tag"] ===
        `staging-${options.identity.publicSourceSha.slice(0, 12)}` &&
      version.metadata?.annotations?.["workers/message"] === deploymentMessage(options.identity),
    "Worker version provenance mismatch"
  );
  const list = z
    .array(z.looseObject({ name: z.string(), type: z.string() }))
    .parse(version.resources?.bindings);
  assert(new Set(list.map((b) => b.name)).size === list.length, "Duplicate runtime binding");
  if (worker === options.config.functionalWorker) await resourceBindings(options, list);
  for (const [field, binding] of Object.entries(bindings))
    assert(
      list.filter(
        (b) =>
          b.name === binding &&
          b.type === "plain_text" &&
          b.text === String(options.identity[field])
      ).length === 1,
      "Runtime provenance mismatch"
    );
  for (const [name, text] of [
    ["DEPLOYMENT_ENVIRONMENT", "staging"],
    ["FUNCTIONAL_ORIGIN", options.config.functionalOrigin],
    ["MARKETING_ORIGIN", options.config.marketingOrigin]
  ])
    assert(
      list.filter((b) => b.name === name && b.type === "plain_text" && b.text === text).length ===
        1,
      "Runtime origin mismatch"
    );
  return { id: UUID.parse(version.id), tag: version.metadata.annotations["workers/tag"] };
}
async function workflowVersion(options) {
  const workflow = await workflowConfiguration(options);
  const values = (
    await api(options, `/workflows/${options.config.providerWorkflow}/versions?per_page=100&page=1`)
  ).result;
  const versions = z
    .array(
      z.looseObject({ id: UUID, workflow_id: UUID, class_name: z.string(), created_on: timestamp })
    )
    .parse(values);
  assert(versions.length > 0, "Missing Workflow version");
  versions.sort((a, b) => Date.parse(b.created_on) - Date.parse(a.created_on));
  assert(
    versions.length === 1 || versions[0].created_on !== versions[1].created_on,
    "Ambiguous Workflow version"
  );
  const version = (
    await api(options, `/workflows/${options.config.providerWorkflow}/versions/${versions[0].id}`)
  ).result;
  assert(
    version.id === versions[0].id &&
      version.workflow_id === workflow.id &&
      version.class_name === "StagingReliabilityWorkflow",
    "Wrong Workflow version"
  );
  return UUID.parse(version.id); // workflow.id and Worker script version are different identities.
}
export async function readRelease(value) {
  try {
    const options = context(value);
    const functional = await activeVersion(options, options.config.functionalWorker),
      marketing = await activeVersion(options, options.config.marketingWorker);
    const providerWorkflowVersionId = await workflowVersion(options);
    const smoke = await runDeliverySmoke({
      functionalOrigin: options.config.functionalOrigin,
      marketingOrigin: options.config.marketingOrigin,
      fetchImplementation: options.smokeTransport ?? options.transport ?? fetch
    });
    const deployment = workerVersionsSchema.parse({
      functionalVersionId: functional.id,
      functionalVersionTag: functional.tag,
      marketingVersionId: marketing.id,
      marketingVersionTag: marketing.tag,
      providerWorkflowVersionId,
      smokeEvidenceDigest: digest(
        encode({
          schemaVersion: 2,
          identity: options.identity,
          functionalVersionId: functional.id,
          marketingVersionId: marketing.id,
          providerWorkflowVersionId,
          ...smoke
        })
      )
    });
    // Detect a deployment moving during independent smoke/version reads.
    assert(
      encode(await activeVersion(options, options.config.functionalWorker)).equals(
        encode(functional)
      ) &&
        encode(await activeVersion(options, options.config.marketingWorker)).equals(
          encode(marketing)
        ) &&
        (await workflowVersion(options)) === providerWorkflowVersionId,
      "Release changed during smoke"
    );
    return deployment;
  } catch {
    fail();
  }
}
function campaignInput(options, assertion, deployment) {
  return {
    schemaVersion: 2,
    deploymentEnvironment: "staging",
    ...options.identity,
    ...deployment,
    releaseAssertionDigest: options.releaseAssertionDigest,
    campaignAssertionDigest: options.campaignAssertionDigest,
    campaignIssuedAt: assertion.issuedAt,
    campaignExpiresAt: assertion.expiresAt
  };
}
export async function campaign(value) {
  try {
    const options = context(value),
      deployment = workerVersionsSchema.parse(options.deployment),
      assertion = authorization(options, "onceurl.staging.campaign.v1", deployment);
    const live = await readRelease(options);
    assert(encode(live).equals(encode(deployment)), "Campaign release changed");
    const path = `/workflows/${options.config.providerWorkflow}/instances/${options.identity.campaignId}`;
    assert(
      (await api(options, path, "GET", undefined, true)) === null,
      "Campaign instance already exists"
    );
    reserve(options, "campaign");
    const input = campaignInput(options, assertion, deployment);
    await firstWrite(options, assertion);
    await api(options, `/workflows/${options.config.providerWorkflow}/instances`, "POST", {
      instance_id: options.identity.campaignId,
      params: input
    });
    const sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    for (let attempt = 0; attempt < 120; attempt++) {
      const instance = (await api(options, path)).result;
      assert(
        instance.versionId === deployment.providerWorkflowVersionId,
        "Campaign Workflow version mismatch"
      );
      if (instance.status === "complete") return await readEvidence({ ...options, deployment });
      assert(
        !["errored", "terminated", "paused", "rollingBack", "unknown"].includes(instance.status),
        "Campaign failed"
      );
      if (attempt < 119) await sleep(5000);
    }
    fail();
  } catch {
    fail();
  }
}
async function instanceCreation(options, deployment) {
  // Exact ID selected from provider metadata, with bounded pagination. Caller or
  // Workflow output clocks cannot manufacture the creation timestamp.
  const rows = [];
  let cursor;
  for (let page = 0; page < 10; page++) {
    const response = await api(
      options,
      `/workflows/${options.config.providerWorkflow}/instances?per_page=100&direction=desc${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`
    );
    assert(Array.isArray(response.result), "Missing instance metadata");
    rows.push(...response.result.filter((r) => r.id === options.identity.campaignId));
    const next = response.result_info?.cursor;
    if (!next || response.result.length < 100) break;
    assert(next !== cursor && page < 9, "Instance metadata pagination bound");
    cursor = next;
  }
  assert(rows.length === 1, "Missing/ambiguous exact campaign instance");
  const row = rows[0];
  assert(
    row.version_id === deployment.providerWorkflowVersionId &&
      row.status === "complete" &&
      row.trigger_source === "api",
    "Wrong campaign metadata"
  );
  const workflow = await workflowConfiguration(options);
  assert(row.workflow_id === workflow.id, "Wrong campaign Workflow");
  const at = Date.parse(timestamp.parse(row.created_on));
  assert(Number.isSafeInteger(at) && at > 0, "Invalid provider creation time");
  return Math.floor(at / 1000);
}
export async function readEvidence(value) {
  try {
    const options = context(value),
      deployment = workerVersionsSchema.parse(options.deployment);
    assert(
      encode(await readRelease(options)).equals(encode(deployment)),
      "Evidence release changed"
    );
    const path = `/workflows/${options.config.providerWorkflow}/instances/${options.identity.campaignId}`;
    const instance = (await api(options, path)).result;
    assert(
      instance.status === "complete" &&
        instance.success === true &&
        instance.versionId === deployment.providerWorkflowVersionId,
      "Campaign incomplete or wrong version"
    );
    const params = z
      .strictObject({
        schemaVersion: z.literal(2),
        deploymentEnvironment: z.literal("staging"),
        ...campaignIdentitySchema.shape,
        ...workerVersionsSchema.shape,
        releaseAssertionDigest: DIGEST,
        campaignAssertionDigest: DIGEST,
        campaignIssuedAt: z.number().int().nonnegative(),
        campaignExpiresAt: z.number().int().positive()
      })
      .parse(instance.params);
    for (const [field, expected] of Object.entries({ ...options.identity, ...deployment }))
      assert(params[field] === expected, "Instance provenance mismatch");
    assert(
      params.campaignExpiresAt > params.campaignIssuedAt &&
        params.campaignExpiresAt - params.campaignIssuedAt <= 60,
      "Invalid campaign window"
    );
    const steps = z
      .array(
        z.looseObject({
          type: z.string(),
          name: z.string().optional(),
          success: z.boolean().nullable().optional()
        })
      )
      .parse(instance.steps);
    const completed = steps.filter(
      (s) =>
        s.type === "step" &&
        s.success === true &&
        (s.name === STEP ||
          /^record sanitized acceptance evidence-[1-9][0-9]*$/u.test(s.name ?? ""))
    );
    assert(completed.length === 1, "Missing/ambiguous final evidence step");
    const step = (
      await api(options, `${path}/step?name=${encodeURIComponent(completed[0].name)}&type=step`)
    ).result;
    assert(step.status === "complete", "Incomplete final evidence step");
    const evidence = verifyEvidence(
      typeof step.output === "string" ? JSON.parse(step.output) : step.output,
      options.identity,
      deployment,
      params.releaseAssertionDigest,
      params.campaignAssertionDigest
    );
    const campaignStartedAt = await instanceCreation(options, deployment);
    assert(
      evidence.campaignStartedAt === campaignStartedAt &&
        campaignStartedAt >= params.campaignIssuedAt &&
        campaignStartedAt < params.campaignExpiresAt,
      "Provider creation outside campaign grant"
    );
    if (options.releaseAssertionDigest !== undefined)
      assert(
        evidence.releaseAssertionDigest === options.releaseAssertionDigest &&
          evidence.campaignAssertionDigest === options.campaignAssertionDigest,
        "Wrong campaign grants"
      );
    return evidence;
  } catch {
    fail();
  }
}
