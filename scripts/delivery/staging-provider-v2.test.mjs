import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { digest, encode } from "../publication/contract.mjs";
import * as runner from "./staging-provider-v2.mjs";
import { successfulSmokeFetch } from "./staging-provider-v2-fixture.mjs";

const sourceRoot = resolve(import.meta.dirname, "../..");
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const bindingNames = {
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
function fixture() {
  mkdirSync(resolve(sourceRoot, ".tmp"), { recursive: true });
  const root = mkdtempSync(resolve(sourceRoot, ".tmp/provider-v2-"));
  for (const path of ["apps/worker", "apps/marketing", "publication"])
    mkdirSync(resolve(root, path), { recursive: true });
  for (const surface of ["worker", "marketing"])
    writeFileSync(
      resolve(root, `apps/${surface}/wrangler.jsonc`),
      readFileSync(resolve(sourceRoot, `apps/${surface}/wrangler.jsonc`))
    );
  const manifest = {
    canonicalSourceSha: "a".repeat(40),
    exportDigest: "b".repeat(64),
    publication: { publicationSequence: 4 }
  };
  writeFileSync(resolve(root, "publication/manifest.json"), encode(manifest));
  const git = (args) =>
    execFileSync(
      "git",
      [
        "-c",
        "commit.gpgsign=false",
        "-c",
        "user.name=Provider Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        ...args
      ],
      { cwd: root, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }
    );
  git(["init", "-b", "main"]);
  git(["config", "core.autocrlf", "false"]);
  git(["add", "."]);
  git(["commit", "-m", "Synthetic provider contract"]);
  const publicSourceSha = git(["rev-parse", "HEAD"]).trim();
  const config = {
    accountId: "f".repeat(32),
    databaseId: uuid(7),
    bucketName: "onceurl-staging-test",
    functionalOrigin: "https://functional.staging.onceurl.mistyislesoftware.co.uk",
    marketingOrigin: "https://marketing.staging.onceurl.mistyislesoftware.co.uk",
    functionalWorker: "onceurl-worker-staging",
    marketingWorker: "onceurl-marketing-staging",
    providerWorkflow: "onceurl-staging-reliability"
  };
  const identity = { ...manifest, publication: undefined };
  delete identity.publication;
  Object.assign(identity, {
    publicSourceSha,
    publicationSequence: 4,
    acceptedRecordDigest: "c".repeat(64),
    publicCiWorkflowRunId: "101",
    publicCiWorkflowRunAttempt: 1,
    publicCiJobId: "102",
    workflowRunId: "103",
    workflowRunAttempt: 1,
    campaignId: `ou-staging-103-1-${publicSourceSha.slice(0, 12)}`,
    configurationDigest: digest(encode(config))
  });
  const calls = [],
    commands = [],
    routes = new Map(),
    at = 1000,
    tag = `staging-${publicSourceSha.slice(0, 12)}`;
  const runtimeBindings = [
    ...Object.entries(bindingNames).map(([field, name]) => ({
      name,
      type: "plain_text",
      text: String(identity[field])
    })),
    ...[
      ["DEPLOYMENT_ENVIRONMENT", "staging"],
      ["FUNCTIONAL_ORIGIN", config.functionalOrigin],
      ["MARKETING_ORIGIN", config.marketingOrigin]
    ].map(([name, text]) => ({ name, type: "plain_text", text }))
  ];
  const resourceBindings = [
    { name: "DB", type: "d1", id: config.databaseId },
    { name: "FILES", type: "r2_bucket", bucket_name: config.bucketName },
    { name: "ASYNC_JOBS", type: "queue", queue_id: "a".repeat(32) },
    { name: "STAGING_RELIABILITY_HMAC_KEY", type: "secret_text" },
    { name: "CAPABILITY_STATE", type: "durable_object_namespace", namespace_id: "b".repeat(32) },
    { name: "ABUSE_CONTROL", type: "durable_object_namespace", namespace_id: "c".repeat(32) },
    {
      name: "STAGING_RELIABILITY",
      type: "workflow",
      workflow_name: config.providerWorkflow,
      class_name: "StagingReliabilityWorkflow"
    },
    { name: "CF_VERSION_METADATA", type: "version_metadata" }
  ];
  routes.set(`/d1/database/${config.databaseId}`, {
    uuid: config.databaseId,
    name: "onceurl-staging"
  });
  routes.set(`/r2/buckets/${config.bucketName}`, { name: config.bucketName });
  routes.set(`/workers/scripts/${config.functionalWorker}/settings`, {
    bindings: resourceBindings
  });
  routes.set("/queues?per_page=100&page=1", [
    { queue_name: "onceurl-staging-async-jobs", queue_id: "a".repeat(32) },
    { queue_name: "onceurl-staging-async-jobs-dead-letter", queue_id: "d".repeat(32) }
  ]);
  routes.set("/workers/durable_objects/namespaces?per_page=100&page=1", [
    {
      id: "b".repeat(32),
      script: config.functionalWorker,
      class: "CapabilityDurableObject",
      use_sqlite: true
    },
    {
      id: "c".repeat(32),
      script: config.functionalWorker,
      class: "AbuseControlDurableObject",
      use_sqlite: true
    }
  ]);
  const workflow = {
    id: uuid(90),
    name: config.providerWorkflow,
    script_name: config.functionalWorker,
    class_name: "StagingReliabilityWorkflow"
  };
  routes.set(`/workflows/${config.providerWorkflow}`, workflow);
  const workflowVersion = {
    id: uuid(3),
    workflow_id: workflow.id,
    class_name: workflow.class_name,
    created_on: "2026-10-03T10:00:00.000Z"
  };
  routes.set(`/workflows/${config.providerWorkflow}/versions?per_page=100&page=1`, [
    workflowVersion
  ]);
  routes.set(`/workflows/${config.providerWorkflow}/versions/${uuid(3)}`, workflowVersion);
  for (const [worker, id, n] of [
    [config.functionalWorker, uuid(1), 11],
    [config.marketingWorker, uuid(2), 12]
  ]) {
    routes.set(`/workers/scripts/${worker}/deployments`, {
      deployments: [
        {
          id: uuid(n),
          created_on: "2026-10-03T10:00:00.000Z",
          versions: [{ version_id: id, percentage: 100 }]
        }
      ]
    });
    routes.set(`/workers/scripts/${worker}/versions/${id}`, {
      id,
      metadata: {
        annotations: {
          "workers/tag": tag,
          "workers/message": `onceurl.public-staging.v2 ${digest(encode(identity))}`
        }
      },
      resources: {
        bindings:
          worker === config.functionalWorker
            ? [...runtimeBindings, ...resourceBindings]
            : runtimeBindings
      }
    });
  }
  const instancePath = `/workflows/${config.providerWorkflow}/instances/${identity.campaignId}`;
  let evidence;
  const transport = vi.fn(async (urlValue, init) => {
    const url = new URL(urlValue),
      path = url.pathname.replace(`/client/v4/accounts/${config.accountId}`, "") + url.search;
    calls.push({ path, method: init.method });
    if (init.method === "POST") {
      const payload = JSON.parse(Buffer.from(init.body).toString());
      expect(path).toBe(`/workflows/${config.providerWorkflow}/instances`);
      expect(Object.keys(payload).sort()).toEqual(["instance_id", "params"]);
      expect(payload.instance_id).toBe(identity.campaignId);
      expect(payload.params).toBeTypeOf("object");
      const params = payload.params;
      evidence = {
        schemaVersion: 2,
        ...identity,
        ...Object.fromEntries(
          [
            "functionalVersionId",
            "functionalVersionTag",
            "marketingVersionId",
            "marketingVersionTag",
            "providerWorkflowVersionId",
            "smokeEvidenceDigest",
            "releaseAssertionDigest",
            "campaignAssertionDigest"
          ].map((k) => [k, params[k]])
        ),
        campaignStartedAt: at,
        smokePassed: true,
        outcome: "passed",
        cases: [
          {
            caseName: "claim_replay_and_projection",
            releases: 1,
            attempts: 4,
            queueD1Converged: true,
            replayUnavailable: true,
            staleD1AuthorizedRelease: false,
            duplicateEventRows: 1
          },
          {
            caseName: "bounded_concurrent_claim",
            releases: 1,
            attempts: 8,
            queueD1Converged: true
          },
          {
            caseName: "actual_uncertain_restore_command",
            releases: 0,
            attempts: 2,
            queueD1Converged: true,
            ciphertextAbsent: true
          }
        ],
        cleanup: {
          capabilityCount: 3,
          releases: 0,
          ciphertextAbsent: true,
          pendingOutboxes: 0,
          remainingD1Rows: 0,
          exactRowsOnly: true,
          passed: true
        },
        unsupportedProviderBehaviors: [
          "forced_durable_object_eviction_or_reinstantiation",
          "durable_object_pitr_or_time_travel",
          "d1_provider_time_travel"
        ]
      };
      routes.set(instancePath, {
        status: "complete",
        success: true,
        versionId: uuid(3),
        params,
        steps: [{ type: "step", name: "record sanitized acceptance evidence", success: true }]
      });
      routes.set(instancePath + "/step?name=record%20sanitized%20acceptance%20evidence&type=step", {
        status: "complete",
        output: evidence
      });
      routes.set(`/workflows/${config.providerWorkflow}/instances?per_page=100&direction=desc`, [
        {
          id: identity.campaignId,
          created_on: new Date(at * 1000).toISOString(),
          version_id: uuid(3),
          workflow_id: workflow.id,
          status: "complete",
          trigger_source: "api"
        }
      ]);
      return Response.json({ success: true, result: { id: identity.campaignId } });
    }
    if (!routes.has(path)) return new Response("Synthetic missing", { status: 404 });
    return Response.json({ success: true, result: routes.get(path) });
  });
  const options = {
    root,
    identity,
    config,
    apiToken: "synthetic-provider-test-identity",
    transport,
    smokeTransport: vi.fn(async (url) => successfulSmokeFetch(url)),
    execute: vi.fn((program, args, configuration) => {
      commands.push({ program, args, configuration });
      return { status: 0 };
    }),
    now: () => at,
    sleep: vi.fn(async () => {}),
    beforeMutation: vi.fn()
  };
  const assertion = (purpose, deployment = null) => ({
    schemaVersion: 2,
    ...identity,
    purpose,
    audience: "onceurl-public:staging",
    canonicalMainCurrent: true,
    nonce: "d".repeat(64),
    issuedAt: at,
    expiresAt: at + 60,
    releaseAssertionDigest: deployment ? "e".repeat(64) : null,
    deployment
  });
  const releaseOptions = {
    ...options,
    assertion: assertion("onceurl.staging.release.v1"),
    releaseAssertionDigest: "e".repeat(64)
  };
  async function released() {
    await runner.preflight(options);
    await runner.build(options);
    return runner.release(releaseOptions);
  }
  async function completed() {
    const deployment = await released();
    const campaignOptions = {
      ...options,
      deployment,
      assertion: assertion("onceurl.staging.campaign.v1", deployment),
      releaseAssertionDigest: "e".repeat(64),
      campaignAssertionDigest: "f".repeat(64)
    };
    return { deployment, campaignOptions, evidence: await runner.campaign(campaignOptions) };
  }
  return {
    options,
    releaseOptions,
    assertion,
    released,
    completed,
    calls,
    commands,
    routes,
    instancePath,
    resourceBindings,
    runtimeBindings,
    get evidence() {
      return evidence;
    }
  };
}

describe(
  "reviewed provider v2 first-write and independent-read contract",
  { timeout: 20_000 },
  () => {
    it("independently reads a complete release without invoking a build or mutation", async () => {
      const h = fixture();
      const result = await runner.readRelease(h.options);
      expect(result.providerWorkflowVersionId).toBe(uuid(3));
      expect(h.commands).toEqual([]);
      expect(h.calls.every((c) => c.method === "GET")).toBe(true);
    });
    it("implements the exact six-function contract with read-only preflight/build", async () => {
      const h = fixture();
      expect(runner.contract).toBe("onceurl.staging.provider.v2");
      for (const name of [
        "preflight",
        "build",
        "release",
        "campaign",
        "readRelease",
        "readEvidence"
      ])
        expect(runner[name]).toBeTypeOf("function");
      await runner.preflight(h.options);
      await runner.build(h.options);
      expect(h.calls.every((c) => c.method === "GET")).toBe(true);
      expect(h.commands).toHaveLength(2);
      expect(h.commands.every((c) => c.configuration.env.CLOUDFLARE_API_TOKEN === undefined)).toBe(
        true
      );
      expect(h.options.beforeMutation).not.toHaveBeenCalled();
    });
    it("starts one coherent migration/two-Worker sequence and refuses release replay", async () => {
      const h = fixture(),
        deployment = await h.released();
      expect(deployment.providerWorkflowVersionId).toBe(uuid(3));
      expect(deployment.functionalVersionId).toBe(uuid(1));
      expect(h.options.beforeMutation).toHaveBeenCalledTimes(1);
      expect(h.commands).toHaveLength(5);
      expect(h.commands[2].args).toContain("apply");
      expect(h.commands.slice(3).every((c) => c.args.includes("deploy"))).toBe(true);
      await expect(runner.release(h.releaseOptions)).rejects.toThrow(/failed closed/u);
      expect(h.commands).toHaveLength(5);
    });
    it.each([
      "callback rejects",
      "callback expires",
      "missing callback",
      "wrong purpose",
      "future",
      "wrong identity"
    ])("refuses release %s before first write", async (kind) => {
      const h = fixture();
      await runner.build(h.options);
      const options = { ...h.releaseOptions };
      if (kind === "callback rejects")
        options.beforeMutation = async () => {
          throw new Error("denied");
        };
      if (kind === "callback expires") {
        let clock = 1000;
        options.now = () => clock;
        options.beforeMutation = () => {
          clock = 1060;
        };
      }
      if (kind === "missing callback") delete options.beforeMutation;
      if (kind === "wrong purpose")
        options.assertion = { ...options.assertion, purpose: "onceurl.staging.campaign.v1" };
      if (kind === "future") options.assertion = { ...options.assertion, issuedAt: 1001 };
      if (kind === "wrong identity")
        options.assertion = { ...options.assertion, canonicalSourceSha: "9".repeat(40) };
      await expect(runner.release(options)).rejects.toThrow(/failed closed/u);
      expect(h.commands).toHaveLength(2);
    });
    it("uses one exact campaign instance and independently reproduces sanitized evidence", async () => {
      const h = fixture(),
        result = await h.completed();
      expect(result.evidence.schemaVersion).toBe(2);
      expect(result.evidence.campaignStartedAt).toBe(1000);
      expect(h.calls.filter((c) => c.method === "POST")).toHaveLength(1);
      expect(h.options.beforeMutation).toHaveBeenCalledTimes(2);
      const before = h.commands.length;
      const read = await runner.readEvidence({ ...h.options, deployment: result.deployment });
      expect(read).toEqual(result.evidence);
      expect(h.commands).toHaveLength(before);
      await expect(runner.campaign(result.campaignOptions)).rejects.toThrow(/failed closed/u);
      expect(h.calls.filter((c) => c.method === "POST")).toHaveLength(1);
    });
    it.each([
      "workflow ID",
      "worker version",
      "caller clock",
      "unknown secret field",
      "bad cleanup",
      "bad cases",
      "changed instance identity",
      "duplicate step"
    ])("rejects independent evidence %s", async (kind) => {
      const h = fixture(),
        { deployment } = await h.completed(),
        instance = h.routes.get(h.instancePath);
      if (kind === "workflow ID") instance.versionId = uuid(90);
      if (kind === "worker version") instance.versionId = uuid(1);
      if (kind === "caller clock")
        h.routes.get(
          `/workflows/${h.options.config.providerWorkflow}/instances?per_page=100&direction=desc`
        )[0].created_on = new Date(1060 * 1000).toISOString();
      if (kind === "unknown secret field") h.evidence.publicBearer = "synthetic-forbidden-field";
      if (kind === "bad cleanup") h.evidence.cleanup.remainingD1Rows = 1;
      if (kind === "bad cases") h.evidence.cases[1].releases = 2;
      if (kind === "changed instance identity") instance.params.exportDigest = "9".repeat(64);
      if (kind === "duplicate step") instance.steps.push(instance.steps[0]);
      await expect(runner.readEvidence({ ...h.options, deployment })).rejects.toThrow(
        /failed closed/u
      );
    });
    it.each([
      "tag",
      "message",
      "dual SHA",
      "split deployment",
      "smoke failure",
      "workflow class",
      "active database",
      "duplicate binding"
    ])("rejects release readback %s", async (kind) => {
      const h = fixture();
      const version = h.routes.get(
        `/workers/scripts/${h.options.config.functionalWorker}/versions/${uuid(1)}`
      );
      if (kind === "tag") version.metadata.annotations["workers/tag"] = "staging-999999999999";
      if (kind === "message") version.metadata.annotations["workers/message"] = "wrong";
      if (kind === "dual SHA")
        h.runtimeBindings.find((b) => b.name === "STAGING_CANONICAL_SOURCE_SHA").text =
          h.options.identity.publicSourceSha;
      if (kind === "split deployment")
        h.routes
          .get(`/workers/scripts/${h.options.config.functionalWorker}/deployments`)
          .deployments[0].versions.push({ version_id: uuid(4), percentage: 50 });
      if (kind === "smoke failure")
        h.options.smokeTransport = async () => new Response("", { status: 503 });
      if (kind === "workflow class")
        h.routes.get(`/workflows/${h.options.config.providerWorkflow}`).class_name = "WrongClass";
      if (kind === "active database")
        version.resources.bindings.find((b) => b.name === "DB").id = uuid(99);
      if (kind === "duplicate binding")
        version.resources.bindings.push(version.resources.bindings[0]);
      await expect(runner.readRelease(h.options)).rejects.toThrow(/failed closed/u);
      expect(h.calls.every((c) => c.method === "GET")).toBe(true);
    });
    it.each(["database", "bucket", "namespace", "HMAC", "origin", "configuration digest"])(
      "refuses preflight resource %s without writes",
      async (kind) => {
        const h = fixture();
        if (kind === "database")
          h.routes.get(`/d1/database/${h.options.config.databaseId}`).name = "another-database";
        if (kind === "bucket")
          h.resourceBindings.find((b) => b.name === "FILES").bucket_name = "foreign";
        if (kind === "namespace")
          h.routes.get("/workers/durable_objects/namespaces?per_page=100&page=1")[0].script =
            "foreign-worker";
        if (kind === "HMAC")
          h.resourceBindings.splice(
            h.resourceBindings.findIndex((b) => b.name === "STAGING_RELIABILITY_HMAC_KEY"),
            1
          );
        if (kind === "origin")
          h.options.config.functionalOrigin = "https://functional.staging.invalid";
        if (kind === "configuration digest")
          h.options.identity.configurationDigest = "0".repeat(64);
        await expect(runner.preflight(h.options)).rejects.toThrow(/failed closed/u);
        expect(h.commands).toEqual([]);
        expect(h.calls.every((c) => c.method === "GET")).toBe(true);
      }
    );
    it("discards arbitrary provider exception bodies and credentials", async () => {
      const h = fixture();
      h.options.transport = async () => {
        throw new Error("synthetic-bearer-body-do-not-output");
      };
      await expect(runner.preflight(h.options)).rejects.toThrow(
        "Staging provider operation failed closed; preserve recovery evidence"
      );
    });
  }
);
