import { env, type WorkflowStep, type WorkflowEvent } from "cloudflare:workers";
import { applyD1Migrations, type D1Migration } from "cloudflare:test";
import { expect, it } from "vitest";
import {
  STAGING_IDENTITY_BINDINGS,
  type StagingReliabilityInput
} from "./staging-reliability-core";
import { StagingReliabilityWorkflow } from "./staging-reliability-workflow";
import type { WorkerEnv } from "./env";

it("executes all bounded cases and exact cleanup against local DO, Queue and D1", async () => {
  const runtime = env as WorkerEnv & { DB: D1Database; TEST_D1_MIGRATIONS: D1Migration[] };
  await applyD1Migrations(runtime.DB, runtime.TEST_D1_MIGRATIONS);
  const at = new Date(),
    issuedAt = Math.floor(at.getTime() / 1000);
  const input: StagingReliabilityInput = {
    schemaVersion: 2,
    deploymentEnvironment: "staging",
    canonicalSourceSha: "a".repeat(40),
    publicSourceSha: "b".repeat(40),
    exportDigest: "c".repeat(64),
    publicationSequence: 4,
    acceptedRecordDigest: "d".repeat(64),
    publicCiWorkflowRunId: "101",
    publicCiWorkflowRunAttempt: 1,
    publicCiJobId: "102",
    workflowRunId: "103",
    workflowRunAttempt: 1,
    campaignId: "ou-staging-103-1-bbbbbbbbbbbb",
    configurationDigest: "e".repeat(64),
    functionalVersionId: "00000000-0000-4000-8000-000000000001",
    functionalVersionTag: "staging-bbbbbbbbbbbb",
    marketingVersionId: "00000000-0000-4000-8000-000000000002",
    marketingVersionTag: "staging-bbbbbbbbbbbb",
    providerWorkflowVersionId: "00000000-0000-4000-8000-000000000003",
    smokeEvidenceDigest: "f".repeat(64),
    releaseAssertionDigest: "1".repeat(64),
    campaignAssertionDigest: "2".repeat(64),
    campaignIssuedAt: issuedAt,
    campaignExpiresAt: issuedAt + 60
  };
  const staging = {
    ...runtime,
    DEPLOYMENT_ENVIRONMENT: "staging",
    FUNCTIONAL_ORIGIN: "https://functional.staging.onceurl.mistyislesoftware.co.uk",
    MARKETING_ORIGIN: "https://marketing.staging.onceurl.mistyislesoftware.co.uk",
    STAGING_RELIABILITY_HMAC_KEY: "A".repeat(43),
    CF_VERSION_METADATA: {
      id: input.functionalVersionId,
      tag: input.functionalVersionTag,
      timestamp: at.toISOString()
    },
    ...Object.fromEntries(
      Object.entries(STAGING_IDENTITY_BINDINGS).map(([field, binding]) => [
        binding,
        String(input[field as keyof StagingReliabilityInput])
      ])
    )
  };
  const outputs: unknown[] = [];
  const names: string[] = [];
  // This local harness accelerates Workflow sleeps. Provider scheduling, instance
  // metadata and the production quiet interval are covered by the reader contract.
  const step = {
    do: async (
      name: string,
      config: { retries: { limit: number } },
      callback: () => Promise<unknown>
    ) => {
      expect(config.retries.limit).toBe(0);
      names.push(name);
      const result = await callback();
      outputs.push(result);
      return result;
    },
    sleep: async () => {
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  } as unknown as WorkflowStep;
  const event = {
    payload: input,
    instanceId: input.campaignId,
    timestamp: at
  } as WorkflowEvent<StagingReliabilityInput>;
  const result = await StagingReliabilityWorkflow.prototype.run.call(
    { env: staging } as unknown as StagingReliabilityWorkflow,
    event,
    step
  );
  expect(result).toMatchObject({
    schemaVersion: 2,
    outcome: "passed",
    campaignStartedAt: issuedAt,
    cases: [
      { caseName: "claim_replay_and_projection", releases: 1, attempts: 4, queueD1Converged: true },
      { caseName: "bounded_concurrent_claim", releases: 1, attempts: 8, queueD1Converged: true },
      {
        caseName: "actual_uncertain_restore_command",
        releases: 0,
        attempts: 2,
        queueD1Converged: true
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
    }
  });
  expect(names.at(-1)).toBe("record sanitized acceptance evidence");
  const evidence = JSON.stringify(outputs);
  for (const field of [
    "publicBearerSecret",
    "ownerBearerSecret",
    "ciphertextEnvelope",
    "plaintext",
    "accessCode",
    "https://capability.invalid"
  ])
    expect(evidence).not.toContain(field);
}, 90000);
