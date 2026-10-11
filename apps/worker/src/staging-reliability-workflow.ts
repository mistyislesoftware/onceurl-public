import {
  WorkflowEntrypoint,
  type WorkflowEvent,
  type WorkflowStep,
  type WorkflowStepConfig
} from "cloudflare:workers";
import { NonRetryableError } from "cloudflare:workflows";
import { z } from "zod";
import {
  parseCapabilityProjectionMessage,
  type CapabilityProjectionMessage
} from "./capability-durable-object-core";
import type { WorkerEnv } from "./env";
import {
  deriveSyntheticCapability,
  deriveSyntheticNonce,
  deriveSyntheticOperationId,
  STAGING_RELIABILITY_CAPABILITY_COUNT,
  STAGING_RELIABILITY_CONCURRENT_CLAIMS,
  stagingReliabilityInputSchema,
  validateStagingReliabilityPreflight,
  type StagingReliabilityInput,
  type StagingReliabilityPreflightEvidence,
  type SyntheticCapabilityIdentity
} from "./staging-reliability-core";

const STEP_CONFIG = {
  retries: { limit: 0, delay: "1 second", backoff: "constant" },
  timeout: "2 minutes"
} as const satisfies WorkflowStepConfig;
const POLL_ATTEMPTS = 12;
const POLL_DELAY = "5 seconds";
const CLEANUP_QUIET_PERIOD = "70 seconds";
const MAX_START_DELAY_MS = 10 * 60 * 1_000;

type StagingReliabilityEnv = WorkerEnv & {
  readonly DB: D1Database;
  readonly CAPABILITY_STATE: DurableObjectNamespace;
  readonly ASYNC_JOBS: Queue<CapabilityProjectionMessage>;
  readonly CF_VERSION_METADATA: WorkerVersionMetadata;
  readonly STAGING_RELIABILITY_HMAC_KEY: string;
};

const createResultSchema = z.strictObject({ ok: z.literal(true) });
const claimReleasedSchema = z.strictObject({
  ok: z.literal(true),
  outcome: z.literal("released"),
  ciphertextEnvelope: z.unknown()
});
const claimFailureSchema = z.strictObject({
  ok: z.literal(false),
  code: z.enum([
    "invalid_command",
    "not_found",
    "unauthorized",
    "nonce_conflict",
    "event_conflict",
    "rate_limited",
    "challenge_required",
    "verification_failed",
    "unavailable",
    "malformed_state"
  ]),
  retryAfter: z.number().int().positive().optional()
});
const authorizeResultSchema = z.strictObject({
  ok: z.literal(true),
  authority: z.enum(["public", "owner"]),
  capability: z.strictObject({
    kind: z.literal("secret"),
    state: z.enum([
      "DRAFT",
      "ACTIVE",
      "CONSUMED",
      "EXPIRED",
      "DISABLED",
      "ABUSE_LOCKED",
      "DELETED"
    ]),
    createdAt: z.string(),
    expiresAt: z.number().nullable(),
    isAvailable: z.boolean(),
    policy: z.strictObject({ maxConsumptions: z.literal(1) }),
    accessCodeRequired: z.boolean(),
    events: z.array(z.unknown()).optional()
  })
});
const failClosedResultSchema = z.strictObject({
  ok: z.literal(true),
  state: z.literal("DELETED"),
  projectionVersion: z.number().int().positive(),
  ciphertextPresent: z.literal(false)
});
const reconciliationResultSchema = z.strictObject({
  ok: z.literal(true),
  message: z.unknown(),
  pendingOutboxCount: z.number().int().nonnegative(),
  nextDueAt: z.number().int().nonnegative().nullable()
});
const catalogueRowSchema = z.strictObject({
  state: z.string(),
  version: z.number().int().positive(),
  consumed_at: z.number().int().nonnegative().nullable(),
  deleted_at: z.number().int().nonnegative().nullable()
});
const tombstoneRowSchema = z.strictObject({
  terminal_state: z.enum(["CONSUMED", "EXPIRED", "DELETED"]),
  projection_version: z.number().int().positive(),
  terminal_event_id: z.string(),
  last_verified_at: z.number().int().nonnegative().nullable()
});
const countRowSchema = z.strictObject({ count: z.number().int().nonnegative() });
const candidateRowSchema = z.strictObject({
  last_attempt_at: z.number().int().nonnegative().nullable()
});

interface ProjectionSnapshot {
  readonly catalogue: z.infer<typeof catalogueRowSchema> | null;
  readonly tombstone: z.infer<typeof tombstoneRowSchema> | null;
  readonly eventCount: number;
  readonly terminalEventCount: number;
  readonly candidateLastAttemptAt: number | null;
}

interface ProjectionPollResult {
  readonly ready: boolean;
  readonly lifecycleState?: string;
  readonly projectionVersion?: number;
  readonly eventCount?: number;
  readonly terminalEventCount?: number;
  readonly candidateLastAttemptAt?: number | null;
  readonly duplicateProcessed?: boolean;
  readonly cataloguePresent?: boolean;
  readonly deletedCapabilities?: number;
  readonly pendingOutboxes?: number;
}

interface SingleClaimEvidence {
  readonly caseName: "claim_replay_and_projection";
  readonly claims: number;
  readonly releases: 1;
  readonly sameOperationReplayUnavailable: true;
  readonly freshRetryUnavailable: true;
  readonly separateWorkflowStepRequests: true;
  readonly forcedDurableObjectReinstantiation: false;
  readonly lifecycleState: "CONSUMED";
  readonly projectionVersion: 2;
  readonly queueD1Converged: true;
  readonly staleD1Observed: true;
  readonly staleD1AuthorizedRelease: false;
  readonly duplicateProjectionEventRows: 1;
}

interface ConcurrentClaimEvidence {
  readonly caseName: "bounded_concurrent_claim";
  readonly attempts: number;
  readonly releases: 1;
  readonly lifecycleState: "CONSUMED";
  readonly projectionVersion: 2;
  readonly queueD1Converged: true;
}

interface UncertainRestoreEvidence {
  readonly caseName: "actual_uncertain_restore_command";
  readonly commandInvocations: 2;
  readonly releasesAfterDecision: 0;
  readonly lifecycleState: "DELETED";
  readonly projectionVersion: 2;
  readonly ciphertextAbsent: true;
  readonly queueD1Converged: true;
}

interface CleanupEvidence {
  readonly attemptedCapabilities: number;
  readonly deletedCapabilities: number;
  readonly releasesAfterCleanup: 0;
  readonly ciphertextAbsent: true;
  readonly pendingOutboxes: 0;
  readonly remainingD1Rows: 0;
  readonly exactRowCleanupOnly: true;
  readonly passed: true;
}

export class StagingReliabilityWorkflow extends WorkflowEntrypoint<
  StagingReliabilityEnv,
  StagingReliabilityInput
> {
  override async run(
    event: Readonly<WorkflowEvent<StagingReliabilityInput>>,
    step: WorkflowStep
  ): Promise<unknown> {
    let input: StagingReliabilityInput | null = null;
    let preflight: StagingReliabilityPreflightEvidence | null = null;
    let singleClaim: SingleClaimEvidence | null = null;
    let concurrentClaim: ConcurrentClaimEvidence | null = null;
    let uncertainRestore: UncertainRestoreEvidence | null = null;
    let primaryFailure: string | null = null;

    try {
      preflight = await step.do("verify exact staging deployment provenance", STEP_CONFIG, () => {
        const validation = validateStagingReliabilityPreflight(
          event.payload,
          event.instanceId,
          this.env
        );
        const startedAt = event.timestamp.getTime();
        if (
          !Number.isSafeInteger(startedAt) ||
          startedAt <= 0 ||
          Date.now() - startedAt > MAX_START_DELAY_MS ||
          startedAt < event.payload.campaignIssuedAt * 1000 ||
          startedAt >= event.payload.campaignExpiresAt * 1000 ||
          startedAt > Date.now()
        ) {
          throw new Error("staging_reliability_stale_trigger");
        }
        return Promise.resolve(validation.evidence);
      });
      const parsedInput = stagingReliabilityInputSchema.safeParse(event.payload);
      if (!parsedInput.success) throw new Error("staging_reliability_invalid_input");
      input = parsedInput.data;
      singleClaim = await runSingleClaimCase(this.env, input, event, step);
      concurrentClaim = await runConcurrentClaimCase(this.env, input, event, step);
      uncertainRestore = await runUncertainRestoreCase(this.env, input, event, step);
    } catch (error) {
      primaryFailure = sanitizedFailureCode(error);
    }

    if (input === null || preflight === null) {
      throw new NonRetryableError(primaryFailure ?? "staging_reliability_preflight_failed");
    }

    let cleanup: CleanupEvidence;
    try {
      cleanup = await runFinallyCleanup(this.env, input, event, step);
    } catch {
      throw new NonRetryableError("staging_reliability_cleanup_failed");
    }

    if (primaryFailure !== null) throw new NonRetryableError(primaryFailure);
    if (singleClaim === null || concurrentClaim === null || uncertainRestore === null) {
      throw new NonRetryableError("staging_reliability_missing_case_evidence");
    }

    return step.do("record sanitized acceptance evidence", STEP_CONFIG, () =>
      Promise.resolve({
        schemaVersion: 2 as const,
        campaignStartedAt: Math.floor(event.timestamp.getTime() / 1000),
        smokePassed: true as const,
        outcome: "passed" as const,
        ...preflight,
        cases: [
          {
            caseName: singleClaim.caseName,
            releases: singleClaim.releases,
            attempts: singleClaim.claims,
            queueD1Converged: singleClaim.queueD1Converged,
            replayUnavailable:
              singleClaim.sameOperationReplayUnavailable && singleClaim.freshRetryUnavailable,
            staleD1AuthorizedRelease: singleClaim.staleD1AuthorizedRelease,
            duplicateEventRows: singleClaim.duplicateProjectionEventRows
          },
          {
            caseName: concurrentClaim.caseName,
            releases: concurrentClaim.releases,
            attempts: concurrentClaim.attempts,
            queueD1Converged: concurrentClaim.queueD1Converged
          },
          {
            caseName: uncertainRestore.caseName,
            releases: uncertainRestore.releasesAfterDecision,
            attempts: uncertainRestore.commandInvocations,
            queueD1Converged: uncertainRestore.queueD1Converged,
            ciphertextAbsent: uncertainRestore.ciphertextAbsent
          }
        ],
        cleanup: {
          capabilityCount: cleanup.deletedCapabilities,
          releases: cleanup.releasesAfterCleanup,
          ciphertextAbsent: cleanup.ciphertextAbsent,
          pendingOutboxes: cleanup.pendingOutboxes,
          remainingD1Rows: cleanup.remainingD1Rows,
          exactRowsOnly: cleanup.exactRowCleanupOnly,
          passed: cleanup.passed
        },
        unsupportedProviderBehaviors: [
          "forced_durable_object_eviction_or_reinstantiation",
          "durable_object_pitr_or_time_travel",
          "d1_provider_time_travel"
        ] as const
      })
    );
  }
}

async function runSingleClaimCase(
  env: StagingReliabilityEnv,
  input: StagingReliabilityInput,
  event: Readonly<WorkflowEvent<StagingReliabilityInput>>,
  step: WorkflowStep
): Promise<SingleClaimEvidence> {
  const caseName = "claim_replay" as const;
  const createdAt = event.timestamp.getTime();
  await step.do("single claim create request", STEP_CONFIG, async () => {
    assertCurrentProvenance(env, input, event.instanceId);
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    await createCapability(env, input, identity, caseName);
    return { caseName, created: true as const, providerRequests: 1 };
  });

  await pollProjection(step, "single claim active projection", async () => {
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    const snapshot = await readProjectionSnapshot(
      env.DB,
      identity,
      await operationId(env, input, caseName, "create")
    );
    const ready =
      snapshot.catalogue?.state === "ACTIVE" &&
      snapshot.catalogue.version === 1 &&
      snapshot.eventCount === 1;
    return {
      ready,
      lifecycleState: snapshot.catalogue?.state ?? "MISSING",
      projectionVersion: snapshot.catalogue?.version ?? 0,
      eventCount: snapshot.eventCount
    };
  });

  await step.do("single claim explicit release request", STEP_CONFIG, async () => {
    assertCurrentProvenance(env, input, event.instanceId);
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    const operation = await operationId(env, input, caseName, "claim");
    const nonce = await syntheticNonce(env, input, caseName, "claim");
    const result = await claim(env, identity, operation, nonce);
    const released = claimReleasedSchema.safeParse(result);
    if (
      !released.success ||
      !sameJsonValue(released.data.ciphertextEnvelope, identity.ciphertextEnvelope)
    ) {
      throw new Error("staging_reliability_single_release_failed");
    }
    return { releases: 1 as const, lifecycleTransitionExpected: "CONSUMED" as const };
  });

  await step.do("single claim replay and fresh retry requests", STEP_CONFIG, async () => {
    assertCurrentProvenance(env, input, event.instanceId);
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    const operation = await operationId(env, input, caseName, "claim");
    const nonce = await syntheticNonce(env, input, caseName, "claim");
    assertUnavailable(await claim(env, identity, operation, nonce));
    assertUnavailable(
      await claim(
        env,
        identity,
        await operationId(env, input, caseName, "fresh-retry"),
        await syntheticNonce(env, input, caseName, "fresh-retry")
      )
    );
    const owner = await authorizeOwner(env, identity);
    if (owner.capability.state !== "CONSUMED" || owner.capability.isAvailable) {
      throw new Error("staging_reliability_single_terminal_state_failed");
    }
    return {
      totalClaimRequests: 3,
      releases: 1,
      sameOperationReplayUnavailable: true,
      freshRetryUnavailable: true,
      lifecycleState: "CONSUMED" as const
    };
  });

  await pollProjection(step, "single claim consumed projection", async () => {
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    const claimEventId = await operationId(env, input, caseName, "claim");
    const snapshot = await readProjectionSnapshot(env.DB, identity, claimEventId);
    const ready =
      snapshot.catalogue?.state === "CONSUMED" &&
      snapshot.catalogue.version === 2 &&
      snapshot.tombstone?.terminal_state === "CONSUMED" &&
      snapshot.tombstone.projection_version === 2 &&
      snapshot.terminalEventCount === 1;
    return {
      ready,
      lifecycleState: snapshot.catalogue?.state ?? "MISSING",
      projectionVersion: snapshot.catalogue?.version ?? 0,
      terminalEventCount: snapshot.terminalEventCount
    };
  });

  await step.do("make exact synthetic D1 projection stale", STEP_CONFIG, async () => {
    assertCurrentProvenance(env, input, event.instanceId);
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    const terminalEventId = await operationId(env, input, caseName, "claim");
    await env.DB.batch([
      env.DB.prepare(
        "DELETE FROM capability_terminal_tombstones WHERE capability_id = ? AND routing_locator = ?"
      ).bind(identity.capabilityId, identity.locator),
      env.DB.prepare(
        "DELETE FROM capability_projection_events WHERE capability_id = ? AND event_id = ?"
      ).bind(identity.capabilityId, terminalEventId),
      env.DB.prepare(
        `UPDATE capabilities
          SET state = 'ACTIVE', consumed_at = NULL, disabled_at = NULL, deleted_at = NULL,
              updated_at = created_at, version = 1
          WHERE id = ? AND routing_locator = ?`
      ).bind(identity.capabilityId, identity.locator)
    ]);
    const stale = await readProjectionSnapshot(env.DB, identity, terminalEventId);
    if (stale.catalogue?.state !== "ACTIVE" || stale.catalogue.version !== 1) {
      throw new Error("staging_reliability_stale_d1_setup_failed");
    }
    assertUnavailable(
      await claim(
        env,
        identity,
        await operationId(env, input, caseName, "stale-d1-claim"),
        await syntheticNonce(env, input, caseName, "stale-d1-claim")
      )
    );
    const message = await currentProjection(env, identity);
    await env.ASYNC_JOBS.send(asQueueDelivery(message));
    return {
      d1State: "ACTIVE" as const,
      d1Version: 1 as const,
      authoritativeRelease: false,
      repairQueued: true
    };
  });

  const firstRepair = await pollProjection(
    step,
    "stale projection first queue repair",
    async () => {
      const identity = await deriveIdentity(env, input, caseName, createdAt);
      const terminalEventId = await operationId(env, input, caseName, "claim");
      const snapshot = await readProjectionSnapshot(env.DB, identity, terminalEventId);
      const ready =
        snapshot.catalogue?.state === "CONSUMED" &&
        snapshot.catalogue.version === 2 &&
        snapshot.tombstone?.terminal_state === "CONSUMED" &&
        snapshot.terminalEventCount === 1 &&
        snapshot.candidateLastAttemptAt !== null;
      return {
        ready,
        lifecycleState: snapshot.catalogue?.state ?? "MISSING",
        projectionVersion: snapshot.catalogue?.version ?? 0,
        terminalEventCount: snapshot.terminalEventCount,
        candidateLastAttemptAt: snapshot.candidateLastAttemptAt
      };
    }
  );
  if (typeof firstRepair.candidateLastAttemptAt !== "number") {
    throw new Error("staging_reliability_first_repair_evidence_missing");
  }
  const firstRepairAttemptAt = firstRepair.candidateLastAttemptAt;

  await step.do("inject one duplicate terminal projection", STEP_CONFIG, async () => {
    assertCurrentProvenance(env, input, event.instanceId);
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    await env.ASYNC_JOBS.send(asQueueDelivery(await currentProjection(env, identity)));
    return { duplicateMessagesInjected: 1 as const };
  });

  await pollProjection(step, "duplicate projection acknowledgement", async () => {
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    const terminalEventId = await operationId(env, input, caseName, "claim");
    const snapshot = await readProjectionSnapshot(env.DB, identity, terminalEventId);
    const ready =
      snapshot.candidateLastAttemptAt !== null &&
      snapshot.candidateLastAttemptAt > firstRepairAttemptAt &&
      snapshot.terminalEventCount === 1 &&
      snapshot.catalogue?.state === "CONSUMED" &&
      snapshot.catalogue.version === 2;
    return {
      ready,
      lifecycleState: snapshot.catalogue?.state ?? "MISSING",
      projectionVersion: snapshot.catalogue?.version ?? 0,
      terminalEventCount: snapshot.terminalEventCount,
      duplicateProcessed: ready
    };
  });

  return {
    caseName: "claim_replay_and_projection",
    claims: 4,
    releases: 1,
    sameOperationReplayUnavailable: true,
    freshRetryUnavailable: true,
    separateWorkflowStepRequests: true,
    forcedDurableObjectReinstantiation: false,
    lifecycleState: "CONSUMED",
    projectionVersion: 2,
    queueD1Converged: true,
    staleD1Observed: true,
    staleD1AuthorizedRelease: false,
    duplicateProjectionEventRows: 1
  };
}

async function runConcurrentClaimCase(
  env: StagingReliabilityEnv,
  input: StagingReliabilityInput,
  event: Readonly<WorkflowEvent<StagingReliabilityInput>>,
  step: WorkflowStep
): Promise<ConcurrentClaimEvidence> {
  const caseName = "concurrent_claim" as const;
  const createdAt = event.timestamp.getTime();
  await step.do("concurrent claim create request", STEP_CONFIG, async () => {
    assertCurrentProvenance(env, input, event.instanceId);
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    await createCapability(env, input, identity, caseName);
    return { caseName, created: true as const };
  });

  await pollProjection(step, "concurrent claim active projection", async () => {
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    const snapshot = await readProjectionSnapshot(
      env.DB,
      identity,
      await operationId(env, input, caseName, "create")
    );
    return {
      ready: snapshot.catalogue?.state === "ACTIVE" && snapshot.catalogue.version === 1,
      lifecycleState: snapshot.catalogue?.state ?? "MISSING",
      projectionVersion: snapshot.catalogue?.version ?? 0
    };
  });

  await step.do("bounded concurrent claim requests", STEP_CONFIG, async () => {
    assertCurrentProvenance(env, input, event.instanceId);
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    const requests = await Promise.all(
      Array.from({ length: STAGING_RELIABILITY_CONCURRENT_CLAIMS }, async (_value, index) =>
        claim(
          env,
          identity,
          await operationId(env, input, caseName, `claim-${index}`),
          await syntheticNonce(env, input, caseName, `claim-${index}`)
        )
      )
    );
    let releases = 0;
    let unavailable = 0;
    for (const result of requests) {
      const released = claimReleasedSchema.safeParse(result);
      if (released.success) {
        if (!sameJsonValue(released.data.ciphertextEnvelope, identity.ciphertextEnvelope)) {
          throw new Error("staging_reliability_concurrent_payload_mismatch");
        }
        releases += 1;
        continue;
      }
      const failure = claimFailureSchema.safeParse(result);
      if (failure.success && failure.data.code === "unavailable") unavailable += 1;
      else throw new Error("staging_reliability_concurrent_unexpected_result");
    }
    if (releases !== 1 || unavailable !== STAGING_RELIABILITY_CONCURRENT_CLAIMS - 1) {
      throw new Error("staging_reliability_concurrent_release_count_failed");
    }
    return { attempts: requests.length, releases, unavailable };
  });

  await pollProjection(step, "concurrent claim consumed projection", async () => {
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    const snapshot = await readProjectionSnapshot(env.DB, identity, null);
    const ready =
      snapshot.catalogue?.state === "CONSUMED" &&
      snapshot.catalogue.version === 2 &&
      snapshot.tombstone?.terminal_state === "CONSUMED";
    return {
      ready,
      lifecycleState: snapshot.catalogue?.state ?? "MISSING",
      projectionVersion: snapshot.catalogue?.version ?? 0
    };
  });

  return {
    caseName: "bounded_concurrent_claim",
    attempts: STAGING_RELIABILITY_CONCURRENT_CLAIMS,
    releases: 1,
    lifecycleState: "CONSUMED",
    projectionVersion: 2,
    queueD1Converged: true
  };
}

async function runUncertainRestoreCase(
  env: StagingReliabilityEnv,
  input: StagingReliabilityInput,
  event: Readonly<WorkflowEvent<StagingReliabilityInput>>,
  step: WorkflowStep
): Promise<UncertainRestoreEvidence> {
  const caseName = "uncertain_restore" as const;
  const createdAt = event.timestamp.getTime();
  await step.do("uncertain restore create request", STEP_CONFIG, async () => {
    assertCurrentProvenance(env, input, event.instanceId);
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    await createCapability(env, input, identity, caseName);
    return { caseName, created: true as const };
  });

  await pollProjection(step, "uncertain restore active projection", async () => {
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    const snapshot = await readProjectionSnapshot(
      env.DB,
      identity,
      await operationId(env, input, caseName, "create")
    );
    return {
      ready: snapshot.catalogue?.state === "ACTIVE" && snapshot.catalogue.version === 1,
      lifecycleState: snapshot.catalogue?.state ?? "MISSING",
      projectionVersion: snapshot.catalogue?.version ?? 0
    };
  });

  await step.do("invoke actual uncertain restore command boundary", STEP_CONFIG, async () => {
    assertCurrentProvenance(env, input, event.instanceId);
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    const operation = await operationId(env, input, caseName, "fail-closed");
    const first = await failClosed(env, identity, operation);
    const replay = await failClosed(env, identity, operation);
    for (const result of [first, replay]) {
      if (
        result.state !== "DELETED" ||
        result.projectionVersion !== 2 ||
        result.ciphertextPresent
      ) {
        throw new Error("staging_reliability_uncertain_restore_result_failed");
      }
    }
    assertUnavailable(
      await claim(
        env,
        identity,
        await operationId(env, input, caseName, "post-decision-claim"),
        await syntheticNonce(env, input, caseName, "post-decision-claim")
      )
    );
    const owner = await authorizeOwner(env, identity);
    if (owner.capability.state !== "DELETED" || owner.capability.isAvailable) {
      throw new Error("staging_reliability_uncertain_restore_authorization_failed");
    }
    return {
      commandInvocations: 2 as const,
      commandPath: "/internal/capability/fail-closed-uncertain-restore" as const,
      lifecycleState: "DELETED" as const,
      projectionVersion: 2 as const,
      ciphertextPresent: false as const,
      releasesAfterDecision: 0 as const
    };
  });

  await pollProjection(step, "uncertain restore deleted projection", async () => {
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    const terminalEventId = await operationId(env, input, caseName, "fail-closed");
    const snapshot = await readProjectionSnapshot(env.DB, identity, terminalEventId);
    const ready =
      snapshot.catalogue === null &&
      snapshot.tombstone?.terminal_state === "DELETED" &&
      snapshot.tombstone.projection_version === 2 &&
      snapshot.terminalEventCount === 1;
    return {
      ready,
      cataloguePresent: snapshot.catalogue !== null,
      lifecycleState: snapshot.tombstone?.terminal_state ?? "MISSING",
      projectionVersion: snapshot.tombstone?.projection_version ?? 0,
      terminalEventCount: snapshot.terminalEventCount
    };
  });

  return {
    caseName: "actual_uncertain_restore_command",
    commandInvocations: 2,
    releasesAfterDecision: 0,
    lifecycleState: "DELETED",
    projectionVersion: 2,
    ciphertextAbsent: true,
    queueD1Converged: true
  };
}

async function runFinallyCleanup(
  env: StagingReliabilityEnv,
  input: StagingReliabilityInput,
  event: Readonly<WorkflowEvent<StagingReliabilityInput>>,
  step: WorkflowStep
): Promise<CleanupEvidence> {
  let failed = false;
  try {
    await step.do("finally fail closed every synthetic capability", STEP_CONFIG, async () => {
      assertCurrentProvenance(env, input, event.instanceId);
      let deletedCapabilities = 0;
      let releases = 0;
      let ciphertextAbsent = true;
      let operationFailures = 0;
      for (const caseName of ["claim_replay", "concurrent_claim", "uncertain_restore"] as const) {
        try {
          const identity = await deriveIdentity(env, input, caseName, event.timestamp.getTime());
          const result = await failClosed(
            env,
            identity,
            await operationId(env, input, caseName, "finally-cleanup")
          );
          deletedCapabilities += result.state === "DELETED" ? 1 : 0;
          ciphertextAbsent &&= !result.ciphertextPresent;
          const claimResult = await claim(
            env,
            identity,
            await operationId(env, input, caseName, "finally-claim"),
            await syntheticNonce(env, input, caseName, "finally-claim")
          );
          if (claimReleasedSchema.safeParse(claimResult).success) releases += 1;
          else assertUnavailable(claimResult);
          const owner = await authorizeOwner(env, identity);
          if (owner.capability.state !== "DELETED" || owner.capability.isAvailable) {
            operationFailures += 1;
          }
        } catch {
          operationFailures += 1;
        }
      }
      if (
        operationFailures !== 0 ||
        deletedCapabilities !== STAGING_RELIABILITY_CAPABILITY_COUNT ||
        releases !== 0 ||
        !ciphertextAbsent
      ) {
        throw new Error("staging_reliability_authoritative_cleanup_failed");
      }
      return {
        attemptedCapabilities: STAGING_RELIABILITY_CAPABILITY_COUNT,
        deletedCapabilities,
        releases,
        ciphertextAbsent
      };
    });
  } catch {
    failed = true;
  }

  let pendingOutboxes = -1;
  try {
    const convergence = await pollProjection(step, "finally deletion convergence", async () => {
      let deletedCapabilities = 0;
      let pending = 0;
      for (const caseName of ["claim_replay", "concurrent_claim", "uncertain_restore"] as const) {
        const identity = await deriveIdentity(env, input, caseName, event.timestamp.getTime());
        const snapshot = await readProjectionSnapshot(env.DB, identity, null);
        const reconciliation = await currentProjectionWithPending(env, identity);
        if (
          snapshot.catalogue === null &&
          snapshot.tombstone?.terminal_state === "DELETED" &&
          reconciliation.message.projection.state === "DELETED"
        ) {
          deletedCapabilities += 1;
        }
        pending += reconciliation.pendingOutboxCount;
      }
      return {
        ready: deletedCapabilities === STAGING_RELIABILITY_CAPABILITY_COUNT && pending === 0,
        deletedCapabilities,
        pendingOutboxes: pending
      };
    });
    if (typeof convergence.pendingOutboxes !== "number") {
      throw new Error("staging_reliability_cleanup_convergence_evidence_missing");
    }
    pendingOutboxes = convergence.pendingOutboxes;
  } catch {
    failed = true;
  }

  try {
    await step.do("delete only exact synthetic D1 rows", STEP_CONFIG, async () => {
      await deleteExactD1Rows(env, input, event.timestamp.getTime());
      const remaining = await countExactD1Rows(env, input, event.timestamp.getTime());
      if (remaining !== 0) throw new Error("staging_reliability_d1_cleanup_failed");
      return { remainingD1Rows: remaining, exactRowCleanupOnly: true as const };
    });
  } catch {
    failed = true;
  }

  await step.sleep("allow acknowledged synthetic queue deliveries to settle", CLEANUP_QUIET_PERIOD);

  let remainingD1Rows = -1;
  try {
    const finalCleanup = await step.do(
      "verify final exact synthetic cleanup",
      STEP_CONFIG,
      async () => {
        await deleteExactD1Rows(env, input, event.timestamp.getTime());
        const remaining = await countExactD1Rows(env, input, event.timestamp.getTime());
        if (remaining !== 0) throw new Error("staging_reliability_final_cleanup_failed");
        return { remainingD1Rows: remaining, exactRowCleanupOnly: true as const };
      }
    );
    remainingD1Rows = finalCleanup.remainingD1Rows;
  } catch {
    failed = true;
  }

  if (failed || pendingOutboxes !== 0 || remainingD1Rows !== 0) {
    throw new Error("staging_reliability_cleanup_failed");
  }
  return {
    attemptedCapabilities: STAGING_RELIABILITY_CAPABILITY_COUNT,
    deletedCapabilities: STAGING_RELIABILITY_CAPABILITY_COUNT,
    releasesAfterCleanup: 0,
    ciphertextAbsent: true,
    pendingOutboxes,
    remainingD1Rows,
    exactRowCleanupOnly: true,
    passed: true
  };
}

function assertCurrentProvenance(
  env: StagingReliabilityEnv,
  input: StagingReliabilityInput,
  instanceId: string
): void {
  validateStagingReliabilityPreflight(input, instanceId, env);
}

async function deriveIdentity(
  env: StagingReliabilityEnv,
  input: StagingReliabilityInput,
  caseName: "claim_replay" | "concurrent_claim" | "uncertain_restore",
  createdAt: number
): Promise<SyntheticCapabilityIdentity> {
  return deriveSyntheticCapability(env.STAGING_RELIABILITY_HMAC_KEY, input, caseName, createdAt);
}

function operationId(
  env: StagingReliabilityEnv,
  input: StagingReliabilityInput,
  caseName: string,
  name: string
): Promise<string> {
  return deriveSyntheticOperationId(env.STAGING_RELIABILITY_HMAC_KEY, input, caseName, name);
}

function syntheticNonce(
  env: StagingReliabilityEnv,
  input: StagingReliabilityInput,
  caseName: string,
  name: string
): Promise<string> {
  return deriveSyntheticNonce(env.STAGING_RELIABILITY_HMAC_KEY, input, caseName, name);
}

async function createCapability(
  env: StagingReliabilityEnv,
  input: StagingReliabilityInput,
  identity: SyntheticCapabilityIdentity,
  caseName: string
): Promise<void> {
  const now = Date.now();
  const result = await invokeCapability(env, identity, "/internal/capability/create", {
    operationId: await operationId(env, input, caseName, "create"),
    capabilityId: identity.capabilityId,
    locator: identity.locator,
    createdAt: identity.createdAt,
    policy: identity.policy,
    policyHash: identity.policyHash,
    publicBearerSecretHash: identity.publicBearerSecretHash,
    ownerBearerSecretHash: identity.ownerBearerSecretHash,
    ciphertextEnvelope: identity.ciphertextEnvelope,
    accessCodeVerifier: null,
    now
  });
  if (!createResultSchema.safeParse(result).success) {
    throw new Error("staging_reliability_create_failed");
  }
}

function claim(
  env: StagingReliabilityEnv,
  identity: SyntheticCapabilityIdentity,
  operationIdValue: string,
  nonce: string
): Promise<unknown> {
  return invokeCapability(env, identity, "/internal/capability/claim", {
    publicBearerSecret: identity.publicBearerSecret,
    operationId: operationIdValue,
    nonce,
    now: Date.now()
  });
}

async function authorizeOwner(
  env: StagingReliabilityEnv,
  identity: SyntheticCapabilityIdentity
): Promise<z.infer<typeof authorizeResultSchema>> {
  const result = await invokeCapability(env, identity, "/internal/capability/authorize", {
    authority: "owner",
    bearerSecret: identity.ownerBearerSecret,
    now: Date.now()
  });
  const parsed = authorizeResultSchema.safeParse(result);
  if (!parsed.success || parsed.data.authority !== "owner") {
    throw new Error("staging_reliability_owner_authorization_failed");
  }
  return parsed.data;
}

async function failClosed(
  env: StagingReliabilityEnv,
  identity: SyntheticCapabilityIdentity,
  operationIdValue: string
): Promise<z.infer<typeof failClosedResultSchema>> {
  const result = await invokeCapability(
    env,
    identity,
    "/internal/capability/fail-closed-uncertain-restore",
    {
      operationId: operationIdValue,
      capabilityId: identity.capabilityId,
      locator: identity.locator,
      decision: "delete_uncertain_restored_state",
      now: Date.now()
    }
  );
  const parsed = failClosedResultSchema.safeParse(result);
  if (!parsed.success) throw new Error("staging_reliability_fail_closed_command_failed");
  return parsed.data;
}

async function currentProjection(
  env: StagingReliabilityEnv,
  identity: SyntheticCapabilityIdentity
): Promise<CapabilityProjectionMessage> {
  return (await currentProjectionWithPending(env, identity)).message;
}

async function currentProjectionWithPending(
  env: StagingReliabilityEnv,
  identity: SyntheticCapabilityIdentity
): Promise<{ readonly message: CapabilityProjectionMessage; readonly pendingOutboxCount: number }> {
  const result = await invokeCapability(env, identity, "/internal/capability/reconcile", {
    now: Date.now(),
    terminalEvidence: null
  });
  const parsed = reconciliationResultSchema.safeParse(result);
  if (!parsed.success) throw new Error("staging_reliability_reconciliation_failed");
  const message = parseCapabilityProjectionMessage(parsed.data.message);
  if (message === null || message.deliveryEventId !== null) {
    throw new Error("staging_reliability_reconciliation_message_failed");
  }
  return { message, pendingOutboxCount: parsed.data.pendingOutboxCount };
}

function asQueueDelivery(message: CapabilityProjectionMessage): CapabilityProjectionMessage {
  return { ...message, deliveryEventId: message.event.eventId };
}

async function invokeCapability(
  env: StagingReliabilityEnv,
  identity: SyntheticCapabilityIdentity,
  path: string,
  body: unknown
): Promise<unknown> {
  const response = await env.CAPABILITY_STATE.getByName(identity.locator).fetch(
    new Request(`https://capability.invalid${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    })
  );
  try {
    return await response.json();
  } catch {
    throw new Error("staging_reliability_malformed_capability_response");
  }
}

function assertUnavailable(result: unknown): void {
  const parsed = claimFailureSchema.safeParse(result);
  if (!parsed.success || parsed.data.code !== "unavailable") {
    throw new Error("staging_reliability_expected_unavailable");
  }
}

async function readProjectionSnapshot(
  database: D1Database,
  identity: SyntheticCapabilityIdentity,
  terminalEventId: string | null
): Promise<ProjectionSnapshot> {
  const [catalogueValue, tombstoneValue, eventCountValue, terminalEventCountValue, candidateValue] =
    await Promise.all([
      database
        .prepare(
          `SELECT state, version, consumed_at, deleted_at FROM capabilities
          WHERE id = ? AND routing_locator = ?`
        )
        .bind(identity.capabilityId, identity.locator)
        .first(),
      database
        .prepare(
          `SELECT terminal_state, projection_version, terminal_event_id, last_verified_at
          FROM capability_terminal_tombstones
          WHERE capability_id = ? AND routing_locator = ?`
        )
        .bind(identity.capabilityId, identity.locator)
        .first(),
      database
        .prepare(
          "SELECT count(*) AS count FROM capability_projection_events WHERE capability_id = ?"
        )
        .bind(identity.capabilityId)
        .first(),
      terminalEventId === null
        ? Promise.resolve({ count: 0 })
        : database
            .prepare(
              `SELECT count(*) AS count FROM capability_projection_events
              WHERE capability_id = ? AND event_id = ?`
            )
            .bind(identity.capabilityId, terminalEventId)
            .first(),
      database
        .prepare(
          `SELECT last_attempt_at FROM capability_reconciliation_candidates
          WHERE capability_id = ? AND routing_locator = ?`
        )
        .bind(identity.capabilityId, identity.locator)
        .first()
    ]);
  const catalogue = parseNullable(catalogueRowSchema, catalogueValue);
  const tombstone = parseNullable(tombstoneRowSchema, tombstoneValue);
  const eventCount = countRowSchema.safeParse(eventCountValue);
  const terminalEventCount = countRowSchema.safeParse(terminalEventCountValue);
  const candidate = parseNullable(candidateRowSchema, candidateValue);
  if (!eventCount.success || !terminalEventCount.success) {
    throw new Error("staging_reliability_malformed_d1_count");
  }
  return {
    catalogue,
    tombstone,
    eventCount: eventCount.data.count,
    terminalEventCount: terminalEventCount.data.count,
    candidateLastAttemptAt: candidate?.last_attempt_at ?? null
  };
}

function parseNullable<T>(schema: z.ZodType<T>, value: unknown): T | null {
  if (value === null) return null;
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new Error("staging_reliability_malformed_d1_row");
  return parsed.data;
}

async function pollProjection(
  step: WorkflowStep,
  name: string,
  check: () => Promise<ProjectionPollResult>
): Promise<ProjectionPollResult> {
  for (let attempt = 1; attempt <= POLL_ATTEMPTS; attempt += 1) {
    const result = await step.do<ProjectionPollResult>(
      `${name} check ${attempt}`,
      STEP_CONFIG,
      check
    );
    if (result.ready) return result;
    if (attempt < POLL_ATTEMPTS) {
      await step.sleep(`${name} wait ${attempt}`, POLL_DELAY);
    }
  }
  throw new Error("staging_reliability_projection_timeout");
}

async function deleteExactD1Rows(
  env: StagingReliabilityEnv,
  input: StagingReliabilityInput,
  createdAt: number
): Promise<void> {
  for (const caseName of ["claim_replay", "concurrent_claim", "uncertain_restore"] as const) {
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    await env.DB.batch([
      env.DB.prepare("DELETE FROM capability_counters WHERE capability_id = ?").bind(
        identity.capabilityId
      ),
      env.DB.prepare("DELETE FROM capability_projection_events WHERE capability_id = ?").bind(
        identity.capabilityId
      ),
      env.DB.prepare(
        "DELETE FROM capability_reconciliation_candidates WHERE capability_id = ?"
      ).bind(identity.capabilityId),
      env.DB.prepare("DELETE FROM capability_terminal_tombstones WHERE capability_id = ?").bind(
        identity.capabilityId
      ),
      env.DB.prepare("DELETE FROM capabilities WHERE id = ? AND routing_locator = ?").bind(
        identity.capabilityId,
        identity.locator
      )
    ]);
  }
}

async function countExactD1Rows(
  env: StagingReliabilityEnv,
  input: StagingReliabilityInput,
  createdAt: number
): Promise<number> {
  let total = 0;
  for (const caseName of ["claim_replay", "concurrent_claim", "uncertain_restore"] as const) {
    const identity = await deriveIdentity(env, input, caseName, createdAt);
    const result = await env.DB.prepare(
      `SELECT
          (SELECT count(*) FROM capability_counters WHERE capability_id = ?) +
          (SELECT count(*) FROM capability_projection_events WHERE capability_id = ?) +
          (SELECT count(*) FROM capability_reconciliation_candidates WHERE capability_id = ?) +
          (SELECT count(*) FROM capability_terminal_tombstones WHERE capability_id = ?) +
          (SELECT count(*) FROM capabilities WHERE id = ? AND routing_locator = ?) AS count`
    )
      .bind(
        identity.capabilityId,
        identity.capabilityId,
        identity.capabilityId,
        identity.capabilityId,
        identity.capabilityId,
        identity.locator
      )
      .first();
    const parsed = countRowSchema.safeParse(result);
    if (!parsed.success) throw new Error("staging_reliability_malformed_cleanup_count");
    total += parsed.data.count;
  }
  return total;
}

function sameJsonValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sanitizedFailureCode(error: unknown): string {
  if (error instanceof Error && /^staging_reliability_[a-z0-9_]+$/u.test(error.message)) {
    return error.message;
  }
  return "staging_reliability_unexpected_failure";
}
