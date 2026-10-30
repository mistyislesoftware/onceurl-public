import { describe, expect, it } from "vitest";
import {
  STAGING_IDENTITY_BINDINGS,
  stagingReliabilityInputSchema,
  validateStagingReliabilityPreflight,
  deriveSyntheticCapability,
  deriveSyntheticOperationId,
  deriveSyntheticNonce,
  type StagingReliabilityInput,
  type StagingReliabilityProvenanceEnv
} from "./staging-reliability-core";

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
  campaignIssuedAt: 1000,
  campaignExpiresAt: 1060
};
const key = btoa(String.fromCharCode(...new Uint8Array(32))).replaceAll("=", "");
function environment(): StagingReliabilityProvenanceEnv {
  return {
    DEPLOYMENT_ENVIRONMENT: "staging",
    FUNCTIONAL_ORIGIN: "https://functional.staging.onceurl.mistyislesoftware.co.uk",
    MARKETING_ORIGIN: "https://marketing.staging.onceurl.mistyislesoftware.co.uk",
    STAGING_RELIABILITY_HMAC_KEY: key,
    CF_VERSION_METADATA: {
      id: input.functionalVersionId,
      tag: input.functionalVersionTag,
      timestamp: "2026-10-03T10:00:00.000Z"
    },
    ...Object.fromEntries(
      Object.entries(STAGING_IDENTITY_BINDINGS).map(([field, binding]) => [
        binding,
        String(input[field as keyof StagingReliabilityInput])
      ])
    )
  };
}
describe("staging runtime dual identity and synthetic derivation", () => {
  it("accepts the exact staging deployment and separates Workflow from Worker versions", () => {
    const result = validateStagingReliabilityPreflight(input, input.campaignId, environment());
    expect(result.evidence.canonicalSourceSha).toBe(input.canonicalSourceSha);
    expect(result.evidence.publicSourceSha).toBe(input.publicSourceSha);
    expect(result.evidence.providerWorkflowVersionId).not.toBe(result.evidence.functionalVersionId);
    expect(result.evidence).not.toHaveProperty("campaignIssuedAt");
  });
  it.each(Object.entries(STAGING_IDENTITY_BINDINGS))(
    "rejects changed deployed %s",
    (_field, binding) => {
      const env = { ...environment(), [binding]: "mismatch" };
      expect(() => validateStagingReliabilityPreflight(input, input.campaignId, env)).toThrow(
        /identity_mismatch/u
      );
    }
  );
  it.each(["local", "preview", "production"])("rejects %s runtime", (DEPLOYMENT_ENVIRONMENT) => {
    expect(() =>
      validateStagingReliabilityPreflight(input, input.campaignId, {
        ...environment(),
        DEPLOYMENT_ENVIRONMENT
      })
    ).toThrow(/non_staging/u);
  });
  it.each([
    "instance",
    "derivation",
    "worker ID",
    "worker tag",
    "marketing tag",
    "long grant",
    "unknown field"
  ])("rejects %s", (kind) => {
    const value = { ...input },
      env = environment();
    let instance = input.campaignId;
    if (kind === "instance") instance += "-other";
    if (kind === "derivation") value.campaignId = "ou-staging-104-1-bbbbbbbbbbbb";
    if (kind === "worker ID") value.functionalVersionId = input.providerWorkflowVersionId;
    if (kind === "worker tag") value.functionalVersionTag = "staging-aaaaaaaaaaaa";
    if (kind === "marketing tag") value.marketingVersionTag = "staging-aaaaaaaaaaaa";
    if (kind === "long grant") value.campaignExpiresAt = 1061;
    if (kind === "unknown field") Object.assign(value, { bearer: "forbidden-field" });
    expect(() => validateStagingReliabilityPreflight(value, instance, env)).toThrow();
  });
  it.each([undefined, "", "A".repeat(42), "B".repeat(43)])(
    "rejects unavailable or noncanonical HMAC",
    (STAGING_RELIABILITY_HMAC_KEY) => {
      expect(() =>
        validateStagingReliabilityPreflight(input, input.campaignId, {
          ...environment(),
          STAGING_RELIABILITY_HMAC_KEY
        })
      ).toThrow(/hmac_unavailable/u);
    }
  );
  it.each([
    "https://functional.staging.invalid",
    "https://unapproved.example",
    "http://functional.staging.onceurl.mistyislesoftware.co.uk",
    "https://functional.staging.onceurl.mistyislesoftware.co.uk/"
  ])("rejects invalid origin %s", (FUNCTIONAL_ORIGIN) => {
    expect(() =>
      validateStagingReliabilityPreflight(input, input.campaignId, {
        ...environment(),
        FUNCTIONAL_ORIGIN
      })
    ).toThrow(/invalid_origin/u);
  });
  it("deterministically isolates cases, operation classes, public/canonical identity and exports", async () => {
    const first = await deriveSyntheticCapability(key, input, "claim_replay", 1000000);
    expect(await deriveSyntheticCapability(key, input, "claim_replay", 1000000)).toEqual(first);
    for (const changed of [
      { ...input, canonicalSourceSha: "9".repeat(40) },
      { ...input, publicSourceSha: "9".repeat(40) },
      { ...input, exportDigest: "9".repeat(64) }
    ])
      expect(
        (await deriveSyntheticCapability(key, changed, "claim_replay", 1000000)).locator
      ).not.toBe(first.locator);
    expect(
      (await deriveSyntheticCapability(key, input, "concurrent_claim", 1000000)).locator
    ).not.toBe(first.locator);
    expect(first.publicBearerSecret).not.toBe(first.ownerBearerSecret);
    expect(first.publicBearerSecretHash).not.toBe(first.ownerBearerSecretHash);
    expect(await deriveSyntheticOperationId(key, input, "claim_replay", "claim")).not.toBe(
      await deriveSyntheticOperationId(key, input, "claim_replay", "delete")
    );
    expect(await deriveSyntheticNonce(key, input, "claim_replay", "claim")).not.toBe(
      await deriveSyntheticNonce(key, input, "concurrent_claim", "claim")
    );
    expect(stagingReliabilityInputSchema.safeParse({ ...input, schemaVersion: 1 }).success).toBe(
      false
    );
  });
});
