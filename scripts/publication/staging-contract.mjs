import { verify, createPublicKey } from "node:crypto";
import { z } from "zod";
import { assert, SHA, DIGEST, encode, digest, keyFingerprint } from "./contract.mjs";

export const RUN = z.string().regex(/^[1-9][0-9]{0,19}$/u);
export const ATTEMPT = z.number().int().positive().max(1000);
export const UUID = z.string().uuid();
export const campaignIdentitySchema = z.strictObject({
  canonicalSourceSha: SHA,
  publicSourceSha: SHA,
  exportDigest: DIGEST,
  publicationSequence: z.number().int().min(2).safe(),
  acceptedRecordDigest: DIGEST,
  publicCiWorkflowRunId: RUN,
  publicCiWorkflowRunAttempt: ATTEMPT,
  publicCiJobId: RUN,
  workflowRunId: RUN,
  workflowRunAttempt: ATTEMPT,
  campaignId: z.string().regex(/^ou-staging-[1-9][0-9]*-[1-9][0-9]*-[a-f0-9]{12}$/u),
  configurationDigest: DIGEST
});
export const workerVersionsSchema = z.strictObject({
  functionalVersionId: UUID,
  functionalVersionTag: z.string().regex(/^staging-[a-f0-9]{12}$/u),
  marketingVersionId: UUID,
  marketingVersionTag: z.string().regex(/^staging-[a-f0-9]{12}$/u),
  providerWorkflowVersionId: UUID,
  smokeEvidenceDigest: DIGEST
});
export const freshnessAssertionSchema = z.strictObject({
  schemaVersion: z.literal(2),
  purpose: z.enum(["onceurl.staging.release.v1", "onceurl.staging.campaign.v1"]),
  audience: z.literal("onceurl-public:staging"),
  canonicalMainCurrent: z.literal(true),
  ...campaignIdentitySchema.shape,
  nonce: DIGEST,
  issuedAt: z.number().int().nonnegative().safe(),
  expiresAt: z.number().int().positive().safe(),
  releaseAssertionDigest: DIGEST.nullable(),
  deployment: workerVersionsSchema.nullable()
});
export const freshnessEnvelopeSchema = z.strictObject({
  assertion: freshnessAssertionSchema,
  keyFingerprint: DIGEST,
  signature: z.string().regex(/^[A-Za-z0-9+/]{86}==$/u)
});
export function campaignIdentity(value) {
  const identity = campaignIdentitySchema.parse(value);
  assert(
    identity.campaignId ===
      `ou-staging-${identity.workflowRunId}-${identity.workflowRunAttempt}-${identity.publicSourceSha.slice(0, 12)}`,
    "Campaign identity mismatch"
  );
  return identity;
}
export function validateAssertion(value, expected, now) {
  const assertion = freshnessAssertionSchema.parse(value);
  campaignIdentity(
    campaignIdentitySchema.parse(
      Object.fromEntries(Object.keys(campaignIdentitySchema.shape).map((k) => [k, assertion[k]]))
    )
  );
  assert(
    Number.isSafeInteger(now) &&
      assertion.issuedAt <= now &&
      now < assertion.expiresAt &&
      assertion.expiresAt > assertion.issuedAt &&
      assertion.expiresAt - assertion.issuedAt <= 60,
    "Expired/future freshness authorization"
  );
  for (const field of [
    ...Object.keys(campaignIdentitySchema.shape),
    "nonce",
    "purpose",
    "releaseAssertionDigest",
    "deployment"
  ])
    assert(
      expected[field] !== undefined && encode(assertion[field]).equals(encode(expected[field])),
      `Freshness ${field} mismatch`
    );
  if (assertion.purpose === "onceurl.staging.release.v1")
    assert(
      assertion.deployment === null && assertion.releaseAssertionDigest === null,
      "Release cannot authorize a provider campaign"
    );
  else
    assert(
      assertion.deployment !== null && assertion.releaseAssertionDigest !== null,
      "Campaign must bind the completed release"
    );
  return assertion;
}
export function verifyFreshness(bytes, publicKey, fingerprint, expected, now) {
  const envelope = freshnessEnvelopeSchema.parse(JSON.parse(bytes.toString("utf8")));
  assert(encode(envelope).equals(bytes), "Noncanonical freshness envelope");
  assert(
    keyFingerprint(publicKey) === fingerprint && envelope.keyFingerprint === fingerprint,
    "Wrong freshness signer"
  );
  const key = createPublicKey(publicKey);
  const signature = Buffer.from(envelope.signature, "base64");
  assert(
    signature.toString("base64") === envelope.signature &&
      verify(null, encode(envelope.assertion), key, signature),
    "Invalid freshness signature"
  );
  return validateAssertion(envelope.assertion, expected, now);
}
export const releaseEvidenceSchema = z.strictObject({
  schemaVersion: z.literal(2),
  ...campaignIdentitySchema.shape,
  ...workerVersionsSchema.shape,
  releaseAssertionDigest: DIGEST,
  campaignAssertionDigest: DIGEST,
  campaignStartedAt: z.number().int().nonnegative().safe(),
  smokePassed: z.literal(true),
  outcome: z.literal("passed"),
  cases: z.tuple([
    z.strictObject({
      caseName: z.literal("claim_replay_and_projection"),
      releases: z.literal(1),
      attempts: z.literal(4),
      queueD1Converged: z.literal(true),
      replayUnavailable: z.literal(true),
      staleD1AuthorizedRelease: z.literal(false),
      duplicateEventRows: z.literal(1)
    }),
    z.strictObject({
      caseName: z.literal("bounded_concurrent_claim"),
      releases: z.literal(1),
      attempts: z.literal(8),
      queueD1Converged: z.literal(true)
    }),
    z.strictObject({
      caseName: z.literal("actual_uncertain_restore_command"),
      releases: z.literal(0),
      attempts: z.literal(2),
      queueD1Converged: z.literal(true),
      ciphertextAbsent: z.literal(true)
    })
  ]),
  cleanup: z.strictObject({
    capabilityCount: z.literal(3),
    releases: z.literal(0),
    ciphertextAbsent: z.literal(true),
    pendingOutboxes: z.literal(0),
    remainingD1Rows: z.literal(0),
    exactRowsOnly: z.literal(true),
    passed: z.literal(true)
  }),
  unsupportedProviderBehaviors: z.tuple([
    z.literal("forced_durable_object_eviction_or_reinstantiation"),
    z.literal("durable_object_pitr_or_time_travel"),
    z.literal("d1_provider_time_travel")
  ])
});
export function verifyEvidence(value, identity, deployment, releaseDigest, campaignDigest) {
  const evidence = releaseEvidenceSchema.parse(value);
  for (const [field, expected] of Object.entries({
    ...campaignIdentity(identity),
    ...workerVersionsSchema.parse(deployment),
    releaseAssertionDigest: releaseDigest,
    campaignAssertionDigest: campaignDigest
  }))
    assert(evidence[field] === expected, `Provider evidence ${field} mismatch`);
  assert(
    evidence.functionalVersionTag === `staging-${identity.publicSourceSha.slice(0, 12)}` &&
      evidence.marketingVersionTag === evidence.functionalVersionTag,
    "Wrong public deployment tags"
  );
  return evidence;
}
export const assertionDigest = (envelope) =>
  digest(encode(freshnessEnvelopeSchema.parse(envelope)));
