import { randomBytes } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { assert, digest, encode, SHA, DIGEST } from "../publication/contract.mjs";
import {
  campaignIdentity,
  workerVersionsSchema,
  verifyFreshness,
  verifyEvidence,
  freshnessEnvelopeSchema,
  assertionDigest
} from "../publication/staging-contract.mjs";
import {
  PUBLIC,
  currentMain,
  verifyCi,
  pages,
  githubClient
} from "../publication/public-github.mjs";
import { verifyTree } from "../publication/verify.mjs";
import { git, readTree } from "../publication/git.mjs";
import { validateOriginPair, parseCloudflareAccountId } from "./config.mjs";
import { providerAdapter } from "./public-provider.mjs";

export const stagingConfigurationSchema = z.strictObject({
  accountId: z.string().regex(/^[a-f0-9]{32}$/u),
  databaseId: z.string().uuid(),
  bucketName: z.string().regex(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/u),
  functionalOrigin: z.string(),
  marketingOrigin: z.string(),
  functionalWorker: z.literal("onceurl-worker-staging"),
  marketingWorker: z.literal("onceurl-marketing-staging"),
  providerWorkflow: z.literal("onceurl-staging-reliability")
});
export function stagingConfiguration(value) {
  const config = stagingConfigurationSchema.parse(value);
  parseCloudflareAccountId(config.accountId);
  assert(
    config.databaseId !== "00000000-0000-0000-0000-000000000000" &&
      config.bucketName !== "onceurl-staging-files-unconfigured",
    "Staging resources unconfigured"
  );
  validateOriginPair(config.marketingOrigin, config.functionalOrigin);
  for (const origin of [config.functionalOrigin, config.marketingOrigin])
    assert(
      new URL(origin).hostname.endsWith(".onceurl.mistyislesoftware.co.uk"),
      "Origin outside approved namespace"
    );
  return config;
}
export function requireCredentials(token, activation) {
  assert(
    activation === "owner-authorized" &&
      typeof token === "string" &&
      token.length >= 20 &&
      !/\s/u.test(token),
    "Staging inactive or missing staging credential"
  );
}
export async function publicEligibility({ api, identity, manifest, authorityAppId }) {
  assert(
    authorityAppId === 5146876 &&
      manifest.schemaVersion === 2 &&
      manifest.canonicalSourceSha === identity.canonicalSourceSha &&
      manifest.exportDigest === identity.exportDigest &&
      manifest.publication.publicationSequence === identity.publicationSequence,
    "Publication identity mismatch"
  );
  await currentMain(api, PUBLIC, identity.publicSourceSha);
  const ci = await verifyCi(
    api,
    PUBLIC,
    1353866049,
    identity.publicSourceSha,
    ".github/workflows/ci.yml",
    "public-checks"
  );
  assert(
    String(ci.runId) === identity.publicCiWorkflowRunId &&
      ci.attempt === identity.publicCiWorkflowRunAttempt &&
      String(ci.jobId) === identity.publicCiJobId,
    "Missing/changed exact public CI"
  );
  const checks = (
    await pages(
      api,
      `/repos/${PUBLIC}/commits/${identity.publicSourceSha}/check-runs?filter=all`,
      "check_runs"
    )
  ).filter((c) => c.name === "publication/accepted");
  assert(
    checks.length === 1 &&
      checks[0].app?.id === authorityAppId &&
      checks[0].head_sha === identity.publicSourceSha &&
      checks[0].external_id === identity.acceptedRecordDigest &&
      checks[0].status === "completed" &&
      checks[0].conclusion === "success",
    "Publication not independently accepted"
  );
}

// The provider adapter has no opportunity to run before all local/remote gates.
// No failing freshness/main gate is retried; release/campaign are distinct uses.
export async function runPublicStaging({
  identity: value,
  config: configValue,
  apiToken,
  activation,
  manifest,
  api,
  freshnessPublicKey,
  freshnessFingerprint,
  publicationFingerprint,
  authorize,
  consume,
  provider,
  authorityAppId = 5146876,
  now = () => Math.floor(Date.now() / 1000)
}) {
  const identity = campaignIdentity(value),
    config = stagingConfiguration(configValue);
  requireCredentials(apiToken, activation);
  assert(
    identity.configurationDigest === digest(encode(config)) &&
      freshnessFingerprint !== publicationFingerprint,
    "Staging configuration or trust separation mismatch"
  );
  const eligibility = () => publicEligibility({ api, identity, manifest, authorityAppId });
  await eligibility();
  await provider.preflight(identity, config);
  await provider.build(identity, config);
  async function grant(purpose, releaseAssertionDigest, deployment) {
    await eligibility();
    const nonce = randomBytes(32).toString("hex");
    const expected = { ...identity, purpose, nonce, releaseAssertionDigest, deployment };
    const bytes = await authorize({ identity, purpose, nonce, releaseAssertionDigest, deployment });
    const assertion = verifyFreshness(
      bytes,
      freshnessPublicKey,
      freshnessFingerprint,
      expected,
      now()
    );
    await eligibility();
    // Final synchronous validation + exclusive consume immediately before the
    // corresponding bounded provider sequence starts.
    verifyFreshness(bytes, freshnessPublicKey, freshnessFingerprint, expected, now());
    await consume(assertion);
    return freshnessEnvelopeSchema.parse(JSON.parse(bytes.toString("utf8")));
  }
  const release = await grant("onceurl.staging.release.v1", null, null);
  assert(now() < release.assertion.expiresAt, "Release authorization expired before mutation");
  const deployment = workerVersionsSchema.parse(
    await provider.release(identity, config, assertionDigest(release), release.assertion)
  );
  // A new grant reads both mains again after coherent deployment and smoke.
  const campaign = await grant("onceurl.staging.campaign.v1", assertionDigest(release), deployment);
  assert(now() < campaign.assertion.expiresAt, "Campaign authorization expired before trigger");
  const evidence = await provider.campaign(
    identity,
    config,
    deployment,
    assertionDigest(release),
    assertionDigest(campaign),
    campaign.assertion
  );
  const verified = verifyEvidence(
    evidence,
    identity,
    deployment,
    assertionDigest(release),
    assertionDigest(campaign)
  );
  await eligibility();
  return verified; // Public success alone is never final canonical acceptance.
}

export async function requestFreshness(endpointValue, request, env, transport = fetch) {
  const endpoint = new URL(endpointValue);
  assert(
    endpoint.protocol === "https:" &&
      !endpoint.username &&
      !endpoint.password &&
      endpoint.hostname.endsWith(".onceurl.mistyislesoftware.co.uk") &&
      endpoint.pathname === "/v1/authorize" &&
      !endpoint.search &&
      !endpoint.hash,
    "Invalid freshness authority endpoint"
  );
  const oidc = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  assert(
    oidc.protocol === "https:" &&
      oidc.hostname.endsWith(".actions.githubusercontent.com") &&
      !oidc.username &&
      !oidc.password &&
      typeof env.ACTIONS_ID_TOKEN_REQUEST_TOKEN === "string" &&
      env.ACTIONS_ID_TOKEN_REQUEST_TOKEN.length > 0,
    "Missing protected workflow OIDC identity"
  );
  oidc.searchParams.set("audience", "onceurl-public:staging");
  const tokenResponse = await transport(oidc, {
    headers: { Authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` },
    redirect: "error",
    signal: globalThis.AbortSignal.timeout(30_000)
  });
  assert(tokenResponse.ok, "Workflow OIDC unavailable");
  const { value } = await tokenResponse.json();
  assert(typeof value === "string" && value.length <= 16_000, "Invalid workflow OIDC response");
  const response = await transport(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${value}`,
      "Content-Type": "application/json"
    },
    body: encode(request),
    redirect: "error",
    signal: globalThis.AbortSignal.timeout(30_000)
  });
  assert(response.ok, "Freshness authorization refused");
  const bytes = Buffer.from(await response.arrayBuffer());
  assert(bytes.length <= 16_000, "Oversized freshness response");
  return bytes;
}

export async function runCli(env = process.env) {
  assert(
    env.GITHUB_REPOSITORY === PUBLIC &&
      env.GITHUB_REF === "refs/heads/main" &&
      env.GITHUB_EVENT_NAME === "workflow_dispatch",
    "Public staging requires protected public main dispatch"
  );
  const root = process.cwd(),
    sha = SHA.parse(env.PUBLIC_SOURCE_SHA);
  assert(
    git(root, ["rev-parse", "HEAD"]).toString().trim() === sha &&
      git(root, ["status", "--porcelain", "--untracked-files=all"]).length === 0,
    "Staging checkout moved or dirty"
  );
  const tree = readTree(root, sha);
  const manifest = verifyTree(tree, {
    trustedFingerprint: DIGEST.parse(env.PUBLICATION_KEY_FINGERPRINT)
  });
  const config = stagingConfiguration({
    accountId: env.CLOUDFLARE_ACCOUNT_ID,
    databaseId: env.STAGING_DATABASE_ID,
    bucketName: env.STAGING_BUCKET_NAME,
    functionalOrigin: env.FUNCTIONAL_ORIGIN,
    marketingOrigin: env.MARKETING_ORIGIN,
    functionalWorker: "onceurl-worker-staging",
    marketingWorker: "onceurl-marketing-staging",
    providerWorkflow: "onceurl-staging-reliability"
  });
  const identity = campaignIdentity({
    canonicalSourceSha: manifest.canonicalSourceSha,
    publicSourceSha: sha,
    exportDigest: manifest.exportDigest,
    publicationSequence: manifest.publication?.publicationSequence,
    acceptedRecordDigest: env.ACCEPTED_RECORD_DIGEST,
    publicCiWorkflowRunId: env.PUBLIC_CI_RUN_ID,
    publicCiWorkflowRunAttempt: Number(env.PUBLIC_CI_RUN_ATTEMPT),
    publicCiJobId: env.PUBLIC_CI_JOB_ID,
    workflowRunId: env.GITHUB_RUN_ID,
    workflowRunAttempt: Number(env.GITHUB_RUN_ATTEMPT),
    campaignId: `ou-staging-${env.GITHUB_RUN_ID}-${env.GITHUB_RUN_ATTEMPT}-${sha.slice(0, 12)}`,
    configurationDigest: digest(encode(config))
  });
  requireCredentials(env.CLOUDFLARE_API_TOKEN, env.STAGING_ACTIVATION);
  mkdirSync(resolve(root, ".tmp/public-staging"), { recursive: true });
  const evidence = await runPublicStaging({
    identity,
    config,
    apiToken: env.CLOUDFLARE_API_TOKEN,
    activation: env.STAGING_ACTIVATION,
    manifest,
    api: githubClient(env.GITHUB_TOKEN),
    freshnessPublicKey: env.FRESHNESS_PUBLIC_KEY,
    freshnessFingerprint: DIGEST.parse(env.FRESHNESS_KEY_FINGERPRINT),
    publicationFingerprint: env.PUBLICATION_KEY_FINGERPRINT,
    authorize: (request) => requestFreshness(env.FRESHNESS_AUTHORITY_URL, request, env),
    consume: (assertion) =>
      writeFileSync(resolve(root, `.tmp/public-staging/used-${assertion.nonce}`), "consumed\n", {
        flag: "wx",
        mode: 0o600
      }),
    provider: providerAdapter({ root, tree, config, apiToken: env.CLOUDFLARE_API_TOKEN })
  });
  writeFileSync(resolve(root, ".tmp/public-staging/evidence.json"), encode(evidence), {
    flag: "wx",
    mode: 0o600
  });
  return {
    outcome: "passed",
    evidenceDigest: digest(encode(evidence)),
    finalCanonicalAcceptanceRequired: true
  };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(`${JSON.stringify(await runCli())}\n`);
  } catch {
    process.stderr.write(
      "Public staging failed closed; preserve partial-release evidence and use reviewed recovery. No credential/provider details emitted.\n"
    );
    process.exitCode = 1;
  }
}
