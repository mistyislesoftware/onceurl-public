import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { z } from "zod";
import { assert, DIGEST, digest } from "../publication/contract.mjs";

export const runnerDescriptorSchema = z.strictObject({
  schemaVersion: z.literal(1),
  contract: z.literal("onceurl.staging.provider.v2"),
  available: z.boolean(),
  moduleDigest: DIGEST.nullable()
});
export function requireReviewedRunner(tree) {
  const descriptor = runnerDescriptorSchema.parse(
    JSON.parse(tree.get("publication/staging-runner.json")?.bytes.toString("utf8") ?? "null")
  );
  const module = tree.get("scripts/delivery/staging-provider-v2.mjs");
  assert(
    descriptor.available &&
      descriptor.moduleDigest &&
      module?.mode === "100644" &&
      digest(module.bytes) === descriptor.moduleDigest,
    "Reviewed provider v2 runner unavailable"
  );
  return descriptor;
}

// The reliability tranche supplies the separately reviewed implementation. No fallback
// to the old single-SHA runner or to canonical staging is permitted.
export function providerAdapter({
  root,
  config,
  apiToken,
  tree,
  now = () => Math.floor(Date.now() / 1000)
}) {
  let runner;
  async function load() {
    const descriptor = requireReviewedRunner(tree);
    const path = resolve(root, "scripts/delivery/staging-provider-v2.mjs");
    assert(
      digest(readFileSync(path)) === descriptor.moduleDigest,
      "Provider implementation changed after verification"
    );
    runner = await import(pathToFileURL(path).href);
    assert(
      runner.contract === "onceurl.staging.provider.v2" &&
        ["preflight", "build", "release", "campaign", "readRelease", "readEvidence"].every(
          (name) => typeof runner[name] === "function"
        ),
      "Provider implementation lacks reviewed governance contract"
    );
    return runner;
  }
  const context = () => ({ root, config, apiToken });
  function boundary(assertion) {
    assert(
      assertion && now() >= assertion.issuedAt && now() < assertion.expiresAt,
      "Provider authorization expired before mutation"
    );
  }
  return {
    async preflight(identity) {
      await load();
      return runner.preflight({ ...context(), identity });
    },
    build: (identity) => runner.build({ ...context(), identity }),
    release(identity, _config, releaseAssertionDigest, assertion) {
      boundary(assertion);
      return runner.release({
        ...context(),
        identity,
        releaseAssertionDigest,
        assertion,
        beforeMutation: () => boundary(assertion)
      });
    },
    campaign(
      identity,
      _config,
      deployment,
      releaseAssertionDigest,
      campaignAssertionDigest,
      assertion
    ) {
      boundary(assertion);
      return runner.campaign({
        ...context(),
        identity,
        deployment,
        releaseAssertionDigest,
        campaignAssertionDigest,
        assertion,
        beforeMutation: () => boundary(assertion)
      });
    },
    async readRelease(identity) {
      await load();
      return runner.readRelease({ ...context(), identity });
    },
    async readEvidence(identity, deployment) {
      await load();
      return runner.readEvidence({ ...context(), identity, deployment });
    }
  };
}
