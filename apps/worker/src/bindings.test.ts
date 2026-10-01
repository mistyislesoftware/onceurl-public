import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createTestWorkerEnv } from "./testing/env";

const rootDirectory = fileURLToPath(new URL("../../..", import.meta.url).href);
const configPath = join(rootDirectory, "apps", "worker", "wrangler.jsonc");
const generatedTypesPath = join(rootDirectory, "apps", "worker", "worker-configuration.d.ts");

describe("Cloudflare binding configuration", () => {
  it("parses the canonical Wrangler JSONC configuration", () => {
    expect((): unknown => JSON.parse(readFileSync(configPath, "utf8"))).not.toThrow();
  });

  it("declares the required SQLite-backed Durable Object migration", () => {
    const config = JSON.parse(readFileSync(configPath, "utf8")) as {
      migrations: Array<{ new_sqlite_classes?: string[] }>;
    };

    expect(config.migrations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ new_sqlite_classes: ["CapabilityDurableObject"] }),
        expect.objectContaining({ new_sqlite_classes: ["AbuseControlDurableObject"] })
      ])
    );
  });

  it("keeps the native preparation limiter explicitly coarse and non-authoritative", () => {
    const config = JSON.parse(readFileSync(configPath, "utf8")) as {
      ratelimits: Array<{
        name: string;
        namespace_id: string;
        simple: { limit: number; period: number };
      }>;
      env: {
        staging: {
          ratelimits: Array<{
            name: string;
            namespace_id: string;
            simple: { limit: number; period: number };
          }>;
        };
      };
    };

    for (const limiter of [config.ratelimits[0], config.env.staging.ratelimits[0]]) {
      expect(limiter).toMatchObject({
        name: "PREPARATION_FLOOD_LIMITER",
        simple: { limit: 30, period: 60 }
      });
      expect(limiter?.namespace_id).toMatch(/^\d+$/u);
    }
  });

  it("does not commit remote account IDs or plaintext managed secrets in Wrangler config", () => {
    const configText = readFileSync(configPath, "utf8");

    expect(configText).not.toContain("account_id");
    expect(configText).not.toContain("TURNSTILE_SECRET_KEY");
    expect(configText).not.toContain("SECRET_PREPARATION_HMAC_KEY");
    expect(configText).not.toContain("SECRET_PREPARATION_HMAC_PREVIOUS_KEY");
    expect(configText).not.toContain("ABUSE_IP_HMAC_KEY");
    expect(configText).not.toContain("ABUSE_IP_HMAC_PREVIOUS_KEY");
  });

  it("exports the CapabilityDurableObject class", () => {
    const indexSource = readFileSync(
      join(rootDirectory, "apps", "worker", "src", "index.ts"),
      "utf8"
    );
    const classSource = readFileSync(
      join(rootDirectory, "apps", "worker", "src", "capability-durable-object.ts"),
      "utf8"
    );

    expect(indexSource).toContain("export { CapabilityDurableObject }");
    expect(indexSource).toContain("export { AbuseControlDurableObject }");
    expect(classSource).toContain("class CapabilityDurableObject");
  });

  it("generated Worker types isolate preview resources and retain staging bindings", () => {
    const generatedTypes = readFileSync(generatedTypesPath, "utf8");
    const previewTypes = generatedTypes.slice(
      generatedTypes.indexOf("interface PreviewEnv"),
      generatedTypes.indexOf("interface StagingEnv")
    );
    const stagingTypes = generatedTypes.slice(
      generatedTypes.indexOf("interface StagingEnv"),
      generatedTypes.indexOf("interface Env extends")
    );

    expect(previewTypes).toContain("ASSETS: Fetcher");
    for (const binding of [
      "DB",
      "FILES",
      "CAPABILITY_STATE",
      "ABUSE_CONTROL",
      "PREPARATION_FLOOD_LIMITER",
      "ASYNC_JOBS"
    ]) {
      expect(previewTypes).not.toContain(`${binding}:`);
      expect(stagingTypes).toContain(`${binding}:`);
    }
  });

  it("central test environment helper supplies the complete environment contract", () => {
    const env = createTestWorkerEnv();

    expect(env.ASSETS).toBeDefined();
    expect(env.DB).toBeDefined();
    expect(env.FILES).toBeDefined();
    expect(env.CAPABILITY_STATE).toBeDefined();
    expect(env.ABUSE_CONTROL).toBeDefined();
    expect(env.PREPARATION_FLOOD_LIMITER).toBeDefined();
    expect(env.ASYNC_JOBS).toBeDefined();
    expect(env.TURNSTILE_SECRET_KEY).toBe("1x0000000000000000000000000000000AA");
    expect(env.TURNSTILE_SITE_KEY).toBe("1x00000000000000000000AA");
    expect(env.ABUSE_IP_HMAC_KEY).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(env.SECRET_PREPARATION_HMAC_KEY).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(env.SECRET_PREPARATION_HMAC_PREVIOUS_KEY).toBeUndefined();
    expect(() => env.ASSETS.fetch("https://example.test")).toThrow(/Unexpected test use/);
  });
});
