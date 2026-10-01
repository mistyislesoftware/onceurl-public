import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const rootDirectory = fileURLToPath(new URL("../../..", import.meta.url).href);

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(rootDirectory, path), "utf8")) as Record<string, unknown>;
}

function runtimeSourceText(directory: string): string {
  return readdirSync(directory)
    .flatMap((entry) => {
      const path = join(directory, entry);
      if (statSync(path).isDirectory()) {
        return runtimeSourceText(path);
      }
      return entry.endsWith(".ts") && !entry.includes(".test.") ? readFileSync(path, "utf8") : [];
    })
    .join("\n");
}

describe("deployable dependency and configuration boundaries", () => {
  it("keeps marketing outside the functional workspace dependency graph", () => {
    const marketing = readJson("apps/marketing/package.json");
    const worker = readJson("apps/worker/package.json");
    const web = readJson("apps/web/package.json");

    expect(marketing.dependencies).toBeUndefined();
    expect(JSON.stringify(worker)).not.toContain("@onceurl/marketing");
    expect(JSON.stringify(web)).not.toContain("@onceurl/marketing");
    expect(runtimeSourceText(join(rootDirectory, "apps", "marketing", "src"))).not.toContain(
      "@onceurl/"
    );
    expect(runtimeSourceText(join(rootDirectory, "apps", "worker", "src"))).not.toContain(
      "@onceurl/marketing"
    );
  });

  it("declares distinct artifacts, Worker names, configs and dry-run outputs", () => {
    const functionalConfig = readJson("apps/worker/wrangler.jsonc");
    const marketingConfig = readJson("apps/marketing/wrangler.jsonc");
    const rootPackage = readJson("package.json");
    const functionalAssets = functionalConfig.assets as { directory: string };
    const marketingAssets = marketingConfig.assets as { directory: string };
    const scripts = rootPackage.scripts as Record<string, string>;

    expect(functionalConfig.name).toBe("onceurl-worker");
    expect(marketingConfig.name).toBe("onceurl-marketing");
    expect(functionalAssets.directory).toBe("../web/dist");
    expect(marketingAssets.directory).toBe("dist");
    expect(functionalConfig).toHaveProperty("assets.run_worker_first", true);
    expect(marketingConfig).toHaveProperty("assets.run_worker_first", true);
    expect(marketingConfig).not.toHaveProperty("d1_databases");
    expect(marketingConfig).not.toHaveProperty("r2_buckets");
    expect(marketingConfig).not.toHaveProperty("durable_objects");
    expect(marketingConfig).not.toHaveProperty("queues");
    expect(functionalConfig).toHaveProperty("observability.logs.invocation_logs", false);
    expect(marketingConfig).toHaveProperty("observability.enabled", false);
    expect(scripts["build:functional"]).not.toContain("@onceurl/marketing");
    expect(scripts["build:marketing"]).not.toContain("@onceurl/worker");
    expect(scripts["wrangler:validate:functional"]).toContain("wrangler-functional-dry-run");
    expect(scripts["wrangler:validate:marketing"]).toContain("wrangler-marketing-dry-run");
    expect(scripts["wrangler:validate:preview"]).toContain("wrangler-functional-preview-dry-run");
    expect(scripts["wrangler:validate:preview"]).toContain("wrangler-marketing-preview-dry-run");
  });

  it("uses distinct local hosts and environment-owned later origins without a production domain", () => {
    const topology = readJson("config/deployable-origins.json") as {
      environments: Record<
        string,
        {
          configured: boolean;
          source: string;
          marketingOrigin?: string;
          functionalOrigin?: string;
        }
      >;
      requiredVariables: string[];
    };
    const local = topology.environments.local;

    expect(topology.requiredVariables).toEqual([
      "DEPLOYMENT_ENVIRONMENT",
      "MARKETING_ORIGIN",
      "FUNCTIONAL_ORIGIN"
    ]);
    expect(new URL(local?.marketingOrigin ?? "").hostname).not.toBe(
      new URL(local?.functionalOrigin ?? "").hostname
    );

    for (const environment of ["preview", "staging", "production"]) {
      expect(topology.environments[environment]).toEqual({
        configured: false,
        source: "deployment-environment"
      });
    }

    const configs = [
      readJson("apps/worker/wrangler.jsonc"),
      readJson("apps/marketing/wrangler.jsonc")
    ];
    for (const config of configs) {
      expect(config).not.toHaveProperty("routes");
      expect(config).not.toHaveProperty("env.production");
      expect(JSON.stringify(config)).not.toMatch(/onceurl\.(?:com|co|io|net|org)/iu);
      expect(config).toHaveProperty(
        "env.preview.vars.MARKETING_ORIGIN",
        "https://marketing.preview.invalid"
      );
      expect(config).toHaveProperty(
        "env.preview.vars.FUNCTIONAL_ORIGIN",
        "https://functional.preview.invalid"
      );
      expect(config).toHaveProperty(
        "env.staging.vars.MARKETING_ORIGIN",
        "https://marketing.staging.invalid"
      );
      expect(config).toHaveProperty(
        "env.staging.vars.FUNCTIONAL_ORIGIN",
        "https://functional.staging.invalid"
      );
    }
  });
});
