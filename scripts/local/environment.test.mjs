import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  assertExactResetTarget,
  developmentEnvironment,
  localStateDirectory,
  resolveDevelopmentRuntime,
  rootDirectory
} from "./config.mjs";
import { resetLocalState } from "./reset.mjs";
import { validateNodeVersion } from "./toolchain.mjs";

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

describe("repository-owned development environment", () => {
  it("keeps the toolchain, Dev Container, ports, and package scripts in sync", async () => {
    const packageJson = await readJson(join(rootDirectory, "package.json"));
    const devContainer = await readJson(join(rootDirectory, ".devcontainer", "devcontainer.json"));
    const workerPackage = await readJson(join(rootDirectory, "apps", "worker", "package.json"));
    const marketingPackage = await readJson(
      join(rootDirectory, "apps", "marketing", "package.json")
    );

    expect((await readFile(join(rootDirectory, ".nvmrc"), "utf8")).trim()).toBe("24");
    expect(packageJson.packageManager).toBe("pnpm@11.13.0");
    expect(packageJson.engines.node).toBe(">=24.11.0 <25");
    expect(devContainer.image).toMatch(
      /^mcr\.microsoft\.com\/devcontainers\/typescript-node:5\.0\.1-24-bookworm@sha256:[a-f0-9]{64}$/u
    );
    expect(devContainer.postCreateCommand).toBe("./scripts/local/bootstrap.sh");
    expect(devContainer.forwardPorts).toEqual(developmentEnvironment.forwardedPorts);
    expect(Object.keys(devContainer.portsAttributes).map(Number).sort()).toEqual([8789, 8790]);
    expect(
      Object.values(devContainer.portsAttributes).map((attributes) => attributes.protocol)
    ).toEqual(["https", "https"]);
    expect(developmentEnvironment.forwardedProtocol).toBe("https");
    expect(workerPackage.scripts.dev).toContain("--ip 127.0.0.1 --port 8789");
    expect(workerPackage.scripts.dev).toContain("--persist-to ../../.wrangler/state");
    expect(marketingPackage.scripts.dev).toContain("--ip 127.0.0.2 --port 8790");
    expect(localStateDirectory).toBe(join(rootDirectory, ".wrangler", "state"));
  });

  it("derives distinct browser origins from Codespaces-owned variables", () => {
    const runtime = resolveDevelopmentRuntime({
      CODESPACES: "true",
      CODESPACE_NAME: "synthetic-onceurl-space",
      GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN: "app.github.dev",
      GITHUB_TOKEN: "synthetic-test-token"
    });

    expect(runtime).toMatchObject({
      kind: "codespaces",
      listenIp: "0.0.0.0",
      listenProtocol: "https",
      functionalOrigin: "https://synthetic-onceurl-space-8789.app.github.dev",
      marketingOrigin: "https://synthetic-onceurl-space-8790.app.github.dev"
    });
    expect(runtime.readinessHeaders).toEqual({
      "X-Github-Token": "synthetic-test-token"
    });
  });

  it("accepts an explicit forwarded pair and rejects incomplete or collapsed origins", () => {
    expect(
      resolveDevelopmentRuntime({
        ONCEURL_FUNCTIONAL_ORIGIN: "https://functional.example.test",
        ONCEURL_MARKETING_ORIGIN: "https://marketing.example.test"
      })
    ).toMatchObject({
      kind: "forwarded",
      listenIp: "0.0.0.0",
      listenProtocol: "https",
      functionalOrigin: "https://functional.example.test",
      marketingOrigin: "https://marketing.example.test"
    });

    expect(() =>
      resolveDevelopmentRuntime({
        ONCEURL_FUNCTIONAL_ORIGIN: "https://functional.example.test"
      })
    ).toThrow(/together/u);
    expect(() =>
      resolveDevelopmentRuntime({
        ONCEURL_FUNCTIONAL_ORIGIN: "https://same.example.test:8789",
        ONCEURL_MARKETING_ORIGIN: "https://same.example.test:8790"
      })
    ).toThrow(/different hostnames/u);
  });

  it("validates the minimum Node release and rejects another major", () => {
    expect(validateNodeVersion("v24.11.0")).toBe("24.11.0");
    expect(validateNodeVersion("v24.18.0")).toBe("24.18.0");
    expect(() => validateNodeVersion("v24.10.9")).toThrow(/24\.11\.0/u);
    expect(() => validateNodeVersion("v25.0.0")).toThrow(/24\.x/u);
  });

  it("resets only the exact repository-owned persistence path and rejects symlinks", async () => {
    const repository = join(rootDirectory, ".tmp", "local-reset-contract-test");
    const state = join(repository, ".wrangler", "state");
    const outside = join(rootDirectory, ".tmp", "local-reset-outside");
    await rm(repository, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
    await mkdir(state, { recursive: true });
    await writeFile(join(state, "sentinel"), "synthetic", "utf8");

    expect(assertExactResetTarget(repository, state)).toBe(state);
    expect(() => assertExactResetTarget(repository, repository)).toThrow(/exactly/u);
    expect(() => assertExactResetTarget(repository, outside)).toThrow(/inside/u);
    await expect(resetLocalState(repository, state)).resolves.toBe(state);

    await mkdir(join(repository, ".wrangler"), { recursive: true });
    await mkdir(outside, { recursive: true });
    await symlink(outside, state);
    await expect(resetLocalState(repository, state)).rejects.toThrow(/symbolic-link/u);

    await rm(repository, { recursive: true, force: true });
    await mkdir(repository, { recursive: true });
    await writeFile(join(outside, "sentinel"), "must survive", "utf8");
    await symlink(outside, join(repository, ".wrangler"));
    await expect(resetLocalState(repository, state)).rejects.toThrow(/symbolic-link/u);
    await expect(readFile(join(outside, "sentinel"), "utf8")).resolves.toBe("must survive");

    await rm(repository, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  });

  it("keeps the deterministic seed explicitly synthetic and fixed", async () => {
    const seed = await readFile(join(rootDirectory, "scripts", "local", "seed.sql"), "utf8");

    expect(seed).toContain("local-synthetic-alpha");
    expect(seed).toContain("local-synthetic-beta");
    expect(seed).toContain('"synthetic":true');
    expect(seed).toContain("1704067200000");
    expect(seed).toContain(`loc1_${"a".repeat(48)}`);
    expect(seed).toContain(`loc1_${"b".repeat(48)}`);
    expect(seed).not.toMatch(/bearer|token_hash|authorization_hash/iu);
    expect(seed).not.toMatch(/INSERT\s+INTO\s+(users|workspaces|file_objects)/iu);
  });
});
