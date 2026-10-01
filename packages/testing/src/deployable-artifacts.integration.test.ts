import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const rootDirectory = fileURLToPath(new URL("../../..", import.meta.url).href);
const functionalDist = join(rootDirectory, "apps", "web", "dist");
const marketingDist = join(rootDirectory, "apps", "marketing", "dist");

function artifactFiles(directory: string): string[] {
  return readdirSync(directory)
    .flatMap((entry) => {
      const path = join(directory, entry);
      return statSync(path).isDirectory() ? artifactFiles(path) : [path];
    })
    .sort();
}

function artifactText(directory: string): string {
  return artifactFiles(directory)
    .filter((path) => !/\.(?:gif|ico|jpe?g|png|webp|woff2?)$/iu.test(path))
    .map((path) => readFileSync(path, "utf8"))
    .join("\n");
}

describe("built deployable artifact isolation", () => {
  it("produces distinct manifests and asset namespaces", () => {
    const functionalManifest = join(functionalDist, ".vite", "manifest.json");
    const marketingManifest = join(marketingDist, ".vite", "manifest.json");

    expect(existsSync(functionalManifest)).toBe(true);
    expect(existsSync(marketingManifest)).toBe(true);
    expect(functionalDist).not.toBe(marketingDist);

    const functionalFiles = artifactFiles(functionalDist).map((path) =>
      relative(functionalDist, path)
    );
    const marketingFiles = artifactFiles(marketingDist).map((path) =>
      relative(marketingDist, path)
    );

    expect(functionalFiles.some((path) => path.startsWith("assets/"))).toBe(true);
    expect(functionalFiles.some((path) => path.startsWith("marketing-assets/"))).toBe(false);
    expect(marketingFiles.some((path) => path.startsWith("marketing-assets/"))).toBe(true);
    expect(marketingFiles.some((path) => path.startsWith("assets/"))).toBe(false);
    expect(marketingFiles.some((path) => basename(path).endsWith(".js"))).toBe(false);
  });

  it("keeps marketing runtime and terms out of the functional artifact", () => {
    const text = artifactText(functionalDist);

    for (const forbidden of [
      "Non-production placeholder.",
      "marketing-assets/",
      "challenges.cloudflare.com",
      "consent-manager",
      "tracking-pixel",
      "experiment-runtime"
    ]) {
      expect(text).not.toContain(forbidden);
    }
  });

  it("keeps functional routes, capability data and browser runtime out of marketing", () => {
    const text = artifactText(marketingDist);

    for (const forbidden of [
      "/api/",
      "/s/locator",
      "public-bearer",
      "fragment key",
      "ciphertext",
      "onceurl-worker",
      "challenges.cloudflare.com",
      "<script"
    ]) {
      expect(text).not.toContain(forbidden);
    }
    expect(text).not.toMatch(/https?:\/\//iu);
  });
});
