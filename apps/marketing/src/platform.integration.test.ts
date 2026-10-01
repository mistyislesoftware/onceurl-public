import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const rootDirectory = fileURLToPath(new URL("../../..", import.meta.url).href);
const marketingDistDirectory = join(rootDirectory, "apps", "marketing", "dist");
const wranglerBinPath = join(rootDirectory, "node_modules", "wrangler", "bin", "wrangler.js");
const wranglerLogDirectory = join(rootDirectory, ".tmp", "wrangler-logs");
const port = Number(process.env.ONCEURL_MARKETING_PLATFORM_TEST_PORT ?? "8790");
const inspectorPort = Number(process.env.ONCEURL_MARKETING_PLATFORM_TEST_INSPECTOR_PORT ?? "9240");
const origin = `http://127.0.0.2:${port}`;
const startupTimeoutMs = 30_000;

let wrangler: ChildProcessWithoutNullStreams | undefined;
let wranglerOutput = "";

const wait = (milliseconds: number) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function fetchUntilReady(): Promise<void> {
  const deadline = Date.now() + startupTimeoutMs;
  let lastError: unknown;

  while (Date.now() < deadline) {
    if (wrangler?.exitCode !== null) {
      throw new Error(`Wrangler exited before becoming ready.\n${wranglerOutput}`);
    }

    try {
      const response = await fetch(`${origin}/_marketing/health`);
      if (response.ok) {
        return;
      }
      lastError = new Error(`Health check returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }

    await wait(500);
  }

  throw new Error(
    `Timed out waiting for Wrangler dev server. Last error: ${String(lastError)}\n${wranglerOutput}`
  );
}

beforeAll(async () => {
  if (!existsSync(marketingDistDirectory)) {
    throw new Error(
      "apps/marketing/dist is missing. Run pnpm --filter @onceurl/marketing build before integration tests."
    );
  }

  wrangler = spawn(
    process.execPath,
    [
      wranglerBinPath,
      "dev",
      "--config",
      "wrangler.jsonc",
      "--ip",
      "127.0.0.2",
      "--port",
      String(port),
      "--inspector-port",
      String(inspectorPort)
    ],
    {
      cwd: join(rootDirectory, "apps", "marketing"),
      env: { ...process.env, NO_COLOR: "1", WRANGLER_LOG_PATH: wranglerLogDirectory }
    }
  );

  wrangler.stdout.on("data", (chunk: Buffer) => {
    wranglerOutput += chunk.toString();
  });
  wrangler.stderr.on("data", (chunk: Buffer) => {
    wranglerOutput += chunk.toString();
  });

  await fetchUntilReady();
}, startupTimeoutMs + 5_000);

afterAll(async () => {
  if (!wrangler || wrangler.exitCode !== null) {
    return;
  }

  wrangler.kill("SIGTERM");

  await Promise.race([
    new Promise<void>((resolve) => wrangler?.once("exit", () => resolve())),
    wait(5_000).then(() => {
      if (wrangler?.exitCode === null) {
        wrangler.kill("SIGKILL");
      }
    })
  ]);
});

describe("marketing platform routing", () => {
  it("serves only the inert document with the marketing route policy", async () => {
    const response = await fetch(`${origin}/`);
    const body = await response.text();
    const csp = response.headers.get("Content-Security-Policy") ?? "";

    expect(response.status).toBe(200);
    expect(body).toContain("Non-production placeholder.");
    expect(body).not.toContain("<script");
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=0, must-revalidate");
    expect(response.headers.get("X-Robots-Tag")).toBe("noindex, nofollow, noarchive");
    expect(response.headers.has("Set-Cookie")).toBe(false);
    expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
    expect(csp).toContain("script-src 'none'");
    expect(csp).toContain("connect-src 'none'");
    expect(csp).toContain("worker-src 'none'");
  });

  it("serves a marketing asset without exposing functional routing", async () => {
    const indexResponse = await fetch(`${origin}/`);
    const indexHtml = await indexResponse.text();
    const assetPath = indexHtml.match(/href="([^"]*\/marketing-assets\/[^"]+)"/)?.[1];

    expect(assetPath).toBeDefined();
    const assetResponse = await fetch(new URL(assetPath ?? "/", origin));
    expect(assetResponse.status).toBe(200);
    expect(assetResponse.headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable");
  });

  it("does not serve API, application, asset, or capability paths", async () => {
    for (const path of [
      "/api/v1/health",
      "/health",
      "/dashboard",
      "/assets/app.js",
      "/s/locator/public-bearer"
    ]) {
      const response = await fetch(`${origin}${path}`);

      expect(response.status).toBe(404);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
    }
  });

  it.each([
    ["POST", "/api/v1/health"],
    ["PUT", "/dashboard"],
    ["OPTIONS", "/s/locator/public-bearer"]
  ])("returns a method-independent 404 for %s %s", async (method, path) => {
    const response = await fetch(`${origin}${path}`, { method });

    expect(response.status).toBe(404);
    expect(response.headers.has("Allow")).toBe(false);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
  });
});
