import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { prepareSecretCreation } from "./secret-creation";

const rootDirectory = fileURLToPath(new URL("../../..", import.meta.url).href);
const webDistDirectory = join(rootDirectory, "apps", "web", "dist");
const wranglerBinPath = join(rootDirectory, "node_modules", "wrangler", "bin", "wrangler.js");
const wranglerLogDirectory = join(rootDirectory, ".tmp", "wrangler-logs");
const port = Number(process.env.ONCEURL_PLATFORM_TEST_PORT ?? "8789");
const inspectorPort = Number(process.env.ONCEURL_PLATFORM_TEST_INSPECTOR_PORT ?? "9239");
const origin = `http://127.0.0.1:${port}`;
const startupTimeoutMs = 30_000;

interface PreparedSecret {
  readonly creation: {
    readonly operation_id: string;
    readonly capability_id: string;
    readonly locator: string;
    readonly created_at: string;
    readonly policy_hash: string;
    readonly public_bearer: string;
    readonly owner_bearer: string;
  };
  readonly policy: Record<string, unknown> & { readonly expires_at: string };
  readonly complete_by: string;
  readonly preparation_proof: string;
}

let wrangler: ChildProcessWithoutNullStreams | undefined;
let wranglerOutput = "";
const testEnvironmentDirectory = join(rootDirectory, ".tmp", "platform-integration-environment");
const testEnvironmentPath = join(testEnvironmentDirectory, "functional.env");
let preparationSigningKey = "";
let abuseIpSigningKey = "";

const wait = (milliseconds: number) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function fetchUntilReady(): Promise<void> {
  const deadline = Date.now() + startupTimeoutMs;
  let lastError: unknown;

  while (Date.now() < deadline) {
    if (wrangler?.exitCode !== null) {
      throw new Error(`Wrangler exited before becoming ready.\n${wranglerOutput}`);
    }

    try {
      const response = await fetch(`${origin}/api/v1/health`);
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
  if (!existsSync(webDistDirectory)) {
    throw new Error(
      "apps/web/dist is missing. Run pnpm --filter @onceurl/web build before integration tests."
    );
  }

  await mkdir(testEnvironmentDirectory, { recursive: true });
  preparationSigningKey = randomBytes(32).toString("base64url");
  abuseIpSigningKey = randomBytes(32).toString("base64url");
  await writeFile(
    testEnvironmentPath,
    `SECRET_PREPARATION_HMAC_KEY=${preparationSigningKey}\nABUSE_IP_HMAC_KEY=${abuseIpSigningKey}\n`,
    {
      encoding: "utf8",
      mode: 0o600
    }
  );

  wrangler = spawn(
    process.execPath,
    [
      wranglerBinPath,
      "dev",
      "--config",
      "wrangler.jsonc",
      "--env-file",
      testEnvironmentPath,
      "--ip",
      "127.0.0.1",
      "--port",
      String(port),
      "--inspector-port",
      String(inspectorPort)
    ],
    {
      cwd: join(rootDirectory, "apps", "worker"),
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
  if (wrangler && wrangler.exitCode === null) {
    wrangler.kill("SIGTERM");
    await Promise.race([
      new Promise<void>((resolve) => wrangler?.once("exit", () => resolve())),
      wait(5_000).then(() => {
        if (wrangler?.exitCode === null) {
          wrangler.kill("SIGKILL");
        }
      })
    ]);
  }
  if (preparationSigningKey !== "") {
    expect(wranglerOutput).not.toContain(preparationSigningKey);
  }
  if (abuseIpSigningKey !== "") {
    expect(wranglerOutput).not.toContain(abuseIpSigningKey);
  }
  preparationSigningKey = "";
  abuseIpSigningKey = "";
  await rm(testEnvironmentPath, { force: true });
});

describe("common-origin platform routing", () => {
  it("returns HTTP 200 JSON from /api/v1/health", async () => {
    const response = await fetch(`${origin}/api/v1/health`);

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(response.headers.get("X-Request-ID")).toBeTruthy();
    await expect(response.json()).resolves.toEqual({ ok: true, service: "onceurl-worker" });
  });

  it("keeps /health available as a compatibility alias", async () => {
    const response = await fetch(`${origin}/health`);

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    await expect(response.json()).resolves.toEqual({ ok: true, service: "onceurl-worker" });
  });

  it("returns JSON 404 responses for unknown API routes", async () => {
    const response = await fetch(`${origin}/api/v1/missing`);

    expect(response.status).toBe(404);
    expect(response.headers.get("content-type")).toContain("application/json");
    const requestId = response.headers.get("X-Request-ID");
    await expect(response.json()).resolves.toEqual({
      error: {
        code: "not_found",
        message: "The requested API resource was not found.",
        request_id: requestId,
        details: {}
      }
    });
  });

  it("returns JSON 404 for the exact /api boundary", async () => {
    const response = await fetch(`${origin}/api`);

    expect(response.status).toBe(404);
    expect(response.headers.get("content-type")).toContain("application/json");
    const requestId = response.headers.get("X-Request-ID");
    await expect(response.json()).resolves.toEqual({
      error: {
        code: "not_found",
        message: "The requested API resource was not found.",
        request_id: requestId,
        details: {}
      }
    });
  });

  it("does not fall through from unknown API routes to the SPA", async () => {
    const response = await fetch(`${origin}/api/not-a-client-route`);
    const body = await response.text();

    expect(response.status).toBe(404);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(body).not.toContain('id="root"');
  });

  it("serves the SPA fallback for representative non-API client routes", async () => {
    const response = await fetch(`${origin}/dashboard/future-route`);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(body).toContain('id="root"');
  });

  it("does not serve marketing-owned paths from the functional Worker", async () => {
    for (const path of ["/_marketing/health", "/marketing-assets/site.css", "/robots.txt"]) {
      const response = await fetch(`${origin}${path}`);
      const body = await response.text();

      expect(response.status).toBe(404);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(body).not.toContain('id="root"');
    }
  });

  it("enforces capability privacy policy at the real Worker boundary", async () => {
    const response = await fetch(`${origin}/s/locator/public-bearer`, { redirect: "manual" });
    const csp = response.headers.get("Content-Security-Policy") ?? "";

    expect(response.status).toBe(404);
    expect(response.headers.has("Location")).toBe(false);
    expect(response.headers.get("Cache-Control")).toContain("no-store");
    expect(response.headers.get("Cache-Control")).toContain("private");
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(response.headers.get("X-Robots-Tag")).toBe("noindex, nofollow, noarchive");
    expect(response.headers.has("Set-Cookie")).toBe(false);
    expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
    expect(csp).toContain("connect-src 'self'");
    expect(csp).not.toContain("challenges.cloudflare.com");
  });

  it.each(["/%73/locator/public-bearer", "/s%2Flocator/public-bearer", "/S/locator/public-bearer"])(
    "rejects non-canonical reserved path %s without SPA fallback",
    async (path) => {
      const response = await fetch(`${origin}${path}`, { redirect: "manual" });
      const body = await response.text();

      expect(response.status).toBe(404);
      expect(response.headers.has("Location")).toBe(false);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
      expect(response.headers.get("X-Robots-Tag")).toBe("noindex, nofollow, noarchive");
      expect(body).not.toContain('id="root"');
      expect(body).not.toContain("public-bearer");
    }
  );

  it("serves static web assets generated by the real Vite build", async () => {
    const indexResponse = await fetch(`${origin}/`);
    const indexHtml = await indexResponse.text();
    const assetPath = indexHtml.match(/(?:src|href)="([^"]*\/assets\/[^"]+)"/)?.[1];

    expect(indexResponse.status).toBe(200);
    expect(assetPath).toBeDefined();

    const assetResponse = await fetch(new URL(assetPath ?? "/", origin));
    const assetBody = await assetResponse.text();

    expect(assetResponse.status).toBe(200);
    expect(assetResponse.headers.get("content-type")).not.toContain("text/html");
    expect(assetBody).not.toContain('id="root"');
  });

  it.each([
    ["recipient", `/s/loc1_${"a".repeat(48)}/pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`],
    ["owner", `/m/loc1_${"b".repeat(48)}/own1_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE`]
  ])(
    "does not serve the shell or redirect for an unknown direct %s pathname",
    async (_kind, path) => {
      const response = await fetch(`${origin}${path}`, {
        headers: { accept: "text/html" },
        redirect: "manual"
      });
      expect(response.status).toBe(404);
      expect(response.url).toBe(`${origin}${path}`);
      expect(response.headers.has("location")).toBe(false);
      expect(response.headers.get("Cache-Control")).toContain("no-store");
      expect(await response.text()).not.toContain('id="root"');
    }
  );

  it("creates, passively opens, explicitly releases, locally decrypts, and reports one secret end to end", async () => {
    const plaintext = `real local browser boundary ${crypto.randomUUID()} 🔐`;
    const unchallengedPreparation = await fetch(`${origin}/api/v1/secrets/prepare`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ expires_in_seconds: 86_400 })
    });
    expect(unchallengedPreparation.status).toBe(400);
    expect(await unchallengedPreparation.text()).not.toContain(preparationSigningKey);

    // The challenge/Siteverify boundary is covered with an injected provider in app tests. This
    // process-level test constructs the same authenticated, non-persisted preparation material so
    // it can keep exercising real Wrangler routing and SQLite-backed capability state offline.
    const prepared: PreparedSecret = await prepareSecretCreation(86_400, Date.now(), {
      current: preparationSigningKey
    });
    const keyBytes = crypto.getRandomValues(new Uint8Array(32));
    const nonceBytes = crypto.getRandomValues(new Uint8Array(12));
    const associatedData = {
      capabilityId: prepared.creation.capability_id,
      createdAt: prepared.creation.created_at,
      kind: "secret",
      locator: prepared.creation.locator,
      policyHash: prepared.creation.policy_hash,
      purpose: "onceurl.phase1a.secret-text",
      version: "ouzk-v1"
    } as const;
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, [
      "encrypt",
      "decrypt"
    ]);
    const encrypted = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonceBytes,
        additionalData: new TextEncoder().encode(JSON.stringify(associatedData)),
        tagLength: 128
      },
      key,
      new TextEncoder().encode(plaintext)
    );
    const envelope = {
      version: "ouzk-v1",
      alg: "AES-256-GCM",
      nonce: encodeBase64url(nonceBytes),
      ciphertext: encodeBase64url(new Uint8Array(encrypted)),
      ad: associatedData
    };
    const completionRequest = {
      creation: prepared.creation,
      policy: prepared.policy,
      complete_by: prepared.complete_by,
      preparation_proof: prepared.preparation_proof,
      ciphertext_envelope: envelope
    };
    const completionResponse = await fetch(`${origin}/api/v1/secrets`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": prepared.creation.operation_id
      },
      body: JSON.stringify(completionRequest)
    });
    expect(completionResponse.status).toBe(200);
    const completionText = await completionResponse.text();
    expect(completionText).not.toContain(plaintext);
    expect(completionText).not.toContain(encodeBase64url(keyBytes));
    expect(completionText).not.toContain("#k=");
    const completion = JSON.parse(completionText) as {
      recipient_path: string;
      owner_path: string;
      expires_at: string;
    };

    const exactRetryResponse = await fetch(`${origin}/api/v1/secrets`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": prepared.creation.operation_id
      },
      body: JSON.stringify(completionRequest)
    });
    expect(exactRetryResponse.status).toBe(200);
    expect(await exactRetryResponse.text()).toBe(completionText);

    const browserDocument = await fetch(`${origin}${completion.recipient_path}`, {
      headers: { accept: "text/html", "user-agent": "synthetic-link-preview" }
    });
    expect(browserDocument.status).toBe(200);
    expect(browserDocument.url).toBe(`${origin}${completion.recipient_path}`);
    expect(await browserDocument.text()).toContain('id="root"');
    const passiveHead = await fetch(`${origin}${completion.recipient_path}`, { method: "HEAD" });
    expect(passiveHead.status).toBe(200);
    expect(await passiveHead.text()).toBe("");
    const passiveMetadata = await fetch(`${origin}${completion.recipient_path}`, {
      headers: { accept: "application/json" }
    });
    await expect(passiveMetadata.json()).resolves.toMatchObject({
      capability: { state: "ACTIVE", is_available: true }
    });

    const operationId = `reveal_${crypto.randomUUID()}`;
    const claimResponse = await fetch(`${origin}${completion.recipient_path}/claim`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ operation_id: operationId, nonce: `nonce_${crypto.randomUUID()}` })
    });
    expect(claimResponse.status).toBe(200);
    const claim = await claimResponse.json<{
      outcome: "released";
      ciphertext_envelope: typeof envelope;
    }>();
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: decodeBase64url(claim.ciphertext_envelope.nonce),
        additionalData: new TextEncoder().encode(JSON.stringify(claim.ciphertext_envelope.ad)),
        tagLength: 128
      },
      key,
      decodeBase64url(claim.ciphertext_envelope.ciphertext)
    );
    expect(new TextDecoder().decode(decrypted)).toBe(plaintext);

    const secondClaim = await fetch(`${origin}${completion.recipient_path}/claim`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        operation_id: `reveal_${crypto.randomUUID()}`,
        nonce: `nonce_${crypto.randomUUID()}`
      })
    });
    expect(secondClaim.status).toBe(409);
    expect(await secondClaim.text()).not.toContain("ciphertext_envelope");

    const ownerResponse = await fetch(`${origin}${completion.owner_path}`, {
      headers: { accept: "application/json" }
    });
    expect(ownerResponse.status).toBe(200);
    const ownerText = await ownerResponse.text();
    expect(JSON.parse(ownerText)).toMatchObject({
      capability: {
        kind: "secret",
        state: "CONSUMED",
        is_available: false,
        policy: { max_consumptions: 1 },
        events: [{ type: "created" }, { type: "consumed" }]
      }
    });
    for (const forbidden of [
      plaintext,
      prepared.creation.public_bearer,
      prepared.creation.owner_bearer,
      operationId,
      "user_agent",
      "ip_address",
      "ciphertext_envelope"
    ]) {
      expect(ownerText).not.toContain(forbidden);
    }

    const publicAsOwner = await fetch(
      `${origin}/m/${prepared.creation.locator}/${prepared.creation.public_bearer}`,
      { headers: { accept: "application/json" } }
    );
    const ownerAsPublic = await fetch(
      `${origin}/s/${prepared.creation.locator}/${prepared.creation.owner_bearer}`,
      { headers: { accept: "application/json" } }
    );
    expect([publicAsOwner.status, ownerAsPublic.status]).toEqual([404, 404]);
    keyBytes.fill(0);
    nonceBytes.fill(0);
  });
});

function encodeBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function decodeBase64url(value: string): Uint8Array<ArrayBuffer> {
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}
