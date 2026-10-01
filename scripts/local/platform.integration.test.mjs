import { request as httpsRequest } from "node:https";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { developmentEnvironment, rootDirectory } from "./config.mjs";
import { runLocalDevelopment } from "./start.mjs";

function forwardedTlsFetch(urlValue, init = {}) {
  const url = new URL(urlValue);
  const port = url.hostname.includes("-8789.")
    ? developmentEnvironment.local.functional.port
    : developmentEnvironment.local.marketing.port;

  return new Promise((resolvePromise, rejectPromise) => {
    const headers = Object.fromEntries(new Headers(init.headers));
    if (headers["x-github-token"] !== "synthetic-codespaces-token") {
      rejectPromise(new Error("Codespaces readiness requests must carry the ephemeral token"));
      return;
    }
    headers.host = url.host;

    const request = httpsRequest(
      {
        hostname: "127.0.0.1",
        port,
        path: `${url.pathname}${url.search}`,
        method: init.method ?? "GET",
        headers,
        rejectUnauthorized: false,
        signal: init.signal
      },
      (response) => {
        const body = [];
        response.on("data", (chunk) => body.push(chunk));
        response.on("end", () => {
          resolvePromise(
            new Response(Buffer.concat(body), {
              status: response.statusCode,
              headers: response.headers
            })
          );
        });
      }
    );
    request.on("error", rejectPromise);
    request.end();
  });
}

describe("combined local development launcher", () => {
  it("starts both Workers and proves positive and negative browser routing", async () => {
    await expect(
      runLocalDevelopment({
        checkOnly: true,
        quiet: true,
        skipBuild: true,
        stateDirectory: join(rootDirectory, ".tmp", "local-platform-integration", "state")
      })
    ).resolves.toMatchObject({
      checks: 13,
      functionalOrigin: "http://127.0.0.1:8789",
      marketingOrigin: "http://127.0.0.2:8790"
    });
  }, 60_000);

  it("preserves Codespaces HTTPS origins through the Wrangler listener", async () => {
    await expect(
      runLocalDevelopment({
        checkOnly: true,
        environment: {
          CODESPACES: "true",
          CODESPACE_NAME: "synthetic-onceurl-space",
          GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN: "app.github.dev",
          GITHUB_TOKEN: "synthetic-codespaces-token"
        },
        fetchImplementation: forwardedTlsFetch,
        quiet: true,
        skipBuild: true,
        stateDirectory: join(rootDirectory, ".tmp", "local-forwarded-integration", "state")
      })
    ).resolves.toMatchObject({
      checks: 13,
      functionalOrigin: "https://synthetic-onceurl-space-8789.app.github.dev",
      marketingOrigin: "https://synthetic-onceurl-space-8790.app.github.dev"
    });
  }, 60_000);
});
