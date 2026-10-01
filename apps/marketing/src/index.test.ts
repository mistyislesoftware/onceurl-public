import { describe, expect, it, vi } from "vitest";
import { handleMarketingRequest } from "./index";
import { readOriginConfiguration, type MarketingEnv } from "./origins";

function createMarketingEnv() {
  const fetch = vi.fn((request: RequestInfo | URL) => {
    const url = new URL(request instanceof Request ? request.url : String(request));
    if (url.pathname === "/index.html") {
      return Promise.resolve(
        new Response("<!doctype html><main>Deployment boundary</main>", {
          headers: {
            "access-control-allow-origin": "*",
            "content-type": "text/html",
            "set-cookie": "marketing=test; Domain=example.test"
          }
        })
      );
    }
    if (url.pathname === "/marketing-assets/site.css") {
      return Promise.resolve(
        new Response("body{}", {
          headers: { "content-type": "text/css", "service-worker-allowed": "/" }
        })
      );
    }
    return Promise.resolve(new Response("not found", { status: 404 }));
  });

  const env: MarketingEnv = {
    ASSETS: {
      fetch,
      connect: () => {
        throw new Error("Unexpected ASSETS.connect call");
      }
    },
    DEPLOYMENT_ENVIRONMENT: "local",
    MARKETING_ORIGIN: "http://127.0.0.2",
    FUNCTIONAL_ORIGIN: "http://127.0.0.1"
  };

  return { env, fetch };
}

describe("marketing deployable routing and policy", () => {
  it("serves only the inert marketing document with restrictive headers", async () => {
    const { env } = createMarketingEnv();
    const response = await handleMarketingRequest(new Request("http://127.0.0.2/"), env);
    const body = await response.text();
    const csp = response.headers.get("Content-Security-Policy") ?? "";

    expect(response.status).toBe(200);
    expect(body).toContain("Deployment boundary");
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=0, must-revalidate");
    expect(response.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
    expect(response.headers.get("X-Robots-Tag")).toBe("noindex, nofollow, noarchive");
    expect(response.headers.has("Set-Cookie")).toBe(false);
    expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
    expect(csp).toContain("script-src 'none'");
    expect(csp).toContain("connect-src 'none'");
    expect(csp).toContain("worker-src 'none'");
    expect(csp).not.toContain("127.0.0.1");
  });

  it("serves only marketing-namespaced immutable assets", async () => {
    const { env } = createMarketingEnv();
    const response = await handleMarketingRequest(
      new Request("http://127.0.0.2/marketing-assets/site.css"),
      env
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable");
    expect(response.headers.has("Service-Worker-Allowed")).toBe(false);
  });

  it.each([
    "/api/v1/health",
    "/health",
    "/dashboard",
    "/assets/app.js",
    "/s/locator/bearer",
    "/f/locator/bearer",
    "/u/locator/bearer",
    "/r/locator/bearer",
    "/c/locator/bearer",
    "/h/locator/bearer",
    "/ping/locator/bearer"
  ])("returns a non-forwarding 404 for functional path %s", async (path) => {
    const { env, fetch } = createMarketingEnv();
    const response = await handleMarketingRequest(new Request(`http://127.0.0.2${path}`), env);

    expect(response.status).toBe(404);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([
    ["POST", "/api/v1/health"],
    ["PUT", "/dashboard"],
    ["OPTIONS", "/s/locator/bearer"]
  ])("returns a method-independent 404 for %s %s", async (method, path) => {
    const { env, fetch } = createMarketingEnv();
    const response = await handleMarketingRequest(
      new Request(`http://127.0.0.2${path}`, { method }),
      env
    );

    expect(response.status).toBe(404);
    expect(response.headers.has("Allow")).toBe(false);
    expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("retains the method gate for marketing-owned paths", async () => {
    const { env, fetch } = createMarketingEnv();
    const response = await handleMarketingRequest(
      new Request("http://127.0.0.2/", { method: "POST" }),
      env
    );

    expect(response.status).toBe(405);
    expect(response.headers.get("Allow")).toBe("GET, HEAD");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("exposes a private deployment health route", async () => {
    const { env } = createMarketingEnv();
    const response = await handleMarketingRequest(
      new Request("http://127.0.0.2/_marketing/health"),
      env
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true, service: "onceurl-marketing" });
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("fails closed on an unexpected host or collapsed origin pair", async () => {
    const { env } = createMarketingEnv();
    const wrongHost = await handleMarketingRequest(
      new Request("http://unexpected.localhost/"),
      env
    );
    const collapsed = await handleMarketingRequest(new Request("https://same.example.test/"), {
      ...env,
      DEPLOYMENT_ENVIRONMENT: "staging",
      MARKETING_ORIGIN: "https://same.example.test",
      FUNCTIONAL_ORIGIN: "https://same.example.test:8443"
    });

    expect(wrongHost.status).toBe(421);
    expect(collapsed.status).toBe(503);
  });

  it("fails closed for an unknown deployment environment", async () => {
    const { env } = createMarketingEnv();
    const response = await handleMarketingRequest(new Request("http://127.0.0.2/"), {
      ...env,
      DEPLOYMENT_ENVIRONMENT: "stagin"
    });

    expect(response.status).toBe(503);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it.each([
    "http://127.attacker.example",
    "http://127.0.0.256",
    "http://127.1",
    "http://127.0.0.1.",
    "http://localhost.",
    "http://[::ffff:127.0.0.1]",
    "http://0177.0.0.1"
  ])("rejects non-canonical or non-loopback local HTTP origin %s", (marketingOrigin) => {
    expect(
      readOriginConfiguration({
        DEPLOYMENT_ENVIRONMENT: "local",
        MARKETING_ORIGIN: marketingOrigin,
        FUNCTIONAL_ORIGIN: "http://127.0.0.1"
      })
    ).toBeNull();
  });

  it("accepts only canonical loopback HTTP variants in local configuration", () => {
    expect(
      readOriginConfiguration({
        DEPLOYMENT_ENVIRONMENT: "local",
        MARKETING_ORIGIN: "http://127.255.255.254",
        FUNCTIONAL_ORIGIN: "http://localhost"
      })
    ).toEqual({
      deploymentEnvironment: "local",
      marketingOrigin: "http://127.255.255.254",
      functionalOrigin: "http://localhost"
    });
    expect(
      readOriginConfiguration({
        DEPLOYMENT_ENVIRONMENT: "local",
        MARKETING_ORIGIN: "http://[::1]",
        FUNCTIONAL_ORIGIN: "http://127.1.2.3"
      })
    ).toEqual({
      deploymentEnvironment: "local",
      marketingOrigin: "http://[::1]",
      functionalOrigin: "http://127.1.2.3"
    });
  });
});
