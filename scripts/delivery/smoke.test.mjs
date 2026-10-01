import { describe, expect, it, vi } from "vitest";
import { runDeliverySmoke } from "./smoke.mjs";

const functionalOrigin = "https://functional.example";
const marketingOrigin = "https://marketing.example";

function securityHeaders(extra = {}) {
  return {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    ...extra
  };
}

function privateNotFound() {
  return new Response("Not found", {
    headers: { "Cache-Control": "no-store" },
    status: 404
  });
}

function functionalCapabilityNotFound() {
  return new Response("Not found", {
    headers: securityHeaders({
      "Cache-Control": "no-store, private",
      "Content-Security-Policy": [
        "default-src 'none'",
        "base-uri 'none'",
        "connect-src 'self'",
        "font-src 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "img-src 'self' data:",
        "manifest-src 'none'",
        "media-src 'none'",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "worker-src 'none'"
      ].join("; "),
      Pragma: "no-cache",
      "Referrer-Policy": "no-referrer",
      "X-Robots-Tag": "noindex, nofollow, noarchive"
    }),
    status: 404
  });
}

function successfulSmokeFetch(urlValue) {
  const url = new URL(urlValue);

  if (url.origin === functionalOrigin && url.pathname === "/api/v1/health") {
    return Response.json(
      { ok: true, service: "onceurl-worker" },
      {
        headers: securityHeaders({
          "Cache-Control": "no-store",
          "Referrer-Policy": "no-referrer",
          "X-Robots-Tag": "noindex, nofollow, noarchive"
        })
      }
    );
  }
  if (url.origin === functionalOrigin && url.pathname === "/health") {
    return Response.json({ ok: true, service: "onceurl-worker" }, { headers: securityHeaders() });
  }
  if (url.origin === functionalOrigin && url.pathname === "/") {
    return new Response('<div id="root"></div><script src="/assets/app.js"></script>', {
      headers: securityHeaders({ "Cache-Control": "private, no-store" })
    });
  }
  if (url.origin === functionalOrigin && url.pathname === "/assets/app.js") {
    return new Response("app", {
      headers: { "Cache-Control": "public, max-age=31536000, immutable" }
    });
  }
  if (url.origin === functionalOrigin && url.pathname === "/s/smoke-locator/smoke-bearer") {
    return functionalCapabilityNotFound();
  }
  if (url.origin === marketingOrigin && url.pathname === "/_marketing/health") {
    return Response.json(
      { ok: true, service: "onceurl-marketing" },
      { headers: securityHeaders({ "Cache-Control": "no-store" }) }
    );
  }
  if (url.origin === marketingOrigin && url.pathname === "/") {
    return new Response(
      '<link href="/marketing-assets/site.css" rel="stylesheet"><main>Hi</main>',
      {
        headers: securityHeaders({ "Referrer-Policy": "strict-origin-when-cross-origin" })
      }
    );
  }
  if (url.origin === marketingOrigin && url.pathname === "/marketing-assets/site.css") {
    return new Response("css", {
      headers: { "Cache-Control": "public, max-age=31536000, immutable" }
    });
  }

  return privateNotFound();
}

describe("post-deployment route ownership smoke verification", () => {
  it("verifies positive routes, security headers, and both cross-routing directions", async () => {
    const fetchImplementation = vi.fn(async (url) => successfulSmokeFetch(url));
    await expect(
      runDeliverySmoke({
        fetchImplementation,
        functionalOrigin,
        marketingOrigin,
        timeoutMilliseconds: 100
      })
    ).resolves.toEqual({ checks: 13, functionalOrigin, marketingOrigin });

    const requested = fetchImplementation.mock.calls.map(([url]) => new URL(url));
    expect(requested).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ hostname: "marketing.example", pathname: "/api/v1/health" }),
        expect.objectContaining({
          hostname: "functional.example",
          pathname: "/s/smoke-locator/smoke-bearer"
        }),
        expect.objectContaining({
          hostname: "marketing.example",
          pathname: "/s/smoke-locator/smoke-bearer"
        }),
        expect.objectContaining({
          hostname: "functional.example",
          pathname: "/_marketing/health"
        }),
        expect.objectContaining({
          hostname: "functional.example",
          pathname: "/marketing-assets/smoke.css"
        })
      ])
    );
  });

  it("fails a release when a marketing origin owns a functional route", async () => {
    const fetchImplementation = vi.fn(async (urlValue) => {
      const url = new URL(urlValue);
      if (url.origin === marketingOrigin && url.pathname === "/api/v1/health") {
        return new Response("wrong owner", { status: 200 });
      }
      return successfulSmokeFetch(url);
    });

    await expect(
      runDeliverySmoke({
        fetchImplementation,
        functionalOrigin,
        marketingOrigin,
        timeoutMilliseconds: 100
      })
    ).rejects.toThrow(/must return 404/u);
  });

  it("fails a release when the functional capability boundary can set a cookie", async () => {
    const fetchImplementation = vi.fn(async (urlValue) => {
      const url = new URL(urlValue);
      if (url.origin === functionalOrigin && url.pathname === "/s/smoke-locator/smoke-bearer") {
        const response = functionalCapabilityNotFound();
        response.headers.set("Set-Cookie", "session=forbidden");
        return response;
      }
      return successfulSmokeFetch(url);
    });

    await expect(
      runDeliverySmoke({
        fetchImplementation,
        functionalOrigin,
        marketingOrigin,
        timeoutMilliseconds: 100
      })
    ).rejects.toThrow(/Set-Cookie/u);
  });

  it.each(["connect-src", "font-src", "img-src", "media-src", "script-src", "style-src"])(
    "fails a release when capability CSP %s allows an extra remote source",
    async (directiveName) => {
      const fetchImplementation = vi.fn(async (urlValue) => {
        const url = new URL(urlValue);
        if (url.origin === functionalOrigin && url.pathname === "/s/smoke-locator/smoke-bearer") {
          const response = functionalCapabilityNotFound();
          const policy = response.headers.get("Content-Security-Policy") ?? "";
          response.headers.set(
            "Content-Security-Policy",
            policy
              .split("; ")
              .map((directive) =>
                directive.startsWith(`${directiveName} `)
                  ? `${directive} https://third-party.example`
                  : directive
              )
              .join("; ")
          );
          return response;
        }
        return successfulSmokeFetch(url);
      });

      await expect(
        runDeliverySmoke({
          fetchImplementation,
          functionalOrigin,
          marketingOrigin,
          timeoutMilliseconds: 100
        })
      ).rejects.toThrow(/Content-Security-Policy/u);
    }
  );
});
