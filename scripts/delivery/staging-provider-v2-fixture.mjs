// Synthetic provider responses only; no remote credentials or resources.
const functionalOrigin = "https://functional.staging.onceurl.mistyislesoftware.co.uk";
const marketingOrigin = "https://marketing.staging.onceurl.mistyislesoftware.co.uk";
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

export function successfulSmokeFetch(urlValue) {
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
