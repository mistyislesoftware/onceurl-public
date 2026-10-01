import { readOriginConfiguration, type MarketingEnv } from "./origins";

const MARKETING_CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "base-uri 'none'",
  "connect-src 'none'",
  "font-src 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "img-src 'self'",
  "manifest-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  "script-src 'none'",
  "style-src 'self'",
  "worker-src 'none'"
].join("; ");

const PERMISSIONS_POLICY = [
  "accelerometer=()",
  "autoplay=()",
  "camera=()",
  "display-capture=()",
  "encrypted-media=()",
  "fullscreen=()",
  "geolocation=()",
  "gyroscope=()",
  "magnetometer=()",
  "microphone=()",
  "midi=()",
  "payment=()",
  "publickey-credentials-get=()",
  "screen-wake-lock=()",
  "usb=()",
  "xr-spatial-tracking=()"
].join(", ");

type MarketingResponseClass = "asset" | "document" | "private";

function hardenMarketingResponse(
  response: Response,
  responseClass: MarketingResponseClass
): Response {
  const headers = new Headers(response.headers);

  for (const header of [
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Headers",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Origin",
    "Service-Worker-Allowed",
    "Set-Cookie"
  ]) {
    headers.delete(header);
  }

  headers.set("Content-Security-Policy", MARKETING_CONTENT_SECURITY_POLICY);
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Origin-Agent-Cluster", "?1");
  headers.set("Permissions-Policy", PERMISSIONS_POLICY);
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");

  if (responseClass === "asset") {
    headers.set("Cache-Control", "public, max-age=31536000, immutable");
  } else if (responseClass === "document") {
    headers.set("Cache-Control", "public, max-age=0, must-revalidate");
  } else {
    headers.set("Cache-Control", "no-store");
    headers.set("Pragma", "no-cache");
  }

  return new Response(response.body, {
    headers,
    status: response.status,
    statusText: response.statusText
  });
}

function bodyForMethod(request: Request, body: BodyInit): BodyInit | null {
  return request.method === "HEAD" ? null : body;
}

function privateResponse(request: Request, status: number, body: string): Response {
  return hardenMarketingResponse(
    new Response(bodyForMethod(request, body), {
      headers: { "Content-Type": "text/plain; charset=utf-8" },
      status
    }),
    "private"
  );
}

function isMarketingOwnedPath(pathname: string): boolean {
  return (
    pathname === "/" ||
    pathname === "/index.html" ||
    pathname === "/_marketing/health" ||
    pathname === "/robots.txt" ||
    pathname.startsWith("/marketing-assets/")
  );
}

export async function handleMarketingRequest(
  request: Request,
  env: MarketingEnv
): Promise<Response> {
  const origins = readOriginConfiguration(env);
  const url = new URL(request.url);

  if (origins === null) {
    return privateResponse(request, 503, "Service unavailable");
  }

  if (url.origin !== origins.marketingOrigin) {
    return privateResponse(request, 421, "Misdirected request");
  }

  if (!isMarketingOwnedPath(url.pathname)) {
    return privateResponse(request, 404, "Not found");
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    return hardenMarketingResponse(
      new Response(null, { headers: { Allow: "GET, HEAD" }, status: 405 }),
      "private"
    );
  }

  if (url.pathname === "/_marketing/health") {
    const body = JSON.stringify({ ok: true, service: "onceurl-marketing" });
    return hardenMarketingResponse(
      new Response(bodyForMethod(request, body), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      }),
      "private"
    );
  }

  if (url.pathname === "/robots.txt") {
    return hardenMarketingResponse(
      new Response(bodyForMethod(request, "User-agent: *\nDisallow: /\n"), {
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      }),
      "private"
    );
  }

  if (url.pathname === "/" || url.pathname === "/index.html") {
    const indexRequest = new Request(new URL("/index.html", origins.marketingOrigin), {
      headers: request.headers,
      method: request.method
    });
    const response = await env.ASSETS.fetch(indexRequest);
    return response.status === 404
      ? privateResponse(request, 404, "Not found")
      : hardenMarketingResponse(response, "document");
  }

  if (url.pathname.startsWith("/marketing-assets/")) {
    const response = await env.ASSETS.fetch(request);
    return response.status === 404
      ? privateResponse(request, 404, "Not found")
      : hardenMarketingResponse(response, "asset");
  }

  return privateResponse(request, 404, "Not found");
}

export default {
  fetch: handleMarketingRequest
} satisfies ExportedHandler<MarketingEnv>;
