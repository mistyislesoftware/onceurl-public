export type FunctionalRouteClass =
  "api" | "application" | "asset" | "boundary" | "capability" | "challenge";

export const TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";

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

const API_CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'"
].join("; ");

const CAPABILITY_CONTENT_SECURITY_POLICY = [
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
].join("; ");

const APPLICATION_CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "base-uri 'none'",
  "connect-src 'self'",
  "font-src 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "img-src 'self' data:",
  "manifest-src 'self'",
  "object-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "worker-src 'none'"
].join("; ");

export const TURNSTILE_CHALLENGE_CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "base-uri 'none'",
  `connect-src 'self' ${TURNSTILE_ORIGIN}`,
  `frame-src ${TURNSTILE_ORIGIN}`,
  "frame-ancestors 'none'",
  "form-action 'none'",
  "object-src 'none'",
  `script-src 'self' ${TURNSTILE_ORIGIN}`,
  "style-src 'self'",
  "worker-src 'none'"
].join("; ");

function exactHttpsOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    return value === url.origin &&
      url.protocol === "https:" &&
      /^[a-z0-9-]+\.r2\.cloudflarestorage\.com$/iu.test(url.hostname) &&
      url.username === "" &&
      url.password === ""
      ? url.origin
      : null;
  } catch {
    return null;
  }
}

export function capabilityTransferContentSecurityPolicy(r2Origin: string): string | null {
  const origin = exactHttpsOrigin(r2Origin);
  return origin === null
    ? null
    : CAPABILITY_CONTENT_SECURITY_POLICY.replace(
        "connect-src 'self'",
        `connect-src 'self' ${origin}`
      );
}

const CAPABILITY_SEGMENTS = new Set(["c", "f", "h", "m", "ping", "r", "s", "u"]);
const MARKETING_SEGMENTS = new Set(["_marketing", "marketing-assets", "robots.txt", "sitemap.xml"]);
const RESERVED_SEGMENTS = new Set([
  ...CAPABILITY_SEGMENTS,
  ...MARKETING_SEGMENTS,
  "api",
  "assets",
  "challenge",
  "health"
]);

function isNonCanonicalPath(pathname: string, firstSegment: string): boolean {
  if (
    !pathname.startsWith("/") ||
    pathname.includes("\\") ||
    (pathname !== "/" && pathname.includes("//")) ||
    pathname.split("/").some((segment) => segment === "." || segment === "..")
  ) {
    return true;
  }

  if (firstSegment.includes("%")) {
    return true;
  }

  const lowerCaseSegment = firstSegment.toLowerCase();
  return RESERVED_SEGMENTS.has(lowerCaseSegment) && firstSegment !== lowerCaseSegment;
}

export function classifyFunctionalRoute(pathname: string): FunctionalRouteClass {
  const firstSegment = pathname.slice(1).split("/", 1)[0] ?? "";

  if (isNonCanonicalPath(pathname, firstSegment)) {
    return "boundary";
  }

  if (MARKETING_SEGMENTS.has(firstSegment)) {
    return "boundary";
  }

  if (firstSegment === "api" || pathname === "/health") {
    return "api";
  }

  if (firstSegment === "challenge") {
    return "challenge";
  }

  if (firstSegment === "health") {
    return "boundary";
  }

  if (CAPABILITY_SEGMENTS.has(firstSegment)) {
    return "capability";
  }

  if (firstSegment === "assets") {
    return "asset";
  }

  return "application";
}

export function applyFunctionalRoutePolicy(
  response: Response,
  routeClass: FunctionalRouteClass
): Response {
  const headers = response.headers;

  for (const header of [
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Headers",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Origin",
    "Service-Worker-Allowed"
  ]) {
    headers.delete(header);
  }

  const setCookie = headers.get("Set-Cookie");
  if (
    routeClass === "capability" ||
    routeClass === "boundary" ||
    /;\s*Domain=/iu.test(setCookie ?? "")
  ) {
    headers.delete("Set-Cookie");
  }

  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Origin-Agent-Cluster", "?1");
  headers.set("Permissions-Policy", PERMISSIONS_POLICY);
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");

  if (routeClass === "asset") {
    headers.set("Cache-Control", "public, max-age=31536000, immutable");
    headers.set("Content-Security-Policy", API_CONTENT_SECURITY_POLICY);
    headers.set("Referrer-Policy", "no-referrer");
    headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
  } else if (routeClass === "application") {
    headers.set("Cache-Control", "private, no-store");
    headers.set("Content-Security-Policy", APPLICATION_CONTENT_SECURITY_POLICY);
    headers.set("Referrer-Policy", "no-referrer");
    headers.set("X-Robots-Tag", "noindex, nofollow");
  } else if (routeClass === "capability") {
    headers.set("Cache-Control", "no-store, private");
    headers.set("Content-Security-Policy", CAPABILITY_CONTENT_SECURITY_POLICY);
    headers.set("Pragma", "no-cache");
    headers.set("Referrer-Policy", "no-referrer");
    headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
  } else if (routeClass === "challenge") {
    headers.set("Cache-Control", "no-store, private");
    headers.set("Content-Security-Policy", TURNSTILE_CHALLENGE_CONTENT_SECURITY_POLICY);
    headers.set("Pragma", "no-cache");
    headers.set("Referrer-Policy", "no-referrer");
    headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
  } else {
    headers.set("Cache-Control", "no-store");
    headers.set("Content-Security-Policy", API_CONTENT_SECURITY_POLICY);
    headers.set("Pragma", "no-cache");
    headers.set("Referrer-Policy", "no-referrer");
    headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
  }

  return response;
}
