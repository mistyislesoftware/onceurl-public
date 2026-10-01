import { assertCondition, validateOriginPair } from "./config.mjs";

function expectHeader(response, name, expected, label) {
  const actual = response.headers.get(name);
  assertCondition(
    typeof expected === "string" ? actual === expected : expected.test(actual ?? ""),
    `${label} returned an unexpected ${name} header`
  );
}

function expectAbsentHeader(response, name, label) {
  assertCondition(response.headers.has(name) === false, `${label} unexpectedly returned ${name}`);
}

const CAPABILITY_CONTENT_SECURITY_POLICY = new Map([
  ["default-src", new Set(["'none'"])],
  ["base-uri", new Set(["'none'"])],
  ["connect-src", new Set(["'self'"])],
  ["font-src", new Set(["'none'"])],
  ["form-action", new Set(["'self'"])],
  ["frame-ancestors", new Set(["'none'"])],
  ["img-src", new Set(["'self'", "data:"])],
  ["manifest-src", new Set(["'none'"])],
  ["media-src", new Set(["'none'"])],
  ["object-src", new Set(["'none'"])],
  ["script-src", new Set(["'self'"])],
  ["style-src", new Set(["'self'"])],
  ["worker-src", new Set(["'none'"])]
]);

function expectCapabilityContentSecurityPolicy(response, label) {
  const header = response.headers.get("Content-Security-Policy") ?? "";
  const actualDirectives = new Map();

  for (const directive of header.split(";")) {
    const tokens = directive.trim().split(/\s+/u);
    if (tokens.length === 1 && tokens[0] === "") {
      continue;
    }
    const name = tokens.shift()?.toLowerCase();
    assertCondition(
      name !== undefined && actualDirectives.has(name) === false,
      `${label} returned an unexpected Content-Security-Policy header`
    );
    actualDirectives.set(name, new Set(tokens));
  }

  assertCondition(
    actualDirectives.size === CAPABILITY_CONTENT_SECURITY_POLICY.size,
    `${label} returned an unexpected Content-Security-Policy header`
  );
  for (const [name, expectedSources] of CAPABILITY_CONTENT_SECURITY_POLICY) {
    const actualSources = actualDirectives.get(name);
    assertCondition(
      actualSources !== undefined &&
        actualSources.size === expectedSources.size &&
        [...expectedSources].every((source) => actualSources.has(source)),
      `${label} returned an unexpected Content-Security-Policy header`
    );
  }
}

async function request(fetchImplementation, origin, path, label, timeoutMilliseconds) {
  let response;
  try {
    response = await fetchImplementation(new URL(path, origin), {
      headers: { "User-Agent": "onceurl-delivery-smoke/1" },
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMilliseconds)
    });
  } catch {
    throw new Error(`${label} request failed`);
  }
  return response;
}

function expectCommonSecurityHeaders(response, label) {
  expectHeader(response, "X-Content-Type-Options", "nosniff", label);
  expectHeader(response, "X-Frame-Options", "DENY", label);
  expectHeader(response, "Strict-Transport-Security", /^max-age=31536000/u, label);
  expectAbsentHeader(response, "Access-Control-Allow-Origin", label);
}

function extractOwnedAssetPath(document, namespace, label) {
  const matches = [...document.matchAll(/(?:href|src)="([^"]+)"/gu)].map((match) => match[1]);
  const assetPath = matches.find((value) => value?.startsWith(`/${namespace}/`));
  assertCondition(assetPath !== undefined, `${label} did not reference an owned build asset`);
  return assetPath;
}

async function expectPrivateNotFound(
  fetchImplementation,
  origin,
  path,
  label,
  timeoutMilliseconds
) {
  const response = await request(fetchImplementation, origin, path, label, timeoutMilliseconds);
  const body = await response.text();
  assertCondition(response.status === 404, `${label} must return 404`);
  expectHeader(response, "Cache-Control", /^no-store/u, label);
  expectAbsentHeader(response, "Location", label);
  expectAbsentHeader(response, "Access-Control-Allow-Origin", label);
  assertCondition(body.includes("smoke-bearer") === false, `${label} reflected a synthetic bearer`);
}

async function expectFunctionalCapabilityBoundary(
  fetchImplementation,
  origin,
  timeoutMilliseconds
) {
  const label = "Functional capability boundary";
  const response = await request(
    fetchImplementation,
    origin,
    "/s/smoke-locator/smoke-bearer",
    label,
    timeoutMilliseconds
  );
  const body = await response.text();
  assertCondition(response.status === 404, `${label} must return 404`);
  expectHeader(response, "Cache-Control", "no-store, private", label);
  expectHeader(response, "Pragma", "no-cache", label);
  expectHeader(response, "Referrer-Policy", "no-referrer", label);
  expectHeader(response, "X-Robots-Tag", "noindex, nofollow, noarchive", label);
  expectAbsentHeader(response, "Location", label);
  expectAbsentHeader(response, "Set-Cookie", label);
  expectAbsentHeader(response, "Access-Control-Allow-Origin", label);
  expectAbsentHeader(response, "Service-Worker-Allowed", label);
  expectCapabilityContentSecurityPolicy(response, label);
  assertCondition(body.includes("smoke-bearer") === false, `${label} reflected a synthetic bearer`);
}

export async function runDeliverySmoke(options) {
  const originValidator = options.originValidator ?? validateOriginPair;
  const origins = originValidator(options.marketingOrigin, options.functionalOrigin);
  const fetchImplementation = options.fetchImplementation ?? fetch;
  const timeoutMilliseconds = options.timeoutMilliseconds ?? 10_000;
  assertCondition(
    Number.isSafeInteger(timeoutMilliseconds) && timeoutMilliseconds > 0,
    "Smoke timeout must be a positive integer"
  );

  const functionalHealth = await request(
    fetchImplementation,
    origins.functionalOrigin,
    "/api/v1/health",
    "Functional API health",
    timeoutMilliseconds
  );
  assertCondition(functionalHealth.status === 200, "Functional API health must return 200");
  assertCondition(
    JSON.stringify(await functionalHealth.json()) ===
      JSON.stringify({ ok: true, service: "onceurl-worker" }),
    "Functional API health returned an unexpected body"
  );
  expectCommonSecurityHeaders(functionalHealth, "Functional API health");
  expectHeader(functionalHealth, "Cache-Control", "no-store", "Functional API health");
  expectHeader(functionalHealth, "Referrer-Policy", "no-referrer", "Functional API health");
  expectHeader(
    functionalHealth,
    "X-Robots-Tag",
    "noindex, nofollow, noarchive",
    "Functional API health"
  );

  const compatibilityHealth = await request(
    fetchImplementation,
    origins.functionalOrigin,
    "/health",
    "Functional compatibility health",
    timeoutMilliseconds
  );
  assertCondition(
    compatibilityHealth.status === 200,
    "Functional compatibility health must return 200"
  );
  assertCondition(
    JSON.stringify(await compatibilityHealth.json()) ===
      JSON.stringify({ ok: true, service: "onceurl-worker" }),
    "Functional compatibility health returned an unexpected body"
  );
  expectCommonSecurityHeaders(compatibilityHealth, "Functional compatibility health");

  const functionalDocument = await request(
    fetchImplementation,
    origins.functionalOrigin,
    "/",
    "Functional application document",
    timeoutMilliseconds
  );
  const functionalHtml = await functionalDocument.text();
  assertCondition(
    functionalDocument.status === 200,
    "Functional application document must return 200"
  );
  assertCondition(functionalHtml.includes('id="root"'), "Functional application shell is missing");
  expectCommonSecurityHeaders(functionalDocument, "Functional application document");
  expectHeader(
    functionalDocument,
    "Cache-Control",
    "private, no-store",
    "Functional application document"
  );
  const functionalAssetPath = extractOwnedAssetPath(
    functionalHtml,
    "assets",
    "Functional application document"
  );
  const functionalAsset = await request(
    fetchImplementation,
    origins.functionalOrigin,
    functionalAssetPath,
    "Functional build asset",
    timeoutMilliseconds
  );
  assertCondition(functionalAsset.status === 200, "Functional build asset must return 200");
  expectHeader(
    functionalAsset,
    "Cache-Control",
    "public, max-age=31536000, immutable",
    "Functional build asset"
  );

  await expectFunctionalCapabilityBoundary(
    fetchImplementation,
    origins.functionalOrigin,
    timeoutMilliseconds
  );

  const marketingHealth = await request(
    fetchImplementation,
    origins.marketingOrigin,
    "/_marketing/health",
    "Marketing health",
    timeoutMilliseconds
  );
  assertCondition(marketingHealth.status === 200, "Marketing health must return 200");
  assertCondition(
    JSON.stringify(await marketingHealth.json()) ===
      JSON.stringify({ ok: true, service: "onceurl-marketing" }),
    "Marketing health returned an unexpected body"
  );
  expectCommonSecurityHeaders(marketingHealth, "Marketing health");
  expectHeader(marketingHealth, "Cache-Control", "no-store", "Marketing health");

  const marketingDocument = await request(
    fetchImplementation,
    origins.marketingOrigin,
    "/",
    "Marketing document",
    timeoutMilliseconds
  );
  const marketingHtml = await marketingDocument.text();
  assertCondition(marketingDocument.status === 200, "Marketing document must return 200");
  assertCondition(
    marketingHtml.includes("<script") === false,
    "Marketing document contains script runtime"
  );
  expectCommonSecurityHeaders(marketingDocument, "Marketing document");
  expectHeader(
    marketingDocument,
    "Referrer-Policy",
    "strict-origin-when-cross-origin",
    "Marketing document"
  );
  const marketingAssetPath = extractOwnedAssetPath(
    marketingHtml,
    "marketing-assets",
    "Marketing document"
  );
  const marketingAsset = await request(
    fetchImplementation,
    origins.marketingOrigin,
    marketingAssetPath,
    "Marketing build asset",
    timeoutMilliseconds
  );
  assertCondition(marketingAsset.status === 200, "Marketing build asset must return 200");
  expectHeader(
    marketingAsset,
    "Cache-Control",
    "public, max-age=31536000, immutable",
    "Marketing build asset"
  );

  await expectPrivateNotFound(
    fetchImplementation,
    origins.marketingOrigin,
    "/api/v1/health",
    "Marketing-to-functional API boundary",
    timeoutMilliseconds
  );
  await expectPrivateNotFound(
    fetchImplementation,
    origins.marketingOrigin,
    "/s/smoke-locator/smoke-bearer",
    "Marketing-to-capability boundary",
    timeoutMilliseconds
  );
  await expectPrivateNotFound(
    fetchImplementation,
    origins.functionalOrigin,
    "/_marketing/health",
    "Functional-to-marketing health boundary",
    timeoutMilliseconds
  );
  await expectPrivateNotFound(
    fetchImplementation,
    origins.functionalOrigin,
    "/marketing-assets/smoke.css",
    "Functional-to-marketing asset boundary",
    timeoutMilliseconds
  );
  await expectPrivateNotFound(
    fetchImplementation,
    origins.functionalOrigin,
    "/robots.txt",
    "Functional-to-marketing robots boundary",
    timeoutMilliseconds
  );

  return {
    checks: 13,
    functionalOrigin: origins.functionalOrigin,
    marketingOrigin: origins.marketingOrigin
  };
}

async function runCli() {
  const result = await runDeliverySmoke({
    functionalOrigin: process.env.FUNCTIONAL_ORIGIN ?? "",
    marketingOrigin: process.env.MARKETING_ORIGIN ?? "",
    timeoutMilliseconds: Number(process.env.SMOKE_TIMEOUT_MS ?? "10000")
  });
  process.stdout.write(
    `Delivery smoke verification passed ${result.checks} route and policy groups.\n`
  );
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  await runCli();
}
