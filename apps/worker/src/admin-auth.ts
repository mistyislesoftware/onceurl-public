import { z } from "zod";
import type { WorkerEnv } from "./env";

const email = z
  .string()
  .max(254)
  .regex(/^[^\s@*]+@[^\s@*]+\.[^\s@*]+$/u);
const claimsSchema = z.object({
  iss: z.string(),
  aud: z.array(z.string()).min(1).max(16),
  exp: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  nbf: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  iat: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  email
});
const headerSchema = z.strictObject({
  alg: z.literal("RS256"),
  kid: z
    .string()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9_-]+$/u),
  typ: z.literal("JWT").optional()
});
const jwkSchema = z.object({
  kty: z.literal("RSA"),
  kid: headerSchema.shape.kid,
  alg: z.literal("RS256").optional(),
  use: z.literal("sig").optional(),
  key_ops: z.array(z.literal("verify")).min(1).max(1).optional(),
  n: z
    .string()
    .min(342)
    .max(1366)
    .regex(/^[A-Za-z0-9_-]+$/u),
  e: z.literal("AQAB")
});
const jwksSchema = z.object({ keys: z.array(jwkSchema).min(1).max(16) });
const KEY_CACHE_MS = 5 * 60_000;

export class AdminBoundaryError extends Error {
  constructor(readonly status: 403 | 503) {
    super("Administrative request unavailable");
  }
}

export interface AuthorizedOperator {
  readonly actor: string;
  readonly session: string;
  readonly expiresAt: number;
}

export function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

export function decodeBase64url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/u.test(value) || value.length % 4 === 1) return null;
  try {
    const bytes = Uint8Array.from(
      atob(
        value
          .replaceAll("-", "+")
          .replaceAll("_", "/")
          .padEnd(Math.ceil(value.length / 4) * 4, "=")
      ),
      (c) => c.charCodeAt(0)
    );
    return base64url(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

export async function securityDigest(domain: string, value: string): Promise<string> {
  return base64url(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(domain + "\0" + value))
    )
  );
}

function trustConfiguration(env: WorkerEnv) {
  try {
    const issuer = new URL(env.ADMIN_ACCESS_ISSUER ?? "");
    if (
      issuer.origin !== env.ADMIN_ACCESS_ISSUER ||
      issuer.protocol !== "https:" ||
      issuer.username !== "" ||
      issuer.password !== "" ||
      issuer.port !== "" ||
      !(
        /^[a-z0-9-]+\.cloudflareaccess\.com$/u.test(issuer.hostname) ||
        (env.DEPLOYMENT_ENVIRONMENT === "local" && issuer.hostname.endsWith(".invalid"))
      )
    )
      throw new Error();
    const audience = z
      .string()
      .min(1)
      .max(256)
      .regex(/^[A-Za-z0-9_-]+$/u)
      .parse(env.ADMIN_ACCESS_AUDIENCE);
    const operators = z
      .array(email)
      .min(1)
      .max(16)
      .parse(JSON.parse(env.ADMIN_OPERATOR_EMAILS ?? ""));
    if (new Set(operators).size !== operators.length) throw new Error();
    return { issuer: issuer.origin, audience, operators };
  } catch {
    throw new AdminBoundaryError(503);
  }
}

/** Caches trusted keys only; authentication/authorization is repeated on every request. */
export function createAdminVerifier(fetcher: typeof fetch = fetch) {
  const cache = new Map<string, { fetchedAt: number; keys: z.infer<typeof jwkSchema>[] }>();
  async function loadKeys(issuer: string, now: number) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5_000);
    try {
      const response = await fetcher(`${issuer}/cdn-cgi/access/certs`, {
        signal: controller.signal,
        redirect: "error"
      });
      if (!response.ok || response.body === null) throw new Error();
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let length = 0;
      while (true) {
        const { done, value } = (await reader.read()) as ReadableStreamReadResult<Uint8Array>;
        if (done) break;
        length += value.byteLength;
        if (length > 64 * 1024) {
          await reader.cancel();
          throw new Error();
        }
        chunks.push(value);
      }
      const bytes = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
      }
      const { keys } = jwksSchema.parse(
        JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes))
      );
      if (new Set(keys.map((key) => key.kid)).size !== keys.length) throw new Error();
      if (cache.size >= 4) cache.delete(cache.keys().next().value ?? "");
      cache.set(issuer, { fetchedAt: now, keys });
      return keys;
    } catch {
      cache.delete(issuer);
      throw new AdminBoundaryError(503);
    } finally {
      clearTimeout(timer);
    }
  }
  return async (
    request: Request,
    env: WorkerEnv,
    now = Date.now()
  ): Promise<AuthorizedOperator> => {
    const config = trustConfiguration(env);
    const token = request.headers.get("Cf-Access-Jwt-Assertion");
    if (token === null || token.length > 16_384) throw new AdminBoundaryError(403);
    const segments = token.split(".");
    if (segments.length !== 3) throw new AdminBoundaryError(403);
    const [encodedHeader = "", encodedClaims = "", encodedSignature = ""] = segments;
    const headerBytes = decodeBase64url(encodedHeader);
    const claimBytes = decodeBase64url(encodedClaims);
    const signature = decodeBase64url(encodedSignature);
    if (
      headerBytes === null ||
      claimBytes === null ||
      signature === null ||
      signature.length < 256 ||
      signature.length > 1024
    )
      throw new AdminBoundaryError(403);
    let header: z.infer<typeof headerSchema>;
    let claims: z.infer<typeof claimsSchema>;
    try {
      const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
      header = headerSchema.parse(JSON.parse(decoder.decode(headerBytes)));
      claims = claimsSchema.parse(JSON.parse(decoder.decode(claimBytes)));
    } catch {
      throw new AdminBoundaryError(403);
    }
    const cached = cache.get(config.issuer);
    let keys =
      cached !== undefined && now >= cached.fetchedAt && now < cached.fetchedAt + KEY_CACHE_MS
        ? cached.keys
        : await loadKeys(config.issuer, now);
    let key = keys.find((candidate) => candidate.kid === header.kid);
    // At most one refresh retry for an unknown kid; trust never comes from the assertion.
    if (key === undefined && cached !== undefined && keys === cached.keys) {
      keys = await loadKeys(config.issuer, now);
      key = keys.find((candidate) => candidate.kid === header.kid);
    }
    if (key === undefined) throw new AdminBoundaryError(403);
    let verified: boolean;
    try {
      const imported = await crypto.subtle.importKey(
        "jwk",
        key,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"]
      );
      verified = await crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        imported,
        signature,
        new TextEncoder().encode(`${encodedHeader}.${encodedClaims}`)
      );
    } catch {
      throw new AdminBoundaryError(503);
    }
    const seconds = now / 1000;
    if (
      !verified ||
      claims.iss !== config.issuer ||
      !claims.aud.includes(config.audience) ||
      claims.nbf > seconds ||
      claims.iat > seconds ||
      claims.exp <= seconds ||
      claims.exp <= claims.nbf ||
      claims.exp <= claims.iat ||
      claims.exp - claims.iat > 900 ||
      !config.operators.includes(claims.email)
    )
      throw new AdminBoundaryError(403);
    return {
      actor: claims.email,
      session: await securityDigest("onceurl.admin-session.v1", token),
      expiresAt: claims.exp * 1000
    };
  };
}
