import keys from "./admin-test-keys.json";
import { base64url } from "../admin-auth";
import { createTestWorkerEnv } from "./env";

export const ADMIN_TEST_ISSUER = "https://access.invalid";
export const ADMIN_TEST_AUDIENCE = "onceurl-test-application";
export const ADMIN_TEST_OPERATOR = "operator@onceurl.invalid";
export const ADMIN_TEST_JWKS = { keys: keys.map((key) => key.public) };
export function adminTestEnv() {
  return createTestWorkerEnv({
    ADMIN_ACCESS_ISSUER: ADMIN_TEST_ISSUER,
    ADMIN_ACCESS_AUDIENCE: ADMIN_TEST_AUDIENCE,
    ADMIN_OPERATOR_EMAILS: JSON.stringify([ADMIN_TEST_OPERATOR])
  });
}
export async function adminTestAssertion(
  now: number,
  options: {
    claims?: Record<string, unknown>;
    header?: Record<string, unknown>;
    keyIndex?: number;
  } = {}
) {
  const fixture = keys[options.keyIndex ?? 0];
  if (fixture === undefined) throw new Error("Missing synthetic signing fixture");
  const header = base64url(
    new TextEncoder().encode(
      JSON.stringify({ alg: "RS256", typ: "JWT", kid: fixture.public.kid, ...options.header })
    )
  );
  const claims = base64url(
    new TextEncoder().encode(
      JSON.stringify({
        iss: ADMIN_TEST_ISSUER,
        aud: [ADMIN_TEST_AUDIENCE],
        email: ADMIN_TEST_OPERATOR,
        iat: Math.floor(now / 1000),
        nbf: Math.floor(now / 1000),
        exp: Math.floor(now / 1000) + 900,
        ...options.claims
      })
    )
  );
  const key = await crypto.subtle.importKey(
    "jwk",
    fixture.private,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      key,
      new TextEncoder().encode(`${header}.${claims}`)
    )
  );
  return `${header}.${claims}.${base64url(signature)}`;
}
