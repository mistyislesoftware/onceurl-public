import { z } from "zod";

const LOCATOR_RANDOM_BYTES = 24;
const BEARER_RANDOM_BYTES = 32;
const AUTHORIZATION_HASH_BYTES = 32;
const MAX_OWNER_BEARER_GENERATION_ATTEMPTS = 4;

const locatorSchema = z
  .string()
  .regex(/^loc1_[0-9a-f]{48}$/u)
  .brand<"CapabilityLocator">();
const publicBearerSecretSchema = z
  .string()
  .regex(/^pub1_[A-Za-z0-9_-]{43}$/u)
  .brand<"PublicBearerSecret">();
const ownerBearerSecretSchema = z
  .string()
  .regex(/^own1_[A-Za-z0-9_-]{43}$/u)
  .brand<"OwnerBearerSecret">();
const authorizationHashSchema = z
  .string()
  .regex(/^bh1_[A-Za-z0-9_-]{43}$/u)
  .brand<"BearerAuthorizationHash">();

export type CapabilityAuthority = "public" | "owner";
export type CapabilityLocator = z.infer<typeof locatorSchema>;
export type PublicBearerSecret = z.infer<typeof publicBearerSecretSchema>;
export type OwnerBearerSecret = z.infer<typeof ownerBearerSecretSchema>;
export type BearerAuthorizationHash = z.infer<typeof authorizationHashSchema>;

export interface CapabilityRouteSecrets {
  readonly locator: CapabilityLocator;
  readonly publicBearerSecret: PublicBearerSecret;
  readonly ownerBearerSecret: OwnerBearerSecret;
}

export interface CapabilityRoutePaths {
  readonly publicPath: string;
  readonly ownerPath: string;
}

export type RandomBytesSource = (length: number) => Uint8Array;

export function generateCapabilityRouteSecrets(
  randomBytes: RandomBytesSource = secureRandomBytes
): CapabilityRouteSecrets {
  const locatorBytes = exactRandomBytes(randomBytes, LOCATOR_RANDOM_BYTES);
  const publicBytes = exactRandomBytes(randomBytes, BEARER_RANDOM_BYTES);
  let ownerBytes: Uint8Array | null = null;
  for (let attempt = 0; attempt < MAX_OWNER_BEARER_GENERATION_ATTEMPTS; attempt += 1) {
    const candidate = exactRandomBytes(randomBytes, BEARER_RANDOM_BYTES);
    if (!timingSafeEqual(publicBytes, candidate)) {
      ownerBytes = candidate;
      break;
    }
  }
  if (ownerBytes === null) {
    throw new Error("Unable to generate independent capability bearer secrets");
  }

  return {
    locator: locatorSchema.parse(`loc1_${hexEncode(locatorBytes)}`),
    publicBearerSecret: publicBearerSecretSchema.parse(`pub1_${base64urlEncode(publicBytes)}`),
    ownerBearerSecret: ownerBearerSecretSchema.parse(`own1_${base64urlEncode(ownerBytes)}`)
  };
}

export function buildCapabilityRoutePaths(
  locator: CapabilityLocator,
  publicBearerSecret: PublicBearerSecret,
  ownerBearerSecret: OwnerBearerSecret
): CapabilityRoutePaths {
  return {
    publicPath: `/s/${locator}/${publicBearerSecret}`,
    ownerPath: `/m/${locator}/${ownerBearerSecret}`
  };
}

export function parseCapabilityLocator(value: unknown): CapabilityLocator | null {
  const parsed = locatorSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

export function parseBearerSecret(authority: "public", value: unknown): PublicBearerSecret | null;
export function parseBearerSecret(authority: "owner", value: unknown): OwnerBearerSecret | null;
export function parseBearerSecret(
  authority: CapabilityAuthority,
  value: unknown
): PublicBearerSecret | OwnerBearerSecret | null;
export function parseBearerSecret(
  authority: CapabilityAuthority,
  value: unknown
): PublicBearerSecret | OwnerBearerSecret | null {
  const prefix = authority === "public" ? "pub1_" : "own1_";
  const parsed = (
    authority === "public" ? publicBearerSecretSchema : ownerBearerSecretSchema
  ).safeParse(value);
  if (!parsed.success) {
    return null;
  }

  const decoded = base64urlDecode(parsed.data.slice(prefix.length));
  return decoded?.byteLength === BEARER_RANDOM_BYTES ? parsed.data : null;
}

export function bearerSecretsHaveEqualPayload(
  publicBearerSecret: PublicBearerSecret,
  ownerBearerSecret: OwnerBearerSecret
): boolean {
  const publicBytes = base64urlDecode(publicBearerSecret.slice("pub1_".length));
  const ownerBytes = base64urlDecode(ownerBearerSecret.slice("own1_".length));
  if (
    publicBytes?.byteLength !== BEARER_RANDOM_BYTES ||
    ownerBytes?.byteLength !== BEARER_RANDOM_BYTES
  ) {
    throw new Error("Bearer secret payload is not canonical");
  }
  return timingSafeEqual(publicBytes, ownerBytes);
}

export function parseAuthorizationHash(value: unknown): BearerAuthorizationHash | null {
  const parsed = authorizationHashSchema.safeParse(value);
  if (!parsed.success || decodeAuthorizationHash(parsed.data) === null) {
    return null;
  }
  return parsed.data;
}

export async function hashBearerSecret(
  authority: CapabilityAuthority,
  bearerSecret: PublicBearerSecret | OwnerBearerSecret
): Promise<BearerAuthorizationHash> {
  const parsed = parseBearerSecret(authority, bearerSecret);
  if (parsed === null) {
    throw new Error("Bearer secret does not match the requested authority format");
  }

  const domain = `onceurl.bearer-hash.v1.${authority}\u0000`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(domain + parsed));
  return authorizationHashSchema.parse(`bh1_${base64urlEncode(new Uint8Array(digest))}`);
}

export async function verifyBearerSecret(
  authority: CapabilityAuthority,
  presentedBearerSecret: unknown,
  expectedHash: unknown
): Promise<"match" | "mismatch" | "invalid_hash"> {
  const bearer = parseBearerSecret(authority, presentedBearerSecret);
  if (bearer === null) {
    return "mismatch";
  }

  const parsedExpectedHash = parseAuthorizationHash(expectedHash);
  if (parsedExpectedHash === null) {
    return "invalid_hash";
  }

  const computedHash = await hashBearerSecret(authority, bearer);
  const computedBytes = decodeAuthorizationHash(computedHash);
  const expectedBytes = decodeAuthorizationHash(parsedExpectedHash);
  if (computedBytes === null || expectedBytes === null) {
    return "invalid_hash";
  }

  return timingSafeEqual(computedBytes, expectedBytes) ? "match" : "mismatch";
}

function secureRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function exactRandomBytes(source: RandomBytesSource, length: number): Uint8Array {
  const bytes = source(length);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== length) {
    throw new Error(`Random byte source must return exactly ${length} bytes`);
  }
  return bytes;
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64urlDecode(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/u.test(value) || value.length % 4 === 1) {
    return null;
  }
  try {
    const padded = value
      .replaceAll("-", "+")
      .replaceAll("_", "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return base64urlEncode(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

function decodeAuthorizationHash(value: BearerAuthorizationHash): Uint8Array | null {
  const bytes = base64urlDecode(value.slice("bh1_".length));
  return bytes?.byteLength === AUTHORIZATION_HASH_BYTES ? bytes : null;
}

function timingSafeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength || left.byteLength !== AUTHORIZATION_HASH_BYTES) {
    return false;
  }

  // Cloudflare Workers exposes this Web Crypto extension. The fixed-length fallback exists only
  // for Node-based unit tests, whose SubtleCrypto implementation does not provide it.
  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(left, right);
  }

  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
