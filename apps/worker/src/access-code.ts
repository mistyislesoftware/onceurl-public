import { z } from "zod";

export const ACCESS_CODE_PBKDF2_ITERATIONS = 210_000;
export const ACCESS_CODE_MAX_BYTES = 128;

const accessCodeVerifierSchema = z.strictObject({
  version: z.literal("acv1"),
  algorithm: z.literal("PBKDF2-SHA-256"),
  iterations: z.literal(ACCESS_CODE_PBKDF2_ITERATIONS),
  salt: z
    .string()
    .regex(/^[A-Za-z0-9_-]{22}$/u)
    .refine((value) => decodeBase64url(value, 16) !== null),
  digest: z
    .string()
    .regex(/^[A-Za-z0-9_-]{43}$/u)
    .refine((value) => decodeBase64url(value, 32) !== null)
});

export type AccessCodeVerifier = z.infer<typeof accessCodeVerifierSchema>;

export function parseAccessCodeVerifier(value: unknown): AccessCodeVerifier | null {
  const parsed = accessCodeVerifierSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

export async function verifyAccessCode(
  candidate: unknown,
  verifier: AccessCodeVerifier
): Promise<boolean> {
  if (typeof candidate !== "string") return false;
  const bytes = new TextEncoder().encode(candidate);
  if (bytes.byteLength < 1 || bytes.byteLength > ACCESS_CODE_MAX_BYTES) {
    bytes.fill(0);
    return false;
  }
  const salt = decodeBase64url(verifier.salt, 16);
  const expected = decodeBase64url(verifier.digest, 32);
  if (salt === null || expected === null) {
    bytes.fill(0);
    salt?.fill(0);
    expected?.fill(0);
    return false;
  }
  try {
    const key = await crypto.subtle.importKey("raw", bytes, "PBKDF2", false, ["deriveBits"]);
    const derived = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt,
          iterations: verifier.iterations
        },
        key,
        256
      )
    );
    try {
      return timingSafeEqual(derived, expected);
    } finally {
      derived.fill(0);
    }
  } catch {
    return false;
  } finally {
    bytes.fill(0);
    salt.fill(0);
    expected.fill(0);
  }
}

function decodeBase64url(value: string, expectedLength: number): Uint8Array | null {
  try {
    const padded = value
      .replaceAll("-", "+")
      .replaceAll("_", "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=");
    const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    return bytes.byteLength === expectedLength && base64urlEncode(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function timingSafeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== 32 || right.byteLength !== 32) return false;
  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(left, right);
  }
  let difference = 0;
  for (let index = 0; index < 32; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
