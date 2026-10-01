import { encodeBase64url } from "./zero-knowledge";

export const ACCESS_CODE_PBKDF2_ITERATIONS = 210_000;
export const ACCESS_CODE_MAX_BYTES = 128;

export interface AccessCodeVerifier {
  readonly version: "acv1";
  readonly algorithm: "PBKDF2-SHA-256";
  readonly iterations: 210_000;
  readonly salt: string;
  readonly digest: string;
}

export async function deriveAccessCodeVerifier(code: string): Promise<AccessCodeVerifier> {
  const codeBytes = new TextEncoder().encode(code);
  if (codeBytes.byteLength < 1 || codeBytes.byteLength > ACCESS_CODE_MAX_BYTES) {
    codeBytes.fill(0);
    throw new Error("Access code must be between 1 and 128 UTF-8 bytes.");
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  try {
    const key = await crypto.subtle.importKey("raw", codeBytes, "PBKDF2", false, ["deriveBits"]);
    const digest = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt,
          iterations: ACCESS_CODE_PBKDF2_ITERATIONS
        },
        key,
        256
      )
    );
    try {
      return {
        version: "acv1",
        algorithm: "PBKDF2-SHA-256",
        iterations: ACCESS_CODE_PBKDF2_ITERATIONS,
        salt: encodeBase64url(salt),
        digest: encodeBase64url(digest)
      };
    } finally {
      digest.fill(0);
    }
  } finally {
    codeBytes.fill(0);
    salt.fill(0);
  }
}

export function isAccessCodeVerifier(value: unknown): value is AccessCodeVerifier {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["version", "algorithm", "iterations", "salt", "digest"]) &&
    value.version === "acv1" &&
    value.algorithm === "PBKDF2-SHA-256" &&
    value.iterations === ACCESS_CODE_PBKDF2_ITERATIONS &&
    typeof value.salt === "string" &&
    /^[A-Za-z0-9_-]{22}$/u.test(value.salt) &&
    typeof value.digest === "string" &&
    /^[A-Za-z0-9_-]{43}$/u.test(value.digest)
  );
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const candidateKeys = Object.keys(value);
  return candidateKeys.length === keys.length && keys.every((key) => candidateKeys.includes(key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
