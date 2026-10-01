import { describe, expect, it } from "vitest";
import {
  ACCESS_CODE_MAX_BYTES,
  deriveAccessCodeVerifier,
  isAccessCodeVerifier
} from "./access-code";
import { decodeBase64url } from "./zero-knowledge";

describe("browser access-code verifier", () => {
  it("derives a canonical salted PBKDF2 verifier without retaining the raw code", async () => {
    const code = "separate code 🔐";
    const verifier = await deriveAccessCodeVerifier(code);
    expect(isAccessCodeVerifier(verifier)).toBe(true);
    expect(JSON.stringify(verifier)).not.toContain(code);
    const salt = decodeBase64url(verifier.salt, 16);
    const expected = decodeBase64url(verifier.digest, 32);
    const codeBytes = new TextEncoder().encode(code);
    const key = await crypto.subtle.importKey("raw", codeBytes, "PBKDF2", false, ["deriveBits"]);
    const actual = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt, iterations: verifier.iterations },
        key,
        256
      )
    );
    expect(actual).toEqual(expected);
    codeBytes.fill(0);
    salt.fill(0);
    expected.fill(0);
    actual.fill(0);
  });

  it("rejects empty and oversized UTF-8 codes", async () => {
    await expect(deriveAccessCodeVerifier("")).rejects.toThrow();
    await expect(deriveAccessCodeVerifier("x".repeat(ACCESS_CODE_MAX_BYTES + 1))).rejects.toThrow();
  });
});
