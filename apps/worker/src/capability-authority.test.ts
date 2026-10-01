import { describe, expect, it } from "vitest";
import {
  buildCapabilityRoutePaths,
  bearerSecretsHaveEqualPayload,
  generateCapabilityRouteSecrets,
  hashBearerSecret,
  parseAuthorizationHash,
  parseBearerSecret,
  parseCapabilityLocator,
  verifyBearerSecret
} from "./capability-authority";

function deterministicBytes() {
  let call = 0;
  return (length: number) => {
    call += 1;
    return Uint8Array.from({ length }, (_, index) => (call * 53 + index) % 256);
  };
}

describe("capability routing authority primitives", () => {
  it("generates versioned locator and independent 256-bit bearer secrets", () => {
    const secrets = generateCapabilityRouteSecrets(deterministicBytes());

    expect(secrets.locator).toMatch(/^loc1_[0-9a-f]{48}$/u);
    expect(secrets.publicBearerSecret).toMatch(/^pub1_[A-Za-z0-9_-]{43}$/u);
    expect(secrets.ownerBearerSecret).toMatch(/^own1_[A-Za-z0-9_-]{43}$/u);
    expect(secrets.publicBearerSecret.slice(5)).not.toBe(secrets.ownerBearerSecret.slice(5));
    expect(
      bearerSecretsHaveEqualPayload(secrets.publicBearerSecret, secrets.ownerBearerSecret)
    ).toBe(false);
    expect(parseCapabilityLocator(secrets.locator)).toBe(secrets.locator);
    expect(parseBearerSecret("public", secrets.publicBearerSecret)).toBe(
      secrets.publicBearerSecret
    );
    expect(parseBearerSecret("owner", secrets.ownerBearerSecret)).toBe(secrets.ownerBearerSecret);
  });

  it("builds only non-sequential public and owner paths", () => {
    const secrets = generateCapabilityRouteSecrets(deterministicBytes());
    const paths = buildCapabilityRoutePaths(
      secrets.locator,
      secrets.publicBearerSecret,
      secrets.ownerBearerSecret
    );

    expect(paths).toEqual({
      publicPath: `/s/${secrets.locator}/${secrets.publicBearerSecret}`,
      ownerPath: `/m/${secrets.locator}/${secrets.ownerBearerSecret}`
    });
    expect(JSON.stringify(paths)).not.toMatch(/capability[_/-]?id|\/\d+(?:\/|$)/iu);
  });

  it("uses authority-domain-separated hashes and rejects substitution", async () => {
    const secrets = generateCapabilityRouteSecrets(deterministicBytes());
    const publicHash = await hashBearerSecret("public", secrets.publicBearerSecret);
    const ownerHash = await hashBearerSecret("owner", secrets.ownerBearerSecret);

    expect(parseAuthorizationHash(publicHash)).toBe(publicHash);
    expect(parseAuthorizationHash(ownerHash)).toBe(ownerHash);
    expect(publicHash).not.toBe(ownerHash);
    await expect(
      verifyBearerSecret("public", secrets.publicBearerSecret, publicHash)
    ).resolves.toBe("match");
    await expect(verifyBearerSecret("owner", secrets.ownerBearerSecret, ownerHash)).resolves.toBe(
      "match"
    );
    await expect(verifyBearerSecret("owner", secrets.publicBearerSecret, ownerHash)).resolves.toBe(
      "mismatch"
    );
    await expect(verifyBearerSecret("public", secrets.ownerBearerSecret, publicHash)).resolves.toBe(
      "mismatch"
    );
  });

  it("rejects malformed formats and random sources without weakening production randomness", async () => {
    const secrets = generateCapabilityRouteSecrets(deterministicBytes());

    expect(parseCapabilityLocator("loc1_1234")).toBeNull();
    expect(parseBearerSecret("public", secrets.ownerBearerSecret)).toBeNull();
    expect(parseBearerSecret("owner", secrets.publicBearerSecret)).toBeNull();
    expect(parseBearerSecret("public", `pub1_${"B".repeat(43)}`)).toBeNull();
    expect(parseAuthorizationHash("bh1_not-canonical")).toBeNull();
    await expect(
      verifyBearerSecret("public", secrets.publicBearerSecret, "bh1_not-canonical")
    ).resolves.toBe("invalid_hash");
    expect(() => generateCapabilityRouteSecrets(() => new Uint8Array(1))).toThrow(
      "Random byte source must return exactly"
    );
  });

  it("regenerates equal owner material within a bound and fails closed for a defective source", () => {
    let call = 0;
    const regenerated = generateCapabilityRouteSecrets((length) => {
      call += 1;
      if (call === 1) return new Uint8Array(length).fill(7);
      if (call <= 3) return new Uint8Array(length).fill(8);
      return new Uint8Array(length).fill(9);
    });
    expect(regenerated.publicBearerSecret.slice(5)).not.toBe(
      regenerated.ownerBearerSecret.slice(5)
    );
    expect(call).toBe(4);

    expect(() => generateCapabilityRouteSecrets((length) => new Uint8Array(length))).toThrow(
      "Unable to generate independent capability bearer secrets"
    );
  });
});
