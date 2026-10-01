import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  MAX_PLAINTEXT_BYTES,
  SecretDecryptionError,
  SecretProtocolError,
  buildAssociatedData,
  canonicalAssociatedData,
  countUtf8Bytes,
  decodeBase64url,
  decryptSecret,
  encryptSecret,
  parseFragmentKey,
  validateEnvelope,
  type OuzkEnvelopeV1
} from "./zero-knowledge";

interface FixtureVector {
  readonly name: string;
  readonly plaintextUtf8: string;
  readonly key: { readonly hex: string; readonly base64url: string };
  readonly nonce: { readonly hex: string; readonly base64url: string };
  readonly associatedData: {
    readonly object: Record<string, string>;
    readonly canonicalJson: string;
  };
  readonly ciphertextAndTag: { readonly base64url: string };
}

const fixture = JSON.parse(
  await readFile(
    new URL("../../../packages/domain/fixtures/ouzk-v1-vectors.json", import.meta.url),
    "utf8"
  )
) as { readonly vectors: readonly FixtureVector[] };

describe("browser ouzk-v1 production crypto", () => {
  it.each(fixture.vectors)("matches independent published vector $name", async (vector) => {
    const randomValues = [hexBytes(vector.key.hex), hexBytes(vector.nonce.hex)];
    const encrypted = await encryptSecret(
      vector.plaintextUtf8,
      {
        capabilityId: vector.associatedData.object.capabilityId ?? "",
        createdAt: vector.associatedData.object.createdAt ?? "",
        locator: vector.associatedData.object.locator ?? "",
        policyHash: vector.associatedData.object.policyHash ?? ""
      },
      () => randomValues.shift() ?? new Uint8Array()
    );

    expect(encrypted.keyBase64url).toBe(vector.key.base64url);
    expect(encrypted.envelope.nonce).toBe(vector.nonce.base64url);
    expect(encrypted.envelope.ciphertext).toBe(vector.ciphertextAndTag.base64url);
    expect(canonicalAssociatedData(encrypted.envelope.ad)).toBe(
      vector.associatedData.canonicalJson
    );
    await expect(decryptSecret(encrypted.envelope, vector.key.base64url)).resolves.toBe(
      vector.plaintextUtf8
    );
  });

  it("uses exact canonical associated-data ordering and rejects missing, extra, or reordered keys", () => {
    const ad = buildAssociatedData({
      capabilityId: "cap_test",
      createdAt: "2026-08-01T00:00:00.000Z",
      locator: `loc1_${"a".repeat(48)}`,
      policyHash: "A".repeat(43)
    });
    expect(Object.keys(ad)).toEqual([
      "capabilityId",
      "createdAt",
      "kind",
      "locator",
      "policyHash",
      "purpose",
      "version"
    ]);
    expect(canonicalAssociatedData(ad)).toBe(JSON.stringify(ad));
    const reordered = Object.fromEntries([
      ["createdAt", ad.createdAt],
      ["capabilityId", ad.capabilityId],
      ...Object.entries(ad).filter(([key]) => key !== "createdAt" && key !== "capabilityId")
    ]);
    expect(() => canonicalAssociatedData(reordered as never)).toThrow(SecretProtocolError);
    expect(() => canonicalAssociatedData({ ...ad, extra: "no" } as never)).toThrow(
      SecretProtocolError
    );
    const missing = { ...ad } as Record<string, unknown>;
    delete missing.policyHash;
    expect(() => canonicalAssociatedData(missing as never)).toThrow(SecretProtocolError);
  });

  it("validates canonical fragments and exact 32-byte keys before claim", () => {
    const key = fixture.vectors[0]?.key.base64url ?? "";
    expect(parseFragmentKey(`#k=${key}&v=ouzk-v1`)).toHaveLength(32);
    for (const fragment of [
      "",
      "#v=ouzk-v1",
      `#v=ouzk-v1&k=${key}`,
      `#k=${key}= &v=ouzk-v1`,
      `#k=${key}&v=ouzk-v0`,
      `#k=${key}&v=ouzk-v1&extra=1`,
      "#k=AA&v=ouzk-v1"
    ]) {
      expect(() => parseFragmentKey(fragment)).toThrow(SecretProtocolError);
    }
  });

  it("rejects non-canonical base64url, nonce sizes, ciphertext bounds, fields, versions, and algorithms", () => {
    const envelope = fixtureEnvelope(fixture.vectors[0]!);
    expect(() => decodeBase64url(`${envelope.nonce}=`)).toThrow(SecretProtocolError);
    expect(() => decodeBase64url(`+${envelope.nonce.slice(1)}`)).toThrow(SecretProtocolError);
    expect(() => decodeBase64url("bh")).toThrow(SecretProtocolError);
    expect(() => validateEnvelope({ ...envelope, version: "ouzk-v0" })).toThrow(
      SecretProtocolError
    );
    expect(() => validateEnvelope({ ...envelope, alg: "AES-128-GCM" })).toThrow(
      SecretProtocolError
    );
    expect(() => validateEnvelope({ ...envelope, nonce: "AA" })).toThrow(SecretProtocolError);
    expect(() => validateEnvelope({ ...envelope, ciphertext: "A".repeat(87_404) })).toThrow(
      SecretProtocolError
    );
    expect(() => validateEnvelope({ ...envelope, ciphertext: "A".repeat(22) })).toThrow(
      SecretProtocolError
    );
    expect(() => validateEnvelope({ ...envelope, extra: "no" })).toThrow(SecretProtocolError);
  });

  it("returns one generic failure for wrong key, ciphertext, tag, nonce, AD, truncation, and version", async () => {
    const vector = fixture.vectors[0]!;
    const envelope = fixtureEnvelope(vector);
    const wrongKey = decodeBase64url(vector.key.base64url);
    wrongKey[0] = (wrongKey[0] ?? 0) ^ 0xff;
    const mutated = decodeBase64url(envelope.ciphertext);
    mutated[0] = (mutated[0] ?? 0) ^ 1;
    const tamperedCiphertext = base64url(mutated);
    const tagMutated = decodeBase64url(envelope.ciphertext);
    tagMutated[tagMutated.length - 1] = (tagMutated.at(-1) ?? 0) ^ 1;
    const tamperedTag = base64url(tagMutated);
    const cases: readonly [unknown, string | Uint8Array][] = [
      [envelope, wrongKey],
      [{ ...envelope, ciphertext: tamperedCiphertext }, vector.key.base64url],
      [{ ...envelope, ciphertext: tamperedTag }, vector.key.base64url],
      [{ ...envelope, nonce: "_" + envelope.nonce.slice(1) }, vector.key.base64url],
      [
        { ...envelope, ad: { ...envelope.ad, purpose: "onceurl.phase1a.secret-tamper" } },
        vector.key.base64url
      ],
      [
        { ...envelope, ad: { ...envelope.ad, capabilityId: "cap_substituted" } },
        vector.key.base64url
      ],
      [{ ...envelope, ciphertext: envelope.ciphertext.slice(0, -2) }, vector.key.base64url],
      [{ ...envelope, version: "ouzk-v0" }, vector.key.base64url]
    ];
    for (const [candidate, key] of cases) {
      await expect(decryptSecret(candidate, key)).rejects.toEqual(new SecretDecryptionError());
    }
  });

  it("enforces zero, one-byte, Unicode, and exact maximum UTF-8 plaintext boundaries", async () => {
    expect(countUtf8Bytes("🔐")).toBe(4);
    const metadata = {
      capabilityId: "cap_boundary",
      createdAt: "2026-08-01T00:00:00.000Z",
      locator: `loc1_${"b".repeat(48)}`,
      policyHash: "B".repeat(43)
    };
    await expect(encryptSecret("", metadata)).rejects.toThrow(SecretProtocolError);
    await expect(encryptSecret("x".repeat(MAX_PLAINTEXT_BYTES + 1), metadata)).rejects.toThrow(
      SecretProtocolError
    );
    const encrypted = await encryptSecret("x".repeat(MAX_PLAINTEXT_BYTES), metadata);
    expect(decodeBase64url(encrypted.envelope.ciphertext)).toHaveLength(MAX_PLAINTEXT_BYTES + 16);
  });
});

function fixtureEnvelope(vector: FixtureVector): OuzkEnvelopeV1 {
  return {
    version: "ouzk-v1",
    alg: "AES-256-GCM",
    nonce: vector.nonce.base64url,
    ciphertext: vector.ciphertextAndTag.base64url,
    ad: vector.associatedData.object as unknown as OuzkEnvelopeV1["ad"]
  };
}

function hexBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/.{2}/gu) ?? [], (byte) => Number.parseInt(byte, 16));
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
