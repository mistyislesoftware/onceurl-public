import vectors from "../fixtures/ouzk-v1-vectors.json" with { type: "json" };
import { describe, expect, it } from "vitest";

interface VectorFile {
  readonly schema: string;
  readonly version: string;
  readonly algorithm: string;
  readonly limits: {
    readonly keyBytes: number;
    readonly nonceBytes: number;
    readonly tagBytes: number;
    readonly maxPlaintextBytes: number;
    readonly maxAssociatedDataBytes: number;
  };
  readonly vectors: readonly TestVector[];
  readonly negativeCases: readonly NegativeCase[];
}

interface TestVector {
  readonly name: string;
  readonly plaintextUtf8: string;
  readonly key: EncodedBytes;
  readonly nonce: EncodedBytes;
  readonly associatedData: {
    readonly object: Record<string, string>;
    readonly canonicalJson: string;
    readonly hex: string;
  };
  readonly ciphertext: EncodedBytes;
  readonly tag: EncodedBytes;
  readonly ciphertextAndTag: EncodedBytes;
}

interface EncodedBytes {
  readonly hex: string;
  readonly base64url: string;
}

interface NegativeCase {
  readonly name: string;
  readonly vector: string | null;
  readonly mutation: string;
  readonly expected: string;
}

const fixture = vectors as VectorFile;

const base64urlPattern = /^[A-Za-z0-9_-]*$/u;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

describe("ouzk-v1 cryptographic vectors", () => {
  it("describes the Phase 1A vector schema and limits", () => {
    expect(fixture.schema).toBe("onceurl.ouzk-v1.test-vectors");
    expect(fixture.version).toBe("ouzk-v1");
    expect(fixture.algorithm).toBe("AES-256-GCM");
    expect(fixture.limits).toMatchObject({
      keyBytes: 32,
      nonceBytes: 12,
      tagBytes: 16,
      maxPlaintextBytes: 65_536,
      maxAssociatedDataBytes: 2_048
    });
    expect(fixture.vectors.length).toBeGreaterThanOrEqual(3);
  });

  it.each(fixture.vectors)("decrypts independent AES-GCM vector $name", async (vector) => {
    validateEncodings(vector);

    const key = await crypto.subtle.importKey(
      "raw",
      decodeBase64url(vector.key.base64url),
      "AES-GCM",
      false,
      ["decrypt"]
    );

    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: decodeBase64url(vector.nonce.base64url),
        additionalData: textEncoder.encode(vector.associatedData.canonicalJson),
        tagLength: 128
      },
      key,
      decodeBase64url(vector.ciphertextAndTag.base64url)
    );

    expect(textDecoder.decode(plaintext)).toBe(vector.plaintextUtf8);
  });

  it.each(fixture.vectors)(
    "re-encrypts vector $name to the stored expected output",
    async (vector) => {
      const key = await crypto.subtle.importKey(
        "raw",
        decodeBase64url(vector.key.base64url),
        "AES-GCM",
        false,
        ["encrypt"]
      );

      const encrypted = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: decodeBase64url(vector.nonce.base64url),
          additionalData: textEncoder.encode(vector.associatedData.canonicalJson),
          tagLength: 128
        },
        key,
        textEncoder.encode(vector.plaintextUtf8)
      );

      expect(encodeBase64url(new Uint8Array(encrypted))).toBe(vector.ciphertextAndTag.base64url);
    }
  );

  it("covers required negative case categories", () => {
    expect(fixture.negativeCases.map((testCase) => testCase.name)).toEqual([
      "wrong-key",
      "wrong-nonce",
      "ciphertext-bit-flip",
      "tag-bit-flip",
      "associated-data-purpose-tamper",
      "unsupported-version",
      "wrong-algorithm",
      "padded-base64url",
      "invalid-base64url-alphabet",
      "non-canonical-base64url-pad-bits",
      "truncated-tag",
      "oversize-ciphertext",
      "zero-length-plaintext",
      "missing-associated-data-field",
      "mismatched-capability-metadata"
    ]);
  });

  it.each(fixture.negativeCases)("rejects negative case $name", exerciseNegativeCase);
});

async function exerciseNegativeCase(testCase: NegativeCase): Promise<void> {
  switch (testCase.expected) {
    case "decrypt_failure":
      await expectAuthenticationFailure(testCase);
      return;
    case "invalid_encoding":
      expect(() => decodeBase64url(invalidEncodingFor(testCase))).toThrow("invalid base64url");
      return;
    case "unsupported_version":
      expect(() => validateEnvelopeParameters("ouzk-v0", fixture.algorithm)).toThrow(
        "unsupported version"
      );
      return;
    case "unsupported_algorithm":
      expect(() => validateEnvelopeParameters(fixture.version, "AES-128-GCM")).toThrow(
        "unsupported algorithm"
      );
      return;
    case "size_limit_exceeded":
      expect(() =>
        validateCiphertextSize(fixture.limits.maxPlaintextBytes + fixture.limits.tagBytes + 1)
      ).toThrow("size limit exceeded");
      return;
    case "invalid_plaintext_size":
      expect(() => validatePlaintextSize(0)).toThrow("invalid plaintext size");
      return;
    case "invalid_associated_data": {
      const vector = findVector(testCase.vector);
      const missingField = { ...vector.associatedData.object };
      delete missingField.policyHash;
      expect(() => validateAssociatedData(missingField, vector.associatedData.object)).toThrow(
        "invalid associated data"
      );
      return;
    }
    case "associated_data_mismatch": {
      const vector = findVector(testCase.vector);
      const mismatched = {
        ...vector.associatedData.object,
        capabilityId: `${vector.associatedData.object.capabilityId}-tampered`
      };
      expect(() => validateAssociatedData(mismatched, vector.associatedData.object)).toThrow(
        "associated data mismatch"
      );
      return;
    }
    default:
      throw new Error(`unhandled expected result ${testCase.expected} for ${testCase.name}`);
  }
}

const invalidEncodingFor = (testCase: NegativeCase): string => {
  const vector = findVector(testCase.vector);
  switch (testCase.name) {
    case "padded-base64url":
      return `${vector.nonce.base64url}=`;
    case "invalid-base64url-alphabet":
      return `+${vector.nonce.base64url.slice(1)}`;
    case "non-canonical-base64url-pad-bits":
      expect(vector.ciphertext.base64url).toBe("bg");
      return "bh";
    default:
      throw new Error(`unhandled invalid encoding case ${testCase.name}`);
  }
};

async function expectAuthenticationFailure(testCase: NegativeCase): Promise<void> {
  const vector = findVector(testCase.vector);
  const keyBytes = decodeBase64url(vector.key.base64url);
  const nonceBytes = decodeBase64url(vector.nonce.base64url);
  const cipherBytes = decodeBase64url(vector.ciphertextAndTag.base64url);
  let associatedData = vector.associatedData.canonicalJson;

  switch (testCase.name) {
    case "wrong-key":
      keyBytes[0] = 0xff;
      break;
    case "wrong-nonce":
      nonceBytes[0] = 0xff;
      break;
    case "ciphertext-bit-flip":
      cipherBytes[0] = (cipherBytes[0] ?? 0) ^ 0x01;
      break;
    case "tag-bit-flip":
      cipherBytes[cipherBytes.length - 1] = (cipherBytes[cipherBytes.length - 1] ?? 0) ^ 0x01;
      break;
    case "associated-data-purpose-tamper":
      associatedData = associatedData.replace("secret-text", "secret-tamper");
      break;
    case "truncated-tag":
      break;
    default:
      throw new Error(`unhandled authentication case ${testCase.name}`);
  }

  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  await expect(
    crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonceBytes,
        additionalData: textEncoder.encode(associatedData),
        tagLength: 128
      },
      key,
      testCase.name === "truncated-tag" ? cipherBytes.slice(0, -1) : cipherBytes
    )
  ).rejects.toThrow();
}

const findVector = (name: string | null): TestVector => {
  const vector = fixture.vectors.find((candidate) => candidate.name === name);
  if (!vector) {
    throw new Error(`missing vector ${name ?? "<null>"}`);
  }
  return vector;
};

const validateEncodings = (vector: TestVector): void => {
  validateEnvelopeParameters(fixture.version, fixture.algorithm);
  validatePlaintextSize(textEncoder.encode(vector.plaintextUtf8).byteLength);
  expect(decodeBase64url(vector.key.base64url)).toHaveLength(fixture.limits.keyBytes);
  expect(decodeBase64url(vector.nonce.base64url)).toHaveLength(fixture.limits.nonceBytes);
  expect(decodeBase64url(vector.tag.base64url)).toHaveLength(fixture.limits.tagBytes);
  const ciphertextSize = decodeBase64url(vector.ciphertextAndTag.base64url).byteLength;
  validateCiphertextSize(ciphertextSize);
  expect(ciphertextSize).toBe(
    textEncoder.encode(vector.plaintextUtf8).byteLength + fixture.limits.tagBytes
  );
  expect(textEncoder.encode(vector.associatedData.canonicalJson).byteLength).toBeLessThanOrEqual(
    fixture.limits.maxAssociatedDataBytes
  );
  expect(vector.associatedData.canonicalJson).toBe(JSON.stringify(vector.associatedData.object));
  validateAssociatedData(vector.associatedData.object, vector.associatedData.object);
};

const validateEnvelopeParameters = (version: string, algorithm: string): void => {
  if (version !== fixture.version) {
    throw new Error("unsupported version");
  }
  if (algorithm !== fixture.algorithm) {
    throw new Error("unsupported algorithm");
  }
};

const validatePlaintextSize = (size: number): void => {
  if (size < 1 || size > fixture.limits.maxPlaintextBytes) {
    throw new Error("invalid plaintext size");
  }
};

const validateCiphertextSize = (size: number): void => {
  const minimum = fixture.limits.tagBytes + 1;
  const maximum = fixture.limits.maxPlaintextBytes + fixture.limits.tagBytes;
  if (size < minimum || size > maximum) {
    throw new Error("size limit exceeded");
  }
};

const associatedDataKeys = [
  "capabilityId",
  "createdAt",
  "kind",
  "locator",
  "policyHash",
  "purpose",
  "version"
];

const validateAssociatedData = (
  candidate: Record<string, string>,
  authoritative: Record<string, string>
): void => {
  if (
    Object.keys(candidate).length !== associatedDataKeys.length ||
    !associatedDataKeys.every((key, index) => Object.keys(candidate)[index] === key) ||
    Object.values(candidate).some((value) => typeof value !== "string") ||
    candidate.kind !== "secret" ||
    candidate.purpose !== "onceurl.phase1a.secret-text" ||
    candidate.version !== fixture.version
  ) {
    throw new Error("invalid associated data");
  }

  for (const key of ["capabilityId", "createdAt", "locator", "policyHash"] as const) {
    if (candidate[key] !== authoritative[key]) {
      throw new Error("associated data mismatch");
    }
  }
};

const decodeBase64url = (input: string): Uint8Array<ArrayBuffer> => {
  if (!base64urlPattern.test(input) || input.includes("=")) {
    throw new Error("invalid base64url");
  }
  const padded = input
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(input.length / 4) * 4, "=");
  const binary = atob(padded);
  const output = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    output[index] = binary.charCodeAt(index);
  }
  if (encodeBase64url(output) !== input) {
    throw new Error("invalid base64url");
  }
  return output;
};

const encodeBase64url = (input: Uint8Array): string => {
  let binary = "";
  for (const byte of input) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
};
