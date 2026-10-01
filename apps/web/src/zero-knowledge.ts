export const OUZK_VERSION = "ouzk-v1" as const;
export const OUZK_ALGORITHM = "AES-256-GCM" as const;
export const OUZK_PURPOSE = "onceurl.phase1a.secret-text" as const;
export const MAX_PLAINTEXT_BYTES = 65_536;
export const MAX_ASSOCIATED_DATA_BYTES = 2_048;
export const MAX_ENVELOPE_BYTES = 96 * 1_024;
export const KEY_BYTES = 32;
export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const base64urlPattern = /^[A-Za-z0-9_-]+$/u;
const associatedDataKeys = [
  "capabilityId",
  "createdAt",
  "kind",
  "locator",
  "policyHash",
  "purpose",
  "version"
] as const;

export interface OuzkAssociatedDataV1 {
  readonly capabilityId: string;
  readonly createdAt: string;
  readonly kind: "secret";
  readonly locator: string;
  readonly policyHash: string;
  readonly purpose: typeof OUZK_PURPOSE;
  readonly version: typeof OUZK_VERSION;
}

export interface OuzkEnvelopeV1 {
  readonly version: typeof OUZK_VERSION;
  readonly alg: typeof OUZK_ALGORITHM;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly ad: OuzkAssociatedDataV1;
}

export interface OuzkAuthoritativeMetadata {
  readonly capabilityId: string;
  readonly createdAt: string;
  readonly locator: string;
  readonly policyHash: string;
}

export interface EncryptedSecret {
  readonly envelope: OuzkEnvelopeV1;
  readonly keyBase64url: string;
}

export type BrowserBytes = Uint8Array<ArrayBuffer>;
export type RandomBytesSource = (length: number) => Uint8Array;

export class SecretProtocolError extends Error {
  constructor() {
    super("This secret could not be processed securely.");
    this.name = "SecretProtocolError";
  }
}

export class SecretDecryptionError extends Error {
  constructor() {
    super("This secret could not be decrypted.");
    this.name = "SecretDecryptionError";
  }
}

export function countUtf8Bytes(value: string): number {
  return textEncoder.encode(value).byteLength;
}

export function buildAssociatedData(metadata: OuzkAuthoritativeMetadata): OuzkAssociatedDataV1 {
  return {
    capabilityId: metadata.capabilityId,
    createdAt: metadata.createdAt,
    kind: "secret",
    locator: metadata.locator,
    policyHash: metadata.policyHash,
    purpose: OUZK_PURPOSE,
    version: OUZK_VERSION
  };
}

export function canonicalAssociatedData(ad: OuzkAssociatedDataV1): string {
  validateAssociatedData(ad);
  const canonical = JSON.stringify(ad);
  if (countUtf8Bytes(canonical) > MAX_ASSOCIATED_DATA_BYTES) {
    throw new SecretProtocolError();
  }
  return canonical;
}

export async function encryptSecret(
  plaintext: string,
  metadata: OuzkAuthoritativeMetadata,
  randomBytes: RandomBytesSource = secureRandomBytes
): Promise<EncryptedSecret> {
  const plaintextBytes = textEncoder.encode(plaintext);
  if (plaintextBytes.byteLength < 1 || plaintextBytes.byteLength > MAX_PLAINTEXT_BYTES) {
    throw new SecretProtocolError();
  }

  const keyBytes = exactRandomBytes(randomBytes, KEY_BYTES);
  const nonceBytes = exactRandomBytes(randomBytes, NONCE_BYTES);
  const ad = buildAssociatedData(metadata);
  const additionalData = textEncoder.encode(canonicalAssociatedData(ad));

  try {
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonceBytes,
        additionalData,
        tagLength: TAG_BYTES * 8
      },
      key,
      plaintextBytes
    );
    const envelope: OuzkEnvelopeV1 = {
      version: OUZK_VERSION,
      alg: OUZK_ALGORITHM,
      nonce: encodeBase64url(nonceBytes),
      ciphertext: encodeBase64url(new Uint8Array(ciphertext)),
      ad
    };
    validateEnvelope(envelope);
    return { envelope, keyBase64url: encodeBase64url(keyBytes) };
  } catch (error) {
    if (error instanceof SecretProtocolError) {
      throw error;
    }
    throw new SecretProtocolError();
  } finally {
    plaintextBytes.fill(0);
    nonceBytes.fill(0);
    keyBytes.fill(0);
  }
}

export async function decryptSecret(
  candidate: unknown,
  keyMaterial: string | Uint8Array
): Promise<string> {
  let keyBytes: BrowserBytes | undefined;
  try {
    keyBytes =
      typeof keyMaterial === "string"
        ? decodeBase64url(keyMaterial, KEY_BYTES)
        : copyExactBytes(keyMaterial, KEY_BYTES);
    const envelope = validateEnvelope(candidate);
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: decodeBase64url(envelope.nonce, NONCE_BYTES),
        additionalData: textEncoder.encode(canonicalAssociatedData(envelope.ad)),
        tagLength: TAG_BYTES * 8
      },
      key,
      decodeBase64url(envelope.ciphertext)
    );
    return textDecoder.decode(plaintext);
  } catch {
    throw new SecretDecryptionError();
  } finally {
    keyBytes?.fill(0);
  }
}

export function validateEnvelope(candidate: unknown): OuzkEnvelopeV1 {
  if (
    !isRecord(candidate) ||
    !hasExactKeys(candidate, ["version", "alg", "nonce", "ciphertext", "ad"])
  ) {
    throw new SecretProtocolError();
  }
  if (
    candidate.version !== OUZK_VERSION ||
    candidate.alg !== OUZK_ALGORITHM ||
    typeof candidate.nonce !== "string" ||
    typeof candidate.ciphertext !== "string"
  ) {
    throw new SecretProtocolError();
  }

  const nonce = decodeBase64url(candidate.nonce, NONCE_BYTES);
  const ciphertext = decodeBase64url(candidate.ciphertext);
  if (
    ciphertext.byteLength < TAG_BYTES + 1 ||
    ciphertext.byteLength > MAX_PLAINTEXT_BYTES + TAG_BYTES
  ) {
    throw new SecretProtocolError();
  }
  const ad = validateAssociatedData(candidate.ad);
  const envelope: OuzkEnvelopeV1 = {
    version: candidate.version,
    alg: candidate.alg,
    nonce: candidate.nonce,
    ciphertext: candidate.ciphertext,
    ad
  };
  if (countUtf8Bytes(JSON.stringify(envelope)) > MAX_ENVELOPE_BYTES) {
    throw new SecretProtocolError();
  }
  nonce.fill(0);
  ciphertext.fill(0);
  canonicalAssociatedData(ad);
  return envelope;
}

export function parseFragmentKey(fragment: string): BrowserBytes {
  const raw = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  const parts = raw.split("&");
  if (parts.length !== 2 || !parts[0]?.startsWith("k=") || parts[1] !== `v=${OUZK_VERSION}`) {
    throw new SecretProtocolError();
  }
  const key = parts[0].slice(2);
  if (`k=${key}&v=${OUZK_VERSION}` !== raw) {
    throw new SecretProtocolError();
  }
  return decodeBase64url(key, KEY_BYTES);
}

export function buildRecipientFragment(keyBase64url: string): string {
  const keyBytes = decodeBase64url(keyBase64url, KEY_BYTES);
  keyBytes.fill(0);
  return `#k=${keyBase64url}&v=${OUZK_VERSION}`;
}

export function encodeBase64url(input: Uint8Array): string {
  let binary = "";
  for (const byte of input) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function decodeBase64url(input: string, expectedBytes?: number): BrowserBytes {
  if (!base64urlPattern.test(input) || input.includes("=") || input.length % 4 === 1) {
    throw new SecretProtocolError();
  }
  try {
    const padded = input
      .replaceAll("-", "+")
      .replaceAll("_", "/")
      .padEnd(Math.ceil(input.length / 4) * 4, "=");
    const binary = atob(padded);
    const output = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (
      encodeBase64url(output) !== input ||
      (expectedBytes !== undefined && output.byteLength !== expectedBytes)
    ) {
      output.fill(0);
      throw new SecretProtocolError();
    }
    return output;
  } catch (error) {
    if (error instanceof SecretProtocolError) {
      throw error;
    }
    throw new SecretProtocolError();
  }
}

function validateAssociatedData(candidate: unknown): OuzkAssociatedDataV1 {
  if (!isRecord(candidate) || !hasExactKeys(candidate, associatedDataKeys)) {
    throw new SecretProtocolError();
  }
  if (
    Object.values(candidate).some((value) => typeof value !== "string") ||
    candidate.kind !== "secret" ||
    candidate.purpose !== OUZK_PURPOSE ||
    candidate.version !== OUZK_VERSION
  ) {
    throw new SecretProtocolError();
  }
  return candidate as unknown as OuzkAssociatedDataV1;
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const candidateKeys = Object.keys(value);
  return (
    candidateKeys.length === keys.length && keys.every((key, index) => candidateKeys[index] === key)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function secureRandomBytes(length: number): BrowserBytes {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function exactRandomBytes(source: RandomBytesSource, length: number): BrowserBytes {
  const sourceBytes = source(length);
  try {
    return copyExactBytes(sourceBytes, length);
  } finally {
    if (sourceBytes instanceof Uint8Array) {
      sourceBytes.fill(0);
    }
  }
}

function copyExactBytes(value: Uint8Array, length: number): BrowserBytes {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    throw new SecretProtocolError();
  }
  return new Uint8Array(value);
}
