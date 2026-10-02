import { createHash, createPublicKey, verify } from "node:crypto";
import { z } from "zod";

export const SHA = z.string().regex(/^[a-f0-9]{40}$/u);
export const DIGEST = z.string().regex(/^[a-f0-9]{64}$/u);
export const PUBLIC_REPOSITORY = "mistyislesoftware/onceurl-public";
export const MANIFEST_PATH = "publication/manifest.json";
export const SIGNATURE_PATH = "publication/signature.json";
export const PUBLIC_KEY_PATH = "publication/verification-key.pem";
export function assert(value, message) {
  if (!value) throw new Error(message);
}

// Restricted canonical JSON: schema keys are ASCII, numbers are safe integers,
// no optional/undefined values. Recursive key order is lexical, arrays retain order.
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(",")}}`;
  }
  assert(
    value === null ||
      typeof value === "string" ||
      typeof value === "boolean" ||
      Number.isSafeInteger(value),
    "Unsupported canonical value"
  );
  return JSON.stringify(value);
}
export const encode = (value) => Buffer.from(`${canonical(value)}\n`, "utf8");
export const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function safePath(path) {
  assert(typeof path === "string" && /^[A-Za-z0-9_.\-/]+$/u.test(path), "Invalid path");
  assert(
    !path.startsWith("/") &&
      !path
        .split("/")
        .some(
          (part) =>
            part === "" ||
            part === "." ||
            part === ".." ||
            part.endsWith(".") ||
            /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/iu.test(part)
        ),
    "Unsafe path"
  );
  assert(!path.split("/").some((part) => part.toLowerCase() === ".git"), "Git metadata prohibited");
  return path;
}
export const pathSchema = z.string().superRefine((path, ctx) => {
  try {
    safePath(path);
  } catch {
    ctx.addIssue({ code: "custom", message: "Unsafe path" });
  }
});
export const fileSchema = z.strictObject({
  path: pathSchema,
  mode: z.enum(["100644", "100755"]),
  size: z.number().int().nonnegative().max(10_000_000),
  sha256: DIGEST
});
const bootstrapManifestSchema = z.strictObject({
  schemaVersion: z.literal(1),
  purpose: z.literal("onceurl.publication.v1"),
  canonicalSourceSha: SHA,
  policyDigest: DIGEST,
  exporterDigest: DIGEST,
  publicRepository: z.literal(PUBLIC_REPOSITORY),
  publicBranch: z.literal("main"),
  files: z.array(fileSchema).min(1).max(10000),
  exportDigest: DIGEST
});
export const publicationParentSchema = z.strictObject({
  publicationSequence: z.number().int().min(2).safe(),
  previousAcceptedDigest: DIGEST,
  previousPublicSourceSha: SHA,
  signerFingerprint: DIGEST
});
export const manifestSchema = z.union([
  bootstrapManifestSchema,
  bootstrapManifestSchema.extend({
    schemaVersion: z.literal(2),
    purpose: z.literal("onceurl.publication.v2"),
    publication: publicationParentSchema
  })
]);
export function parseManifest(bytes) {
  const manifest = manifestSchema.parse(JSON.parse(bytes.toString("utf8")));
  assert(encode(manifest).equals(bytes), "Manifest is not canonical JSON");
  const paths = manifest.files.map((file) => file.path);
  assert(
    new Set(paths.map((p) => p.toLowerCase())).size === paths.length,
    "Duplicate/case-colliding paths"
  );
  assert(
    JSON.stringify(paths) === JSON.stringify([...paths].sort()),
    "Manifest paths must be sorted"
  );
  assert(
    !paths.includes(MANIFEST_PATH) &&
      !paths.includes(SIGNATURE_PATH) &&
      !paths.includes(PUBLIC_KEY_PATH),
    "Manifest recursion/envelope path"
  );
  assert(digest(encode(manifest.files)) === manifest.exportDigest, "Aggregate digest mismatch");
  return manifest;
}

export const signatureSchema = z.strictObject({
  schemaVersion: z.literal(1),
  algorithm: z.literal("Ed25519"),
  keyFingerprint: DIGEST,
  manifestDigest: DIGEST,
  signature: z.string().regex(/^[A-Za-z0-9+/]{86}==$/u)
});
export function keyFingerprint(pem) {
  const text = Buffer.isBuffer(pem) ? pem.toString("utf8") : pem;
  assert(
    typeof text === "string" && text.startsWith("-----BEGIN PUBLIC KEY-----\n"),
    "Only public SPKI PEM is permitted"
  );
  const key = createPublicKey(pem);
  assert(key.asymmetricKeyType === "ed25519", "Expected Ed25519 public key");
  assert(key.export({ type: "spki", format: "pem" }) === text, "Noncanonical public key PEM");
  return digest(key.export({ type: "spki", format: "der" }));
}
export function verifyProvenance(manifestBytes, signatureBytes, publicKey, trustedFingerprint) {
  const manifest = parseManifest(manifestBytes);
  DIGEST.parse(trustedFingerprint);
  assert(keyFingerprint(publicKey) === trustedFingerprint, "Untrusted publication key");
  const signature = signatureSchema.parse(JSON.parse(signatureBytes.toString("utf8")));
  assert(encode(signature).equals(signatureBytes), "Noncanonical signature envelope");
  assert(signature.keyFingerprint === trustedFingerprint, "Signature key mismatch");
  assert(signature.manifestDigest === digest(manifestBytes), "Manifest digest mismatch");
  const raw = Buffer.from(signature.signature, "base64");
  assert(raw.toString("base64") === signature.signature, "Noncanonical signature");
  assert(verify(null, manifestBytes, publicKey, raw), "Invalid provenance signature");
  return manifest;
}

// This is an additional tripwire, never a claim of exhaustive secret detection.
export function scanPublicContent(path, bytes) {
  safePath(path);
  assert(
    !/(?:^|\/)(?:AGENTS\.md|PRODUCT_SPEC(?:\.md|\.pdf)|ARCHITECTURE_DECISIONS\.md|\.env(?:\..*)?|\.dev\.vars|\.wrangler|node_modules)(?:\/|$)/iu.test(
      path
    ),
    "Nonexportable path"
  );
  const text = bytes.toString("utf8");
  assert(
    Buffer.from(text).equals(bytes) && !text.includes("\0"),
    "Only UTF-8 text is classified in version 1"
  );
  assert(
    !/linear\.app|chatgpt\.com\/|chat\.openai\.com\/|codex:\/\/|-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----|\bgh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|\bAKIA[A-Z0-9]{16}/iu.test(
      text
    ),
    "Private identity or secret marker"
  );
}

export const evidenceIdentitySchema = z.strictObject({
  canonicalSourceSha: SHA,
  publicSourceSha: SHA,
  exportDigest: DIGEST,
  publicCiWorkflowRunId: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  workflowRunId: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  workflowRunAttempt: z.number().int().positive().max(1000)
});
export const freshnessSchema = z.strictObject({
  schemaVersion: z.literal(1),
  ...evidenceIdentitySchema.shape,
  purpose: z.enum(["onceurl.staging.release.v1", "onceurl.staging.campaign.v1"]),
  audience: z.literal("onceurl-public:staging"),
  nonce: z.string().regex(/^[a-f0-9]{64}$/u),
  issuedAt: z.number().int().nonnegative(),
  expiresAt: z.number().int().positive()
});
export function validateFreshness(value, expected, now) {
  const assertion = freshnessSchema.parse(value);
  assert(Number.isSafeInteger(now), "Invalid verifier clock");
  assert(
    assertion.expiresAt > assertion.issuedAt && assertion.expiresAt - assertion.issuedAt <= 60,
    "Invalid assertion lifetime"
  );
  assert(
    now >= assertion.issuedAt && now < assertion.expiresAt,
    "Assertion expired or future issued"
  );
  for (const field of [
    ...Object.keys(evidenceIdentitySchema.shape),
    "purpose",
    "audience",
    "nonce"
  ]) {
    assert(
      expected[field] !== undefined && assertion[field] === expected[field],
      `Freshness ${field} mismatch`
    );
  }
  return assertion;
}
