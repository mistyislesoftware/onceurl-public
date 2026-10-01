import { z } from "zod";
import type { WorkerEnv } from "./env";

export type ExactIpQuotaKind = "preparation" | "passive" | "reveal";
export type TurnstileAction = "onceurl_prepare" | "onceurl_access_code";

const ABUSE_DIGEST_DOMAIN = "onceurl.abuse-ip-digest.v1\u0000";
const CHALLENGE_DIGEST_DOMAIN = "onceurl.challenge-digest.v1\u0000";
const CHALLENGE_TICKET_DOMAIN = "onceurl.challenge-ticket.v2\u0000";
const CHALLENGE_LIFETIME_MS = 5 * 60 * 1_000;
const canonicalKeyPattern = /^[A-Za-z0-9_-]{43}$/u;
const challengeIdPattern = /^chl2_([pa])_(\d{1,16})_([A-Za-z0-9_-]{22})_([A-Za-z0-9_-]{43})$/u;

const abuseControlResultSchema = z.union([
  z.strictObject({ ok: z.literal(true) }),
  z.strictObject({ ok: z.literal(true), verified: z.boolean() }),
  z.strictObject({ ok: z.literal(false), code: z.string(), retryAfter: z.number().optional() })
]);

type AbuseControlResult = z.infer<typeof abuseControlResultSchema>;

interface HmacKeySet {
  readonly current: CryptoKey;
  readonly previous?: CryptoKey;
}

interface ParsedChallengeTicket {
  readonly createdAt: number;
}

export class AbuseControlConfigurationError extends Error {
  constructor() {
    super("Abuse-control configuration is unavailable");
    this.name = "AbuseControlConfigurationError";
  }
}

export class AbuseControlDependencyError extends Error {
  constructor() {
    super("Abuse-control dependency is unavailable");
    this.name = "AbuseControlDependencyError";
  }
}

export function canonicalizeClientIp(value: unknown): string | null {
  if (typeof value !== "string" || value === "" || value !== value.trim()) {
    return null;
  }

  if (!value.includes(":")) {
    const parts = value.split(".");
    if (
      parts.length !== 4 ||
      parts.some(
        (part) =>
          !/^(0|[1-9]\d{0,2})$/u.test(part) || Number(part) > 255 || String(Number(part)) !== part
      )
    ) {
      return null;
    }
    return parts.join(".");
  }

  if (value.includes("%") || value.includes("[") || value.includes("]")) {
    return null;
  }
  try {
    const hostname = new URL(`http://[${value}]/`).hostname;
    if (!hostname.startsWith("[") || !hostname.endsWith("]")) {
      return null;
    }
    return hostname.slice(1, -1).toLowerCase();
  } catch {
    return null;
  }
}

export async function deriveIpDigests(
  canonicalIp: string,
  env: Pick<WorkerEnv, "ABUSE_IP_HMAC_KEY" | "ABUSE_IP_HMAC_PREVIOUS_KEY">
): Promise<readonly string[]> {
  const keys = await importHmacKeys(env);
  const current = await hmacDigest(keys.current, ABUSE_DIGEST_DOMAIN, canonicalIp, "ipd1_");
  if (keys.previous === undefined) {
    return [current];
  }
  const previous = await hmacDigest(keys.previous, ABUSE_DIGEST_DOMAIN, canonicalIp, "ipd1_");
  return previous === current ? [current] : [previous, current];
}

export async function consumeExactIpQuota(
  env: WorkerEnv,
  canonicalIp: string,
  kind: ExactIpQuotaKind,
  now: number
): Promise<{ readonly allowed: true } | { readonly allowed: false; readonly retryAfter: number }> {
  const digests = await deriveIpDigests(canonicalIp, env);
  const currentDigest = digests[digests.length - 1];
  if (currentDigest === undefined) {
    throw new AbuseControlConfigurationError();
  }
  const currentObjectName = `ip:${currentDigest}`;
  const previousDigest = digests.length === 2 ? digests[0] : undefined;
  if (previousDigest !== undefined) {
    const handoff = await abuseObjectCommand(
      env,
      `ip:${previousDigest}`,
      "/internal/abuse/handoff",
      { targetObjectName: currentObjectName, now }
    );
    if (!handoff.ok) throw new AbuseControlDependencyError();
  }

  const result = await abuseObjectCommand(env, currentObjectName, "/internal/abuse/quota", {
    kind,
    now
  });
  if (result.ok) return { allowed: true };
  if (result.code === "rate_limited" && validRetryAfter(result.retryAfter)) {
    return { allowed: false, retryAfter: result.retryAfter };
  }
  throw new AbuseControlDependencyError();
}

export async function coarsePreparationAllowed(
  env: WorkerEnv,
  currentDigest: string
): Promise<boolean> {
  const limiter = env.PREPARATION_FLOOD_LIMITER;
  if (limiter === undefined) {
    throw new AbuseControlDependencyError();
  }
  try {
    const outcome = await limiter.limit({
      key: `${env.DEPLOYMENT_ENVIRONMENT}:prepare:${currentDigest}`
    });
    return outcome.success;
  } catch {
    throw new AbuseControlDependencyError();
  }
}

export async function createChallengeTicket(
  env: WorkerEnv,
  action: TurnstileAction,
  now: number
): Promise<string> {
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new AbuseControlConfigurationError();
  }
  const keys = await importHmacKeys(env);
  const actionCode = action === "onceurl_prepare" ? "p" : "a";
  const nonce = base64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
  const unsigned = `chl2_${actionCode}_${now}_${nonce}`;
  const signature = await hmacDigest(keys.current, CHALLENGE_TICKET_DOMAIN, unsigned, "");
  return `${unsigned}_${signature}`;
}

export async function markChallengeVerified(
  env: WorkerEnv,
  challengeId: string,
  action: TurnstileAction,
  now: number
): Promise<boolean> {
  const ticket = await parseChallengeTicket(env, challengeId, action, now);
  if (ticket === null) return false;
  const objectName = (await challengeObjectNames(env, challengeId))[0];
  if (objectName === undefined) throw new AbuseControlConfigurationError();
  const result = await abuseObjectCommand(env, objectName, "/internal/challenge/create-verified", {
    action,
    createdAt: ticket.createdAt,
    now
  });
  if (result.ok) return true;
  if (result.code === "unavailable") return false;
  throw new AbuseControlDependencyError();
}

export async function readChallengeStatus(
  env: WorkerEnv,
  challengeId: string,
  action: TurnstileAction,
  now: number
): Promise<boolean | null> {
  if ((await parseChallengeTicket(env, challengeId, action, now)) === null) return null;
  for (const objectName of await challengeObjectNames(env, challengeId)) {
    const result = await abuseObjectCommand(env, objectName, "/internal/challenge/status", {
      action,
      now
    });
    if (result.ok && "verified" in result) return result.verified;
    if (!result.ok && result.code === "unavailable") continue;
    throw new AbuseControlDependencyError();
  }
  return false;
}

export async function consumeChallengeTicket(
  env: WorkerEnv,
  challengeId: string,
  action: TurnstileAction,
  now: number
): Promise<boolean> {
  if ((await parseChallengeTicket(env, challengeId, action, now)) === null) return false;
  const objectName = await findChallengeObject(env, challengeId, action, now);
  if (objectName === null) return false;
  const result = await abuseObjectCommand(env, objectName, "/internal/challenge/consume", {
    action,
    now
  });
  if (result.ok) return true;
  if (result.code === "unavailable") return false;
  throw new AbuseControlDependencyError();
}

async function findChallengeObject(
  env: WorkerEnv,
  challengeId: string,
  action: TurnstileAction,
  now: number
): Promise<string | null> {
  for (const objectName of await challengeObjectNames(env, challengeId)) {
    const result = await abuseObjectCommand(env, objectName, "/internal/challenge/status", {
      action,
      now
    });
    if (result.ok && "verified" in result) return objectName;
    if (!result.ok && result.code === "unavailable") continue;
    throw new AbuseControlDependencyError();
  }
  return null;
}

async function challengeObjectNames(env: WorkerEnv, challengeId: string): Promise<string[]> {
  if (!challengeIdPattern.test(challengeId)) return [];
  const keys = await importHmacKeys(env);
  const names = [
    `challenge:${await hmacDigest(keys.current, CHALLENGE_DIGEST_DOMAIN, challengeId, "chd1_")}`
  ];
  if (keys.previous !== undefined) {
    const previous = `challenge:${await hmacDigest(
      keys.previous,
      CHALLENGE_DIGEST_DOMAIN,
      challengeId,
      "chd1_"
    )}`;
    if (!names.includes(previous)) names.push(previous);
  }
  return names;
}

async function parseChallengeTicket(
  env: Pick<WorkerEnv, "ABUSE_IP_HMAC_KEY" | "ABUSE_IP_HMAC_PREVIOUS_KEY">,
  challengeId: string,
  action: TurnstileAction,
  now: number
): Promise<ParsedChallengeTicket | null> {
  const match = challengeIdPattern.exec(challengeId);
  if (match === null || !Number.isSafeInteger(now) || now < 0) return null;
  const [, actionCode, createdAtText, nonce, signatureText] = match;
  if (
    actionCode !== (action === "onceurl_prepare" ? "p" : "a") ||
    createdAtText === undefined ||
    nonce === undefined ||
    signatureText === undefined ||
    !/^(0|[1-9]\d*)$/u.test(createdAtText)
  ) {
    return null;
  }
  const createdAt = Number(createdAtText);
  if (
    !Number.isSafeInteger(createdAt) ||
    createdAt < 0 ||
    createdAt > now ||
    now > createdAt + CHALLENGE_LIFETIME_MS
  ) {
    return null;
  }
  const unsigned = `chl2_${actionCode}_${createdAtText}_${nonce}`;
  const signature = base64urlDecode(signatureText, 32);
  if (signature === null) return null;
  const keys = await importHmacKeys(env);
  try {
    if (await verifyHmac(keys.current, CHALLENGE_TICKET_DOMAIN, unsigned, signature)) {
      return { createdAt };
    }
    if (
      keys.previous !== undefined &&
      (await verifyHmac(keys.previous, CHALLENGE_TICKET_DOMAIN, unsigned, signature))
    ) {
      return { createdAt };
    }
    return null;
  } finally {
    signature.fill(0);
  }
}

async function importHmacKeys(
  env: Pick<WorkerEnv, "ABUSE_IP_HMAC_KEY" | "ABUSE_IP_HMAC_PREVIOUS_KEY">
): Promise<HmacKeySet> {
  const currentBytes = decodeCanonicalKey(env.ABUSE_IP_HMAC_KEY);
  const previousBytes =
    env.ABUSE_IP_HMAC_PREVIOUS_KEY === undefined
      ? undefined
      : decodeCanonicalKey(env.ABUSE_IP_HMAC_PREVIOUS_KEY);
  if (!(currentBytes instanceof Uint8Array) || previousBytes === null) {
    throw new AbuseControlConfigurationError();
  }
  try {
    const current = await crypto.subtle.importKey(
      "raw",
      currentBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
    const previous =
      previousBytes === undefined
        ? undefined
        : await crypto.subtle.importKey(
            "raw",
            previousBytes,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign", "verify"]
          );
    return { current, ...(previous === undefined ? {} : { previous }) };
  } catch {
    throw new AbuseControlConfigurationError();
  } finally {
    currentBytes.fill(0);
    previousBytes?.fill(0);
  }
}

async function hmacDigest(
  key: CryptoKey,
  domain: string,
  value: string,
  prefix: string
): Promise<string> {
  const digest = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(domain + value));
  return `${prefix}${base64urlEncode(new Uint8Array(digest))}`;
}

function verifyHmac(
  key: CryptoKey,
  domain: string,
  value: string,
  signature: Uint8Array
): Promise<boolean> {
  return crypto.subtle.verify("HMAC", key, signature, new TextEncoder().encode(domain + value));
}

function decodeCanonicalKey(value: unknown): Uint8Array | null | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !canonicalKeyPattern.test(value)) return null;
  try {
    const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=";
    const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    return bytes.byteLength === 32 && base64urlEncode(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

function base64urlDecode(value: string, expectedLength: number): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/u.test(value) || value.length % 4 === 1) return null;
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

async function abuseObjectCommand(
  env: WorkerEnv,
  objectName: string,
  path: string,
  command: unknown
): Promise<AbuseControlResult> {
  const namespace = env.ABUSE_CONTROL;
  if (namespace === undefined) throw new AbuseControlDependencyError();
  try {
    const response = await namespace.getByName(objectName).fetch(
      new Request(`https://abuse-control.internal${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(command)
      })
    );
    return abuseControlResultSchema.parse(await response.json());
  } catch (error) {
    if (error instanceof AbuseControlConfigurationError) throw error;
    throw new AbuseControlDependencyError();
  }
}

function validRetryAfter(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
