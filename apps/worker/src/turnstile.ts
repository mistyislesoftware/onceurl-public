import { z } from "zod";
import type { TurnstileAction } from "./abuse-control";

const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const TOKEN_VALIDITY_MS = 5 * 60 * 1_000;
const SITEVERIFY_TIMEOUT_MS = 5_000;

const tokenSchema = z.string().min(1).max(2_048);
const siteKeySchema = z.string().regex(/^[A-Za-z0-9_-]{3,128}$/u);
const siteverifyResponseSchema = z.object({
  success: z.boolean(),
  challenge_ts: z.string().optional(),
  hostname: z.string().optional(),
  action: z.string().optional(),
  "error-codes": z.array(z.string()).optional()
});

export type TurnstileVerificationResult = "verified" | "rejected";

export class TurnstileDependencyError extends Error {
  constructor() {
    super("Turnstile verification is unavailable");
    this.name = "TurnstileDependencyError";
  }
}

export async function verifyTurnstileToken(
  token: unknown,
  action: TurnstileAction,
  expectedHostname: string,
  secretKey: unknown,
  now: number,
  fetcher: typeof fetch = fetch
): Promise<TurnstileVerificationResult> {
  const parsedToken = tokenSchema.safeParse(token);
  if (!parsedToken.success) return "rejected";
  if (typeof secretKey !== "string" || secretKey.length < 1 || secretKey.length > 256) {
    throw new TurnstileDependencyError();
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), SITEVERIFY_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetcher(SITEVERIFY_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        secret: secretKey,
        response: parsedToken.data,
        idempotency_key: crypto.randomUUID()
      }),
      signal: controller.signal
    });
  } catch {
    throw new TurnstileDependencyError();
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    throw new TurnstileDependencyError();
  }

  let candidate: unknown;
  try {
    candidate = await response.json();
  } catch {
    throw new TurnstileDependencyError();
  }
  const parsed = siteverifyResponseSchema.safeParse(candidate);
  if (!parsed.success) {
    throw new TurnstileDependencyError();
  }
  const verification = parsed.data;
  if (!verification.success) {
    const dependencyCodes = new Set([
      "internal-error",
      "bad-request",
      "missing-input-secret",
      "invalid-input-secret"
    ]);
    if ((verification["error-codes"] ?? []).some((code) => dependencyCodes.has(code))) {
      throw new TurnstileDependencyError();
    }
    return "rejected";
  }

  const challengedAt = Date.parse(verification.challenge_ts ?? "");
  if (
    verification.hostname !== expectedHostname ||
    verification.action !== action ||
    !Number.isFinite(challengedAt) ||
    challengedAt > now + 5_000 ||
    now - challengedAt > TOKEN_VALIDITY_MS
  ) {
    return "rejected";
  }
  return "verified";
}

export function turnstileChallengeDocument(siteKey: unknown): string | null {
  const parsed = siteKeySchema.safeParse(siteKey);
  if (!parsed.success) return null;
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="robots" content="noindex,nofollow,noarchive">
    <meta name="onceurl-turnstile-sitekey" content="${parsed.data}">
    <title>OnceURL security check</title>
    <script src="/challenge/client.js" defer></script>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onceUrlTurnstileReady&render=explicit" defer></script>
  </head>
  <body>
    <main>
      <h1>Complete the security check</h1>
      <p>This separate page cannot see the secret, capability URL, or account state.</p>
      <div id="turnstile-widget"></div>
      <p id="challenge-status" role="status">Loading security check...</p>
    </main>
  </body>
</html>`;
}

export const TURNSTILE_CHALLENGE_CLIENT = `(() => {
  const status = document.getElementById("challenge-status");
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const challengeId = fragment.get("c");
  const action = fragment.get("a");
  const valid = fragment.size === 2 && /^chl2_[pa]_\\d{1,16}_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}$/.test(challengeId || "") &&
    (action === "onceurl_prepare" || action === "onceurl_access_code");
  window.history.replaceState(null, "", window.location.pathname);
  if (!valid) {
    if (status) status.textContent = "This security check is unavailable.";
    return;
  }
  const sitekey = document.querySelector('meta[name="onceurl-turnstile-sitekey"]')?.getAttribute("content");
  window.onceUrlTurnstileReady = () => {
    window.turnstile.render("#turnstile-widget", {
      sitekey,
      action,
      callback: async (token) => {
        if (status) status.textContent = "Verifying...";
        try {
          const response = await fetch("/api/v1/challenges/verify", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ challenge_id: challengeId, action, token })
          });
          if (!response.ok) throw new Error("rejected");
          if (status) status.textContent = "Security check complete. You may close this page.";
        } catch {
          if (status) status.textContent = "The security check did not complete. Refresh and try again.";
          window.turnstile.reset();
        }
      },
      "error-callback": () => {
        if (status) status.textContent = "The security check is unavailable. Refresh and try again.";
      },
      "expired-callback": () => {
        if (status) status.textContent = "The security check expired. Please try again.";
      }
    });
  };
})();`;
