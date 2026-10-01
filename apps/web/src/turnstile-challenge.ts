export type ChallengeAction = "onceurl_prepare" | "onceurl_access_code";

export interface ChallengeTicket {
  readonly id: string;
  readonly action: ChallengeAction;
}

const challengeTicketPattern = /^chl2_[pa]_\d{1,16}_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}$/u;

export async function requestChallenge(action: "onceurl_prepare"): Promise<ChallengeTicket> {
  const response = await fetch("/api/v1/challenges", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ action })
  });
  const body: unknown = await safeJson(response);
  if (
    !response.ok ||
    !isRecord(body) ||
    !hasExactKeys(body, ["challenge_id", "expires_in_seconds"]) ||
    typeof body.challenge_id !== "string" ||
    !challengeTicketPattern.test(body.challenge_id) ||
    body.expires_in_seconds !== 300
  ) {
    throw new Error("The security check is unavailable.");
  }
  return { id: body.challenge_id, action };
}

export function accessCodeChallengeFromDetails(details: unknown): ChallengeTicket | null {
  if (
    !isRecord(details) ||
    !hasExactKeys(details, ["challenge_id", "expires_in_seconds"]) ||
    typeof details.challenge_id !== "string" ||
    !/^chl2_a_\d{1,16}_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}$/u.test(details.challenge_id) ||
    details.expires_in_seconds !== 300
  ) {
    return null;
  }
  return { id: details.challenge_id, action: "onceurl_access_code" };
}

export async function challengeIsVerified(ticket: ChallengeTicket): Promise<boolean> {
  const response = await fetch("/api/v1/challenges/status", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ challenge_id: ticket.id, action: ticket.action })
  });
  const body: unknown = await safeJson(response);
  if (
    !response.ok ||
    !isRecord(body) ||
    !hasExactKeys(body, ["verified"]) ||
    typeof body.verified !== "boolean"
  ) {
    throw new Error("The security check is unavailable.");
  }
  return body.verified;
}

export function challengeUrl(ticket: ChallengeTicket): string {
  return `/challenge#c=${encodeURIComponent(ticket.id)}&a=${encodeURIComponent(ticket.action)}`;
}

async function safeJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const candidateKeys = Object.keys(value);
  return candidateKeys.length === keys.length && keys.every((key) => candidateKeys.includes(key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
