import { DurableObject } from "cloudflare:workers";
import { z } from "zod";
import type { WorkerEnv } from "./env";

const QUOTA_RECORD_KEY = "abuse:v1:quota";
const QUOTA_HANDOFF_KEY = "abuse:v1:quota-handoff";
const ACCEPTED_HANDOFF_KEY = "abuse:v1:accepted-handoff";
const CHALLENGE_RECORD_KEY = "abuse:v1:challenge";
const MAX_STATE_LIFETIME_MS = 24 * 60 * 60 * 1_000;
const CHALLENGE_LIFETIME_MS = 5 * 60 * 1_000;
const ipObjectName = z.string().regex(/^ip:ipd1_[A-Za-z0-9_-]{43}$/u);
const handoffId = z.string().regex(/^hof1_[A-Za-z0-9_-]{43}$/u);

const epochMilliseconds = z.number().refine((value) => Number.isSafeInteger(value) && value >= 0);

const quotaCommandSchema = z.strictObject({
  kind: z.enum(["preparation", "passive", "reveal"]),
  now: epochMilliseconds
});

const challengeCreateVerifiedSchema = z.strictObject({
  action: z.enum(["onceurl_prepare", "onceurl_access_code"]),
  createdAt: epochMilliseconds,
  now: epochMilliseconds
});

const challengeStateCommandSchema = z.strictObject({
  action: z.enum(["onceurl_prepare", "onceurl_access_code"]),
  now: epochMilliseconds
});

const quotaRecordSchema = z.strictObject({
  schemaVersion: z.literal(1),
  preparation: z.array(epochMilliseconds).max(60),
  passive: z.array(epochMilliseconds).max(120),
  reveal: z.array(epochMilliseconds).max(30)
});

const quotaHandoffCommandSchema = z.strictObject({
  targetObjectName: ipObjectName,
  now: epochMilliseconds
});

const quotaHandoffRecordSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    handoffId,
    targetObjectName: ipObjectName,
    snapshot: quotaRecordSchema.nullable(),
    startedAt: epochMilliseconds,
    expiresAt: epochMilliseconds,
    completed: z.boolean()
  })
  .refine(
    (record) =>
      record.expiresAt > record.startedAt && record.completed === (record.snapshot === null)
  );

const acceptHandoffCommandSchema = z.strictObject({
  handoffId,
  snapshot: quotaRecordSchema,
  now: epochMilliseconds
});

const acceptedHandoffRecordSchema = z.strictObject({
  schemaVersion: z.literal(1),
  handoffId,
  acceptedAt: epochMilliseconds
});

const challengeRecordSchema = z.strictObject({
  schemaVersion: z.literal(1),
  action: z.enum(["onceurl_prepare", "onceurl_access_code"]),
  createdAt: epochMilliseconds,
  expiresAt: epochMilliseconds,
  verifiedAt: epochMilliseconds,
  consumedAt: epochMilliseconds.nullable()
});

type QuotaKind = z.infer<typeof quotaCommandSchema>["kind"];
type QuotaRecord = z.infer<typeof quotaRecordSchema>;
type ChallengeAction = z.infer<typeof challengeCreateVerifiedSchema>["action"];
type ChallengeRecord = z.infer<typeof challengeRecordSchema>;
type QuotaHandoffRecord = z.infer<typeof quotaHandoffRecordSchema>;
type QuotaDecision =
  | { readonly type: "forward"; readonly handoff: QuotaHandoffRecord }
  | { readonly type: "result"; readonly result: AbuseControlResult };

type AbuseControlResult =
  | { readonly ok: true }
  | { readonly ok: true; readonly verified: boolean }
  | { readonly ok: false; readonly code: "invalid_command" | "invalid_state" | "unavailable" }
  | { readonly ok: false; readonly code: "rate_limited"; readonly retryAfter: number };

export class AbuseControlDurableObject extends DurableObject<WorkerEnv> {
  override async fetch(request: Request): Promise<Response> {
    const pathname = new URL(request.url).pathname;
    if (
      ![
        "/internal/abuse/quota",
        "/internal/abuse/handoff",
        "/internal/abuse/accept-handoff",
        "/internal/challenge/create-verified",
        "/internal/challenge/status",
        "/internal/challenge/consume"
      ].includes(pathname)
    ) {
      return jsonResponse({ ok: false, code: "not_found" }, 404);
    }
    if (request.method !== "POST") {
      return jsonResponse({ ok: false, code: "method_not_allowed" }, 405, { allow: "POST" });
    }

    let command: unknown;
    try {
      command = await request.json();
    } catch {
      return jsonResponse({ ok: false, code: "invalid_command" }, 400);
    }

    try {
      const result = await this.execute(pathname, command);
      return jsonResponse(result, statusForResult(result));
    } catch {
      return jsonResponse({ ok: false, code: "internal_error" }, 500);
    }
  }

  override async alarm(): Promise<void> {
    const storedQuota = await this.ctx.storage.get(QUOTA_RECORD_KEY);
    const storedHandoff = await this.ctx.storage.get(QUOTA_HANDOFF_KEY);
    const storedAcceptedHandoff = await this.ctx.storage.get(ACCEPTED_HANDOFF_KEY);
    const storedChallenge = await this.ctx.storage.get(CHALLENGE_RECORD_KEY);
    const quota = parseQuotaRecord(storedQuota);
    const handoff = parseQuotaHandoffRecord(storedHandoff);
    const acceptedHandoff = parseAcceptedHandoffRecord(storedAcceptedHandoff);
    const challenge = parseChallengeRecord(storedChallenge);
    if (
      (storedQuota !== undefined && quota === null) ||
      (storedHandoff !== undefined && handoff === null) ||
      (storedAcceptedHandoff !== undefined && acceptedHandoff === null) ||
      (storedChallenge !== undefined && challenge === null)
    ) {
      throw new Error("Malformed abuse-control state");
    }
    const now = Date.now();
    const latestQuotaEvent = quota === null ? null : latestEvent(quota);
    const quotaStillRelevant =
      latestQuotaEvent !== null && latestQuotaEvent + MAX_STATE_LIFETIME_MS > now;
    const handoffStillRelevant = handoff !== null && handoff.expiresAt > now;
    const acceptedHandoffStillRelevant =
      acceptedHandoff !== null && acceptedHandoff.acceptedAt + MAX_STATE_LIFETIME_MS > now;
    const challengeStillRelevant = challenge !== null && challenge.expiresAt > now;

    if (
      !quotaStillRelevant &&
      !handoffStillRelevant &&
      !acceptedHandoffStillRelevant &&
      !challengeStillRelevant
    ) {
      await this.ctx.storage.deleteAll();
      return;
    }

    if (!quotaStillRelevant) await this.ctx.storage.delete(QUOTA_RECORD_KEY);
    if (!acceptedHandoffStillRelevant) await this.ctx.storage.delete(ACCEPTED_HANDOFF_KEY);
    if (!challengeStillRelevant) await this.ctx.storage.delete(CHALLENGE_RECORD_KEY);

    const nextAlarm = Math.min(
      quotaStillRelevant ? latestQuotaEvent + MAX_STATE_LIFETIME_MS : Infinity,
      handoffStillRelevant ? handoff.expiresAt : Infinity,
      acceptedHandoffStillRelevant ? acceptedHandoff.acceptedAt + MAX_STATE_LIFETIME_MS : Infinity,
      challengeStillRelevant ? challenge.expiresAt : Infinity
    );
    if (Number.isFinite(nextAlarm)) await this.ctx.storage.setAlarm(nextAlarm);
  }

  private execute(pathname: string, command: unknown): Promise<AbuseControlResult> {
    switch (pathname) {
      case "/internal/abuse/quota":
        return this.consumeQuota(command);
      case "/internal/abuse/handoff":
        return this.handoffQuota(command);
      case "/internal/abuse/accept-handoff":
        return this.acceptHandoff(command);
      case "/internal/challenge/create-verified":
        return this.createVerifiedChallenge(command);
      case "/internal/challenge/status":
        return this.challengeStatus(command);
      case "/internal/challenge/consume":
        return this.consumeChallenge(command);
      default:
        return Promise.resolve({ ok: false, code: "invalid_command" });
    }
  }

  private async consumeQuota(input: unknown): Promise<AbuseControlResult> {
    const parsed = quotaCommandSchema.safeParse(input);
    if (!parsed.success) {
      return { ok: false, code: "invalid_command" };
    }
    const { kind, now } = parsed.data;

    const decision = await this.ctx.storage.transaction<QuotaDecision>(async (txn) => {
      const storedHandoff = await txn.get(QUOTA_HANDOFF_KEY);
      const handoff = parseQuotaHandoffRecord(storedHandoff);
      if (storedHandoff !== undefined && handoff === null) {
        return { type: "result", result: { ok: false, code: "invalid_state" } as const };
      }
      if (handoff !== null && handoff.expiresAt > now) {
        const refreshed = { ...handoff, expiresAt: now + MAX_STATE_LIFETIME_MS };
        await txn.put(QUOTA_HANDOFF_KEY, refreshed);
        return { type: "forward", handoff: refreshed } as const;
      }
      if (handoff !== null) await txn.delete(QUOTA_HANDOFF_KEY);

      const stored = await txn.get(QUOTA_RECORD_KEY);
      const current = stored === undefined ? emptyQuotaRecord() : parseQuotaRecord(stored);
      if (current === null) {
        return { type: "result", result: { ok: false, code: "invalid_state" } as const };
      }

      const record = pruneQuotaRecord(current, now);
      const retryAfter = quotaRetryAfter(record, kind, now);
      if (retryAfter !== null) {
        return {
          type: "result",
          result: { ok: false, code: "rate_limited", retryAfter } as const
        };
      }

      const next: QuotaRecord = { ...record, [kind]: [...record[kind], now] };
      await txn.put(QUOTA_RECORD_KEY, next);
      return { type: "result", result: { ok: true } as const };
    });

    if (decision.type === "forward") {
      if (!(await this.ensureHandoffTransferred(decision.handoff, now))) {
        return { ok: false, code: "unavailable" };
      }
      return this.forwardCommand(decision.handoff.targetObjectName, "/internal/abuse/quota", {
        kind,
        now
      });
    }
    const result = decision.result;
    if (result.ok) {
      await this.scheduleCleanup(now + MAX_STATE_LIFETIME_MS);
    }
    return result;
  }

  private async handoffQuota(input: unknown): Promise<AbuseControlResult> {
    const parsed = quotaHandoffCommandSchema.safeParse(input);
    if (!parsed.success) {
      return { ok: false, code: "invalid_command" };
    }
    const { targetObjectName, now } = parsed.data;
    const handoff = await this.ctx.storage.transaction(async (txn) => {
      const stored = await txn.get(QUOTA_HANDOFF_KEY);
      const existing = parseQuotaHandoffRecord(stored);
      if (stored !== undefined && existing === null) return null;
      if (existing !== null && existing.expiresAt > now) {
        if (existing.targetObjectName !== targetObjectName) return null;
        const refreshed = { ...existing, expiresAt: now + MAX_STATE_LIFETIME_MS };
        await txn.put(QUOTA_HANDOFF_KEY, refreshed);
        return refreshed;
      }
      if (existing !== null) await txn.delete(QUOTA_HANDOFF_KEY);

      const storedQuota = await txn.get(QUOTA_RECORD_KEY);
      const current =
        storedQuota === undefined ? emptyQuotaRecord() : parseQuotaRecord(storedQuota);
      if (current === null) return null;
      const record: QuotaHandoffRecord = {
        schemaVersion: 1,
        handoffId: `hof1_${base64urlEncode(crypto.getRandomValues(new Uint8Array(32)))}`,
        targetObjectName,
        snapshot: pruneQuotaRecord(current, now),
        startedAt: now,
        expiresAt: now + MAX_STATE_LIFETIME_MS,
        completed: false
      };
      await txn.put(QUOTA_HANDOFF_KEY, record);
      return record;
    });
    if (handoff === null || !(await this.ensureHandoffTransferred(handoff, now))) {
      return { ok: false, code: "unavailable" };
    }
    await this.scheduleCleanup(now + MAX_STATE_LIFETIME_MS);
    return { ok: true };
  }

  private async acceptHandoff(input: unknown): Promise<AbuseControlResult> {
    const parsed = acceptHandoffCommandSchema.safeParse(input);
    if (!parsed.success) {
      return { ok: false, code: "invalid_command" };
    }
    const { handoffId: acceptedId, snapshot, now } = parsed.data;
    const result = await this.ctx.storage.transaction(async (txn) => {
      const storedHandoff = await txn.get(QUOTA_HANDOFF_KEY);
      const ownHandoff = parseQuotaHandoffRecord(storedHandoff);
      if (storedHandoff !== undefined && ownHandoff === null) {
        return { ok: false, code: "invalid_state" } as const;
      }
      if (ownHandoff !== null && ownHandoff.expiresAt > now) {
        return { ok: false, code: "unavailable" } as const;
      }
      if (ownHandoff !== null) await txn.delete(QUOTA_HANDOFF_KEY);

      const storedAccepted = await txn.get(ACCEPTED_HANDOFF_KEY);
      const accepted = parseAcceptedHandoffRecord(storedAccepted);
      if (storedAccepted !== undefined && accepted === null) {
        return { ok: false, code: "invalid_state" } as const;
      }
      if (accepted?.handoffId === acceptedId) return { ok: true } as const;

      const storedQuota = await txn.get(QUOTA_RECORD_KEY);
      const current =
        storedQuota === undefined ? emptyQuotaRecord() : parseQuotaRecord(storedQuota);
      if (current === null) return { ok: false, code: "invalid_state" } as const;
      const activeCurrent = pruneQuotaRecord(current, now);
      if (latestEvent(activeCurrent) !== null) {
        return { ok: false, code: "unavailable" } as const;
      }

      await txn.put(QUOTA_RECORD_KEY, pruneQuotaRecord(snapshot, now));
      await txn.put(ACCEPTED_HANDOFF_KEY, {
        schemaVersion: 1,
        handoffId: acceptedId,
        acceptedAt: now
      });
      return { ok: true } as const;
    });
    if (result.ok) await this.scheduleCleanup(now + MAX_STATE_LIFETIME_MS);
    return result;
  }

  private async createVerifiedChallenge(input: unknown): Promise<AbuseControlResult> {
    const parsed = challengeCreateVerifiedSchema.safeParse(input);
    if (!parsed.success) {
      return { ok: false, code: "invalid_command" };
    }
    const { action, createdAt, now } = parsed.data;
    if (createdAt > now || now > createdAt + CHALLENGE_LIFETIME_MS) {
      return { ok: false, code: "unavailable" };
    }
    const result = await this.ctx.storage.transaction(async (txn) => {
      const stored = await txn.get(CHALLENGE_RECORD_KEY);
      if (stored !== undefined) {
        const existing = parseChallengeRecord(stored);
        return existing !== null &&
          existing.action === action &&
          existing.createdAt === createdAt &&
          existing.consumedAt === null
          ? ({ ok: true } as const)
          : ({ ok: false, code: "unavailable" } as const);
      }
      const record: ChallengeRecord = {
        schemaVersion: 1,
        action,
        createdAt,
        expiresAt: createdAt + CHALLENGE_LIFETIME_MS,
        verifiedAt: now,
        consumedAt: null
      };
      await txn.put(CHALLENGE_RECORD_KEY, record);
      return { ok: true } as const;
    });
    if (result.ok) await this.scheduleCleanup(createdAt + CHALLENGE_LIFETIME_MS);
    return result;
  }

  private async challengeStatus(input: unknown): Promise<AbuseControlResult> {
    const parsed = challengeStateCommandSchema.safeParse(input);
    if (!parsed.success) {
      return { ok: false, code: "invalid_command" };
    }
    const record = parseChallengeRecord(await this.ctx.storage.get(CHALLENGE_RECORD_KEY));
    if (
      !validChallenge(record, parsed.data.action, parsed.data.now) ||
      record.consumedAt !== null
    ) {
      return { ok: false, code: "unavailable" };
    }
    return { ok: true, verified: true };
  }

  private async consumeChallenge(input: unknown): Promise<AbuseControlResult> {
    const parsed = challengeStateCommandSchema.safeParse(input);
    if (!parsed.success) {
      return { ok: false, code: "invalid_command" };
    }
    return this.ctx.storage.transaction(async (txn) => {
      const record = parseChallengeRecord(await txn.get(CHALLENGE_RECORD_KEY));
      if (
        !validChallenge(record, parsed.data.action, parsed.data.now) ||
        record.consumedAt !== null
      ) {
        return { ok: false, code: "unavailable" } as const;
      }
      await txn.put(CHALLENGE_RECORD_KEY, { ...record, consumedAt: parsed.data.now });
      return { ok: true } as const;
    });
  }

  private async scheduleCleanup(candidate: number): Promise<void> {
    const existing = await this.ctx.storage.getAlarm();
    if (existing === null || candidate > existing) {
      await this.ctx.storage.setAlarm(candidate);
    }
  }

  private async ensureHandoffTransferred(
    handoff: QuotaHandoffRecord,
    now: number
  ): Promise<boolean> {
    if (handoff.completed) return true;
    if (handoff.snapshot === null) return false;
    const accepted = await this.forwardCommand(
      handoff.targetObjectName,
      "/internal/abuse/accept-handoff",
      { handoffId: handoff.handoffId, snapshot: handoff.snapshot, now }
    );
    if (!accepted.ok) return false;

    return this.ctx.storage.transaction(async (txn) => {
      const current = parseQuotaHandoffRecord(await txn.get(QUOTA_HANDOFF_KEY));
      if (
        current === null ||
        current.handoffId !== handoff.handoffId ||
        current.targetObjectName !== handoff.targetObjectName
      ) {
        return false;
      }
      await txn.delete(QUOTA_RECORD_KEY);
      await txn.delete(ACCEPTED_HANDOFF_KEY);
      await txn.put(QUOTA_HANDOFF_KEY, {
        ...current,
        snapshot: null,
        expiresAt: now + MAX_STATE_LIFETIME_MS,
        completed: true
      });
      return true;
    });
  }

  private async forwardCommand(
    objectName: string,
    path: string,
    command: unknown
  ): Promise<AbuseControlResult> {
    const namespace = this.env.ABUSE_CONTROL;
    if (namespace === undefined) return { ok: false, code: "unavailable" };
    try {
      const response = await namespace.getByName(objectName).fetch(
        new Request(`https://abuse-control.internal${path}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(command)
        })
      );
      return internalResultSchema.parse(await response.json());
    } catch {
      return { ok: false, code: "unavailable" };
    }
  }
}

function emptyQuotaRecord(): QuotaRecord {
  return { schemaVersion: 1, preparation: [], passive: [], reveal: [] };
}

function parseQuotaRecord(value: unknown): QuotaRecord | null {
  if (value === undefined) {
    return null;
  }
  const parsed = quotaRecordSchema.safeParse(value);
  if (!parsed.success) {
    return null;
  }
  return parsed.data;
}

function parseChallengeRecord(value: unknown): ChallengeRecord | null {
  const parsed = challengeRecordSchema.safeParse(value);
  if (
    !parsed.success ||
    parsed.data.expiresAt - parsed.data.createdAt !== CHALLENGE_LIFETIME_MS ||
    parsed.data.verifiedAt < parsed.data.createdAt ||
    parsed.data.verifiedAt > parsed.data.expiresAt ||
    (parsed.data.consumedAt !== null && parsed.data.consumedAt < parsed.data.verifiedAt)
  ) {
    return null;
  }
  return parsed.data;
}

function parseQuotaHandoffRecord(value: unknown): QuotaHandoffRecord | null {
  if (value === undefined) return null;
  const parsed = quotaHandoffRecordSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

function parseAcceptedHandoffRecord(
  value: unknown
): z.infer<typeof acceptedHandoffRecordSchema> | null {
  if (value === undefined) return null;
  const parsed = acceptedHandoffRecordSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

function validChallenge(
  record: ChallengeRecord | null,
  action: ChallengeAction,
  now: number
): record is ChallengeRecord {
  return (
    record !== null &&
    record.action === action &&
    now >= record.createdAt &&
    now <= record.expiresAt
  );
}

function pruneQuotaRecord(record: QuotaRecord, now: number): QuotaRecord {
  return {
    schemaVersion: 1,
    preparation: record.preparation.filter((at) => at > now - MAX_STATE_LIFETIME_MS && at <= now),
    passive: record.passive.filter((at) => at > now - 60_000 && at <= now),
    reveal: record.reveal.filter((at) => at > now - 60_000 && at <= now)
  };
}

function quotaRetryAfter(record: QuotaRecord, kind: QuotaKind, now: number): number | null {
  const windows =
    kind === "preparation"
      ? [
          {
            events: record.preparation.filter((at) => at > now - 10 * 60_000),
            limit: 10,
            window: 10 * 60_000
          },
          { events: record.preparation, limit: 60, window: MAX_STATE_LIFETIME_MS }
        ]
      : kind === "passive"
        ? [{ events: record.passive, limit: 120, window: 60_000 }]
        : [{ events: record.reveal, limit: 30, window: 60_000 }];

  let retryAfter = 0;
  for (const window of windows) {
    if (window.events.length >= window.limit) {
      const oldest = window.events[window.events.length - window.limit];
      if (oldest !== undefined) {
        retryAfter = Math.max(retryAfter, Math.ceil((oldest + window.window - now) / 1_000));
      }
    }
  }
  return retryAfter > 0 ? retryAfter : null;
}

function latestEvent(record: QuotaRecord): number | null {
  const events = [...record.preparation, ...record.passive, ...record.reveal];
  return events.length === 0 ? null : Math.max(...events);
}

function statusForResult(result: AbuseControlResult): number {
  if (result.ok) return 200;
  return result.code === "invalid_command"
    ? 400
    : result.code === "rate_limited"
      ? 429
      : result.code === "unavailable"
        ? 409
        : 500;
}

function jsonResponse(
  body: unknown,
  status: number,
  extraHeaders: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "cache-control": "no-store", "content-type": "application/json", ...extraHeaders }
  });
}

const internalResultSchema = z.union([
  z.strictObject({ ok: z.literal(true) }),
  z.strictObject({ ok: z.literal(true), verified: z.boolean() }),
  z.strictObject({
    ok: z.literal(false),
    code: z.enum(["invalid_command", "invalid_state", "unavailable"])
  }),
  z.strictObject({
    ok: z.literal(false),
    code: z.literal("rate_limited"),
    retryAfter: z.number()
  })
]);

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
