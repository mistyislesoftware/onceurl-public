import { z } from "zod";
import {
  AdminBoundaryError,
  base64url,
  securityDigest,
  type AuthorizedOperator
} from "./admin-auth";
import type { WorkerEnv } from "./env";

const epoch = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const opaque = z.string().regex(/^(rpt1|csrf1)_[A-Za-z0-9_-]{43}$/u);
const reportBinding = z.strictObject({
  locator: z.string().regex(/^loc1_[0-9a-f]{48}$/u),
  authorized: z.boolean()
});
const csrfBinding = z.strictObject({
  actor: z.string().min(1).max(254),
  session: z.string().length(43),
  mutation: z.string().length(43)
});
export const ticketRecordSchema = z.discriminatedUnion("purpose", [
  z.strictObject({
    purpose: z.literal("report"),
    createdAt: epoch,
    expiresAt: epoch,
    consumedAt: epoch.nullable(),
    binding: reportBinding
  }),
  z.strictObject({
    purpose: z.literal("csrf"),
    createdAt: epoch,
    expiresAt: epoch,
    consumedAt: epoch.nullable(),
    binding: csrfBinding
  })
]);
type Ticket = z.infer<typeof ticketRecordSchema>;
const ticketCommand = z.discriminatedUnion("type", [
  z.strictObject({ type: z.literal("create"), record: ticketRecordSchema, now: epoch }),
  z.strictObject({ type: z.literal("consume-report"), now: epoch }),
  z.strictObject({ type: z.literal("consume-csrf"), binding: csrfBinding, now: epoch })
]);
const KEY = "abuse:security-ticket:v1";

/** These commands run only on an independently named opaque-ticket object. */
export async function executeSecurityTicket(storage: DurableObjectStorage, input: unknown) {
  const parsed = ticketCommand.safeParse(input);
  if (!parsed.success) return { ok: false };
  const command = parsed.data;
  return storage.transaction(async (txn) => {
    const stored = await txn.get(KEY);
    if (command.type === "create") {
      const record = command.record;
      const maxLifetime = record.purpose === "report" ? 600_000 : 300_000;
      if (
        stored !== undefined ||
        record.createdAt !== command.now ||
        record.consumedAt !== null ||
        record.expiresAt <= command.now ||
        record.expiresAt - record.createdAt > maxLifetime
      )
        return { ok: false };
      await txn.put(KEY, record);
      await txn.setAlarm(record.expiresAt);
      return { ok: true };
    }
    if (stored === undefined) return { ok: false };
    const record = ticketRecordSchema.parse(stored);
    if (
      record.createdAt > command.now ||
      record.expiresAt <= command.now ||
      record.consumedAt !== null
    )
      return { ok: false };
    if (command.type === "consume-report") {
      if (record.purpose !== "report") return { ok: false };
      const consumed = { ...record, consumedAt: command.now };
      await txn.put(KEY, consumed);
      return { ok: true, record: consumed };
    }
    if (
      record.purpose !== "csrf" ||
      JSON.stringify(record.binding) !== JSON.stringify(command.binding)
    )
      return { ok: false };
    await txn.put(KEY, { ...record, consumedAt: command.now });
    return { ok: true };
  });
}

export async function cleanupSecurityTicket(
  storage: DurableObjectStorage,
  now: number
): Promise<boolean> {
  const stored = await storage.get(KEY);
  if (stored === undefined) return false;
  const record = ticketRecordSchema.parse(stored);
  if (now >= record.expiresAt) await storage.deleteAll();
  else await storage.setAlarm(record.expiresAt);
  return true;
}

async function ticketCommandRequest(
  env: WorkerEnv,
  token: string,
  command: unknown
): Promise<{ ok: boolean; record?: Ticket }> {
  if (!opaque.safeParse(token).success) return { ok: false };
  if (env.ABUSE_CONTROL === undefined) throw new AdminBoundaryError(503);
  try {
    const digest = await securityDigest("onceurl.security-ticket.v1", token);
    const response = await env.ABUSE_CONTROL.getByName(`ticket:${digest}`).fetch(
      new Request("https://abuse-control.internal/internal/security/ticket", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(command)
      })
    );
    if (!response.ok) throw new Error();
    return z
      .strictObject({ ok: z.boolean(), record: ticketRecordSchema.optional() })
      .parse(await response.json());
  } catch {
    throw new AdminBoundaryError(503);
  }
}

export async function issueReportNonce(
  env: WorkerEnv,
  locator: string,
  authorized: boolean,
  now: number
): Promise<string> {
  const token = `rpt1_${base64url(crypto.getRandomValues(new Uint8Array(32)))}`;
  const result = await ticketCommandRequest(env, token, {
    type: "create",
    record: {
      purpose: "report",
      createdAt: now,
      expiresAt: now + 600_000,
      consumedAt: null,
      binding: { locator, authorized }
    },
    now
  });
  if (!result.ok) throw new AdminBoundaryError(503);
  return token;
}

export async function consumeReportNonce(env: WorkerEnv, token: string, now: number) {
  if (!token.startsWith("rpt1_")) return null;
  const result = await ticketCommandRequest(env, token, { type: "consume-report", now });
  return result.ok && result.record?.purpose === "report" ? result.record : null;
}

async function csrfBindingFor(operator: AuthorizedOperator, mutation: unknown) {
  return {
    actor: operator.actor,
    session: operator.session,
    mutation: await securityDigest("onceurl.admin-mutation.v1", JSON.stringify(mutation))
  };
}

export async function issueAdminCsrf(
  env: WorkerEnv,
  operator: AuthorizedOperator,
  mutation: unknown,
  now: number
): Promise<string> {
  const token = `csrf1_${base64url(crypto.getRandomValues(new Uint8Array(32)))}`;
  const binding = await csrfBindingFor(operator, mutation);
  const expiresAt = Math.min(now + 300_000, operator.expiresAt);
  const result = await ticketCommandRequest(env, token, {
    type: "create",
    record: { purpose: "csrf", createdAt: now, expiresAt, consumedAt: null, binding },
    now
  });
  if (!result.ok) throw new AdminBoundaryError(503);
  return token;
}

export async function consumeAdminCsrf(
  env: WorkerEnv,
  operator: AuthorizedOperator,
  mutation: unknown,
  token: string | null,
  now: number
) {
  if (token === null || !token.startsWith("csrf1_")) return false;
  const result = await ticketCommandRequest(env, token, {
    type: "consume-csrf",
    binding: await csrfBindingFor(operator, mutation),
    now
  });
  return result.ok;
}
