import { describe, expect, it, vi } from "vitest";
import {
  COMPLETION_ATTEMPT_TIMEOUT_MS,
  COMPLETION_RECOVERY_RESERVE_MS,
  CreationRequestError,
  isCompletionRecoveryExpired,
  prepareEncryptedSecret,
  submitEncryptedSecret,
  type Fetcher
} from "./secret-api";
import { encodeBase64url } from "./zero-knowledge";

const LOCATOR = `loc1_${"a".repeat(48)}`;
const PUBLIC_BEARER = "pub1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OWNER_BEARER = "own1_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const OPERATION_ID = `op1_${"A".repeat(43)}`;
const CAPABILITY_ID = `cap1_${"c".repeat(48)}`;
const POLICY_HASH = "A".repeat(43);
const CREATED_AT = "2026-08-01T10:00:00.000Z";
const EXPIRES_AT = "2026-08-02T10:00:00.000Z";
const CHALLENGE_ID = `chl2_p_1_${"B".repeat(22)}_${"B".repeat(43)}`;

const preparation = {
  creation: {
    operation_id: OPERATION_ID,
    capability_id: CAPABILITY_ID,
    locator: LOCATOR,
    created_at: CREATED_AT,
    policy_hash: POLICY_HASH,
    public_bearer: PUBLIC_BEARER,
    owner_bearer: OWNER_BEARER
  },
  policy: {
    kind: "secret",
    expires_at: EXPIRES_AT,
    max_consumptions: 1,
    reactivation: "forbidden",
    post_consumption: {
      behavior: "retain_capability",
      retention: { mode: "until_expiry" }
    }
  },
  complete_by: "2026-08-01T10:15:00.000Z",
  preparation_proof: `prep1_${"A".repeat(43)}`
} as const;

describe("browser secret creation network boundary", () => {
  it("sends only a browser-derived verifier for an optional access code", async () => {
    const accessCode = "shared separately 🔐";
    let preparationBody = "";
    const fetcher: Fetcher = (_input, init) => {
      preparationBody = requestBodyText(init);
      const parsed = JSON.parse(preparationBody) as { access_code_verifier: unknown };
      return Promise.resolve(
        Response.json({
          ...preparation,
          creation: {
            ...preparation.creation,
            access_code_verifier: parsed.access_code_verifier
          }
        })
      );
    };
    const pending = await prepareEncryptedSecret("protected secret", 86_400, {
      challengeId: CHALLENGE_ID,
      accessCode,
      fetcher
    });
    expect(preparationBody).toContain('"version":"acv1"');
    expect(preparationBody).toContain(`"challenge_id":"${CHALLENGE_ID}"`);
    expect(preparationBody).not.toContain(accessCode);
    expect(JSON.stringify(pending.body)).not.toContain(accessCode);
    expect(pending.body.creation.access_code_verifier).toMatchObject({
      algorithm: "PBKDF2-SHA-256",
      iterations: 210_000
    });
  });

  it("encrypts before completion and sends neither plaintext, key, nor fragment", async () => {
    const prepareFetch = vi.fn<Fetcher>(() => Promise.resolve(Response.json(preparation)));
    const plaintext = "server must never receive this plaintext 🔐";
    const pending = await prepareEncryptedSecret(plaintext, 86_400, {
      challengeId: CHALLENGE_ID,
      fetcher: prepareFetch
    });
    const keyBase64url = encodeBase64url(pending.keyBytes);

    expect(prepareFetch).toHaveBeenCalledOnce();
    expect(requestBodyText(prepareFetch.mock.calls[0]?.[1])).not.toContain(plaintext);
    const completionBody = JSON.stringify(pending.body);
    expect(completionBody).not.toContain(plaintext);
    expect(completionBody).not.toContain(keyBase64url);
    expect(completionBody).not.toContain("#k=");
    expect(pending.body.ciphertext_envelope.ad).toEqual({
      capabilityId: CAPABILITY_ID,
      createdAt: CREATED_AT,
      kind: "secret",
      locator: LOCATOR,
      policyHash: POLICY_HASH,
      purpose: "onceurl.phase1a.secret-text",
      version: "ouzk-v1"
    });
    expect(pending.body.complete_by).toBe(preparation.complete_by);
    expect(pending.body.preparation_proof).toBe(preparation.preparation_proof);

    const completeFetch = vi.fn<Fetcher>(() =>
      Promise.resolve(
        Response.json({
          recipient_path: `/s/${LOCATOR}/${PUBLIC_BEARER}`,
          owner_path: `/m/${LOCATOR}/${OWNER_BEARER}`,
          expires_at: EXPIRES_AT
        })
      )
    );
    const result = await submitEncryptedSecret(pending, "https://functional.example", {
      fetcher: completeFetch
    });
    const request = completeFetch.mock.calls[0]?.[1];
    expect(request?.headers).toMatchObject({ "idempotency-key": OPERATION_ID });
    expect(requestBodyText(request)).toBe(completionBody);
    expect(requestBodyText(request)).not.toContain(keyBase64url);
    expect(result.recipientUrl).toBe(
      `https://functional.example/s/${LOCATOR}/${PUBLIC_BEARER}#k=${keyBase64url}&v=ouzk-v1`
    );
    expect(result.ownerUrl).toBe(`https://functional.example/m/${LOCATOR}/${OWNER_BEARER}`);
    expect(result.ownerUrl).not.toContain("#");
    expect(pending.keyBytes.every((byte) => byte === 0)).toBe(true);
  });

  it("retries an ambiguous completion with the exact stable operation and ciphertext", async () => {
    const pending = await prepareEncryptedSecret("retry safely", 86_400, {
      challengeId: CHALLENGE_ID,
      fetcher: () => Promise.resolve(Response.json(preparation))
    });
    const calls: RequestInit[] = [];
    const uncertain: Fetcher = (_input, init) => {
      calls.push(init ?? {});
      return Promise.reject(new TypeError("network response lost"));
    };
    await expect(
      submitEncryptedSecret(pending, "https://functional.example", { fetcher: uncertain })
    ).rejects.toMatchObject({ ambiguous: true });
    expect(pending.keyBytes.some((byte) => byte !== 0)).toBe(true);
    const rejectedRetry: Fetcher = (_input, init) => {
      calls.push(init ?? {});
      return Promise.resolve(Response.json({}, { status: 400 }));
    };
    await expect(
      submitEncryptedSecret(pending, "https://functional.example", {
        fetcher: rejectedRetry,
        uncertaintyAlreadyKnown: true
      })
    ).rejects.toMatchObject({ ambiguous: true });
    expect(pending.keyBytes.some((byte) => byte !== 0)).toBe(true);
    const success: Fetcher = (_input, init) => {
      calls.push(init ?? {});
      return Promise.resolve(
        Response.json({
          recipient_path: `/s/${LOCATOR}/${PUBLIC_BEARER}`,
          owner_path: `/m/${LOCATOR}/${OWNER_BEARER}`,
          expires_at: EXPIRES_AT
        })
      );
    };
    await submitEncryptedSecret(pending, "https://functional.example", {
      fetcher: success,
      uncertaintyAlreadyKnown: true
    });
    expect(calls).toHaveLength(3);
    expect(calls[0]?.body).toBe(calls[1]?.body);
    expect(calls[1]?.body).toBe(calls[2]?.body);
    expect(calls[0]?.headers).toEqual(calls[1]?.headers);
    expect(calls[1]?.headers).toEqual(calls[2]?.headers);
    expect(pending.keyBytes.every((byte) => byte === 0)).toBe(true);
  });

  it("anchors the authenticated recovery duration to monotonic time despite wall-clock skew", async () => {
    const preparationRequestedAt = 12_345;
    const pending = await prepareEncryptedSecret("deadline", 86_400, {
      challengeId: CHALLENGE_ID,
      fetcher: () => Promise.resolve(Response.json(preparation)),
      monotonicNow: () => preparationRequestedAt
    });
    const recoveryDuration = Date.parse(preparation.complete_by) - Date.parse(CREATED_AT);
    expect(pending.recoveryDeadlineMonotonicMs).toBe(preparationRequestedAt + recoveryDuration);

    const wallClock = vi.spyOn(Date, "now");
    wallClock.mockReturnValue(Date.parse(preparation.complete_by) + 24 * 60 * 60 * 1_000);
    expect(isCompletionRecoveryExpired(pending, pending.recoveryDeadlineMonotonicMs)).toBe(false);
    wallClock.mockReturnValue(Date.parse(CREATED_AT) - 24 * 60 * 60 * 1_000);
    expect(isCompletionRecoveryExpired(pending, pending.recoveryDeadlineMonotonicMs + 1)).toBe(
      true
    );
    wallClock.mockRestore();
  });

  it.each(["fetch", "body"] as const)(
    "bounds a stalled completion %s and preserves ambiguous recovery material",
    async (stalledPhase) => {
      vi.useFakeTimers();
      try {
        const pending = await prepareEncryptedSecret("bounded completion", 86_400, {
          challengeId: CHALLENGE_ID,
          fetcher: () => Promise.resolve(Response.json(preparation)),
          monotonicNow: () => 0
        });
        const preliminaryTime =
          pending.recoveryDeadlineMonotonicMs -
          COMPLETION_RECOVERY_RESERVE_MS -
          COMPLETION_ATTEMPT_TIMEOUT_MS -
          20_000;
        let monotonicTime = preliminaryTime;
        const monotonicNow = vi.fn(() => {
          const currentTime = monotonicTime;
          monotonicTime += 10_000;
          return currentTime;
        });
        let requestSignal: AbortSignal | null | undefined;
        const stalled = vi.fn<Fetcher>((_input, init) => {
          requestSignal = init?.signal;
          if (stalledPhase === "fetch") {
            return new Promise<Response>(() => undefined);
          }
          return Promise.resolve(
            new Response(new ReadableStream<Uint8Array>({ start: () => undefined }), {
              status: 200,
              headers: { "content-type": "application/json" }
            })
          );
        });
        const attempt = submitEncryptedSecret(pending, "https://functional.example", {
          fetcher: stalled,
          monotonicNow
        });
        const rejection = expect(attempt).rejects.toMatchObject({ ambiguous: true });

        expect(stalled).toHaveBeenCalledOnce();
        expect(monotonicNow).toHaveBeenCalledTimes(3);
        await vi.advanceTimersByTimeAsync(COMPLETION_ATTEMPT_TIMEOUT_MS);
        monotonicTime = pending.recoveryDeadlineMonotonicMs - COMPLETION_RECOVERY_RESERVE_MS;
        await rejection;

        expect(requestSignal?.aborted).toBe(true);
        expect(pending.keyBytes.some((byte) => byte !== 0)).toBe(true);
        expect(pending.recoveryDeadlineMonotonicMs - monotonicTime).toBe(
          COMPLETION_RECOVERY_RESERVE_MS
        );
        await submitEncryptedSecret(pending, "https://functional.example", {
          fetcher: () =>
            Promise.resolve(
              Response.json({
                recipient_path: `/s/${LOCATOR}/${PUBLIC_BEARER}`,
                owner_path: `/m/${LOCATOR}/${OWNER_BEARER}`,
                expires_at: EXPIRES_AT
              })
            ),
          monotonicNow: () => monotonicTime,
          uncertaintyAlreadyKnown: true
        });
        expect(pending.keyBytes.every((byte) => byte === 0)).toBe(true);
      } finally {
        vi.useRealTimers();
      }
    }
  );

  it("rechecks the initial recovery reserve after timeout setup and refuses dispatch definitely", async () => {
    const pending = await prepareEncryptedSecret("reserve", 86_400, {
      challengeId: CHALLENGE_ID,
      fetcher: () => Promise.resolve(Response.json(preparation)),
      monotonicNow: () => 0
    });
    const completion = vi.fn<Fetcher>();
    let monotonicTime =
      pending.recoveryDeadlineMonotonicMs -
      COMPLETION_RECOVERY_RESERVE_MS -
      COMPLETION_ATTEMPT_TIMEOUT_MS;
    const dispatchTime = pending.recoveryDeadlineMonotonicMs - COMPLETION_RECOVERY_RESERVE_MS;
    const monotonicNow = vi.fn(() => monotonicTime);
    const timeoutArm = vi.spyOn(globalThis, "setTimeout").mockImplementation(() => {
      monotonicTime = dispatchTime;
      return 1 as unknown as ReturnType<typeof setTimeout>;
    });
    try {
      await expect(
        submitEncryptedSecret(pending, "https://functional.example", {
          fetcher: completion,
          monotonicNow
        })
      ).rejects.toMatchObject({
        ambiguous: false,
        message: "The secret could not be created. Check the form and try again."
      });
      expect(timeoutArm).toHaveBeenCalledWith(expect.any(Function), COMPLETION_ATTEMPT_TIMEOUT_MS);
    } finally {
      timeoutArm.mockRestore();
    }
    expect(monotonicNow).toHaveBeenCalledTimes(3);
    expect(completion).not.toHaveBeenCalled();
    expect(pending.keyBytes.some((byte) => byte !== 0)).toBe(true);
  });

  it("allows an uncertain exact retry without a new reserve", async () => {
    const pending = await prepareEncryptedSecret("uncertain reserve", 86_400, {
      challengeId: CHALLENGE_ID,
      fetcher: () => Promise.resolve(Response.json(preparation)),
      monotonicNow: () => 0
    });
    const completion = vi.fn<Fetcher>(() =>
      Promise.resolve(
        Response.json({
          recipient_path: `/s/${LOCATOR}/${PUBLIC_BEARER}`,
          owner_path: `/m/${LOCATOR}/${OWNER_BEARER}`,
          expires_at: EXPIRES_AT
        })
      )
    );
    const retryTime = pending.recoveryDeadlineMonotonicMs - 1;
    const monotonicNow = vi.fn(() => retryTime);

    await submitEncryptedSecret(pending, "https://functional.example", {
      fetcher: completion,
      monotonicNow,
      uncertaintyAlreadyKnown: true
    });

    expect(completion).toHaveBeenCalledOnce();
    expect(monotonicNow).toHaveBeenCalledTimes(3);
    expect(pending.keyBytes.every((byte) => byte === 0)).toBe(true);
  });

  it("keeps an uncertain retry ambiguous when the dispatch-time recovery window expires", async () => {
    const pending = await prepareEncryptedSecret("expired retry", 86_400, {
      challengeId: CHALLENGE_ID,
      fetcher: () => Promise.resolve(Response.json(preparation)),
      monotonicNow: () => 0
    });
    const completion = vi.fn<Fetcher>();
    let monotonicTime = pending.recoveryDeadlineMonotonicMs - 1;
    const monotonicNow = vi.fn(() => monotonicTime);
    const timeoutArm = vi.spyOn(globalThis, "setTimeout").mockImplementation(() => {
      monotonicTime = pending.recoveryDeadlineMonotonicMs + 1;
      return 1 as unknown as ReturnType<typeof setTimeout>;
    });

    try {
      await expect(
        submitEncryptedSecret(pending, "https://functional.example", {
          fetcher: completion,
          monotonicNow,
          uncertaintyAlreadyKnown: true
        })
      ).rejects.toMatchObject({ ambiguous: true });
      expect(timeoutArm).toHaveBeenCalledWith(expect.any(Function), COMPLETION_ATTEMPT_TIMEOUT_MS);
    } finally {
      timeoutArm.mockRestore();
    }
    expect(monotonicNow).toHaveBeenCalledTimes(3);
    expect(completion).not.toHaveBeenCalled();
    expect(pending.keyBytes.some((byte) => byte !== 0)).toBe(true);
  });

  it("rejects malformed server material and distinguishes only definite versus uncertain creation failure", async () => {
    await expect(
      prepareEncryptedSecret("secret", 86_400, {
        challengeId: CHALLENGE_ID,
        fetcher: () => Promise.reject(new TypeError("preparation network failed"))
      })
    ).rejects.toMatchObject({ ambiguous: false });
    await expect(
      prepareEncryptedSecret("secret", 86_400, {
        challengeId: CHALLENGE_ID,
        fetcher: () => Promise.resolve(Response.json({}))
      })
    ).rejects.toBeInstanceOf(CreationRequestError);
    const pending = await prepareEncryptedSecret("secret", 86_400, {
      challengeId: CHALLENGE_ID,
      fetcher: () => Promise.resolve(Response.json(preparation))
    });
    await expect(
      submitEncryptedSecret(pending, "https://functional.example", {
        fetcher: () => Promise.resolve(Response.json({}, { status: 400 }))
      })
    ).rejects.toMatchObject({ ambiguous: false });
    await expect(
      submitEncryptedSecret(pending, "https://functional.example", {
        fetcher: () => Promise.resolve(Response.json({}, { status: 503 }))
      })
    ).rejects.toMatchObject({ ambiguous: true });
    await expect(
      submitEncryptedSecret(pending, "https://functional.example", {
        fetcher: () => Promise.resolve(new Response("truncated", { status: 200 }))
      })
    ).rejects.toMatchObject({ ambiguous: true });
    await expect(
      submitEncryptedSecret(pending, "https://functional.example", {
        fetcher: () =>
          Promise.resolve(
            Response.json({
              recipient_path: `/s/${LOCATOR}/pub1_${"E".repeat(43)}`,
              owner_path: `/m/${LOCATOR}/${OWNER_BEARER}`,
              expires_at: EXPIRES_AT
            })
          )
      })
    ).rejects.toMatchObject({ ambiguous: true });
  });
});

function requestBodyText(init: RequestInit | undefined): string {
  if (typeof init?.body !== "string") {
    throw new Error("Expected a string request body");
  }
  return init.body;
}
