import { describe, expect, it } from "vitest";
import {
  ABUSE_LOCK_DECISIONS,
  CAPABILITY_COMMAND_TYPES,
  CAPABILITY_KINDS,
  CAPABILITY_STATES,
  CAPABILITY_TRANSITION_TABLE,
  calculateCapabilityAvailability,
  parseCapabilityPolicy,
  parseEpochMilliseconds,
  parseOptionalConsumptionLimit,
  transitionCapability,
  type CapabilityCommand,
  type CapabilityCommandType,
  type CapabilityLifecycle,
  type CapabilityPolicy,
  type CapabilityState,
  type EpochMilliseconds
} from "./index.js";

const AT_999 = timestamp(999);
const AT_1_000 = timestamp(1_000);
const AT_2_000 = timestamp(2_000);

const expectedTransitionTable = {
  DRAFT: ["activate", "delete"],
  ACTIVE: ["consume", "expire", "disable", "abuse_lock", "delete"],
  CONSUMED: ["delete"],
  EXPIRED: ["delete"],
  DISABLED: ["expire", "reactivate", "delete"],
  ABUSE_LOCKED: ["decide_abuse_lock"],
  DELETED: []
} as const satisfies Record<CapabilityState, readonly CapabilityCommandType[]>;

describe("capability policy", () => {
  it("defines only the canonical capability kinds and lifecycle states", () => {
    expect(CAPABILITY_KINDS).toEqual(["secret", "file_download", "upload_request", "redirect"]);
    expect(CAPABILITY_STATES).toEqual([
      "DRAFT",
      "ACTIVE",
      "CONSUMED",
      "EXPIRED",
      "DISABLED",
      "ABUSE_LOCKED",
      "DELETED"
    ]);
    expect(CAPABILITY_STATES).not.toContain("RESERVED");
    expect(CAPABILITY_STATES).not.toContain("ERROR");
  });

  it.each([
    ["secret", "reveal", 1],
    ["file_download", "issue_download_lease", 2],
    ["upload_request", "finalize_upload", 2]
  ] as const)("builds the %s kind-specific policy extension", (kind, action, maxConsumptions) => {
    const parsed = parseCapabilityPolicy(policyInput({ kind, maxConsumptions }));

    expect(parsed).toMatchObject({
      ok: true,
      value: { kind, explicitConsumptionAction: action }
    });
  });

  it("locks secret policy to zero-knowledge payload destruction", () => {
    const parsed = parseCapabilityPolicy(policyInput({ kind: "secret", maxConsumptions: 1 }));

    expect(parsed).toMatchObject({
      ok: true,
      value: {
        maxConsumptions: 1,
        payloadMode: "zero_knowledge",
        payloadAfterConsumption: "destroy"
      }
    });
  });

  it.each([undefined, null])("normalizes an omitted secret limit %s to one reveal", (value) => {
    const parsed = parseCapabilityPolicy(policyInput({ kind: "secret", maxConsumptions: value }));

    expect(parsed).toMatchObject({
      ok: true,
      value: { kind: "secret", maxConsumptions: 1 }
    });
  });

  it.each([2, Number.MAX_SAFE_INTEGER])("rejects secret consumption limit %s", (value) => {
    expect(parseCapabilityPolicy(policyInput({ kind: "secret", maxConsumptions: value }))).toEqual({
      ok: false,
      error: {
        code: "invalid_kind_policy",
        kind: "secret",
        reason: "secret_requires_single_consumption"
      }
    });
  });

  it("allows exact redirect limits only behind explicit confirmation", () => {
    const confirmed = parseCapabilityPolicy(
      policyInput({ kind: "redirect", redirectMode: "confirmed", maxConsumptions: 2 })
    );
    const direct = parseCapabilityPolicy(
      policyInput({ kind: "redirect", redirectMode: "direct", maxConsumptions: null })
    );
    const invalidDirectLimit = parseCapabilityPolicy(
      policyInput({ kind: "redirect", redirectMode: "direct", maxConsumptions: 2 })
    );

    expect(confirmed).toMatchObject({
      ok: true,
      value: {
        redirectMode: "confirmed",
        explicitConsumptionAction: "confirm_redirect"
      }
    });
    expect(direct).toMatchObject({
      ok: true,
      value: {
        redirectMode: "direct",
        explicitConsumptionAction: null,
        maxConsumptions: null
      }
    });
    expect(invalidDirectLimit).toEqual({
      ok: false,
      error: {
        code: "invalid_kind_policy",
        kind: "redirect",
        reason: "passive_redirect_limit"
      }
    });
  });

  it.each([1, 2, Number.MAX_SAFE_INTEGER])(
    "parses positive safe-integer consumption limit %s",
    (value) => {
      expect(parseOptionalConsumptionLimit(value)).toEqual({ ok: true, value });
    }
  );

  it.each([undefined, null])("parses optional consumption limit %s", (value) => {
    expect(parseOptionalConsumptionLimit(value)).toEqual({ ok: true, value: null });
  });

  it.each([0, -1, 1.5, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1, "1"])(
    "rejects invalid consumption limit %s",
    (value) => {
      expect(parseOptionalConsumptionLimit(value)).toEqual({
        ok: false,
        error: { code: "invalid_consumption_limit", value }
      });
    }
  );

  it.each([-1, 1.5, Number.POSITIVE_INFINITY, "1000"])("rejects invalid expiry %s", (expiresAt) => {
    expect(parseCapabilityPolicy(policyInput({ expiresAt }))).toEqual({
      ok: false,
      error: { code: "invalid_expiry", value: expiresAt }
    });
  });

  it("supports no expiry when retention does not depend on expiry", () => {
    const parsed = parseCapabilityPolicy(
      policyInput({
        expiresAt: null,
        postConsumption: { behavior: "delete_capability" }
      })
    );

    expect(parsed).toMatchObject({ ok: true, value: { expiresAt: null } });
  });

  it("requires an expiry for retain-until-expiry policy", () => {
    const parsed = parseCapabilityPolicy(
      policyInput({
        expiresAt: null,
        postConsumption: {
          behavior: "retain_capability",
          retention: { mode: "until_expiry" }
        }
      })
    );

    expect(parsed).toEqual({
      ok: false,
      error: {
        code: "invalid_post_consumption_policy",
        reason: "missing_expiry"
      }
    });
  });

  it.each([0, -1, 1.5, Number.POSITIVE_INFINITY, "1000"])(
    "rejects invalid retention duration %s",
    (durationMs) => {
      const parsed = parseCapabilityPolicy(
        policyInput({
          postConsumption: {
            behavior: "retain_capability",
            retention: { mode: "for", durationMs }
          }
        })
      );

      expect(parsed).toEqual({
        ok: false,
        error: { code: "invalid_retention_duration", value: durationMs }
      });
    }
  );
});

describe("capability availability", () => {
  it("subtracts committed consumption and active reservations independently", () => {
    const result = calculateCapabilityAvailability({
      lifecycle: { state: "ACTIVE", committedConsumptions: 1 },
      policy: policy({ maxConsumptions: 4 }),
      activeReservations: 2,
      at: AT_1_000
    });

    expect(result).toEqual({
      ok: true,
      value: {
        supportsExplicitConsumption: true,
        isExpired: false,
        isExhausted: false,
        remainingConsumptions: 3,
        availableConsumptions: 1,
        hasAvailableCapacity: true,
        canStartExplicitConsumption: true
      }
    });
  });

  it("does not make a fully reserved capability consumed", () => {
    const lifecycle = { state: "ACTIVE", committedConsumptions: 1 } as const;
    const result = calculateCapabilityAvailability({
      lifecycle,
      policy: policy({ maxConsumptions: 3 }),
      activeReservations: 2,
      at: AT_1_000
    });

    expect(result).toMatchObject({
      ok: true,
      value: {
        isExhausted: false,
        remainingConsumptions: 2,
        availableConsumptions: 0,
        hasAvailableCapacity: false,
        canStartExplicitConsumption: false
      }
    });
    expect(lifecycle.state).toBe("ACTIVE");
  });

  it("marks exhaustion only from committed consumption", () => {
    const result = calculateCapabilityAvailability({
      lifecycle: { state: "ACTIVE", committedConsumptions: 3 },
      policy: policy({ maxConsumptions: 3 }),
      activeReservations: 0,
      at: AT_1_000
    });

    expect(result).toMatchObject({
      ok: true,
      value: {
        isExhausted: true,
        remainingConsumptions: 0,
        availableConsumptions: 0,
        canStartExplicitConsumption: false
      }
    });
  });

  it("represents unlimited explicit consumption without a synthetic numeric limit", () => {
    const result = calculateCapabilityAvailability({
      lifecycle: { state: "ACTIVE", committedConsumptions: 100 },
      policy: policy({ maxConsumptions: null }),
      activeReservations: 50,
      at: AT_1_000
    });

    expect(result).toEqual({
      ok: true,
      value: {
        supportsExplicitConsumption: true,
        isExpired: false,
        isExhausted: false,
        remainingConsumptions: null,
        availableConsumptions: null,
        hasAvailableCapacity: true,
        canStartExplicitConsumption: true
      }
    });
  });

  it.each([
    ["committedConsumptions", -1, 0],
    ["committedConsumptions", 1.5, 0],
    ["activeReservations", 0, -1],
    ["activeReservations", 0, 1.5]
  ] as const)("returns a typed error for invalid %s", (field, committed, reservations) => {
    const result = calculateCapabilityAvailability({
      lifecycle: { state: "ACTIVE", committedConsumptions: committed },
      policy: policy(),
      activeReservations: reservations,
      at: AT_1_000
    });

    const value = field === "committedConsumptions" ? committed : reservations;
    expect(result).toEqual({
      ok: false,
      error: { code: "invalid_count", field, value }
    });
  });

  it("ignores passive reporting metrics for authorization", () => {
    const authorizationInput = {
      lifecycle: { state: "ACTIVE", committedConsumptions: 0 } as const,
      policy: policy({ maxConsumptions: 1 }),
      activeReservations: 0,
      at: AT_1_000
    };
    const withPassiveReporting = {
      ...authorizationInput,
      viewCount: Number.MAX_SAFE_INTEGER,
      headRequestCount: Number.MAX_SAFE_INTEGER,
      unfurlCount: Number.MAX_SAFE_INTEGER
    };

    expect(calculateCapabilityAvailability(withPassiveReporting)).toEqual(
      calculateCapabilityAvailability(authorizationInput)
    );
  });

  it("does not expose direct redirects as explicitly consumable", () => {
    const result = calculateCapabilityAvailability({
      lifecycle: { state: "ACTIVE", committedConsumptions: 0 },
      policy: policy({ kind: "redirect", redirectMode: "direct", maxConsumptions: null }),
      activeReservations: 0,
      at: AT_1_000
    });

    expect(result).toMatchObject({
      ok: true,
      value: {
        supportsExplicitConsumption: false,
        canStartExplicitConsumption: false
      }
    });
  });

  it("blocks new consumption when lifecycle or time is unavailable", () => {
    const inactive = calculateCapabilityAvailability({
      lifecycle: { state: "DISABLED", committedConsumptions: 0 },
      policy: policy(),
      activeReservations: 0,
      at: AT_1_000
    });
    const expired = calculateCapabilityAvailability({
      lifecycle: { state: "ACTIVE", committedConsumptions: 0 },
      policy: policy({ expiresAt: 1_000 }),
      activeReservations: 0,
      at: AT_1_000
    });

    expect(inactive).toMatchObject({
      ok: true,
      value: { isExpired: false, canStartExplicitConsumption: false }
    });
    expect(expired).toMatchObject({
      ok: true,
      value: { isExpired: true, canStartExplicitConsumption: false }
    });
  });
});

describe("capability lifecycle state machine", () => {
  it("exposes the complete reviewed transition table", () => {
    expect(CAPABILITY_TRANSITION_TABLE).toEqual(expectedTransitionTable);
    expect(ABUSE_LOCK_DECISIONS).toEqual(["release", "disable", "delete"]);
  });

  it.each([
    ["DRAFT", "activate", "ACTIVE"],
    ["DRAFT", "delete", "DELETED"],
    ["ACTIVE", "consume", "ACTIVE"],
    ["ACTIVE", "expire", "EXPIRED"],
    ["ACTIVE", "disable", "DISABLED"],
    ["ACTIVE", "abuse_lock", "ABUSE_LOCKED"],
    ["ACTIVE", "delete", "DELETED"],
    ["DISABLED", "expire", "EXPIRED"],
    ["DISABLED", "reactivate", "ACTIVE"],
    ["DISABLED", "delete", "DELETED"],
    ["ABUSE_LOCKED", "decide_abuse_lock", "ACTIVE"],
    ["CONSUMED", "delete", "DELETED"],
    ["EXPIRED", "delete", "DELETED"]
  ] as const)("allows %s -> %s -> %s", (state, commandType, expectedState) => {
    const command = commandFor(commandType, commandType === "expire" ? AT_2_000 : AT_1_000);
    const result = transitionCapability(
      lifecycleFor(state),
      policy({ expiresAt: 2_000, maxConsumptions: 2, reactivation: "allowed" }),
      command
    );

    expect(result).toMatchObject({
      ok: true,
      value: { lifecycle: { state: expectedState } }
    });
  });

  it("rejects every command not listed for the current state", () => {
    for (const state of CAPABILITY_STATES) {
      for (const commandType of CAPABILITY_COMMAND_TYPES) {
        if ((expectedTransitionTable[state] as readonly string[]).includes(commandType)) {
          continue;
        }

        const result = transitionCapability(lifecycleFor(state), policy(), commandFor(commandType));

        expect(result, `${state} must reject ${commandType}`).toEqual({
          ok: false,
          error: { code: "invalid_transition", state, command: commandType }
        });
      }
    }
  });

  it("keeps active state until the explicit-consumption limit is committed", () => {
    const first = transitionCapability(
      { state: "ACTIVE", committedConsumptions: 0 },
      policy({ maxConsumptions: 2 }),
      commandFor("consume")
    );
    expect(first).toMatchObject({
      ok: true,
      value: {
        lifecycle: { state: "ACTIVE", committedConsumptions: 1 },
        event: { exhausted: false }
      }
    });

    if (!first.ok) {
      throw new Error("expected the first consumption fixture to succeed");
    }

    const second = transitionCapability(first.value.lifecycle, policy({ maxConsumptions: 2 }), {
      type: "consume",
      commandId: "command-2",
      at: AT_1_000,
      consumptionId: "consumption-2"
    });
    expect(second).toMatchObject({
      ok: true,
      value: {
        lifecycle: { state: "CONSUMED", committedConsumptions: 2 },
        event: { exhausted: true }
      }
    });
  });

  it("makes a secret terminal after its first successful reveal", () => {
    const result = transitionCapability(
      { state: "ACTIVE", committedConsumptions: 0 },
      policy({ kind: "secret", maxConsumptions: 1 }),
      commandFor("consume")
    );

    expect(result).toMatchObject({
      ok: true,
      value: {
        lifecycle: { state: "CONSUMED", committedConsumptions: 1 },
        event: { exhausted: true }
      }
    });
  });

  it("keeps unlimited explicit consumption active", () => {
    const result = transitionCapability(
      { state: "ACTIVE", committedConsumptions: 10 },
      policy({ maxConsumptions: null }),
      commandFor("consume")
    );

    expect(result).toMatchObject({
      ok: true,
      value: {
        lifecycle: { state: "ACTIVE", committedConsumptions: 11 },
        event: { exhausted: false }
      }
    });
  });

  it("rejects consumption for passive direct redirects", () => {
    const result = transitionCapability(
      { state: "ACTIVE", committedConsumptions: 0 },
      policy({ kind: "redirect", redirectMode: "direct", maxConsumptions: null }),
      commandFor("consume")
    );

    expect(result).toEqual({
      ok: false,
      error: { code: "explicit_consumption_not_supported", kind: "redirect" }
    });
  });

  it("returns a stable exhaustion error instead of throwing", () => {
    const invoke = () =>
      transitionCapability(
        { state: "ACTIVE", committedConsumptions: 1 },
        policy({ maxConsumptions: 1 }),
        commandFor("consume")
      );

    expect(invoke).not.toThrow();
    expect(invoke()).toEqual({
      ok: false,
      error: {
        code: "capability_exhausted",
        maxConsumptions: 1,
        committedConsumptions: 1
      }
    });
  });

  it("treats the exact expiry timestamp as expired", () => {
    const before = transitionCapability(
      { state: "ACTIVE", committedConsumptions: 0 },
      policy({ expiresAt: 1_000 }),
      commandFor("consume", AT_999)
    );
    const atBoundary = transitionCapability(
      { state: "ACTIVE", committedConsumptions: 0 },
      policy({ expiresAt: 1_000 }),
      commandFor("consume", AT_1_000)
    );
    const expireBefore = transitionCapability(
      { state: "ACTIVE", committedConsumptions: 0 },
      policy({ expiresAt: 1_000 }),
      commandFor("expire", AT_999)
    );
    const expireAtBoundary = transitionCapability(
      { state: "ACTIVE", committedConsumptions: 0 },
      policy({ expiresAt: 1_000 }),
      commandFor("expire", AT_1_000)
    );

    expect(before).toMatchObject({ ok: true });
    expect(atBoundary).toEqual({
      ok: false,
      error: { code: "capability_expired", expiresAt: AT_1_000, at: AT_1_000 }
    });
    expect(expireBefore).toEqual({
      ok: false,
      error: { code: "not_expired", expiresAt: AT_1_000, at: AT_999 }
    });
    expect(expireAtBoundary).toMatchObject({
      ok: true,
      value: { lifecycle: { state: "EXPIRED" } }
    });
  });

  it("rejects expiry when the policy has no expiry", () => {
    expect(
      transitionCapability(
        { state: "ACTIVE", committedConsumptions: 0 },
        policy({ expiresAt: null }),
        commandFor("expire")
      )
    ).toEqual({ ok: false, error: { code: "no_expiry_configured" } });
  });

  it("enforces every disabled recovery rule", () => {
    const lifecycle = { state: "DISABLED", committedConsumptions: 0 } as const;
    const command = commandFor("reactivate", AT_1_000);

    expect(transitionCapability(lifecycle, policy({ reactivation: "forbidden" }), command)).toEqual(
      { ok: false, error: { code: "reactivation_forbidden" } }
    );
    expect(
      transitionCapability(
        lifecycle,
        policy({ reactivation: "allowed", expiresAt: 1_000 }),
        command
      )
    ).toEqual({
      ok: false,
      error: { code: "capability_expired", expiresAt: AT_1_000, at: AT_1_000 }
    });
    expect(
      transitionCapability(
        { state: "DISABLED", committedConsumptions: 1 },
        policy({ reactivation: "allowed", maxConsumptions: 1 }),
        command
      )
    ).toEqual({
      ok: false,
      error: { code: "capability_exhausted", maxConsumptions: 1, committedConsumptions: 1 }
    });
    expect(
      transitionCapability(lifecycle, policy({ reactivation: "allowed" }), command)
    ).toMatchObject({ ok: true, value: { lifecycle: { state: "ACTIVE" } } });
  });

  it.each([
    ["release", "ACTIVE"],
    ["disable", "DISABLED"],
    ["delete", "DELETED"]
  ] as const)("requires an explicit privileged %s decision", (decision, state) => {
    const result = transitionCapability(
      { state: "ABUSE_LOCKED", committedConsumptions: 0 },
      policy(),
      {
        type: "decide_abuse_lock",
        commandId: `decision-command-${decision}`,
        at: AT_1_000,
        decision,
        privilegedDecisionId: `moderation-${decision}`
      }
    );

    expect(result).toMatchObject({
      ok: true,
      value: {
        lifecycle: { state },
        event: {
          type: "capability_abuse_lock_decided",
          decision,
          privilegedDecisionId: `moderation-${decision}`
        }
      }
    });
  });

  it("does not release an expired or exhausted abuse lock", () => {
    const command = commandFor("decide_abuse_lock", AT_1_000);
    const expired = transitionCapability(
      { state: "ABUSE_LOCKED", committedConsumptions: 0 },
      policy({ expiresAt: 1_000 }),
      command
    );
    const exhausted = transitionCapability(
      { state: "ABUSE_LOCKED", committedConsumptions: 1 },
      policy({ maxConsumptions: 1 }),
      command
    );

    expect(expired).toEqual({
      ok: false,
      error: { code: "capability_expired", expiresAt: AT_1_000, at: AT_1_000 }
    });
    expect(exhausted).toEqual({
      ok: false,
      error: { code: "capability_exhausted", maxConsumptions: 1, committedConsumptions: 1 }
    });
  });

  it("keeps consumed and expired terminal except for deletion", () => {
    for (const state of ["CONSUMED", "EXPIRED"] as const) {
      for (const commandType of CAPABILITY_COMMAND_TYPES) {
        const result = transitionCapability(lifecycleFor(state), policy(), commandFor(commandType));

        if (commandType === "delete") {
          expect(result).toMatchObject({
            ok: true,
            value: { lifecycle: { state: "DELETED" } }
          });
        } else {
          expect(result).toEqual({
            ok: false,
            error: { code: "invalid_transition", state, command: commandType }
          });
        }
      }
    }
  });

  it("keeps deleted terminal", () => {
    for (const commandType of CAPABILITY_COMMAND_TYPES) {
      expect(
        transitionCapability(lifecycleFor("DELETED"), policy(), commandFor(commandType))
      ).toEqual({
        ok: false,
        error: { code: "invalid_transition", state: "DELETED", command: commandType }
      });
    }
  });

  it("replays the same immutable inputs deterministically", () => {
    const lifecycle = Object.freeze({ state: "ACTIVE", committedConsumptions: 0 } as const);
    const parsedPolicy = Object.freeze(policy({ maxConsumptions: 2 }));
    const command = Object.freeze(commandFor("consume"));

    const first = transitionCapability(lifecycle, parsedPolicy, command);
    const second = transitionCapability(lifecycle, parsedPolicy, command);

    expect(second).toEqual(first);
    expect(first).toMatchObject({
      ok: true,
      value: {
        event: {
          eventId: "command-consume",
          occurredAt: AT_1_000,
          consumptionId: "consumption-1"
        }
      }
    });
    expect(lifecycle).toEqual({ state: "ACTIVE", committedConsumptions: 0 });
  });
});

function policyInput(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: "file_download",
    expiresAt: 2_000,
    maxConsumptions: 2,
    reactivation: "allowed",
    postConsumption: {
      behavior: "retain_capability",
      retention: { mode: "for", durationMs: 60_000 }
    },
    ...overrides
  };
}

function policy(overrides: Record<string, unknown> = {}): CapabilityPolicy {
  const parsed = parseCapabilityPolicy(policyInput(overrides));
  if (!parsed.ok) {
    throw new Error(`invalid test policy: ${parsed.error.code}`);
  }
  return parsed.value;
}

function timestamp(value: number): EpochMilliseconds {
  const parsed = parseEpochMilliseconds(value);
  if (!parsed.ok) {
    throw new Error(`invalid test timestamp: ${value}`);
  }
  return parsed.value;
}

function lifecycleFor(state: CapabilityState): CapabilityLifecycle {
  return {
    state,
    committedConsumptions: state === "CONSUMED" ? 2 : 0
  };
}

function commandFor(
  type: CapabilityCommandType,
  at: EpochMilliseconds = AT_1_000
): CapabilityCommand {
  const base = { commandId: `command-${type}`, at } as const;

  switch (type) {
    case "activate":
    case "expire":
    case "disable":
    case "abuse_lock":
    case "reactivate":
    case "delete":
      return { ...base, type };
    case "consume":
      return { ...base, type, consumptionId: "consumption-1" };
    case "decide_abuse_lock":
      return {
        ...base,
        type,
        decision: "release",
        privilegedDecisionId: "moderation-1"
      };
  }
}
