import type { CapabilityPolicy, EpochMilliseconds } from "./capability-policy.js";
import { err, ok, type Result } from "./result.js";

export const CAPABILITY_STATES = [
  "DRAFT",
  "ACTIVE",
  "CONSUMED",
  "EXPIRED",
  "DISABLED",
  "ABUSE_LOCKED",
  "DELETED"
] as const;

export type CapabilityState = (typeof CAPABILITY_STATES)[number];

export const CAPABILITY_COMMAND_TYPES = [
  "activate",
  "consume",
  "expire",
  "disable",
  "abuse_lock",
  "reactivate",
  "decide_abuse_lock",
  "delete"
] as const;

export type CapabilityCommandType = (typeof CAPABILITY_COMMAND_TYPES)[number];

export const ABUSE_LOCK_DECISIONS = ["release", "disable", "delete"] as const;

export type AbuseLockDecision = (typeof ABUSE_LOCK_DECISIONS)[number];

interface CapabilityCommandBase<Type extends CapabilityCommandType> {
  readonly type: Type;
  readonly commandId: string;
  readonly at: EpochMilliseconds;
}

export type CapabilityCommand =
  | CapabilityCommandBase<"activate">
  | (CapabilityCommandBase<"consume"> & { readonly consumptionId: string })
  | CapabilityCommandBase<"expire">
  | CapabilityCommandBase<"disable">
  | CapabilityCommandBase<"abuse_lock">
  | CapabilityCommandBase<"reactivate">
  | (CapabilityCommandBase<"decide_abuse_lock"> & {
      readonly decision: AbuseLockDecision;
      readonly privilegedDecisionId: string;
    })
  | CapabilityCommandBase<"delete">;

export const CAPABILITY_TRANSITION_TABLE = {
  DRAFT: ["activate", "delete"],
  ACTIVE: ["consume", "expire", "disable", "abuse_lock", "delete"],
  CONSUMED: ["delete"],
  EXPIRED: ["delete"],
  DISABLED: ["expire", "reactivate", "delete"],
  ABUSE_LOCKED: ["decide_abuse_lock"],
  DELETED: []
} as const satisfies Record<CapabilityState, readonly CapabilityCommandType[]>;

export interface CapabilityLifecycle {
  readonly state: CapabilityState;
  readonly committedConsumptions: number;
}

interface CapabilityEventBase<Type extends string> {
  readonly type: Type;
  readonly eventId: string;
  readonly occurredAt: EpochMilliseconds;
  readonly fromState: CapabilityState;
  readonly toState: CapabilityState;
}

export type CapabilityDomainEvent =
  | CapabilityEventBase<"capability_activated">
  | (CapabilityEventBase<"capability_consumption_committed"> & {
      readonly consumptionId: string;
      readonly committedConsumptions: number;
      readonly exhausted: boolean;
    })
  | CapabilityEventBase<"capability_expired">
  | CapabilityEventBase<"capability_disabled">
  | CapabilityEventBase<"capability_abuse_locked">
  | CapabilityEventBase<"capability_reactivated">
  | (CapabilityEventBase<"capability_abuse_lock_decided"> & {
      readonly decision: AbuseLockDecision;
      readonly privilegedDecisionId: string;
    })
  | CapabilityEventBase<"capability_deleted">;

export interface CapabilityTransition {
  readonly lifecycle: CapabilityLifecycle;
  readonly event: CapabilityDomainEvent;
}

export type CapabilityTransitionError =
  | {
      readonly code: "invalid_transition";
      readonly state: CapabilityState;
      readonly command: CapabilityCommandType;
    }
  | {
      readonly code: "invalid_count";
      readonly field: "committedConsumptions" | "activeReservations";
      readonly value: number;
    }
  | {
      readonly code: "capability_expired";
      readonly expiresAt: EpochMilliseconds;
      readonly at: EpochMilliseconds;
    }
  | {
      readonly code: "capability_exhausted";
      readonly maxConsumptions: number;
      readonly committedConsumptions: number;
    }
  | { readonly code: "no_expiry_configured" }
  | {
      readonly code: "not_expired";
      readonly expiresAt: EpochMilliseconds;
      readonly at: EpochMilliseconds;
    }
  | { readonly code: "reactivation_forbidden" }
  | {
      readonly code: "explicit_consumption_not_supported";
      readonly kind: "redirect";
    }
  | { readonly code: "consumption_count_overflow" };

export interface CapabilityAvailabilityInput {
  readonly lifecycle: CapabilityLifecycle;
  readonly policy: CapabilityPolicy;
  readonly activeReservations: number;
  readonly at: EpochMilliseconds;
}

export interface CapabilityAvailability {
  readonly supportsExplicitConsumption: boolean;
  readonly isExpired: boolean;
  readonly isExhausted: boolean;
  readonly remainingConsumptions: number | null;
  readonly availableConsumptions: number | null;
  readonly hasAvailableCapacity: boolean;
  readonly canStartExplicitConsumption: boolean;
}

export const calculateCapabilityAvailability = (
  input: CapabilityAvailabilityInput
): Result<CapabilityAvailability, CapabilityTransitionError> => {
  const committedError = validateCount(
    "committedConsumptions",
    input.lifecycle.committedConsumptions
  );
  if (committedError) {
    return err(committedError);
  }

  const reservationError = validateCount("activeReservations", input.activeReservations);
  if (reservationError) {
    return err(reservationError);
  }

  const isExpired = isCapabilityExpired(input.policy, input.at);
  const supportsExplicitConsumption = input.policy.explicitConsumptionAction !== null;
  const maximum = input.policy.maxConsumptions;

  if (maximum === null) {
    const canStartExplicitConsumption =
      supportsExplicitConsumption && input.lifecycle.state === "ACTIVE" && !isExpired;
    return ok({
      supportsExplicitConsumption,
      isExpired,
      isExhausted: false,
      remainingConsumptions: null,
      availableConsumptions: null,
      hasAvailableCapacity: true,
      canStartExplicitConsumption
    });
  }

  const remainingConsumptions = Math.max(maximum - input.lifecycle.committedConsumptions, 0);
  const availableConsumptions = Math.max(remainingConsumptions - input.activeReservations, 0);
  const isExhausted = remainingConsumptions === 0;
  const hasAvailableCapacity = availableConsumptions > 0;

  return ok({
    supportsExplicitConsumption,
    isExpired,
    isExhausted,
    remainingConsumptions,
    availableConsumptions,
    hasAvailableCapacity,
    canStartExplicitConsumption:
      supportsExplicitConsumption &&
      input.lifecycle.state === "ACTIVE" &&
      !isExpired &&
      !isExhausted &&
      hasAvailableCapacity
  });
};

export const transitionCapability = (
  lifecycle: CapabilityLifecycle,
  policy: CapabilityPolicy,
  command: CapabilityCommand
): Result<CapabilityTransition, CapabilityTransitionError> => {
  const countError = validateCount("committedConsumptions", lifecycle.committedConsumptions);
  if (countError) {
    return err(countError);
  }

  const allowedCommands = CAPABILITY_TRANSITION_TABLE[lifecycle.state] as readonly string[];
  if (!allowedCommands.includes(command.type)) {
    return err({
      code: "invalid_transition",
      state: lifecycle.state,
      command: command.type
    });
  }

  switch (command.type) {
    case "activate":
      return activate(lifecycle, policy, command);
    case "consume":
      return consume(lifecycle, policy, command);
    case "expire":
      return expire(lifecycle, policy, command);
    case "disable":
      return move(lifecycle, command, "DISABLED", "capability_disabled");
    case "abuse_lock":
      return move(lifecycle, command, "ABUSE_LOCKED", "capability_abuse_locked");
    case "reactivate":
      return reactivate(lifecycle, policy, command);
    case "decide_abuse_lock":
      return decideAbuseLock(lifecycle, policy, command);
    case "delete":
      return move(lifecycle, command, "DELETED", "capability_deleted");
  }
};

export const isCapabilityExpired = (
  policy: Pick<CapabilityPolicy, "expiresAt">,
  at: EpochMilliseconds
): boolean => policy.expiresAt !== null && at >= policy.expiresAt;

const activate = (
  lifecycle: CapabilityLifecycle,
  policy: CapabilityPolicy,
  command: Extract<CapabilityCommand, { type: "activate" }>
): Result<CapabilityTransition, CapabilityTransitionError> => {
  const availabilityError = unavailableForActivation(lifecycle, policy, command.at);
  return availabilityError
    ? err(availabilityError)
    : move(lifecycle, command, "ACTIVE", "capability_activated");
};

const consume = (
  lifecycle: CapabilityLifecycle,
  policy: CapabilityPolicy,
  command: Extract<CapabilityCommand, { type: "consume" }>
): Result<CapabilityTransition, CapabilityTransitionError> => {
  if (policy.explicitConsumptionAction === null) {
    return err({ code: "explicit_consumption_not_supported", kind: "redirect" });
  }

  if (isCapabilityExpired(policy, command.at)) {
    return err({
      code: "capability_expired",
      expiresAt: policy.expiresAt as EpochMilliseconds,
      at: command.at
    });
  }

  const maximum = policy.maxConsumptions;
  if (maximum !== null && lifecycle.committedConsumptions >= maximum) {
    return err({
      code: "capability_exhausted",
      maxConsumptions: maximum,
      committedConsumptions: lifecycle.committedConsumptions
    });
  }

  if (lifecycle.committedConsumptions === Number.MAX_SAFE_INTEGER) {
    return err({ code: "consumption_count_overflow" });
  }

  const committedConsumptions = lifecycle.committedConsumptions + 1;
  const exhausted = maximum !== null && committedConsumptions >= maximum;
  const nextState: CapabilityState = exhausted ? "CONSUMED" : "ACTIVE";

  return ok({
    lifecycle: { state: nextState, committedConsumptions },
    event: {
      type: "capability_consumption_committed",
      eventId: command.commandId,
      occurredAt: command.at,
      fromState: lifecycle.state,
      toState: nextState,
      consumptionId: command.consumptionId,
      committedConsumptions,
      exhausted
    }
  });
};

const expire = (
  lifecycle: CapabilityLifecycle,
  policy: CapabilityPolicy,
  command: Extract<CapabilityCommand, { type: "expire" }>
): Result<CapabilityTransition, CapabilityTransitionError> => {
  if (policy.expiresAt === null) {
    return err({ code: "no_expiry_configured" });
  }

  if (command.at < policy.expiresAt) {
    return err({ code: "not_expired", expiresAt: policy.expiresAt, at: command.at });
  }

  return move(lifecycle, command, "EXPIRED", "capability_expired");
};

const reactivate = (
  lifecycle: CapabilityLifecycle,
  policy: CapabilityPolicy,
  command: Extract<CapabilityCommand, { type: "reactivate" }>
): Result<CapabilityTransition, CapabilityTransitionError> => {
  if (policy.reactivation === "forbidden") {
    return err({ code: "reactivation_forbidden" });
  }

  const availabilityError = unavailableForActivation(lifecycle, policy, command.at);
  return availabilityError
    ? err(availabilityError)
    : move(lifecycle, command, "ACTIVE", "capability_reactivated");
};

const decideAbuseLock = (
  lifecycle: CapabilityLifecycle,
  policy: CapabilityPolicy,
  command: Extract<CapabilityCommand, { type: "decide_abuse_lock" }>
): Result<CapabilityTransition, CapabilityTransitionError> => {
  if (command.decision === "release") {
    const availabilityError = unavailableForActivation(lifecycle, policy, command.at);
    if (availabilityError) {
      return err(availabilityError);
    }
  }

  const nextState: CapabilityState =
    command.decision === "release"
      ? "ACTIVE"
      : command.decision === "disable"
        ? "DISABLED"
        : "DELETED";

  return ok({
    lifecycle: { ...lifecycle, state: nextState },
    event: {
      type: "capability_abuse_lock_decided",
      eventId: command.commandId,
      occurredAt: command.at,
      fromState: lifecycle.state,
      toState: nextState,
      decision: command.decision,
      privilegedDecisionId: command.privilegedDecisionId
    }
  });
};

const unavailableForActivation = (
  lifecycle: CapabilityLifecycle,
  policy: CapabilityPolicy,
  at: EpochMilliseconds
): CapabilityTransitionError | null => {
  if (isCapabilityExpired(policy, at)) {
    return {
      code: "capability_expired",
      expiresAt: policy.expiresAt as EpochMilliseconds,
      at
    };
  }

  if (
    policy.maxConsumptions !== null &&
    lifecycle.committedConsumptions >= policy.maxConsumptions
  ) {
    return {
      code: "capability_exhausted",
      maxConsumptions: policy.maxConsumptions,
      committedConsumptions: lifecycle.committedConsumptions
    };
  }

  return null;
};

const move = <EventType extends CapabilityDomainEvent["type"]>(
  lifecycle: CapabilityLifecycle,
  command: CapabilityCommand,
  state: CapabilityState,
  eventType: EventType
): Result<CapabilityTransition, never> =>
  ok({
    lifecycle: { ...lifecycle, state },
    event: {
      type: eventType,
      eventId: command.commandId,
      occurredAt: command.at,
      fromState: lifecycle.state,
      toState: state
    } as Extract<CapabilityDomainEvent, { type: EventType }>
  });

const validateCount = (
  field: "committedConsumptions" | "activeReservations",
  value: number
): Extract<CapabilityTransitionError, { code: "invalid_count" }> | null =>
  Number.isSafeInteger(value) && value >= 0 ? null : { code: "invalid_count", field, value };
