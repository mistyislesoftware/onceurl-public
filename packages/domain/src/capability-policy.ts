import { err, ok, type Result } from "./result.js";

export const CAPABILITY_KINDS = ["secret", "file_download", "upload_request", "redirect"] as const;

export type CapabilityKind = (typeof CAPABILITY_KINDS)[number];

declare const epochMillisecondsBrand: unique symbol;
declare const positiveConsumptionLimitBrand: unique symbol;
declare const positiveDurationMillisecondsBrand: unique symbol;

export type EpochMilliseconds = number & {
  readonly [epochMillisecondsBrand]: "EpochMilliseconds";
};

export type PositiveConsumptionLimit = number & {
  readonly [positiveConsumptionLimitBrand]: "PositiveConsumptionLimit";
};

export type SingleConsumptionLimit = PositiveConsumptionLimit & 1;

const SINGLE_CONSUMPTION_LIMIT = 1 as SingleConsumptionLimit;

export type PositiveDurationMilliseconds = number & {
  readonly [positiveDurationMillisecondsBrand]: "PositiveDurationMilliseconds";
};

export type ReactivationPolicy = "allowed" | "forbidden";

export type PostConsumptionPolicy =
  | { readonly behavior: "delete_capability" }
  | {
      readonly behavior: "retain_capability";
      readonly retention:
        | { readonly mode: "until_expiry" }
        | { readonly mode: "for"; readonly durationMs: PositiveDurationMilliseconds };
    };

interface BaseCapabilityPolicy {
  readonly expiresAt: EpochMilliseconds | null;
  readonly maxConsumptions: PositiveConsumptionLimit | null;
  readonly reactivation: ReactivationPolicy;
  readonly postConsumption: PostConsumptionPolicy;
}

export interface SecretCapabilityPolicy extends BaseCapabilityPolicy {
  readonly kind: "secret";
  readonly explicitConsumptionAction: "reveal";
  readonly maxConsumptions: SingleConsumptionLimit;
  readonly payloadMode: "zero_knowledge";
  readonly payloadAfterConsumption: "destroy";
}

export interface FileDownloadCapabilityPolicy extends BaseCapabilityPolicy {
  readonly kind: "file_download";
  readonly explicitConsumptionAction: "issue_download_lease";
}

export interface UploadRequestCapabilityPolicy extends BaseCapabilityPolicy {
  readonly kind: "upload_request";
  readonly explicitConsumptionAction: "finalize_upload";
}

export interface DirectRedirectCapabilityPolicy extends BaseCapabilityPolicy {
  readonly kind: "redirect";
  readonly redirectMode: "direct";
  readonly explicitConsumptionAction: null;
  readonly maxConsumptions: null;
}

export interface ConfirmedRedirectCapabilityPolicy extends BaseCapabilityPolicy {
  readonly kind: "redirect";
  readonly redirectMode: "confirmed";
  readonly explicitConsumptionAction: "confirm_redirect";
}

export type RedirectCapabilityPolicy =
  DirectRedirectCapabilityPolicy | ConfirmedRedirectCapabilityPolicy;

export type CapabilityPolicy =
  | SecretCapabilityPolicy
  | FileDownloadCapabilityPolicy
  | UploadRequestCapabilityPolicy
  | RedirectCapabilityPolicy;

export type PolicyValidationError =
  | { readonly code: "invalid_policy_shape" }
  | { readonly code: "invalid_capability_kind"; readonly value: unknown }
  | { readonly code: "invalid_expiry"; readonly value: unknown }
  | { readonly code: "invalid_consumption_limit"; readonly value: unknown }
  | { readonly code: "invalid_reactivation_policy"; readonly value: unknown }
  | {
      readonly code: "invalid_post_consumption_policy";
      readonly reason: "invalid_shape" | "missing_expiry";
    }
  | { readonly code: "invalid_retention_duration"; readonly value: unknown }
  | {
      readonly code: "invalid_kind_policy";
      readonly kind: CapabilityKind;
      readonly reason:
        "invalid_redirect_mode" | "passive_redirect_limit" | "secret_requires_single_consumption";
    };

export type TimestampValidationError = {
  readonly code: "invalid_timestamp";
  readonly value: unknown;
};

export const parseEpochMilliseconds = (
  value: unknown
): Result<EpochMilliseconds, TimestampValidationError> =>
  isNonNegativeSafeInteger(value)
    ? ok(value as EpochMilliseconds)
    : err({ code: "invalid_timestamp", value });

export const parseOptionalConsumptionLimit = (
  value: unknown
): Result<PositiveConsumptionLimit | null, PolicyValidationError> => {
  if (value === undefined || value === null) {
    return ok(null);
  }

  return isPositiveSafeInteger(value)
    ? ok(value as PositiveConsumptionLimit)
    : err({ code: "invalid_consumption_limit", value });
};

export const parseCapabilityPolicy = (
  input: unknown
): Result<CapabilityPolicy, PolicyValidationError> => {
  if (!isRecord(input)) {
    return err({ code: "invalid_policy_shape" });
  }

  if (!isCapabilityKind(input.kind)) {
    return err({ code: "invalid_capability_kind", value: input.kind });
  }

  const expiresAtResult = parseOptionalExpiry(input.expiresAt);
  if (!expiresAtResult.ok) {
    return expiresAtResult;
  }

  const maxConsumptionsResult = parseOptionalConsumptionLimit(input.maxConsumptions);
  if (!maxConsumptionsResult.ok) {
    return maxConsumptionsResult;
  }

  if (input.reactivation !== "allowed" && input.reactivation !== "forbidden") {
    return err({ code: "invalid_reactivation_policy", value: input.reactivation });
  }

  const postConsumptionResult = parsePostConsumptionPolicy(
    input.postConsumption,
    expiresAtResult.value
  );
  if (!postConsumptionResult.ok) {
    return postConsumptionResult;
  }

  const base = {
    expiresAt: expiresAtResult.value,
    maxConsumptions: maxConsumptionsResult.value,
    reactivation: input.reactivation,
    postConsumption: postConsumptionResult.value
  } as const;

  switch (input.kind) {
    case "secret": {
      if (base.maxConsumptions !== null && base.maxConsumptions !== 1) {
        return err({
          code: "invalid_kind_policy",
          kind: "secret",
          reason: "secret_requires_single_consumption"
        });
      }

      return ok({
        ...base,
        kind: "secret",
        explicitConsumptionAction: "reveal",
        maxConsumptions: SINGLE_CONSUMPTION_LIMIT,
        payloadMode: "zero_knowledge",
        payloadAfterConsumption: "destroy"
      });
    }
    case "file_download":
      return ok({
        ...base,
        kind: "file_download",
        explicitConsumptionAction: "issue_download_lease"
      });
    case "upload_request":
      return ok({
        ...base,
        kind: "upload_request",
        explicitConsumptionAction: "finalize_upload"
      });
    case "redirect": {
      if (input.redirectMode !== "direct" && input.redirectMode !== "confirmed") {
        return err({
          code: "invalid_kind_policy",
          kind: "redirect",
          reason: "invalid_redirect_mode"
        });
      }

      if (input.redirectMode === "direct") {
        if (base.maxConsumptions !== null) {
          return err({
            code: "invalid_kind_policy",
            kind: "redirect",
            reason: "passive_redirect_limit"
          });
        }

        return ok({
          ...base,
          kind: "redirect",
          redirectMode: "direct",
          explicitConsumptionAction: null,
          maxConsumptions: null
        });
      }

      return ok({
        ...base,
        kind: "redirect",
        redirectMode: "confirmed",
        explicitConsumptionAction: "confirm_redirect"
      });
    }
  }
};

const parseOptionalExpiry = (
  value: unknown
): Result<EpochMilliseconds | null, PolicyValidationError> => {
  if (value === undefined || value === null) {
    return ok(null);
  }

  const result = parseEpochMilliseconds(value);
  return result.ok ? result : err({ code: "invalid_expiry", value });
};

const parsePostConsumptionPolicy = (
  value: unknown,
  expiresAt: EpochMilliseconds | null
): Result<PostConsumptionPolicy, PolicyValidationError> => {
  if (!isRecord(value)) {
    return err({ code: "invalid_post_consumption_policy", reason: "invalid_shape" });
  }

  if (value.behavior === "delete_capability") {
    return ok({ behavior: "delete_capability" });
  }

  if (value.behavior !== "retain_capability" || !isRecord(value.retention)) {
    return err({ code: "invalid_post_consumption_policy", reason: "invalid_shape" });
  }

  if (value.retention.mode === "until_expiry") {
    return expiresAt === null
      ? err({ code: "invalid_post_consumption_policy", reason: "missing_expiry" })
      : ok({ behavior: "retain_capability", retention: { mode: "until_expiry" } });
  }

  if (value.retention.mode === "for") {
    const duration = value.retention.durationMs;
    return isPositiveSafeInteger(duration)
      ? ok({
          behavior: "retain_capability",
          retention: {
            mode: "for",
            durationMs: duration as PositiveDurationMilliseconds
          }
        })
      : err({ code: "invalid_retention_duration", value: duration });
  }

  return err({ code: "invalid_post_consumption_policy", reason: "invalid_shape" });
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isCapabilityKind = (value: unknown): value is CapabilityKind =>
  typeof value === "string" && CAPABILITY_KINDS.includes(value as CapabilityKind);

const isNonNegativeSafeInteger = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

const isPositiveSafeInteger = (value: unknown): value is number =>
  isNonNegativeSafeInteger(value) && value > 0;
