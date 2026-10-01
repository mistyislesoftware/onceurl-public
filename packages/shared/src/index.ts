export * from "./async-job";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export type ApiErrorCode =
  | "not_found"
  | "invalid_request"
  | "capability_unavailable"
  | "rate_limited"
  | "verification_required"
  | "verification_failed"
  | "internal_error";

export interface ApiErrorBody {
  error: {
    code: ApiErrorCode;
    message: string;
    request_id: string;
    details: JsonObject;
  };
}

export const apiErrorMessages = {
  not_found: "The requested API resource was not found.",
  invalid_request: "The request was not valid.",
  capability_unavailable: "This capability is unavailable.",
  rate_limited: "Too many requests. Please wait and try again.",
  verification_required: "Complete the separate security check before trying again.",
  verification_failed: "The verification was not accepted.",
  internal_error: "An unexpected error occurred. Please try again later."
} as const satisfies Record<ApiErrorCode, string>;

export function createApiErrorBody(
  code: ApiErrorCode,
  requestId: string,
  details: JsonObject = {}
): ApiErrorBody {
  return {
    error: {
      code,
      message: apiErrorMessages[code],
      request_id: requestId,
      details
    }
  };
}

export const healthResponse = { ok: true, service: "onceurl-worker" } as const;

export const sharedPackagePurpose = "Shared types and validation placeholders for OnceURL.";
