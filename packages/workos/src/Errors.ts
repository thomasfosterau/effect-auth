/**
 * Errors raised by `@effect-auth/workos`.
 *
 * Every call made through the {@link WorkOS} service that fails is surfaced as a
 * single {@link WorkOSError}. The error preserves the rich metadata that the
 * WorkOS Node SDK attaches to its exceptions (HTTP status, error `code`, the
 * `requestID` for support tickets, rate-limit `retryAfter`, and the
 * AuthKit-specific `authenticationCode`/`pendingAuthenticationToken`) while also
 * keeping the original thrown value under `cause`.
 */

import { Data } from "effect";

/**
 * The shape of the metadata extracted from a thrown WorkOS SDK exception.
 *
 * All fields are optional because the various WorkOS exception classes expose
 * different subsets of metadata. The original thrown value is always retained
 * under {@link WorkOSError.cause}.
 */
export interface WorkOSErrorFields {
  /** Human readable description of what went wrong. */
  readonly message: string;
  /**
   * The WorkOS module + method that produced the error, e.g.
   * `userManagement.authenticateWithPassword`. Useful for tracing.
   */
  readonly operation?: string;
  /** The name of the underlying WorkOS exception, e.g. `NotFoundException`. */
  readonly exception?: string;
  /** HTTP status code returned by the WorkOS API, when available. */
  readonly status?: number;
  /** Machine readable error code returned by the WorkOS API, when available. */
  readonly code?: string;
  /** The WorkOS request id, handy when contacting WorkOS support. */
  readonly requestID?: string;
  /** Seconds to wait before retrying, set for rate-limit errors. */
  readonly retryAfter?: number;
  /**
   * For AuthKit/User Management authentication errors, the code describing the
   * additional step required (e.g. `mfa_challenge`, `email_verification_required`,
   * `organization_selection_required`).
   */
  readonly authenticationCode?: string;
  /**
   * For AuthKit authentication errors, the token to replay when completing the
   * pending step (MFA, email verification, organization selection, ...).
   */
  readonly pendingAuthenticationToken?: string;
  /** The original value thrown by the WorkOS SDK. */
  readonly cause?: unknown;
}

/**
 * Tagged error wrapping every failure originating from the WorkOS Node SDK.
 */
export class WorkOSError extends Data.TaggedError("WorkOSError")<WorkOSErrorFields> {
  /** Convenience type guard. */
  static is(u: unknown): u is WorkOSError {
    return typeof u === "object" && u !== null && (u as { _tag?: unknown })._tag === "WorkOSError";
  }
}

const asRecord = (u: unknown): Record<string, unknown> | undefined =>
  typeof u === "object" && u !== null ? (u as Record<string, unknown>) : undefined;

const stringField = (record: Record<string, unknown>, key: string): string | undefined => {
  const value = record[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
};

const numberField = (record: Record<string, unknown>, key: string): number | undefined => {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
};

/**
 * Build a sanitized copy of a thrown value suitable for storing as
 * {@link WorkOSError.cause}. Any property named `headers` is dropped at every
 * nesting level so that HTTP request headers (which carry
 * `Authorization: Bearer sk_...`) are never retained.
 */
const sanitizeCause = (value: unknown): unknown => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return value;
  const src = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(src)) {
    if (key === "headers") continue;
    out[key] = sanitizeCause(src[key]);
  }
  if (value instanceof Error) {
    if (value.message && !("message" in out)) out["message"] = value.message;
    if (value.stack && !("stack" in out)) out["stack"] = value.stack;
  }
  return out;
};

/**
 * Normalise any value thrown by the WorkOS SDK into a {@link WorkOSError}.
 *
 * The WorkOS Node SDK throws a family of exception classes (`NotFoundException`,
 * `UnauthorizedException`, `RateLimitExceededException`, `AuthenticationException`,
 * `SignatureVerificationException`, ...). Rather than couple to each class via
 * `instanceof` (which is brittle across bundlers), we duck-type the well-known
 * fields they expose.
 */
export const toWorkOSError = (cause: unknown, operation?: string): WorkOSError => {
  const record = asRecord(cause);

  const message =
    (record && stringField(record, "message")) ??
    (cause instanceof Error ? cause.message : undefined) ??
    (typeof cause === "string" ? cause : "WorkOS request failed");

  const fields: {
    message: string;
    cause: unknown;
    operation?: string;
    exception?: string;
    status?: number;
    code?: string;
    requestID?: string;
    retryAfter?: number;
    authenticationCode?: string;
    pendingAuthenticationToken?: string;
  } = { message, cause: sanitizeCause(cause) };

  if (operation !== undefined) fields.operation = operation;

  if (record) {
    const exception = stringField(record, "name");
    if (exception !== undefined) fields.exception = exception;

    const status = numberField(record, "status");
    if (status !== undefined) fields.status = status;

    const code = stringField(record, "code") ?? stringField(record, "error");
    if (code !== undefined) fields.code = code;

    const requestID = stringField(record, "requestID");
    if (requestID !== undefined) fields.requestID = requestID;

    const retryAfter = numberField(record, "retryAfter");
    if (retryAfter !== undefined) fields.retryAfter = retryAfter;

    // AuthenticationException stores step-up data in rawData with snake_case keys
    // (pending_authentication_token, code/error) mirroring the API wire format.
    // Fall back to top-level camelCase properties for forward/backward compat.
    const rawData = asRecord(record["rawData"]);
    const pendingAuthenticationToken =
      (rawData !== undefined && stringField(rawData, "pending_authentication_token")) ||
      stringField(record, "pendingAuthenticationToken");
    if (pendingAuthenticationToken !== undefined) {
      fields.pendingAuthenticationToken = pendingAuthenticationToken;
      const authenticationCode =
        (rawData !== undefined &&
          (stringField(rawData, "code") ?? stringField(rawData, "error"))) ||
        stringField(record, "code");
      if (authenticationCode !== undefined) fields.authenticationCode = authenticationCode;
    }
  }

  return new WorkOSError(fields);
};
