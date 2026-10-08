/**
 * Pluggable message-resolution layer.
 *
 * Domain errors carry a stable `code` (e.g. `"PASSWORD_TOO_SHORT"`) plus
 * optional interpolation `params`. The `Messages` service maps
 * `(code, locale?, params?) → string`, enabling locale overrides without
 * patching the library.
 *
 * Usage:
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * // The app's own French catalog. Codes it lacks fall back to the English default.
 * const frCatalog: Record<string, (params?: Record<string, unknown>) => string> = {
 *   [Auth.ErrorCode.INVALID_CREDENTIALS]: () => "E-mail ou mot de passe invalide",
 * }
 *
 * // Default English – no configuration needed.
 * const english = Effect.gen(function* () {
 *   const messages = yield* Auth.Messages
 *   assert.equal(messages.resolve(Auth.ErrorCode.INVALID_CREDENTIALS), "Invalid email or password")
 * }).pipe(Effect.provide(Auth.Messages.Default))
 *
 * // Custom locale: a French resolver that falls back to the English one.
 * const frenchMessages = Layer.effect(
 *   Auth.Messages,
 *   Effect.gen(function* () {
 *     const fallback = yield* Auth.Messages
 *     return {
 *       resolve: (code, locale, params) =>
 *         locale === "fr"
 *           ? (frCatalog[code]?.(params) ?? fallback.resolve(code, locale, params))
 *           : fallback.resolve(code, locale, params),
 *     }
 *   }),
 * ).pipe(Layer.provide(Auth.Messages.Default))
 *
 * const french = Effect.gen(function* () {
 *   const messages = yield* Auth.Messages
 *   assert.equal(messages.resolve(Auth.ErrorCode.INVALID_CREDENTIALS, "fr"), "E-mail ou mot de passe invalide")
 *   // No French entry for this code, so the English text is used.
 *   assert.equal(
 *     messages.resolve(Auth.ErrorCode.PASSWORD_TOO_SHORT, "fr", { minLength: 10 }),
 *     "Password must be at least 10 characters",
 *   )
 * }).pipe(Effect.provide(frenchMessages))
 *
 * await Effect.runPromise(Effect.all([english, french]))
 * ```
 *
 * @module messages
 */

import { Context, Effect, Layer, Option } from "effect";
import { ErrorCode } from "./Errors.ts";

// ---------------------------------------------------------------------------
// Service interface
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Service class
// ---------------------------------------------------------------------------

/**
 * Resolves an error `code` (with optional locale and parameters) to a human-readable message. `Messages.Default` is the English catalogue; provide your own layer to localise.
 */
export class Messages extends Context.Service<
  Messages,
  {
    /**
     * Resolve `code` to a human-readable string.
     *
     * @param code   - Stable error code (e.g. `"PASSWORD_TOO_SHORT"`).
     * @param locale - BCP-47 locale tag (e.g. `"en"`, `"fr"`). Callers may pass
     *                 `undefined`; the default catalog ignores it.
     * @param params - Interpolation parameters specific to the error.
     */
    readonly resolve: (code: string, locale?: string, params?: Record<string, unknown>) => string;
  }
>()("@effect-auth/Messages") {
  /** Default English catalog – no setup required. */
  static readonly Default: Layer.Layer<Messages> = Layer.succeed(Messages, {
    resolve: defaultResolve,
  });
}

// ---------------------------------------------------------------------------
// English default catalog
// ---------------------------------------------------------------------------

type Resolver = (params?: Record<string, unknown>) => string;

const catalog: Record<string, string | Resolver> = {
  [ErrorCode.AUTH_ERROR]: "An unexpected error occurred",
  [ErrorCode.HASHING_ERROR]: "Password processing failed",

  [ErrorCode.INVALID_CREDENTIALS]: "Invalid email or password",
  [ErrorCode.SESSION_NOT_FOUND]: "Session not found",
  [ErrorCode.SESSION_EXPIRED]: "Session has expired",
  [ErrorCode.USER_NOT_FOUND]: "User not found",

  [ErrorCode.EMAIL_NOT_VERIFIED]: "Email address has not been verified",
  [ErrorCode.EMAIL_IN_USE]: "A user with this email already exists",
  [ErrorCode.EMAIL_VERIFICATION_ERROR]: "Email verification failed",

  [ErrorCode.PASSWORD_TOO_SHORT]: (p) =>
    `Password must be at least ${(p?.minLength as number | undefined) ?? 8} characters`,
  [ErrorCode.PASSWORD_TOO_LONG]: (p) =>
    `Password must be at most ${(p?.maxLength as number | undefined) ?? 128} characters`,
  [ErrorCode.PASSWORD_ALREADY_SET]: "User already has a password; use changePassword instead",
  [ErrorCode.PWNED_PASSWORD]: "This password has appeared in a data breach; please choose another",

  [ErrorCode.SIGN_UP_DISABLED]: "Email/password sign-up is disabled",
  [ErrorCode.INVALID_INPUT]: "A required field is missing or invalid",
  [ErrorCode.CAPTCHA_FAILED]: "Captcha verification failed",

  [ErrorCode.ACCOUNT_LOCKED]: "Account temporarily locked due to too many failed sign-in attempts",
  [ErrorCode.USER_BANNED]: "Your account has been suspended",

  [ErrorCode.PERMISSION_DENIED]: "You do not have permission to perform this action",
  [ErrorCode.INSUFFICIENT_SCOPE]: "Insufficient OAuth scope",

  [ErrorCode.CHALLENGE_NOT_FOUND]: "WebAuthn challenge not found",
  [ErrorCode.CHALLENGE_EXPIRED]: "WebAuthn challenge has expired",
  [ErrorCode.CREDENTIAL_NOT_FOUND]: "WebAuthn credential not found",
  [ErrorCode.WEBAUTHN_VERIFICATION_ERROR]: "WebAuthn verification failed",

  [ErrorCode.OAUTH_STATE_NOT_FOUND]: "OAuth state not found or expired",
  [ErrorCode.OAUTH_STATE_EXPIRED]: "OAuth state has expired",
  [ErrorCode.OAUTH_PROVIDER_ERROR]: "OAuth provider returned an error",
  [ErrorCode.OAUTH_ACCOUNT_NOT_LINKED]: "This OAuth account is not linked to a user",
  [ErrorCode.OAUTH_MISSING_EMAIL]: "OAuth provider did not return an email address",
  [ErrorCode.OAUTH_ACCOUNT_CONFLICT]: "This OAuth account is already linked to another user",
  [ErrorCode.OAUTH_ACCOUNT_NOT_FOUND]: "No OAuth account linked for this provider",
  [ErrorCode.OAUTH_NO_REFRESH_TOKEN]: "No refresh token available for this provider",

  [ErrorCode.RATE_LIMIT_EXCEEDED]: "Too many requests; please slow down",
  [ErrorCode.MAGIC_LINK_ERROR]: "Magic link operation failed",
  [ErrorCode.PASSWORD_RESET_ERROR]: "Password reset failed",
};

function defaultResolve(code: string, _locale?: string, params?: Record<string, unknown>): string {
  const entry = catalog[code];
  if (entry === undefined) return code;
  return typeof entry === "function" ? entry(params) : entry;
}

// ---------------------------------------------------------------------------
// Effect helper: resolve a message, falling back to the error's own message.
// ---------------------------------------------------------------------------

/**
 * Resolve a display message for an error that carries `code` and optional
 * `params`. Falls back to `fallback` when the `Messages` service is absent.
 *
 * Intended for use inside `Effect.catchTags` handlers in the HTTP layer.
 */
export const resolveMessage = (
  code: string,
  fallback: string,
  params?: Record<string, unknown>,
): Effect.Effect<string, never, never> =>
  Effect.serviceOption(Messages).pipe(
    Effect.map((opt) =>
      Option.isSome(opt) ? opt.value.resolve(code, undefined, params) : fallback,
    ),
  );
