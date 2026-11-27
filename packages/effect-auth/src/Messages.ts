/**
 * The {@link Messages} service resolves a domain error's stable `code`, with an
 * optional locale and params, to text, so an application adds locales without
 * patching the library.
 *
 * @example A French catalog over the English default
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * // The app's own French catalog. Codes it lacks fall back to the English default.
 * const frCatalog: Record<string, (params?: Auth.Types.JsonObject) => string> = {
 *   [Auth.Errors.ErrorCode.INVALID_CREDENTIALS]: () => "E-mail ou mot de passe invalide",
 * }
 *
 * // Default English – no configuration needed.
 * const english = Effect.gen(function* () {
 *   const messages = yield* Auth.Messages.Messages
 *   assert.equal(messages.resolve(Auth.Errors.ErrorCode.INVALID_CREDENTIALS), "Invalid email or password")
 * }).pipe(Effect.provide(Auth.Messages.Messages.Default))
 *
 * // Custom locale: a French resolver that falls back to the English one.
 * const frenchMessages = Layer.effect(
 *   Auth.Messages.Messages,
 *   Effect.gen(function* () {
 *     const fallback = yield* Auth.Messages.Messages
 *     return {
 *       resolve: (code, locale, params) =>
 *         locale === "fr"
 *           ? (frCatalog[code]?.(params) ?? fallback.resolve(code, locale, params))
 *           : fallback.resolve(code, locale, params),
 *     }
 *   }),
 * ).pipe(Layer.provide(Auth.Messages.Messages.Default))
 *
 * const french = Effect.gen(function* () {
 *   const messages = yield* Auth.Messages.Messages
 *   assert.equal(messages.resolve(Auth.Errors.ErrorCode.INVALID_CREDENTIALS, "fr"), "E-mail ou mot de passe invalide")
 *   // No French entry for this code, so the English text is used.
 *   assert.equal(
 *     messages.resolve(Auth.Errors.ErrorCode.PASSWORD_TOO_SHORT, "fr", { minLength: 10 }),
 *     "Password must be at least 10 characters",
 *   )
 * }).pipe(Effect.provide(frenchMessages))
 *
 * await Effect.runPromise(Effect.all([english, french]))
 * ```
 *
 * @module messages
 */

import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import { ErrorCode } from "./Errors.ts";
import type * as Types from "./Types.ts";

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
    readonly resolve: (code: string, locale?: string, params?: Types.JsonObject) => string;
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

/** Interpolation parameters, as `Messages.resolve` receives them. */
type MessageParams = Types.JsonObject;

type Resolver = (params?: MessageParams) => string;

/** A printable interpolation parameter, or `fallback` when it is missing or not printable. */
const param = (
  params: MessageParams | undefined,
  key: string,
  fallback: number,
): string | number => {
  const value = params?.[key];
  return P.isString(value) || P.isNumber(value) ? value : fallback;
};

/** Each code's English message, or the resolver that builds it from params. */
interface Catalog {
  readonly [code: string]: string | Resolver;
}

const catalog: Catalog = {
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
    `Password must be at least ${param(p, "minLength", 8)} characters`,
  [ErrorCode.PASSWORD_TOO_LONG]: (p) =>
    `Password must be at most ${param(p, "maxLength", 128)} characters`,
  [ErrorCode.PASSWORD_ALREADY_SET]: "User already has a password; use changePassword instead",
  [ErrorCode.PWNED_PASSWORD]: "This password has appeared in a data breach; please choose another",

  [ErrorCode.SIGN_UP_DISABLED]: "Email/password sign-up is disabled",
  [ErrorCode.INVALID_INPUT]: "A required field is missing or invalid",
  [ErrorCode.CAPTCHA_FAILED]: "Captcha verification failed",
  [ErrorCode.CONFUSABLE_EMAIL]:
    "This email address can be mistaken for another; please use a different one",

  [ErrorCode.ACCOUNT_LOCKED]: "Account temporarily locked due to too many failed sign-in attempts",
  [ErrorCode.USER_BANNED]: "Your account has been suspended",
  [ErrorCode.REAUTHENTICATION_REQUIRED]: "Confirm it's you to continue",

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

  [ErrorCode.IMPERSONATION_FORBIDDEN]: "This change is not allowed while impersonating a user",
};

function defaultResolve(code: string, _locale?: string, params?: MessageParams): string {
  const entry = catalog[code];
  if (entry === undefined) return code;
  return P.isFunction(entry) ? entry(params) : entry;
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
  params?: Types.JsonObject,
): Effect.Effect<string> =>
  Effect.serviceOption(Messages).pipe(
    Effect.map((opt) =>
      Option.isSome(opt) ? opt.value.resolve(code, undefined, params) : fallback,
    ),
  );
