/**
 * General-purpose single-use token service for effect-auth.
 *
 * Tokens are cryptographically random (32 bytes of base64url entropy), stored
 * as SHA-256 digests so a database breach cannot replay them, expire on a
 * configurable TTL, and are consumed (deleted) on first successful
 * {@link OneTimeTokenService.verify} call.
 *
 * Typical use-cases: email-action confirmation links, passwordless sign-in
 * codes, invite tokens, account-deletion confirmation, or any flow that needs
 * a secure one-shot secret.
 *
 * @module one-time-token
 */
import { Context, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import * as Errors from "./Errors.ts";
import { Hooks, type HookError } from "./Hooks.ts";
import { hashToken } from "./TokenHash.ts";
import { SessionService } from "./session/SessionService.ts";
import type * as Types from "./Types.ts";

// ---------------------------------------------------------------------------
// Store record
// ---------------------------------------------------------------------------

/**
 * A persisted one-time-token record.
 * The `token` field holds the SHA-256 hex digest — the raw token is never
 * stored.
 */
export interface OneTimeTokenRecord {
  readonly token: string;
  readonly subject: string;
  readonly metadata?: Record<string, unknown>;
  readonly createdAt: number;
  readonly expiresAt: number;
}

// ---------------------------------------------------------------------------
// Store shape + Context tag
// ---------------------------------------------------------------------------

/**
 * Bring-your-own store for one-time tokens.
 *
 * Provide via `Layer.succeed(OneTimeTokenStore)(impl)`.
 */
export class OneTimeTokenStore extends Context.Service<
  OneTimeTokenStore,
  {
    readonly create: (
      record: OneTimeTokenRecord,
    ) => Effect.Effect<OneTimeTokenRecord, Errors.AuthError>;
    readonly get: (token: string) => Effect.Effect<OneTimeTokenRecord | null, Errors.AuthError>;
    readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/OneTimeTokenStore") {}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface OneTimeTokenConfig {
  /** Default TTL in milliseconds for generated tokens. Defaults to 15 minutes. */
  readonly expiresIn?: number;
}

// ---------------------------------------------------------------------------
// Service types
// ---------------------------------------------------------------------------

export interface OneTimeTokenGenerateOptions {
  /** Per-token TTL override in milliseconds. Falls back to `OneTimeTokenConfig.expiresIn`. */
  readonly expiresIn?: number;
  /** Arbitrary metadata stored alongside the token (e.g. purpose, redirect URL, scopes). */
  readonly metadata?: Record<string, unknown>;
}

export interface OneTimeTokenVerifyResult {
  readonly subject: string;
  readonly metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Service class + Layer
// ---------------------------------------------------------------------------

export class OneTimeTokenService extends Context.Service<
  OneTimeTokenService,
  {
    /**
     * Generate a cryptographically random single-use token for `subject`.
     *
     * Returns the raw (unhashed) token. Deliver it to the end user via email,
     * SMS, URL, QR code, or any out-of-band channel — only its SHA-256 digest
     * is persisted.
     */
    readonly generate: (
      subject: string,
      options?: OneTimeTokenGenerateOptions,
    ) => Effect.Effect<string, Errors.AuthError, OneTimeTokenStore>;

    /**
     * Verify and consume a raw token. On success returns `{ subject, metadata }`.
     *
     * The token is deleted from the store on the first lookup (single-use
     * guarantee). Anti-enumeration: invalid, already-used, and expired tokens
     * all surface the same `OneTimeTokenError` with a generic message.
     */
    readonly verify: (
      token: string,
    ) => Effect.Effect<
      OneTimeTokenVerifyResult,
      Errors.OneTimeTokenError | Errors.AuthError,
      OneTimeTokenStore
    >;
  }
>()("@effect-auth/OneTimeTokenService") {
  /**
   * Construct a Layer providing this service.
   *
   * @param config - Optional configuration (default TTL, etc.)
   */
  static readonly layer = (config?: OneTimeTokenConfig) =>
    Layer.effect(OneTimeTokenService, make(config ?? {}));
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export const make = (
  config: OneTimeTokenConfig,
): Effect.Effect<typeof OneTimeTokenService.Service, never> => {
  const defaultExpiresIn = config.expiresIn ?? 15 * 60 * 1000;

  return Effect.sync((): typeof OneTimeTokenService.Service => ({
    generate: (subject: string, options?: OneTimeTokenGenerateOptions) =>
      Effect.gen(function* () {
        const store = yield* OneTimeTokenStore;
        const rawToken = yield* Effect.sync(() => crypto.randomBytes(32).toString("base64url"));
        const expiresIn = options?.expiresIn ?? defaultExpiresIn;
        const now = Date.now();
        const record: OneTimeTokenRecord = {
          token: hashToken(rawToken),
          subject,
          ...(options?.metadata !== undefined ? { metadata: options.metadata } : {}),
          createdAt: now,
          expiresAt: now + expiresIn,
        };
        yield* store.create(record);
        return rawToken;
      }),

    verify: (rawToken: string) =>
      Effect.gen(function* () {
        const store = yield* OneTimeTokenStore;

        if (!rawToken) {
          return yield* Effect.fail(
            new Errors.OneTimeTokenError({ message: "Invalid or expired token" }),
          );
        }

        const tokenHash = hashToken(rawToken);
        const record = yield* store.get(tokenHash);
        if (!record) {
          return yield* Effect.fail(
            new Errors.OneTimeTokenError({ message: "Invalid or expired token" }),
          );
        }

        // Consume the token immediately — delete before the expiry check so
        // the timing difference between "found-but-expired" and "not found"
        // does not leak whether the hash exists in the store.
        yield* store.delete(tokenHash);

        if (Date.now() > record.expiresAt) {
          return yield* Effect.fail(
            new Errors.OneTimeTokenError({ message: "Invalid or expired token" }),
          );
        }

        return {
          subject: record.subject,
          ...(record.metadata !== undefined ? { metadata: record.metadata } : {}),
        } satisfies OneTimeTokenVerifyResult;
      }),
  }));
};

// ---------------------------------------------------------------------------
// Optional: token → session exchange helper
// ---------------------------------------------------------------------------

/**
 * Verify a one-time token and immediately create a session for its subject.
 *
 * This helper covers the common pattern where the token's `subject` is a user
 * ID and you want to sign the user in after a successful verification (e.g.
 * passwordless sign-in, email-confirmed account activation).
 *
 * @example
 * ```ts
 * const { session, subject } = yield* redeemOneTimeTokenForSession(rawToken);
 * setCookie(response, "session", session.id);
 * ```
 *
 * Requires `OneTimeTokenService`, `OneTimeTokenStore`, and `SessionService`
 * in the Effect context.
 */
export const redeemOneTimeTokenForSession = (
  rawToken: string,
  options?: { readonly sessionAttributes?: Record<string, unknown> },
): Effect.Effect<
  {
    readonly subject: string;
    readonly session: Types.Session;
    readonly metadata?: Record<string, unknown>;
  },
  Errors.OneTimeTokenError | Errors.AuthError | HookError,
  OneTimeTokenService | OneTimeTokenStore | SessionService | Hooks
> =>
  Effect.gen(function* () {
    const service = yield* OneTimeTokenService;
    const sessionService = yield* SessionService;
    const result = yield* service.verify(rawToken);
    const session = yield* sessionService.createSession(result.subject, options?.sessionAttributes);
    return { ...result, session };
  });
