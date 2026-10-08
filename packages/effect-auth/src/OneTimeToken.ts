/**
 * General-purpose single-use token service for effect-auth.
 *
 * Tokens are cryptographically random (32 bytes of base64url entropy), stored
 * as SHA-256 digests so a database breach cannot replay them, expire on a
 * configurable TTL, and are consumed (deleted) by the first
 * {@link OneTimeTokenService.verify} call that finds them, even an expired one.
 *
 * Typical use-cases: email-action confirmation links, passwordless sign-in
 * codes, invite tokens, account-deletion confirmation, or any flow that needs
 * a secure one-shot secret.
 *
 * @module one-time-token
 */
import { Context, Crypto, Effect, Layer } from "effect";
import * as Errors from "./Errors.ts";
import { Hooks, type HookError } from "./Hooks.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { hashToken } from "./TokenHash.ts";
import { SessionService } from "./SessionService.ts";
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

/** Configuration for {@link OneTimeTokenService}. */
export interface OneTimeTokenConfig {
  /** Default TTL in milliseconds for generated tokens. Defaults to 15 minutes. */
  readonly expiresIn?: number;
}

// ---------------------------------------------------------------------------
// Service types
// ---------------------------------------------------------------------------

/** Per-token options for {@link OneTimeTokenService.generate}. */
export interface OneTimeTokenGenerateOptions {
  /** Per-token TTL override in milliseconds. Falls back to `OneTimeTokenConfig.expiresIn`. */
  readonly expiresIn?: number;
  /** Arbitrary metadata stored alongside the token (e.g. purpose, redirect URL, scopes). */
  readonly metadata?: Record<string, unknown>;
}

/** The subject and metadata a verified one-time token was issued for. */
export interface OneTimeTokenVerifyResult {
  readonly subject: string;
  readonly metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Service class + Layer
// ---------------------------------------------------------------------------

/**
 * Single-use, expiring tokens bound to a subject (confirmation links, invite tokens, any one-shot secret), stored as SHA-256 digests and consumed by the first `verify` that finds them, even an expired one.
 *
 * Requires `OneTimeTokenStore`.
 */
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
    ) => Effect.Effect<string, Errors.AuthError>;

    /**
     * Verify and consume a raw token. On success returns `{ subject, metadata }`.
     *
     * The token is deleted from the store on the first lookup (single-use
     * guarantee). Anti-enumeration: invalid, already-used, and expired tokens
     * all surface the same `OneTimeTokenError` with a generic message.
     */
    readonly verify: (
      token: string,
    ) => Effect.Effect<OneTimeTokenVerifyResult, Errors.OneTimeTokenError | Errors.AuthError>;
  }
>()("@effect-auth/OneTimeTokenService") {
  /**
   * Construct a Layer providing this service.
   *
   * @param config - Optional configuration (default TTL, etc.)
   */
  static readonly layer = (config?: OneTimeTokenConfig) =>
    Layer.effect(OneTimeTokenService, make(config ?? {})).pipe(Layer.provide(PlatformCrypto.layer));
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export const make = (
  config: OneTimeTokenConfig,
): Effect.Effect<typeof OneTimeTokenService.Service, never, OneTimeTokenStore | Crypto.Crypto> =>
  Effect.gen(function* () {
    const defaultExpiresIn = config.expiresIn ?? 15 * 60 * 1000;
    const store = yield* OneTimeTokenStore;
    const crypto = yield* Crypto.Crypto;

    const generateRawToken = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomBytes(32).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("base64url")),
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate token", cause }),
        ),
      );

    return {
      generate: Effect.fn("OneTimeTokenService.generate")(
        (subject: string, options?: OneTimeTokenGenerateOptions) =>
          Effect.gen(function* () {
            const rawToken = yield* generateRawToken();
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
      ),

      verify: Effect.fn("OneTimeTokenService.verify")(function* (rawToken: string) {
        if (!rawToken) {
          return yield* new Errors.OneTimeTokenError({ message: "Invalid or expired token" });
        }

        const tokenHash = hashToken(rawToken);
        const record = yield* store.get(tokenHash);
        if (!record) {
          return yield* new Errors.OneTimeTokenError({ message: "Invalid or expired token" });
        }

        // Consume the token immediately — delete before the expiry check so
        // the timing difference between "found-but-expired" and "not found"
        // does not leak whether the hash exists in the store.
        yield* store.delete(tokenHash);

        if (Date.now() > record.expiresAt) {
          return yield* new Errors.OneTimeTokenError({ message: "Invalid or expired token" });
        }

        return {
          subject: record.subject,
          ...(record.metadata !== undefined ? { metadata: record.metadata } : {}),
        } satisfies OneTimeTokenVerifyResult;
      }),
    };
  });

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
 * import assert from "node:assert/strict"
 * import { Effect, Layer, Result } from "effect"
 * import {
 *   Hooks,
 *   OneTimeTokenService,
 *   OneTimeTokenStore,
 *   redeemOneTimeTokenForSession,
 *   SessionService,
 *   SessionStore,
 *   UserStore,
 *   type OneTimeTokenRecord,
 *   type Session,
 *   type User,
 * } from "@thomasfosterau/effect-auth"
 *
 * // In-memory stores. A real app backs these with its database.
 * const tokens = new Map<string, OneTimeTokenRecord>()
 * const sessions = new Map<string, Session>()
 * const users = new Map<string, User>()
 * const stores = Layer.mergeAll(
 *   Layer.succeed(OneTimeTokenStore, {
 *     create: (record) => Effect.sync(() => (tokens.set(record.token, record), record)),
 *     get: (token) => Effect.sync(() => tokens.get(token) ?? null),
 *     delete: (token) => Effect.sync(() => void tokens.delete(token)),
 *   }),
 *   Layer.succeed(SessionStore, {
 *     create: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
 *     get: (id) => Effect.sync(() => sessions.get(id) ?? null),
 *     update: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
 *     delete: (id) => Effect.sync(() => void sessions.delete(id)),
 *     deleteByUserId: (userId) =>
 *       Effect.sync(() => {
 *         for (const [id, session] of sessions) if (session.userId === userId) sessions.delete(id)
 *       }),
 *     listByUserId: (userId) =>
 *       Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
 *   }),
 *   Layer.succeed(UserStore, { get: (id) => Effect.sync(() => users.get(id) ?? null) }),
 * )
 * const services = Layer.mergeAll(
 *   OneTimeTokenService.layer(),
 *   SessionService.layer({ sessionExpiresIn: { activePeriod: 7 * 86_400_000, idlePeriod: 86_400_000 } }),
 * ).pipe(Layer.provideMerge(Layer.mergeAll(stores, Hooks.Default)))
 *
 * // Redeem a token from a sign-in link: the session cookie is set on the response.
 * const redeem = (rawToken: string, response: Headers) =>
 *   Effect.gen(function* () {
 *     const { session, subject } = yield* redeemOneTimeTokenForSession(rawToken)
 *     response.append("set-cookie", `session=${session.id}; Path=/; HttpOnly; Secure`)
 *     return subject
 *   })
 *
 * const program = Effect.gen(function* () {
 *   const now = new Date()
 *   users.set("u-1", { id: "u-1", name: "Ada", createdAt: now, updatedAt: now, attributes: {} })
 *
 *   // The link emailed to the user carries the raw token; the store keeps only its hash.
 *   const tokenService = yield* OneTimeTokenService
 *   const rawToken = yield* tokenService.generate("u-1")
 *
 *   const response = new Headers()
 *   assert.equal(yield* redeem(rawToken, response), "u-1")
 *   assert.match(response.get("set-cookie") ?? "", /^session=/)
 *
 *   // Single use: the same link cannot be redeemed twice.
 *   const again = yield* Effect.result(redeem(rawToken, new Headers()))
 *   assert.ok(Result.isFailure(again))
 * }).pipe(Effect.provide(services))
 *
 * await Effect.runPromise(program)
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
