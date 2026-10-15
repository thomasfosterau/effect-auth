/**
 * Magic link sign-in for effect-auth.
 *
 * Implements passwordless sign-in via single-use, expiring tokens delivered by
 * email (better-auth "magic link" parity). Requesting a link never reveals
 * whether an account exists; verifying a link proves ownership of the email,
 * so newly created users are marked `emailVerified: true`.
 *
 * @module magic-link
 */
import { Context, Crypto, Effect, Layer } from "effect";
import * as Errors from "./Errors.ts";
import { IdentifierStore } from "./Identifier.ts";
import {
  createUserWithIdentifier,
  type CreateUserResult,
  type NewUserIdentifier,
  UserStore,
} from "./UserStore.ts";
import { type HookError } from "./Hooks.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { SessionService } from "./SessionService.ts";
import { hashToken } from "./TokenHash.ts";
import type * as Types from "./Types.ts";
import { normalizeEmail } from "./utils.ts";

/**
 * Magic link token record
 */
export interface MagicLinkToken {
  readonly token: string;
  readonly email: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * Fields for a user created during magic link verification. The email itself
 * is recorded as a verified `Identifier` by the service, and `identifier`
 * carries it to the store as well.
 */
export interface MagicLinkCreateUserInput {
  readonly name?: string;
  /**
   * The login handle the user is created with: a store that keeps it on the
   * user row writes it there on insert, and any other store ignores it (see
   * {@link NewUserIdentifier}).
   */
  readonly identifier?: NewUserIdentifier | undefined;
}

/**
 * Storage interface for magic link tokens
 *
 * Magic link store context tag
 */
export class MagicLinkStore extends Context.Service<
  MagicLinkStore,
  {
    readonly create: (token: MagicLinkToken) => Effect.Effect<MagicLinkToken, Errors.AuthError>;
    readonly get: (token: string) => Effect.Effect<MagicLinkToken | null, Errors.AuthError>;
    readonly getByEmail: (email: string) => Effect.Effect<MagicLinkToken | null, Errors.AuthError>;
    readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
    readonly deleteByEmail: (email: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/MagicLinkStore") {}

/**
 * User store interface for magic link sign-in
 *
 * Magic link user store context tag
 */
export class MagicLinkUserStore extends Context.Service<
  MagicLinkUserStore,
  {
    /**
     * Create a user. `created` in the result is `true` only when this call
     * inserted the user; a user that already existed (as a find-or-create on
     * the address returns) reports `false`, and sign-up then fails without
     * writing to it. The store must leave that row as it was: never an upsert
     * that updates it (see {@link CreateUserResult}).
     */
    readonly createUser: (
      input: MagicLinkCreateUserInput,
    ) => Effect.Effect<CreateUserResult, Errors.AuthError>;
  }
>()("@effect-auth/MagicLinkUserStore") {}

/**
 * Magic link service configuration
 */
export interface MagicLinkConfig {
  readonly expiresIn?: number; // Default: 5 minutes
  readonly disableSignUp?: boolean; // Default: false
  /**
   * Minimum interval (ms) between successive send requests for the same email.
   * When an outstanding token created within this window already exists, `send`
   * fails with {@link Errors.ResendTooSoonError}. Off by default; consider
   * 60_000 for SMS-style flows. Complements the global RateLimit. It applies
   * to every email alike, whether or not it has an account, so the error
   * reveals nothing about which emails are registered. With sign-up disabled,
   * a request for an email with no account stores an undelivered cooldown
   * marker, so if that email gains an account within the window, its first
   * send is delayed by up to the cooldown.
   */
  readonly resendCooldown?: number;
  readonly sendMagicLink: (
    email: string,
    token: string,
  ) => Effect.Effect<void, Errors.MagicLinkError>;
}

/**
 * Options for verifying a magic link token
 */
export interface MagicLinkVerifyOptions {
  readonly sessionAttributes?: Record<string, unknown>;
}

/**
 * Result of a successful magic link verification
 */
export interface MagicLinkResult {
  readonly user: Types.User;
  readonly session: Types.Session;
}

/**
 * Magic link service
 */
export class MagicLinkService extends Context.Service<
  MagicLinkService,
  {
    /**
     * Request a magic link for the given email. Outstanding tokens for the
     * email are invalidated first so only the latest link is usable.
     *
     * Anti-enumeration: when sign-up is enabled the link is always sent (the
     * user is created at verification time); when sign-up is disabled and no
     * user exists this succeeds silently without sending anything.
     *
     * When `resendCooldown` is configured and an outstanding token for the email
     * was created within the cooldown window, fails with
     * {@link Errors.ResendTooSoonError} containing the remaining wait time.
     * The cooldown applies to an email with no account as well: with sign-up
     * disabled, such a request stores a token that is never sent, so a repeat
     * within the window fails the same way for a known and an unknown email.
     */
    readonly send: (
      email: string,
    ) => Effect.Effect<void, Errors.AuthError | Errors.MagicLinkError | Errors.ResendTooSoonError>;

    /**
     * Verify a magic link token (single use) and sign the user in. A
     * successfully verified link proves ownership of the email, so users
     * created here are marked `emailVerified: true`.
     */
    readonly verify: (
      token: string,
      options?: MagicLinkVerifyOptions,
    ) => Effect.Effect<MagicLinkResult, Errors.MagicLinkError | Errors.AuthError | HookError>;
  }
>()("@effect-auth/MagicLinkService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: MagicLinkConfig) =>
    Layer.effect(MagicLinkService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

/**
 * Generate a cryptographically secure magic link token
 */
export const generateMagicLinkToken = (
  crypto: Crypto.Crypto,
): Effect.Effect<string, Errors.AuthError> =>
  crypto.randomBytes(32).pipe(
    Effect.map((bytes) => Buffer.from(bytes).toString("base64url")),
    Effect.mapError(
      (cause) => new Errors.AuthError({ message: "Failed to generate magic link token", cause }),
    ),
  );

/**
 * Create a magic link service
 */
export const make = (
  config: MagicLinkConfig,
): Effect.Effect<
  typeof MagicLinkService.Service,
  never,
  MagicLinkStore | MagicLinkUserStore | IdentifierStore | UserStore | SessionService | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const expiresIn = config.expiresIn ?? 5 * 60 * 1000; // 5 minutes default
    const disableSignUp = config.disableSignUp ?? false;

    const store = yield* MagicLinkStore;
    const userStore = yield* MagicLinkUserStore;
    const identifiers = yield* IdentifierStore;
    const users = yield* UserStore;
    const sessionManager = yield* SessionService;
    const crypto = yield* Crypto.Crypto;

    return {
      send: Effect.fn("MagicLinkService.send")(function* (rawEmail: string) {
        const email = normalizeEmail(rawEmail);
        if (!email) {
          return;
        }

        // Do not reveal whether the user exists to reduce email enumeration
        // risk: when sign-up is disabled and there is no matching account,
        // succeed without sending anything. When sign-up is enabled the link
        // is always sent (the user is created at verify time).
        const deliver = disableSignUp
          ? (yield* identifiers.getByValue("email", email)) !== null
          : true;

        // Without a resend cooldown there is nothing for a later request to
        // see, so an unknown address stores nothing.
        if (!deliver && config.resendCooldown === undefined) {
          return;
        }

        // Resend cooldown: reject if an outstanding token was created within
        // the configured window. It runs for an address with no account too,
        // whose earlier request stored an undelivered token below, so a known
        // and an unknown address get the same answer inside the window.
        if (config.resendCooldown !== undefined) {
          const existing = yield* store.getByEmail(email);
          if (existing !== null) {
            const elapsed = Date.now() - existing.createdAt;
            if (elapsed < config.resendCooldown) {
              return yield* new Errors.ResendTooSoonError({
                message: "Please wait before requesting another magic link",
                retryAfter: config.resendCooldown - elapsed,
              });
            }
          }
        }

        // Invalidate outstanding tokens so only the latest link is usable.
        yield* store.deleteByEmail(email);

        const rawToken = yield* generateMagicLinkToken(crypto);
        const magicLink: MagicLinkToken = {
          // Store the hash — the raw token is delivered to the user via sendMagicLink.
          token: hashToken(rawToken),
          email,
          createdAt: Date.now(),
          expiresAt: Date.now() + expiresIn,
        };

        yield* store.create(magicLink);

        // An address with no account keeps the token only as its cooldown
        // marker. Nobody receives the raw token, so it can never be verified.
        if (!deliver) {
          return;
        }

        yield* Effect.catch(config.sendMagicLink(email, rawToken), (error) =>
          Effect.fail(
            new Errors.MagicLinkError({
              message: `Failed to send magic link to ${email}`,
              cause: error,
            }),
          ),
        );
      }),

      verify: Effect.fn("MagicLinkService.verify")(function* (
        rawToken: string,
        options?: MagicLinkVerifyOptions,
      ) {
        if (!rawToken) {
          return yield* new Errors.MagicLinkError({
            message: "Invalid or expired magic link token",
          });
        }

        const tokenHash = hashToken(rawToken);
        const magicLink = yield* store.get(tokenHash);
        if (!magicLink) {
          return yield* new Errors.MagicLinkError({
            message: "Invalid or expired magic link token",
          });
        }

        // Check expiration
        if (Date.now() > magicLink.expiresAt) {
          yield* store.delete(tokenHash);
          return yield* new Errors.MagicLinkError({
            message: "Magic link token has expired",
          });
        }

        // Consume the token (one-time use)
        yield* store.delete(tokenHash);

        const identifier = yield* identifiers.getByValue("email", magicLink.email);
        let user = identifier === null ? null : yield* users.get(identifier.userId);
        if (identifier !== null && user === null) {
          // Dangling identifier (owner row is gone) — fail rather than
          // silently creating a second claimant.
          return yield* new Errors.MagicLinkError({ message: "Account is unavailable" });
        }
        if (!user) {
          if (disableSignUp) {
            return yield* new Errors.MagicLinkError({
              message: "Sign-up is disabled",
            });
          }

          // A verified magic link proves ownership of the email.
          const created = yield* createUserWithIdentifier(
            identifiers,
            { type: "email", value: magicLink.email, verified: true, verifiedAt: new Date() },
            (identifier) => userStore.createUser({ identifier }),
          ).pipe(
            Effect.catchTag("IdentifierTakenError", () =>
              Effect.fail(new Errors.MagicLinkError({ message: "This email is already in use" })),
            ),
          );
          user = created.user;
        } else if (identifier !== null && !identifier.verified) {
          // The link proves ownership — promote the identifier to verified.
          yield* identifiers.setVerified(identifier.id, new Date());
        }

        const session = yield* sessionManager.createSession(user.id, options?.sessionAttributes);

        return {
          user,
          session,
        } satisfies MagicLinkResult;
      }),
    };
  });
