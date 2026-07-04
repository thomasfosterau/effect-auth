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
import { Context, Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import * as Errors from "./Errors.js";
import { Hooks, type HookError } from "./Hooks.js";
import { SessionManager } from "./Session.js";
import { hashToken } from "./TokenHash.js";
import type * as Types from "./Types.js";
import { normalizeEmail } from "./utils.js";

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
 * Storage interface for magic link tokens
 */
export interface MagicLinkStoreShape {
  readonly create: (token: MagicLinkToken) => Effect.Effect<MagicLinkToken, Errors.AuthError>;
  readonly get: (token: string) => Effect.Effect<MagicLinkToken | null, Errors.AuthError>;
  readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
  readonly deleteByEmail: (email: string) => Effect.Effect<void, Errors.AuthError>;
}

/**
 * Input for creating a user during magic link verification
 */
export interface MagicLinkCreateUserInput {
  readonly email: string;
  readonly emailVerified: boolean;
  readonly name?: string;
}

/**
 * User store interface for magic link sign-in
 */
export interface MagicLinkUserStoreShape {
  readonly getUserByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;
  readonly createUser: (
    input: MagicLinkCreateUserInput,
  ) => Effect.Effect<Types.User, Errors.AuthError>;
}

/**
 * Magic link store context tag
 */
export class MagicLinkStore extends Context.Service<MagicLinkStore, MagicLinkStoreShape>()(
  "@effect-auth/MagicLinkStore",
) {}

/**
 * Magic link user store context tag
 */
export class MagicLinkUserStore extends Context.Service<
  MagicLinkUserStore,
  MagicLinkUserStoreShape
>()("@effect-auth/MagicLinkUserStore") {}

/**
 * Magic link service configuration
 */
export interface MagicLinkConfig {
  readonly expiresIn?: number; // Default: 5 minutes
  readonly disableSignUp?: boolean; // Default: false
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
export interface MagicLinkServiceShape {
  /**
   * Request a magic link for the given email. Outstanding tokens for the
   * email are invalidated first so only the latest link is usable.
   *
   * Anti-enumeration: when sign-up is enabled the link is always sent (the
   * user is created at verification time); when sign-up is disabled and no
   * user exists this succeeds silently without sending anything.
   */
  readonly send: (
    email: string,
  ) => Effect.Effect<
    void,
    Errors.AuthError | Errors.MagicLinkError,
    MagicLinkStore | MagicLinkUserStore
  >;

  /**
   * Verify a magic link token (single use) and sign the user in. A
   * successfully verified link proves ownership of the email, so users
   * created here are marked `emailVerified: true`.
   */
  readonly verify: (
    token: string,
    options?: MagicLinkVerifyOptions,
  ) => Effect.Effect<
    MagicLinkResult,
    Errors.MagicLinkError | Errors.AuthError | HookError,
    MagicLinkStore | MagicLinkUserStore | SessionManager | Hooks
  >;
}

export class MagicLinkService extends Context.Service<MagicLinkService, MagicLinkServiceShape>()(
  "@effect-auth/MagicLinkService",
) {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: MagicLinkConfig) =>
    Layer.effect(MagicLinkService, makeMagicLinkService(config));
}

/**
 * Generate a cryptographically secure magic link token
 */
export const generateMagicLinkToken = (): Effect.Effect<string, Errors.AuthError> =>
  Effect.sync(() => crypto.randomBytes(32).toString("base64url"));

/**
 * Create a magic link service
 */
export const makeMagicLinkService = (
  config: MagicLinkConfig,
): Effect.Effect<MagicLinkServiceShape, never> => {
  const expiresIn = config.expiresIn ?? 5 * 60 * 1000; // 5 minutes default
  const disableSignUp = config.disableSignUp ?? false;

  return Effect.sync(
    (): MagicLinkServiceShape => ({
      send: (rawEmail: string) =>
        Effect.gen(function* () {
          const store = yield* MagicLinkStore;
          const userStore = yield* MagicLinkUserStore;

          const email = normalizeEmail(rawEmail);
          if (!email) {
            return;
          }

          // Do not reveal whether the user exists to reduce email enumeration
          // risk: when sign-up is disabled and there is no matching account,
          // succeed silently without sending anything. When sign-up is enabled
          // the link is always sent (the user is created at verify time).
          if (disableSignUp) {
            const user = yield* userStore.getUserByEmail(email);
            if (!user) {
              return;
            }
          }

          // Invalidate outstanding tokens so only the latest link is usable.
          yield* store.deleteByEmail(email);

          const rawToken = yield* generateMagicLinkToken();
          const magicLink: MagicLinkToken = {
            // Store the hash — the raw token is delivered to the user via sendMagicLink.
            token: hashToken(rawToken),
            email,
            createdAt: Date.now(),
            expiresAt: Date.now() + expiresIn,
          };

          yield* store.create(magicLink);

          yield* Effect.catch(config.sendMagicLink(email, rawToken), (error) =>
            Effect.fail(
              new Errors.MagicLinkError({
                message: `Failed to send magic link to ${email}`,
                cause: error,
              }),
            ),
          );
        }),

      verify: (rawToken: string, options?: MagicLinkVerifyOptions) =>
        Effect.gen(function* () {
          const store = yield* MagicLinkStore;
          const userStore = yield* MagicLinkUserStore;
          const sessionManager = yield* SessionManager;

          if (!rawToken) {
            return yield* Effect.fail(
              new Errors.MagicLinkError({
                message: "Invalid or expired magic link token",
              }),
            );
          }

          const tokenHash = hashToken(rawToken);
          const magicLink = yield* store.get(tokenHash);
          if (!magicLink) {
            return yield* Effect.fail(
              new Errors.MagicLinkError({
                message: "Invalid or expired magic link token",
              }),
            );
          }

          // Check expiration
          if (Date.now() > magicLink.expiresAt) {
            yield* store.delete(tokenHash);
            return yield* Effect.fail(
              new Errors.MagicLinkError({
                message: "Magic link token has expired",
              }),
            );
          }

          // Consume the token (one-time use)
          yield* store.delete(tokenHash);

          let user = yield* userStore.getUserByEmail(magicLink.email);
          if (!user) {
            if (disableSignUp) {
              return yield* Effect.fail(
                new Errors.MagicLinkError({
                  message: "Sign-up is disabled",
                }),
              );
            }

            // A verified magic link proves ownership of the email.
            user = yield* userStore.createUser({
              email: magicLink.email,
              emailVerified: true,
            });
          }

          const session = yield* sessionManager.createSession(user.id, options?.sessionAttributes);

          return {
            user,
            session,
          } satisfies MagicLinkResult;
        }),
    }),
  );
};
