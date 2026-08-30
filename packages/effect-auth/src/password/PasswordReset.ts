import { Context, Crypto, Effect, Layer } from "effect";
import * as Errors from "../Errors.ts";
import { IdentifierStore, resolveUserByIdentifier } from "../Identifier.ts";
import { UserStore } from "../session/UserStore.ts";
import { hashToken } from "../TokenHash.ts";
import { Hooks, type HookError } from "../Hooks.ts";
import { PasswordHasher } from "./Password.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { SessionService } from "../session/SessionService.ts";
import { normalizeEmail } from "../utils.ts";

export interface PasswordResetToken {
  readonly token: string;
  readonly userId: string;
  readonly email: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export class PasswordResetStore extends Context.Service<
  PasswordResetStore,
  {
    readonly create: (
      reset: PasswordResetToken,
    ) => Effect.Effect<PasswordResetToken, Errors.AuthError>;
    readonly get: (token: string) => Effect.Effect<PasswordResetToken | null, Errors.AuthError>;
    readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
    readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/PasswordResetStore") {}

export class PasswordResetUserStore extends Context.Service<
  PasswordResetUserStore,
  {
    readonly setPasswordHash: (
      userId: string,
      hash: string,
    ) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/PasswordResetUserStore") {}

export interface PasswordResetConfig {
  readonly expiresIn?: number;
  readonly minPasswordLength?: number;
  readonly maxPasswordLength?: number;
  readonly revokeSessionsOnPasswordReset?: boolean;
  readonly sendResetPassword: (
    email: string,
    token: string,
  ) => Effect.Effect<void, Errors.PasswordResetError>;
}

export interface PasswordResetResult {
  readonly userId: string;
  readonly email: string;
  readonly reset: true;
}

export class PasswordResetService extends Context.Service<
  PasswordResetService,
  {
    readonly requestPasswordReset: (
      email: string,
    ) => Effect.Effect<void, Errors.AuthError | Errors.PasswordResetError | HookError>;

    readonly resetPassword: (
      token: string,
      newPassword: string,
    ) => Effect.Effect<
      PasswordResetResult,
      Errors.AuthError | Errors.PasswordResetError | Errors.HashingError | HookError
    >;
  }
>()("@effect-auth/PasswordResetService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: PasswordResetConfig) =>
    Layer.effect(PasswordResetService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

const validatePasswordLength = (
  newPassword: string,
  minPasswordLength: number,
  maxPasswordLength: number,
): Effect.Effect<void, Errors.PasswordResetError> =>
  Effect.gen(function* () {
    if (newPassword.length < minPasswordLength) {
      return yield* Effect.fail(
        new Errors.PasswordResetError({
          message: `Password must be at least ${minPasswordLength} characters`,
        }),
      );
    }

    if (newPassword.length > maxPasswordLength) {
      return yield* Effect.fail(
        new Errors.PasswordResetError({
          message: `Password must be at most ${maxPasswordLength} characters`,
        }),
      );
    }
  });

export const make = (
  config: PasswordResetConfig,
): Effect.Effect<
  typeof PasswordResetService.Service,
  never,
  | PasswordResetStore
  | PasswordResetUserStore
  | IdentifierStore
  | UserStore
  | PasswordHasher
  | SessionService
  | Hooks
  | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const expiresIn = config.expiresIn ?? 60 * 60 * 1000;
    const minPasswordLength = config.minPasswordLength ?? 8;
    const maxPasswordLength = config.maxPasswordLength ?? 128;
    const revokeSessionsOnPasswordReset = config.revokeSessionsOnPasswordReset ?? true;

    const resetStore = yield* PasswordResetStore;
    const userStore = yield* PasswordResetUserStore;
    const identifiers = yield* IdentifierStore;
    const users = yield* UserStore;
    const passwordHasher = yield* PasswordHasher;
    const sessionManager = yield* SessionService;
    const hooks = yield* Hooks;
    const crypto = yield* Crypto.Crypto;

    const generateResetToken = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomBytes(32).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("base64url")),
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate reset token", cause }),
        ),
      );

    return {
      requestPasswordReset: Effect.fn("PasswordResetService.requestPasswordReset")(function* (
        rawEmail: string,
      ) {
        const { email } = yield* hooks.beforeRequestPasswordReset({ email: rawEmail });

        const normalizedEmail = normalizeEmail(email);

        if (!normalizedEmail) {
          return;
        }

        const resolved = yield* resolveUserByIdentifier(
          identifiers,
          users.get,
          "email",
          normalizedEmail,
        );
        const user = resolved?.user ?? null;

        // Do not reveal whether the user exists to reduce email enumeration risk.
        // The after-hook fires uniformly (existence is not signalled to plugins).
        if (!user) {
          yield* hooks.afterRequestPasswordReset({ email: normalizedEmail });
          return;
        }

        yield* resetStore.deleteByUserId(user.id);

        const rawToken = yield* generateResetToken();
        const reset: PasswordResetToken = {
          // Store the hash — the raw token is delivered to the user via sendResetPassword.
          token: hashToken(rawToken),
          userId: user.id,
          email: normalizedEmail,
          createdAt: Date.now(),
          expiresAt: Date.now() + expiresIn,
        };

        yield* resetStore.create(reset);

        yield* Effect.catch(config.sendResetPassword(normalizedEmail, rawToken), (error) =>
          Effect.fail(
            new Errors.PasswordResetError({
              message: `Failed to send reset password email to ${normalizedEmail}`,
              cause: error,
            }),
          ),
        );

        yield* hooks.afterRequestPasswordReset({ email: normalizedEmail });
      }),

      resetPassword: Effect.fn("PasswordResetService.resetPassword")(function* (
        rawToken: string,
        rawNewPassword: string,
      ) {
        // Hook receives the raw token from the URL; hash after any hook transform.
        const { token, newPassword } = yield* hooks.beforeResetPassword({
          token: rawToken,
          newPassword: rawNewPassword,
        });

        if (!token) {
          return yield* Effect.fail(
            new Errors.PasswordResetError({
              message: "Invalid password reset token",
            }),
          );
        }

        yield* validatePasswordLength(newPassword, minPasswordLength, maxPasswordLength);

        const tokenHash = hashToken(token);
        const reset = yield* resetStore.get(tokenHash);
        if (!reset) {
          return yield* Effect.fail(
            new Errors.PasswordResetError({
              message: "Invalid or expired password reset token",
            }),
          );
        }

        if (Date.now() > reset.expiresAt) {
          yield* resetStore.delete(tokenHash);
          return yield* Effect.fail(
            new Errors.PasswordResetError({
              message: "Password reset token has expired",
            }),
          );
        }

        const hashedPassword = yield* passwordHasher.hash(newPassword);
        yield* userStore.setPasswordHash(reset.userId, hashedPassword.hash);

        yield* resetStore.delete(tokenHash);

        if (revokeSessionsOnPasswordReset) {
          yield* sessionManager.invalidateUserSessions(reset.userId);
        }

        const result = {
          userId: reset.userId,
          email: reset.email,
          reset: true,
        } satisfies PasswordResetResult;

        return yield* hooks.afterResetPassword(result);
      }),
    };
  });
