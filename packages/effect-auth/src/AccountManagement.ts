/**
 * Account management flows: verification-gated email change and self-service
 * account deletion.
 *
 * Both flows issue a single-use, expiring token bound to the acting user (the
 * email-change token additionally carries the target email). The token is
 * delivered out-of-band via the configured `send*` callback; confirming the
 * token applies the change. This mirrors `EmailVerification`/`MagicLink`: a
 * store interface + `Context.Service` tag + `make*` factory + `*ServiceLayer`.
 *
 * House conventions followed: epoch-ms timestamps, timing-safe token lookup by
 * value (tokens are high-entropy random), anti-enumeration at the HTTP layer
 * (see `HttpServer.ts`), and session invalidation on sensitive changes.
 */
import { Context, Crypto, Data, Effect, Layer } from "effect";
import * as Errors from "./Errors.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import type * as Types from "./Types.ts";
import { UserServiceStore } from "./User.ts";
import { SessionService } from "./session/SessionService.ts";
import { normalizeEmail } from "./utils.ts";
import { anyEmailValue, claimIdentifier, IdentifierStore, makeIdentifier } from "./Identifier.ts";

/** Which flow a pending token belongs to. */
export type AccountTokenPurpose = "change-email" | "delete-account";

/**
 * A pending, single-use account-management token. `newEmail` is only present
 * for `change-email` tokens.
 */
export interface AccountToken {
  readonly token: string;
  readonly userId: string;
  readonly purpose: AccountTokenPurpose;
  readonly newEmail?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * Persistence for pending account-management tokens. Implement over your
 * database; keys are the opaque token strings.
 */
export class AccountManagementStore extends Context.Service<
  AccountManagementStore,
  {
    readonly create: (token: AccountToken) => Effect.Effect<AccountToken, Errors.AuthError>;
    readonly get: (token: string) => Effect.Effect<AccountToken | null, Errors.AuthError>;
    readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
    readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/AccountManagementStore") {}

/** Raised when a confirm token is missing, expired, or of the wrong purpose. */
export class AccountTokenError extends Data.TaggedError("AccountTokenError")<{
  readonly message: string;
}> {}

export interface AccountManagementConfig {
  /** Lifetime of a change-email token in ms. Default 1 hour. */
  readonly changeEmailExpiresIn?: number;
  /** Lifetime of a delete-account token in ms. Default 1 hour. */
  readonly deleteAccountExpiresIn?: number;
  /** Deliver the change-email confirmation token to the NEW address. */
  readonly sendChangeEmailVerification: (params: {
    readonly user: Types.User;
    readonly newEmail: string;
    readonly token: string;
  }) => Effect.Effect<void, Errors.AuthError>;
  /**
   * Deliver the account-deletion confirmation token to the user's address.
   * `email` is the user's resolved email identifier value, or `null` when the
   * user has no email on file (deliver via another channel or fail).
   */
  readonly sendDeleteAccountVerification: (params: {
    readonly user: Types.User;
    readonly email: string | null;
    readonly token: string;
  }) => Effect.Effect<void, Errors.AuthError>;
  /** Optional notice to the OLD address once an email change is confirmed. */
  readonly notifyEmailChanged?: (params: {
    readonly user: Types.User;
    readonly oldEmail: string | null;
    readonly newEmail: string;
  }) => Effect.Effect<void, Errors.AuthError>;
  /**
   * Optional app-data cleanup run just before the user record is deleted (the
   * user still exists at this point so related rows can be resolved). A failure
   * here aborts the deletion.
   */
  readonly beforeDelete?: (user: Types.User) => Effect.Effect<void, Errors.AuthError>;
  /**
   * Revoke all of the user's other sessions when their email changes. Default
   * `true` (an email change is a credential-adjacent event).
   */
  readonly revokeSessionsOnEmailChange?: boolean;
}

/** Result of confirming an email change. */
export interface EmailChangeResult {
  readonly user: Types.User;
}

export class AccountManagementService extends Context.Service<
  AccountManagementService,
  {
    /**
     * Begin an email change: validate the new address is free, then issue a
     * token delivered to the new address. Returns the token (for the caller to
     * decide delivery/anti-enumeration; the HTTP layer answers `{ status: true }`).
     */
    readonly requestEmailChange: (
      userId: string,
      newEmail: string,
    ) => Effect.Effect<
      { readonly token: string; readonly expiresAt: number },
      Errors.AuthError | Errors.UserNotFoundError | Errors.EmailInUseError
    >;

    /** Confirm an email change by token: swaps the email and marks it verified. */
    readonly confirmEmailChange: (
      token: string,
    ) => Effect.Effect<
      EmailChangeResult,
      Errors.AuthError | Errors.UserNotFoundError | AccountTokenError
    >;

    /** Begin account deletion: issue a token delivered to the user's address. */
    readonly requestAccountDeletion: (
      userId: string,
    ) => Effect.Effect<
      { readonly token: string; readonly expiresAt: number },
      Errors.AuthError | Errors.UserNotFoundError
    >;

    /** Confirm deletion by token: runs cleanup, revokes sessions, deletes user. */
    readonly confirmAccountDeletion: (
      token: string,
    ) => Effect.Effect<
      { readonly userId: string },
      Errors.AuthError | Errors.UserNotFoundError | AccountTokenError
    >;
  }
>()("@effect-auth/AccountManagementService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: AccountManagementConfig) =>
    Layer.effect(AccountManagementService, make(config)).pipe(Layer.provide(PlatformCrypto.layer));
}

export const make = (
  config: AccountManagementConfig,
): Effect.Effect<
  typeof AccountManagementService.Service,
  never,
  AccountManagementStore | UserServiceStore | IdentifierStore | SessionService | Crypto.Crypto
> =>
  Effect.gen(function* () {
    const changeEmailExpiresIn = config.changeEmailExpiresIn ?? 60 * 60 * 1000;
    const deleteAccountExpiresIn = config.deleteAccountExpiresIn ?? 60 * 60 * 1000;
    const revokeSessionsOnEmailChange = config.revokeSessionsOnEmailChange ?? true;

    const users = yield* UserServiceStore;
    const identifiers = yield* IdentifierStore;
    const store = yield* AccountManagementStore;
    const sessions = yield* SessionService;
    const crypto = yield* Crypto.Crypto;

    const generateToken = (): Effect.Effect<string, Errors.AuthError> =>
      crypto.randomBytes(32).pipe(
        Effect.map((bytes) => Buffer.from(bytes).toString("base64url")),
        Effect.mapError(
          (cause) => new Errors.AuthError({ message: "Failed to generate token", cause }),
        ),
      );

    return {
      requestEmailChange: Effect.fn("AccountManagementService.requestEmailChange")(function* (
        userId: string,
        rawNewEmail: string,
      ) {
        const user = yield* users.get(userId);
        if (user === null) {
          return yield* new Errors.UserNotFoundError({ message: "User not found", userId });
        }
        const newEmail = normalizeEmail(rawNewEmail);

        // Uniqueness: reject if another account already owns the address.
        const existing = yield* identifiers.getByValue("email", newEmail);
        if (existing !== null && existing.userId !== userId) {
          return yield* new Errors.EmailInUseError({ message: "Email already in use" });
        }

        const token = yield* generateToken();
        const now = Date.now();
        yield* store.create({
          token,
          userId,
          purpose: "change-email",
          newEmail,
          createdAt: now,
          expiresAt: now + changeEmailExpiresIn,
        });

        yield* config.sendChangeEmailVerification({ user, newEmail, token });

        return { token, expiresAt: now + changeEmailExpiresIn };
      }),

      confirmEmailChange: Effect.fn("AccountManagementService.confirmEmailChange")(function* (
        token: string,
      ) {
        const record = yield* store.get(token);
        if (record === null || record.purpose !== "change-email" || record.newEmail === undefined) {
          return yield* new AccountTokenError({ message: "Invalid or expired token" });
        }
        if (Date.now() > record.expiresAt) {
          yield* store.delete(token);
          return yield* new AccountTokenError({ message: "Token has expired" });
        }

        const user = yield* users.get(record.userId);
        if (user === null) {
          return yield* new Errors.UserNotFoundError({
            message: "User not found",
            userId: record.userId,
          });
        }
        const currentIdentifiers = yield* identifiers.listByUser(user.id);
        const oldEmail = anyEmailValue(currentIdentifiers);
        const newEmail = record.newEmail;

        // Re-check uniqueness at confirm time (the address may have been
        // taken between request and confirm).
        const clash = yield* identifiers.getByValue("email", newEmail);
        if (clash !== null && clash.userId !== user.id) {
          yield* store.delete(token);
          return yield* new AccountTokenError({ message: "Email already in use" });
        }

        // Swap the email identifier: remove existing email identifiers, then
        // claim the confirmed one as verified (the token proved ownership).
        if (clash === null) {
          for (const id of currentIdentifiers) {
            if (id.type === "email") {
              yield* identifiers.delete(id.id);
            }
          }
          yield* claimIdentifier(
            identifiers,
            makeIdentifier({
              userId: user.id,
              type: "email",
              value: newEmail,
              verified: true,
              verifiedAt: new Date(),
            }),
          ).pipe(
            Effect.catchTag("IdentifierTakenError", () =>
              Effect.fail(new AccountTokenError({ message: "Email already in use" })),
            ),
          );
        } else if (!clash.verified) {
          // Already this user's identifier — the token proves ownership.
          yield* identifiers.setVerified(clash.id, new Date());
        }

        const updated = yield* users.update({
          ...user,
          updatedAt: new Date(),
        });

        // Single-use.
        yield* store.delete(token);

        if (revokeSessionsOnEmailChange) {
          yield* sessions.invalidateUserSessions(user.id);
        }

        if (config.notifyEmailChanged !== undefined) {
          yield* Effect.ignore(config.notifyEmailChanged({ user: updated, oldEmail, newEmail }));
        }

        return { user: updated };
      }),

      requestAccountDeletion: Effect.fn("AccountManagementService.requestAccountDeletion")(
        function* (userId: string) {
          const user = yield* users.get(userId);
          if (user === null) {
            return yield* new Errors.UserNotFoundError({ message: "User not found", userId });
          }

          const token = yield* generateToken();
          const now = Date.now();
          yield* store.create({
            token,
            userId,
            purpose: "delete-account",
            createdAt: now,
            expiresAt: now + deleteAccountExpiresIn,
          });

          const email = anyEmailValue(yield* identifiers.listByUser(userId));
          yield* config.sendDeleteAccountVerification({ user, email, token });

          return { token, expiresAt: now + deleteAccountExpiresIn };
        },
      ),

      confirmAccountDeletion: Effect.fn("AccountManagementService.confirmAccountDeletion")(
        function* (token: string) {
          const record = yield* store.get(token);
          if (record === null || record.purpose !== "delete-account") {
            return yield* new AccountTokenError({ message: "Invalid or expired token" });
          }
          if (Date.now() > record.expiresAt) {
            yield* store.delete(token);
            return yield* new AccountTokenError({ message: "Token has expired" });
          }

          const user = yield* users.get(record.userId);
          if (user === null) {
            return yield* new Errors.UserNotFoundError({
              message: "User not found",
              userId: record.userId,
            });
          }

          // App-data cleanup while the user still exists (a failure aborts).
          if (config.beforeDelete !== undefined) {
            yield* config.beforeDelete(user);
          }

          // Revoke sessions, then delete the user and the token.
          yield* sessions.invalidateUserSessions(user.id);
          yield* identifiers.deleteByUser(user.id);
          yield* users.delete(user.id);
          yield* store.delete(token);
          yield* store.deleteByUserId(user.id);

          return { userId: user.id };
        },
      ),
    };
  });
