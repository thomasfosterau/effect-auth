/**
 * Account management: verification-gated email change and self-service account
 * deletion, each through a single-use, expiring token sent out of band and
 * confirmed to apply the change. Sensitive changes invalidate sessions.
 */
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as Schema from "effect/Schema";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Arr from "effect/Array";
import { type Digest, SecureRandom } from "effect/crypto";
import { tokenHasher } from "./TokenHash.ts";
import { AccountDeletion } from "./AccountDeletion.ts";
import { EmailPasswordStore } from "./email/EmailPassword.ts";
import { PasswordHasher } from "./password/Password.ts";
import { storedPasswordVerifier } from "./password/DecoyVerify.ts";
import * as Errors from "./Errors.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { randomBase64UrlToken } from "./RandomToken.ts";
import { isImpersonationSession } from "./Types.ts";
import type * as Types from "./Types.ts";
import { UserServiceStore } from "./User.ts";
import { SessionService } from "./SessionService.ts";
import { purgeUser, userPurgeStores } from "./UserPurge.ts";
import { normalizeEmail } from "./Normalize.ts";
import * as Identifier from "./Identifier.ts";
import { definedKeys } from "./DefinedKeys.ts";

/** Which flow a pending token belongs to. */
export type AccountTokenPurpose = "change-email" | "delete-account";

/**
 * A pending, single-use account-management token. `newEmail` is only present
 * for `change-email` tokens.
 */
export interface AccountToken {
  /** The token's SHA-256 digest, the store key; the raw token is only emailed. */
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
    readonly get: (token: string) => Effect.Effect<Option.Option<AccountToken>, Errors.AuthError>;
    readonly delete: (token: string) => Effect.Effect<void, Errors.AuthError>;
    readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/AccountManagementStore") {}

/** Raised when a confirm token is missing, expired, or of the wrong purpose. */
export class AccountTokenError extends Schema.TaggedError<
  AccountTokenError,
  { readonly brand: unique symbol }
>()("AccountTokenError", {
  message: Schema.String,
}) {}

/**
 * Configuration for {@link AccountManagementService}.
 */
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
   * `email` is the user's resolved email identifier value, or `None` when the
   * user has no email on file (deliver via another channel or fail).
   */
  readonly sendDeleteAccountVerification: (params: {
    readonly user: Types.User;
    readonly email: Option.Option<string>;
    readonly token: string;
  }) => Effect.Effect<void, Errors.AuthError>;
  /**
   * Tell the account's current address that an email change was requested,
   * naming the new address, so the holder hears of it while it can still be
   * stopped (the confirmation link goes only to the new address). Sent, and
   * awaited, on every request that passes re-authentication, before the new
   * address is checked, whether or not it is free; a failed send fails the
   * request. Not sent for an account with no email. `emailCallbacks` derives
   * it from an `EmailSender` (purpose `"email-change-requested"`).
   */
  readonly sendEmailChangeNotice: (params: {
    readonly user: Types.User;
    readonly oldEmail: string;
    readonly newEmail: string;
  }) => Effect.Effect<void, Errors.AuthError>;
  /**
   * How recent a sign-in must be, in ms, to start an email change on an
   * account that has no password (see
   * {@link AccountManagementService.requestEmailChange}). Default 5 minutes.
   */
  readonly reauthenticationMaxAge?: number;
  /**
   * Optional notice to the OLD address once an email change is confirmed. A
   * confirmation submitted twice concurrently may send this notice twice.
   */
  readonly notifyEmailChanged?: (params: {
    readonly user: Types.User;
    /** The address the account held before the change, `None` when it held none. */
    readonly oldEmail: Option.Option<string>;
    readonly newEmail: string;
  }) => Effect.Effect<void, Errors.AuthError>;
  /**
   * Optional app-data cleanup run before anything of the user's is deleted
   * (the user, its credentials and its identifiers all still exist, so related
   * rows can be resolved). A failure here aborts the deletion.
   */
  readonly beforeDelete?: (user: Types.User) => Effect.Effect<void, Errors.AuthError>;
  /**
   * Revoke all of the user's other sessions when their email changes. Default
   * `true` (an email change is a credential-adjacent event).
   */
  readonly revokeSessionsOnEmailChange?: boolean;
}

/**
 * The proof that the caller of
 * {@link AccountManagementService.requestEmailChange} is the account holder.
 */
export interface EmailChangeReauthentication {
  /** The account's current password. Required when the account has one. */
  readonly currentPassword?: string;
  /**
   * The session the request arrives on. For an account without a password it
   * must be the user's own, created within `reauthenticationMaxAge`, and not
   * an impersonation.
   */
  readonly session?: Types.Session;
}

/** Result of confirming an email change. */
export interface EmailChangeResult {
  readonly user: Types.User;
}

/**
 * Self-service account changes: a verification-gated email change and account deletion, each confirmed by a single-use token.
 *
 * Requires `AccountManagementStore`, `UserServiceStore`, `IdentifierStore` and `SessionService`; account deletion also clears the user-keyed credential stores present where the layer is built. Re-authenticating an email change reads the password through `EmailPasswordStore` and `PasswordHasher` (and `MultiAlgorithmVerifier`) when they are present where the layer is built; without `EmailPasswordStore`, every account re-authenticates by a recent sign-in.
 */
export class AccountManagementService extends Context.Service<
  AccountManagementService,
  {
    /**
     * Begin an email change. The caller re-authenticates first:
     *
     * - an account with a password gives its current password
     *   (`InvalidCredentialsError` when it is wrong,
     *   `ReauthenticationRequiredError` when it is missing);
     * - an account without one (passwordless: magic link, one-time codes,
     *   passkeys, OAuth) gives the session it is signed in on, which must have
     *   been created within `reauthenticationMaxAge` (default 5 minutes) and
     *   not by impersonation, else `ReauthenticationRequiredError`: the user
     *   signs in again, through whatever method they have, and retries. When
     *   the account is enrolled in a second factor, that sign-in passed it.
     *
     * Then it notifies the current address (`sendEmailChangeNotice`), checks
     * the new address is free, and issues a token delivered to the new
     * address. Returns the token (for the caller to decide delivery and
     * anti-enumeration; the HTTP layer answers `202` either way).
     */
    readonly requestEmailChange: (
      userId: string,
      newEmail: string,
      reauthentication: EmailChangeReauthentication,
    ) => Effect.Effect<
      { readonly token: string; readonly expiresAt: number },
      | Errors.AuthError
      | Errors.UserNotFoundError
      | Errors.EmailInUseError
      | Errors.InvalidCredentialsError
      | Errors.ReauthenticationRequiredError
      | Errors.HashingError
    >;

    /**
     * Confirm an email change by token: replaces the user's email of record
     * with the new address, verified, through `IdentifierStore.replace`, then
     * releases any other email the user holds. If the replacement fails (the
     * address was taken meanwhile, or the store failed) the previous address
     * is left in place and the token is not consumed. A user with no email
     * claims the new address instead.
     *
     * When the email of record changes between the read and the replacement,
     * the confirmation succeeds if the user now holds the new address (a
     * concurrent confirmation of the same change, such as a double submit, made
     * it first) and consumes the token; otherwise it fails with
     * `AccountTokenError` and the token is not consumed. A user with no email
     * whose claim finds the address already theirs converges the same way.
     * Either way the new address ends verified.
     *
     * Every identifier store supports it, including one that holds a single
     * email per user (the single-table store in
     * `@thomasfosterau/effect-auth-drizzle`), whose `replace` rewrites that
     * one address in place.
     */
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

    /**
     * Confirm deletion by token: runs `beforeDelete`, then deletes the user
     * and everything the account holds: every credential and token in
     * the user-keyed stores present where this layer is built (OAuth links,
     * passkeys, API keys, the multi-factor enrolment, trusted devices, OIDC
     * provider tokens and consents, password-reset and email-verification
     * tokens, this store's pending tokens), then the sessions, then the
     * identifiers, and the user row last. A failure part-way leaves the user
     * row (and whatever was not yet removed); the token is gone by then, so
     * the user requests deletion again. Wrap the call in the stores' shared
     * transaction, where they have one, to make it atomic.
     */
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

/** `store` keyed by the digest of each token, never the emailed token itself. */
const hashedAccountTokens = (
  store: typeof AccountManagementStore.Service,
  hash: (token: string) => Effect.Effect<string>,
): typeof AccountManagementStore.Service => ({
  create: (record) =>
    Effect.flatMap(hash(record.token), (token) => store.create({ ...record, token })),
  get: (token) => Effect.flatMap(hash(token), store.get),
  delete: (token) => Effect.flatMap(hash(token), store.delete),
  deleteByUserId: store.deleteByUserId,
});

const make = (
  config: AccountManagementConfig,
): Effect.Effect<
  typeof AccountManagementService.Service,
  never,
  | AccountManagementStore
  | UserServiceStore
  | Identifier.IdentifierStore
  | SessionService
  | SecureRandom.SecureRandom
  | Digest.Digest
> =>
  Effect.gen(function* () {
    const changeEmailExpiresIn = config.changeEmailExpiresIn ?? 60 * 60 * 1000;
    const deleteAccountExpiresIn = config.deleteAccountExpiresIn ?? 60 * 60 * 1000;
    const revokeSessionsOnEmailChange = config.revokeSessionsOnEmailChange ?? true;
    const reauthenticationMaxAge = config.reauthenticationMaxAge ?? 5 * 60 * 1000;

    const users = yield* UserServiceStore;
    const identifiers = yield* Identifier.IdentifierStore;
    const store = hashedAccountTokens(yield* AccountManagementStore, yield* tokenHasher);
    const sessions = yield* SessionService;
    const crypto = yield* SecureRandom.SecureRandom;
    // Optional: an app without passwords re-authenticates every account by
    // a recent sign-in.
    const passwords = Option.getOrUndefined(yield* Effect.serviceOption(EmailPasswordStore));
    const hasher = yield* Effect.serviceOption(PasswordHasher);
    const verifyPassword = Option.isSome(hasher)
      ? yield* storedPasswordVerifier(hasher.value)
      : undefined;
    const purgeServices = {
      ...(yield* userPurgeStores),
      accountTokens: store,
      identifiers: Option.some(identifiers),
      revokeSessions: sessions.invalidateUserSessions,
      deleteUser: users.delete,
    };

    const generateToken = (): Effect.Effect<string> => randomBase64UrlToken(crypto);

    const reauthenticate = Effect.fn("AccountManagementService.reauthenticate")(function* (
      userId: string,
      proof: EmailChangeReauthentication,
    ) {
      const storedHash =
        passwords === undefined ? Option.none() : yield* passwords.getPasswordHash(userId);
      if (Option.isSome(storedHash)) {
        const passwordHash = storedHash.value;
        if (proof.currentPassword === undefined) {
          return yield* new Errors.ReauthenticationRequiredError({
            message: "Enter your current password to change your email address",
          });
        }
        if (verifyPassword === undefined) {
          return yield* new Errors.AuthError({
            message: "A PasswordHasher is required to verify the current password",
          });
        }
        if (!(yield* verifyPassword(proof.currentPassword, passwordHash))) {
          return yield* new Errors.InvalidCredentialsError({ message: "Invalid password" });
        }
        return yield* Effect.void;
      }
      const session = proof.session;
      const now = yield* Clock.currentTimeMillis;
      if (
        session === undefined ||
        session.userId !== userId ||
        isImpersonationSession(session) ||
        now - session.createdAt.getTime() > reauthenticationMaxAge
      ) {
        return yield* new Errors.ReauthenticationRequiredError({
          message: "Sign in again to change your email address",
        });
      }
      return yield* Effect.void;
    });

    return {
      requestEmailChange: Effect.fn("AccountManagementService.requestEmailChange")(function* (
        userId: string,
        rawNewEmail: string,
        proof: EmailChangeReauthentication,
      ) {
        const foundUser = yield* users.get(userId);
        if (Option.isNone(foundUser)) {
          return yield* new Errors.UserNotFoundError({ message: "User not found", userId });
        }
        const user = foundUser.value;
        yield* reauthenticate(userId, proof);
        const newEmail = normalizeEmail(rawNewEmail);

        // Tell the current address before anything else, so an attempt is
        // reported whether or not the new address turns out to be free.
        const oldEmail = Identifier.anyEmailValue(yield* identifiers.listByUser(userId));
        if (Option.isSome(oldEmail) && oldEmail.value !== newEmail) {
          yield* config.sendEmailChangeNotice({ user, oldEmail: oldEmail.value, newEmail });
        }

        // Uniqueness: reject if another account already owns the address.
        const existing = yield* Identifier.lookupIdentifier(identifiers, "email", newEmail);
        if (Option.exists(existing, (held) => held.userId !== userId)) {
          return yield* new Errors.EmailInUseError({
            message: "Email already in use",
            email: newEmail,
          });
        }

        const token = yield* generateToken();
        const now = yield* Clock.currentTimeMillis;
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
        const foundRecord = yield* store.get(token);
        if (Option.isNone(foundRecord) || foundRecord.value.purpose !== "change-email") {
          return yield* new AccountTokenError({ message: "Invalid or expired token" });
        }
        const record = foundRecord.value;
        const newEmail = record.newEmail;
        if (newEmail === undefined) {
          return yield* new AccountTokenError({ message: "Invalid or expired token" });
        }
        if ((yield* Clock.currentTimeMillis) > record.expiresAt) {
          yield* store.delete(token);
          return yield* new AccountTokenError({ message: "Token has expired" });
        }

        const foundUser = yield* users.get(record.userId);
        if (Option.isNone(foundUser)) {
          return yield* new Errors.UserNotFoundError({
            message: "User not found",
            userId: record.userId,
          });
        }
        const user = foundUser.value;
        const currentIdentifiers = yield* identifiers.listByUser(user.id);
        const current = Identifier.anyEmail(currentIdentifiers);
        const oldEmail = Option.map(current, (identifier) => identifier.value);

        // Re-check uniqueness at confirm time (the address may have been
        // taken between request and confirm).
        const clash = yield* Identifier.lookupIdentifier(identifiers, "email", newEmail);
        if (Option.exists(clash, (held) => held.userId !== user.id)) {
          yield* store.delete(token);
          return yield* new AccountTokenError({ message: "Email already in use" });
        }

        // Swap the email of record for the confirmed address (the token proved
        // ownership) in one store call: the store claims the new address before
        // it releases the previous one, or does both at once. A failed claim,
        // whether another account took the address meanwhile or the store
        // failed, leaves the user's previous address in place and verified.
        let replaced: Option.Option<string> = Option.none();
        let held = currentIdentifiers;
        // The identifier holding the confirmed address once this user has it.
        let confirmed: Identifier.Identifier;
        if (Option.isNone(clash)) {
          const verifiedAt = yield* DateTime.nowAsDate;
          const next = Identifier.makeIdentifier({
            userId: user.id,
            type: "email",
            value: newEmail,
            verified: true,
            verifiedAt,
            now: verifiedAt,
          });
          const outcome = yield* (
            Option.isNone(current)
              ? Identifier.claimIdentifier(identifiers, next).pipe(
                  Effect.catchTag("IdentifierRefusedError", (error) =>
                    Effect.fail(Identifier.refusalAuthError(error)),
                  ),
                )
              : Identifier.replaceIdentifier(identifiers, current.value, next)
          ).pipe(
            Effect.map((identifier) => ({ identifier, converged: null })),
            Effect.catchTags({
              // Another account holds the address. Or, for a user with no
              // email, a concurrent confirmation (a double submit) claimed it
              // for this user first: finish that change as this request's own.
              IdentifierTakenError: () =>
                Effect.gen(function* () {
                  const found = Option.isNone(current)
                    ? yield* Identifier.lookupIdentifier(identifiers, "email", newEmail)
                    : Option.none();
                  if (Option.isSome(found) && found.value.userId === user.id) {
                    return { identifier: found.value, converged: currentIdentifiers };
                  }
                  return yield* new AccountTokenError({ message: "Email already in use" });
                }),
              // The email of record changed between the read and the replace.
              // When the user now holds the confirmed address, a concurrent
              // confirmation (a double submit) made this change first: finish it
              // as this request's own. Otherwise refuse and keep the token, so
              // the user can confirm again.
              IdentifierNotFoundError: () =>
                Effect.gen(function* () {
                  const now = yield* identifiers.listByUser(user.id);
                  const found = now.find((id) => id.type === "email" && id.value === newEmail);
                  if (found !== undefined) return { identifier: found, converged: now };
                  return yield* new AccountTokenError({
                    message: "The account's email changed during the confirmation; try again",
                  });
                }),
            }),
          );
          if (outcome.converged === null)
            replaced = Option.map(current, (identifier) => identifier.id);
          else held = outcome.converged;
          confirmed = outcome.identifier;
        } else {
          confirmed = clash.value;
        }

        // The token proves ownership, so the confirmed address ends verified,
        // whichever write put it there: this user's earlier claim, a concurrent
        // confirmation, or a store that reports a row already holding it.
        // A concurrent delete may remove the identifier first; then refuse and
        // keep the token, so the user can confirm again.
        if (!confirmed.verified) {
          const verified = yield* identifiers.setVerified(confirmed.id, yield* DateTime.nowAsDate);
          if (Option.isNone(verified)) {
            return yield* new AccountTokenError({
              message: "The account's email changed during the confirmation; try again",
            });
          }
        }

        // Release every other email identifier the user held. This also runs
        // when the new address is already this user's, so a retry after a
        // failed release converges instead of leaving a previous address
        // behind. The replaced identifier is skipped: it is gone, and a store
        // that keeps one email per user reuses its id for the new address.
        yield* Effect.forEach(
          Arr.filter(
            held,
            (id) =>
              id.type === "email" && id.value !== newEmail && !Option.contains(replaced, id.id),
          ),
          (id) => identifiers.delete(id.id),
          { concurrency: 1, discard: true },
        );

        const updated = yield* users.update({
          ...user,
          updatedAt: yield* DateTime.nowAsDate,
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
          const foundUser = yield* users.get(userId);
          if (Option.isNone(foundUser)) {
            return yield* new Errors.UserNotFoundError({ message: "User not found", userId });
          }
          const user = foundUser.value;

          const token = yield* generateToken();
          const now = yield* Clock.currentTimeMillis;
          yield* store.create({
            token,
            userId,
            purpose: "delete-account",
            createdAt: now,
            expiresAt: now + deleteAccountExpiresIn,
          });

          const email = Identifier.anyEmailValue(yield* identifiers.listByUser(userId));
          yield* config.sendDeleteAccountVerification({ user, email, token });

          return { token, expiresAt: now + deleteAccountExpiresIn };
        },
      ),

      confirmAccountDeletion: Effect.fn("AccountManagementService.confirmAccountDeletion")(
        function* (token: string) {
          const foundRecord = yield* store.get(token);
          if (Option.isNone(foundRecord) || foundRecord.value.purpose !== "delete-account") {
            return yield* new AccountTokenError({ message: "Invalid or expired token" });
          }
          const record = foundRecord.value;
          if ((yield* Clock.currentTimeMillis) > record.expiresAt) {
            yield* store.delete(token);
            return yield* new AccountTokenError({ message: "Token has expired" });
          }

          const foundUser = yield* users.get(record.userId);
          if (Option.isNone(foundUser)) {
            return yield* new Errors.UserNotFoundError({
              message: "User not found",
              userId: record.userId,
            });
          }
          const user = foundUser.value;

          // App-data cleanup while the user still exists (a failure aborts).
          if (config.beforeDelete !== undefined) {
            yield* config.beforeDelete(user);
          }

          // Credentials and tokens (this one included), sessions, identifiers,
          // and the user row last.
          yield* purgeUser(purgeServices, user.id);

          return { userId: user.id };
        },
      ),
    };
  });

/**
 * Provides {@link AccountDeletion}: the purge every account deletion runs,
 * over the stores present where it is built. It deletes the user's
 * credentials and tokens from every user-keyed store in the context (OAuth
 * links, passkeys, API keys, the multi-factor enrolment, trusted devices,
 * OIDC-provider tokens and consents, password-reset, email-verification and
 * account-management tokens), the unspent magic links and one-time codes
 * sent to the user's addresses, then the sessions, then the identifiers, and
 * the user row last. `UserService.deleteUser` delegates to it.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer, Option } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * const ada = Testing.fixtureUser({ name: "Ada" })
 *
 * const program = Effect.gen(function* () {
 *   yield* (yield* Auth.User.UserServiceStore).update(ada)
 *   const { key } = yield* (yield* Auth.ApiKey.ApiKeyService).create(ada.id)
 *   yield* (yield* Auth.User.UserService).deleteUser(ada.id)
 *   assert.ok(Option.isNone(yield* (yield* Auth.User.UserServiceStore).get(ada.id)))
 *   assert.deepEqual(yield* (yield* Auth.ApiKey.ApiKeyStore).listByUserId(ada.id), [])
 *   assert.equal((yield* (yield* Auth.ApiKey.ApiKeyService).verify(key)).valid, false)
 * })
 *
 * const sessions = Auth.SessionService.SessionService.layer(Testing.defaultSessionConfig).pipe(
 *   Layer.provideMerge(Layer.merge(Testing.memoryStores, Auth.Hooks.Hooks.Default)),
 * )
 * const services = Layer.mergeAll(
 *   Auth.User.UserService.layer(),
 *   Auth.ApiKey.ApiKeyService.layer().pipe(Layer.provideMerge(Auth.RateLimit.RateLimiter.layer())),
 * ).pipe(Layer.provideMerge(Auth.AccountManagement.accountDeletionLayer), Layer.provideMerge(sessions))
 *
 * await Effect.runPromise(program.pipe(Effect.provide(services)))
 * ```
 *
 * @since 0.5.0
 * @category layers
 */
export const accountDeletionLayer: Layer.Layer<
  AccountDeletion,
  never,
  UserServiceStore | Identifier.IdentifierStore | SessionService
> = Layer.effect(
  AccountDeletion,
  Effect.gen(function* () {
    const users = yield* UserServiceStore;
    const sessions = yield* SessionService;
    const purgeServices = definedKeys({
      ...(yield* userPurgeStores),
      accountTokens: Option.getOrUndefined(yield* Effect.serviceOption(AccountManagementStore)),
      identifiers: Option.some(yield* Identifier.IdentifierStore),
      revokeSessions: sessions.invalidateUserSessions,
      deleteUser: users.delete,
    });
    return {
      deleteUser: Effect.fn("AccountDeletion.deleteUser")((userId: string) =>
        purgeUser(purgeServices, userId),
      ),
    };
  }),
);
