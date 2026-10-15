import { Context, Effect, Layer, Option } from "effect";
import * as Errors from "../Errors.ts";
import { Hooks, type HookError } from "../Hooks.ts";
import { IdentifierStore, resolveUserByIdentifier, type IdentifierType } from "../Identifier.ts";
import { MultiAlgorithmVerifier, PasswordHasher } from "../password/Password.ts";
import type * as Types from "../Types.ts";
import { normalizeEmail } from "../utils.ts";
import { SessionService } from "../SessionService.ts";
import {
  createUserWithIdentifier,
  type CreateUserResult,
  type NewUserIdentifier,
  UserStore,
} from "../UserStore.ts";
import * as Obs from "../Observability.ts";

/**
 * Fields for a new user record. Services record the login handle as an
 * `Identifier` after the user row exists; `identifier` carries it to the store
 * as well, for a store that keeps it on the user row.
 */
export interface CreateUserInput {
  readonly name?: string;
  readonly image?: string;
  readonly attributes?: Record<string, unknown>;
  /**
   * The login handle the user is created with: a store that keeps it on the
   * user row writes it there on insert, and any other store ignores it (see
   * {@link NewUserIdentifier}).
   */
  readonly identifier?: NewUserIdentifier | undefined;
}

/**
 * The store {@link EmailPasswordService} creates users and reads and writes password hashes through.
 */
export class EmailPasswordStore extends Context.Service<
  EmailPasswordStore,
  {
    /**
     * Create a user. `created` in the result is `true` only when this call
     * inserted the user; a user that already existed (as a find-or-create on
     * the address returns) reports `false`, and sign-up then fails without
     * writing to it (or, with `antiEnumeration`, the same no-session answer as
     * any duplicate). The store must leave that row as it was: never an upsert
     * that updates it (see {@link CreateUserResult}).
     */
    readonly createUser: (
      input: CreateUserInput,
    ) => Effect.Effect<CreateUserResult, Errors.AuthError>;

    /**
     * Optional. Mint an id in the shape `createUser` assigns to a new user,
     * without writing anything. Under `antiEnumeration`, sign-up answers an
     * address another user holds with a stand-in user that no row backs (see
     * {@link EmailPasswordConfig.antiEnumeration}); its id comes from here, so
     * a store whose ids are not random UUIDs (sequential integers, prefixed or
     * time-ordered ids) can keep the stand-in's id the same shape as a real
     * one. The id must be one no user holds or will later be assigned (an id
     * equal to the address holder's would make `UsernameService.signUp` claim
     * the username for that user): draw it from the same sequence
     * `createUser` uses, reserving it. Minting it must not read or change any
     * existing user. Without it the stand-in's id is a random UUID
     * (`crypto.randomUUID()`), the shape effect-auth-sql's `createUser`
     * assigns.
     */
    readonly newUserId?: (() => Effect.Effect<string, Errors.AuthError>) | undefined;

    readonly getPasswordHash: (userId: string) => Effect.Effect<string | null, Errors.AuthError>;

    readonly setPasswordHash: (
      userId: string,
      hash: string,
    ) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/EmailPasswordStore") {}

/**
 * Configuration for {@link EmailPasswordService}.
 */
export interface EmailPasswordConfig {
  readonly disableSignUp?: boolean;
  readonly requireEmailVerification?: boolean;
  readonly minPasswordLength?: number;
  readonly maxPasswordLength?: number;
  readonly autoSignIn?: boolean;
  /**
   * Opt-in anti-enumeration mode for `signUp`. When `true`, a sign-up for an
   * address another user already holds does not fail with `EmailInUseError`.
   * It hashes the submitted password (one hash, as a fresh sign-up pays) and
   * answers with a no-session result for a stand-in user built only from the
   * caller's own input: never the existing user's id or data, and nothing is
   * written. The same answer covers an address found taken at the insert: a
   * lost race, or a store whose `createUser` reports `created: false`.
   *
   * A fresh sign-up gets no session either (as if `autoSignIn: false`), so
   * "a session came back" cannot itself tell the two apart. Over HTTP
   * (`POST /sign-up` through `Http.make`), both answers are a `200` with the
   * same headers (`Content-Length` follows the body, so it matches while the
   * ids have the same length), no `Set-Cookie` and no bearer-token header,
   * and a body with the same fields: `needsEmailVerification`, and a `user`
   * whose `email` is the submitted address, trimmed and lower-cased (after
   * the `beforeSignUp` hooks), with `emailVerified: false`. The stand-in's
   * other fields are what a store that keeps its input as given (as
   * effect-auth-sql's does) returns for a new user: the submitted `name` and
   * `attributes` (`{}` when none), no `image`, and one timestamp, taken
   * during the request, for both `createdAt` and `updatedAt`. Its `id` is a
   * random UUID unless the store implements `EmailPasswordStore.newUserId`;
   * a store whose ids have another shape needs that seam for the two ids to
   * look alike.
   *
   * What still differs: the time a response takes (a fresh sign-up also
   * creates the user, claims the address and stores the hash), what a fresh
   * sign-up also does when email verification is on (it stores a
   * verification record, runs the `beforeCreateVerification` and
   * `afterCreateVerification` hooks, and sends the verification email; see
   * below), the `afterSignUp` hooks (they run for a fresh sign-up only), and
   * anything a later request observes. Signing in with the submitted password succeeds
   * only for a fresh sign-up, and a username sign-up's username is claimed
   * only for a fresh sign-up (see `UsernameService.signUp`).
   *
   * With email verification on, `AuthLifecycleService.signUp` stores a
   * verification record and sends the verification email for a fresh sign-up
   * only (and runs the `beforeCreateVerification` and
   * `afterCreateVerification` hooks for it alone). For an address another
   * user holds it stores nothing and sends
   * `AuthLifecycleConfig.sendExistingAccountNotice` to the address when that
   * is set, since a verification link for the stand-in could never verify.
   *
   * Default `false`: a duplicate fails with `EmailInUseError`.
   */
  readonly antiEnumeration?: boolean;
}

/** Input to {@link EmailPasswordService.signUp}. */
export interface SignUpInput {
  readonly email: string;
  readonly password: string;
  readonly name?: string;
  readonly attributes?: Record<string, unknown>;
  readonly sessionAttributes?: Record<string, unknown>;
  /** Optional captcha token, consumed by the `CaptchaPlugin` `beforeSignUp` hook. */
  readonly captchaToken?: string;
}

/** Input to {@link EmailPasswordService.signIn}. */
export interface SignInInput {
  readonly email: string;
  readonly password: string;
  readonly sessionAttributes?: Record<string, unknown>;
  /** Optional captcha token, consumed by the `CaptchaPlugin` `beforeSignIn` hook. */
  readonly captchaToken?: string;
  /**
   * When `false`, the session cookie is emitted without `Max-Age`/`Expires`
   * (a browser-session cookie that is cleared when the browser is closed).
   * The server-side session lifetime (`activePeriod`/`idlePeriod`) is
   * unchanged; orphaned sessions expire naturally via the idle timeout.
   * Default `true` (persistent cookie matching `session.expiresAt`).
   */
  readonly rememberMe?: boolean;
}

/**
 * A pending second-factor challenge issued during sign-in. The client must
 * redeem the token with the second factor (e.g. a TOTP code) to obtain a
 * session.
 */
export interface SecondFactorChallenge {
  readonly token: string;
  readonly expiresAt: number;
}

/**
 * Optional seam consulted by password sign-in after the first factor
 * succeeds. When present in context (see `MultiFactorGateLayer` in the
 * MultiFactor module) and `required` reports true, sign-in returns a
 * {@link SecondFactorChallenge} instead of a session.
 */
export class SecondFactorGate extends Context.Service<
  SecondFactorGate,
  {
    readonly required: (user: Types.User) => Effect.Effect<boolean, Errors.AuthError>;
    readonly begin: (user: Types.User) => Effect.Effect<SecondFactorChallenge, Errors.AuthError>;
  }
>()("@effect-auth/SecondFactorGate") {}

/**
 * Outcome of a sign-in or sign-up.
 */
export interface AuthResult {
  readonly user: Types.User;
  /**
   * The login handle used for this sign-in/up, when one was involved.
   * Hooks (account lockout reset, last-login-method) key off it; flows
   * without a handle (passkey discoverable login, anonymous) omit it.
   */
  readonly identifier?: { readonly type: IdentifierType; readonly value: string };
  readonly session?: Types.Session;
  /** Present when a second factor is required to complete sign-in. */
  readonly secondFactor?: SecondFactorChallenge;
  /**
   * Sign-in method discriminator (`"email-password"`, `"username"`,
   * `"magic-link"`, ...) for hooks like the last-login-method plugin.
   */
  readonly method?: string;
  /**
   * When `false`, the HTTP layer emits a browser-session cookie (no
   * `Max-Age`/`Expires`). Propagated from `SignInInput.rememberMe`.
   */
  readonly rememberMe?: boolean;
}

/**
 * Whether `result`, an answer from {@link EmailPasswordService.signUp} for the
 * submitted address `email`, is the anti-enumeration stand-in (see
 * {@link EmailPasswordConfig.antiEnumeration}) rather than a fresh sign-up.
 * Internal: the `email` subpath doesn't export it.
 *
 * The stores tell the two apart: a fresh sign-up's user holds the address, a
 * stand-in's does not. Asking them rather than recognising the result object
 * holds when a decorated `EmailPasswordService` copies the result, and both
 * answers pay the same read.
 *
 * This expects the identifier store to read its own writes. A store whose
 * reads lag (a cache of negative lookups, say) can report no holder for the
 * address a fresh sign-up has just claimed, so a missing holder falls back to
 * the user store: the stand-in's id is never stored, so a user found under it
 * is a real sign-up.
 *
 * A decorator must keep `identifier` on the result: without it this reads the
 * address as submitted, before any hook rewrote it.
 */
export const answeredByStandIn = (
  identifiers: typeof IdentifierStore.Service,
  users: typeof UserStore.Service,
  result: AuthResult,
  email: string,
): Effect.Effect<boolean, Errors.AuthError> =>
  Effect.gen(function* () {
    const holder = yield* identifiers.getByValue(
      "email",
      result.identifier?.value ?? normalizeEmail(email),
    );
    return holder !== null
      ? holder.userId !== result.user.id
      : (yield* users.get(result.user.id)) === null;
  });

/** Input to {@link EmailPasswordService.changePassword}. */
export interface ChangePasswordInput {
  readonly userId: string;
  readonly currentPassword: string;
  readonly newPassword: string;
  /** Revoke the user's other sessions after the change (keeps `currentSessionId`). */
  readonly revokeOtherSessions?: boolean;
  /** The session to keep when `revokeOtherSessions` is set; omit to revoke all. */
  readonly currentSessionId?: string;
}

/**
 * Email-and-password sign-up, sign-in and password changes. Sign-in does constant work whether or not the account exists, and honours the multi-factor gate.
 *
 * Requires `EmailPasswordStore`, `PasswordHasher`, `UserStore`, `IdentifierStore`, `SessionService` and `Hooks`.
 */
export class EmailPasswordService extends Context.Service<
  EmailPasswordService,
  {
    readonly signUp: (
      input: SignUpInput,
    ) => Effect.Effect<
      AuthResult,
      | Errors.AuthError
      | Errors.EmailInUseError
      | Errors.HashingError
      | Errors.EmailNotVerifiedError
      | Errors.PasswordPolicyError
      | Errors.SignUpDisabledError
      | Errors.InvalidInputError
      | HookError
    >;

    readonly signIn: (
      input: SignInInput,
    ) => Effect.Effect<
      AuthResult,
      | Errors.InvalidCredentialsError
      | Errors.HashingError
      | Errors.AuthError
      | Errors.EmailNotVerifiedError
      | HookError
    >;

    /**
     * Change the password of a user that already has one, verifying the current
     * password first. Optionally revokes the user's other sessions.
     */
    readonly changePassword: (
      input: ChangePasswordInput,
    ) => Effect.Effect<
      void,
      | Errors.InvalidCredentialsError
      | Errors.HashingError
      | Errors.AuthError
      | Errors.PasswordPolicyError
    >;

    /**
     * Set a password for a user that does not have one yet (e.g. an account
     * created via OAuth). Fails if a password is already set.
     */
    readonly setPassword: (
      userId: string,
      newPassword: string,
    ) => Effect.Effect<
      void,
      | Errors.HashingError
      | Errors.AuthError
      | Errors.PasswordPolicyError
      | Errors.PasswordAlreadySetError
    >;
  }
>()("@effect-auth/EmailPasswordService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: EmailPasswordConfig = {}) =>
    Layer.effect(EmailPasswordService, make(config));
}

const validatePasswordLength = (
  password: string,
  config: Required<Pick<EmailPasswordConfig, "minPasswordLength" | "maxPasswordLength">>,
): Effect.Effect<void, Errors.PasswordPolicyError> =>
  Effect.gen(function* () {
    if (password.length < config.minPasswordLength) {
      return yield* new Errors.PasswordPolicyError({
        code: Errors.ErrorCode.PASSWORD_TOO_SHORT,
        message: `Password must be at least ${config.minPasswordLength} characters`,
        params: { minLength: config.minPasswordLength },
      });
    }

    if (password.length > config.maxPasswordLength) {
      return yield* new Errors.PasswordPolicyError({
        code: Errors.ErrorCode.PASSWORD_TOO_LONG,
        message: `Password must be at most ${config.maxPasswordLength} characters`,
        params: { maxLength: config.maxPasswordLength },
      });
    }
  });

export const make = (
  config: EmailPasswordConfig = {},
): Effect.Effect<
  typeof EmailPasswordService.Service,
  never,
  EmailPasswordStore | IdentifierStore | UserStore | PasswordHasher | SessionService | Hooks
> =>
  Effect.gen(function* () {
    const resolved = {
      disableSignUp: config.disableSignUp ?? false,
      requireEmailVerification: config.requireEmailVerification ?? false,
      minPasswordLength: config.minPasswordLength ?? 8,
      maxPasswordLength: config.maxPasswordLength ?? 128,
      autoSignIn: config.autoSignIn ?? true,
      antiEnumeration: config.antiEnumeration ?? false,
    };

    const store = yield* EmailPasswordStore;
    const identifiers = yield* IdentifierStore;
    const users = yield* UserStore;
    const passwordHasher = yield* PasswordHasher;
    const sessionManager = yield* SessionService;
    const hooks = yield* Hooks;

    // Cached decoy hash — computed on first signIn call so that unknown-user
    // attempts always perform the same hashing work as known-user ones.
    let cachedDecoyHash: string | undefined;
    const getDecoyHash: Effect.Effect<string, Errors.HashingError> = Effect.gen(function* () {
      if (cachedDecoyHash !== undefined) return cachedDecoyHash;
      const result = yield* passwordHasher.hash("effect-auth-decoy");
      cachedDecoyHash = result.hash;
      return cachedDecoyHash;
    });

    // The answer to a sign-up for an address another user holds, however the
    // flow finds that out (the pre-check, a lost insert race, or a store that
    // reports `created: false`). Under anti-enumeration it pays the same
    // hashing cost a fresh sign-up would, then answers with an identical,
    // no-session result for a stand-in user built only from the caller's own
    // input (never the real account's data), so it discloses nothing about
    // the address. The stand-in's fields match what a store's `createUser`
    // returns for the same input: an id in the store's shape when it can mint
    // one, and one timestamp for both `createdAt` and `updatedAt`.
    const addressTaken = (input: SignUpInput, email: string) =>
      Effect.gen(function* () {
        if (!resolved.antiEnumeration) {
          return yield* new Errors.EmailInUseError({
            message: "A user with this email already exists",
          });
        }
        yield* passwordHasher.hash(input.password);
        const id =
          store.newUserId === undefined ? globalThis.crypto.randomUUID() : yield* store.newUserId();
        const now = new Date();
        return {
          user: {
            id,
            ...(input.name !== undefined && { name: input.name }),
            createdAt: now,
            updatedAt: now,
            attributes: input.attributes ?? {},
          },
          identifier: { type: "email", value: email },
          method: "email-password",
        } satisfies AuthResult;
      });

    return {
      signUp: Effect.fn("EmailPasswordService.signUp")((rawInput: SignUpInput) =>
        Effect.gen(function* () {
          const input = yield* hooks.beforeSignUp(rawInput);

          if (resolved.disableSignUp) {
            return yield* new Errors.SignUpDisabledError({
              message: "Email/password sign-up is disabled",
            });
          }

          const email = normalizeEmail(input.email);
          if (!email) {
            return yield* new Errors.InvalidInputError({
              message: "Email is required",
              field: "email",
            });
          }

          yield* validatePasswordLength(input.password, {
            minPasswordLength: resolved.minPasswordLength,
            maxPasswordLength: resolved.maxPasswordLength,
          });

          const taken = yield* identifiers.getByValue("email", email);
          if (taken) return yield* addressTaken(input, email);

          // The identifier's unique (type, value) index is the real claim; a
          // lost race, or a store reporting `created: false`, gets the same
          // answer as the pre-check. When the claim loses it, the just-created
          // user row is orphaned (no identifiers, no password) — harmless but
          // worth a periodic sweep in high-contention deployments. A store
          // that writes the address into the user row loses the race at the
          // insert instead, and no row is left.
          const created = yield* createUserWithIdentifier(
            identifiers,
            { type: "email", value: email, verified: false },
            (identifier) =>
              store.createUser({
                ...(input.name !== undefined && { name: input.name }),
                ...(input.attributes !== undefined && { attributes: input.attributes }),
                identifier,
              }),
          ).pipe(Effect.catchTag("IdentifierTakenError", () => Effect.succeed(null)));
          if (created === null) return yield* addressTaken(input, email);
          const { user, identifier: emailIdentifier } = created;

          const hashedPassword = yield* passwordHasher.hash(input.password);
          yield* store.setPasswordHash(user.id, hashedPassword.hash);

          const handle = { type: "email" as const, value: emailIdentifier.value };

          // `antiEnumeration` forces the same no-session shape here as the
          // duplicate branch above returns, so "a session came back" can
          // never itself be the oracle.
          if (
            !resolved.autoSignIn ||
            resolved.requireEmailVerification ||
            resolved.antiEnumeration
          ) {
            // A freshly claimed email identifier is always unverified.
            return yield* hooks.afterSignUp({ user, identifier: handle, method: "email-password" });
          }

          const session = yield* sessionManager.createSession(user.id, input.sessionAttributes);
          const signUpResult = {
            user,
            session,
            identifier: handle,
            method: "email-password" as const,
          };

          // Session is now live in the store. If afterSignUp fails we must not
          // return an error (that would leave a dangling session the caller
          // doesn't know about). Log and swallow so the caller receives the
          // auth result.
          return yield* hooks
            .afterSignUp(signUpResult)
            .pipe(
              Effect.catch((error) =>
                Effect.logError(
                  "[effect-auth] afterSignUp hook failed after session creation",
                  error,
                ).pipe(Effect.as(signUpResult)),
              ),
            );
        }).pipe(
          Effect.withSpan(Obs.spanNames.signUp, { attributes: { method: "email-password" } }),
          Effect.tap(() => Obs.recordSignUp("email-password", "success")),
          Effect.tapError(() => Obs.recordSignUp("email-password", "failure")),
        ),
      ),

      signIn: Effect.fn("EmailPasswordService.signIn")((rawInput: SignInInput) =>
        Effect.gen(function* () {
          const input = yield* hooks.beforeSignIn(rawInput);

          const email = normalizeEmail(input.email);
          if (!email) {
            return yield* new Errors.InvalidCredentialsError({
              message: "Invalid email or password",
            });
          }

          const resolvedUser = yield* resolveUserByIdentifier(
            identifiers,
            users.get,
            "email",
            email,
          );
          const user = resolvedUser?.user ?? null;
          const passwordHash = user !== null ? yield* store.getPasswordHash(user.id) : null;
          // Always verify against a real or decoy hash so timing is constant
          // regardless of whether the account exists.  Route through
          // MultiAlgorithmVerifier when present so that a hasher switch does not
          // lock out existing users.  Convert HashingError to false so sign-in
          // always returns InvalidCredentialsError and never a 500.
          const hashToVerify = passwordHash ?? (yield* getDecoyHash);
          const multiVerifier = yield* Effect.serviceOption(MultiAlgorithmVerifier);
          const verifyEffect = Option.isSome(multiVerifier)
            ? multiVerifier.value.verify(input.password, hashToVerify)
            : passwordHasher.verify(input.password, hashToVerify);
          const isValid = yield* verifyEffect.pipe(
            Effect.catchTag("HashingError", () => Effect.succeed(false)),
          );
          if (user === null || passwordHash === null || !isValid) {
            return yield* new Errors.InvalidCredentialsError({
              message: "Invalid email or password",
            });
          }

          // Silently upgrade the stored hash when the current hasher considers
          // it outdated (e.g. iteration count raised, algorithm switched).  A
          // failure here must never abort sign-in — the user is already
          // authenticated at this point.
          if (passwordHasher.needsRehash?.(passwordHash!)) {
            yield* passwordHasher.hash(input.password).pipe(
              Effect.flatMap((newHash) => store.setPasswordHash(user.id, newHash.hash)),
              Effect.ignore,
            );
          }

          if (resolved.requireEmailVerification && !resolvedUser!.identifier.verified) {
            return yield* new Errors.EmailNotVerifiedError({
              message: "Email must be verified before sign-in",
              email,
            });
          }

          const handle = { type: "email" as const, value: resolvedUser!.identifier.value };

          // Second factor: when a gate is present and required for this user,
          // return a challenge instead of a session.
          const gate = yield* Effect.serviceOption(SecondFactorGate);
          if (Option.isSome(gate) && (yield* gate.value.required(user))) {
            const secondFactor = yield* gate.value.begin(user);
            return yield* hooks.afterSignIn({
              user,
              secondFactor,
              identifier: handle,
              method: "email-password",
            });
          }

          const session = yield* sessionManager.createSession(user.id, input.sessionAttributes);
          const signInResult = {
            user,
            session,
            identifier: handle,
            method: "email-password" as const,
            ...(input.rememberMe !== undefined && { rememberMe: input.rememberMe }),
          };

          // Session is now live in the store. If afterSignIn fails we must not
          // return an error (that would leave a dangling session the caller
          // doesn't know about). Log and swallow so the caller receives the
          // auth result.
          return yield* hooks
            .afterSignIn(signInResult)
            .pipe(
              Effect.catch((error) =>
                Effect.logError(
                  "[effect-auth] afterSignIn hook failed after session creation",
                  error,
                ).pipe(Effect.as(signInResult)),
              ),
            );
        }).pipe(
          Effect.withSpan(Obs.spanNames.signIn, { attributes: { method: "email-password" } }),
          Effect.tap(() => Obs.recordSignIn("email-password", "success")),
          Effect.tapError(() => Obs.recordSignIn("email-password", "failure")),
        ),
      ),

      changePassword: Effect.fn("EmailPasswordService.changePassword")(function* (
        input: ChangePasswordInput,
      ) {
        yield* validatePasswordLength(input.newPassword, {
          minPasswordLength: resolved.minPasswordLength,
          maxPasswordLength: resolved.maxPasswordLength,
        });

        const currentHash = yield* store.getPasswordHash(input.userId);
        if (!currentHash) {
          return yield* new Errors.InvalidCredentialsError({
            message: "Invalid password",
          });
        }

        const isValid = yield* passwordHasher.verify(input.currentPassword, currentHash);
        if (!isValid) {
          return yield* new Errors.InvalidCredentialsError({
            message: "Invalid password",
          });
        }

        const hashedPassword = yield* passwordHasher.hash(input.newPassword);
        yield* store.setPasswordHash(input.userId, hashedPassword.hash);

        if (input.revokeOtherSessions) {
          if (input.currentSessionId !== undefined) {
            yield* sessionManager.revokeOtherSessions(input.userId, input.currentSessionId);
          } else {
            yield* sessionManager.invalidateUserSessions(input.userId);
          }
        }
      }),

      setPassword: Effect.fn("EmailPasswordService.setPassword")(function* (
        userId: string,
        newPassword: string,
      ) {
        yield* validatePasswordLength(newPassword, {
          minPasswordLength: resolved.minPasswordLength,
          maxPasswordLength: resolved.maxPasswordLength,
        });

        const currentHash = yield* store.getPasswordHash(userId);
        if (currentHash) {
          return yield* new Errors.PasswordAlreadySetError({
            message: "User already has a password; use changePassword instead",
          });
        }

        const hashedPassword = yield* passwordHasher.hash(newPassword);
        yield* store.setPasswordHash(userId, hashedPassword.hash);
      }),
    };
  });
