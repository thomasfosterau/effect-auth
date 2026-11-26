import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Errors from "../Errors.ts";
import { Hooks, type HookError } from "../Hooks.ts";
import {
  IdentifierStore,
  lookupIdentifier,
  resolveUserByIdentifier,
  type IdentifierType,
} from "../Identifier.ts";
import { PasswordHasher } from "../password/Password.ts";
import {
  lazyDecoyHash,
  storedPasswordVerifier,
  verifyPasswordOrDecoy,
} from "../password/DecoyVerify.ts";
import type * as Types from "../Types.ts";
import { normalizeEmail } from "../utils.ts";
import { SessionService } from "../SessionService.ts";
import {
  DEFAULT_SERVER_ONLY_ATTRIBUTES,
  UserService,
  withoutSignUpProtectedAttributes,
} from "../User.ts";
import {
  createUserWithIdentifier,
  type CreateUserResult,
  type NewUserIdentifier,
  UserStore,
} from "../UserStore.ts";
import * as Obs from "../Observability.ts";
import { TrustedDeviceStore } from "../TrustedDeviceStore.ts";
import { definedKeys } from "../DefinedKeys.ts";

/**
 * Fields for a new user record. Services record the login handle as an
 * `Identifier` after the user row exists; `identifier` carries it to the store
 * as well, for a store that keeps it on the user row.
 */
export interface CreateUserInput {
  readonly name?: string;
  readonly image?: string;
  readonly attributes?: Types.Attributes;
  /**
   * The login handle the user is created with: a store that keeps it on the
   * user row writes it there on insert, and any other store ignores it (see
   * {@link NewUserIdentifier}).
   */
  readonly identifier?: NewUserIdentifier;
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
     * (`crypto.randomUUID()`), the shape effect-auth/sql's `createUser`
     * assigns.
     */
    readonly newUserId?: () => Effect.Effect<string, Errors.AuthError>;

    readonly getPasswordHash: (
      userId: string,
    ) => Effect.Effect<Option.Option<string>, Errors.AuthError>;

    readonly setPasswordHash: (
      userId: string,
      hash: string,
    ) => Effect.Effect<void, Errors.AuthError>;

    /**
     * Remove the user's password, so `getPasswordHash` returns `None` and the
     * account has no password to sign in with. A no-op when it has none.
     * `AuthLifecycleService.verifyEmail` calls it through
     * {@link EmailPasswordService.clearPassword} on an address's first
     * verification.
     */
    readonly clearPasswordHash: (userId: string) => Effect.Effect<void, Errors.AuthError>;
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
   * (`POST /users` through `Http.make`), both answers are the same
   * `202 Accepted`: no primary data, only `meta.needsEmailVerification`, the
   * same headers, no `Set-Cookie` and no bearer-token header. Neither names a
   * user, real or stand-in.
   *
   * Called directly, the service still answers with the stand-in user: its
   * `email` is the submitted address, normalised with `normalizeEmail` (after the
   * `beforeSignUp` hooks), with `emailVerified: false`, and its other fields
   * are what a store that keeps its input as given (as effect-auth/sql's
   * does) returns for a new user: the submitted `name` and `attributes` (`{}`
   * when none), no `image`, and one timestamp, taken during the request, for
   * both `createdAt` and `updatedAt`. Its `id` is a random UUID unless the
   * store implements `EmailPasswordStore.newUserId`; a store whose ids have
   * another shape needs that seam for the two ids to look alike to a caller
   * that sees them.
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
  /**
   * The new user's attribute bag. `signUp` drops, after the `beforeSignUp`
   * hooks, every key that carries authority or another flow's state: the
   * configured `UserServiceConfig.serverOnlyAttributes` (default `["role"]`)
   * and `SIGN_UP_PROTECTED_ATTRIBUTES` (the ban, SCIM and anonymous-user
   * keys), whoever supplied them. Set those after the user exists,
   * through their privileged door (`AdminService.setRole` for `role`).
   */
  readonly attributes?: Types.Attributes;
  readonly sessionAttributes?: Types.Attributes;
  /** Optional captcha token, consumed by the `CaptchaPlugin` `beforeSignUp` hook. */
  readonly captchaToken?: string;
}

/** Input to {@link EmailPasswordService.signIn}. */
export interface SignInInput {
  readonly email: string;
  readonly password: string;
  readonly sessionAttributes?: Types.Attributes;
  /** Optional captcha token, consumed by the `CaptchaPlugin` on the `beforeAuthenticate` hook. */
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
 * Optional seam consulted by every sign-in method after the first factor
 * succeeds (see {@link secondFactorChallenge}). When present in context (see
 * `MultiFactorGateLayer` in the MultiFactor module) and `required` reports
 * true, sign-in returns a {@link SecondFactorChallenge} instead of a session,
 * unless the method is in {@link SecondFactorExemptMethods}.
 */
export class SecondFactorGate extends Context.Service<
  SecondFactorGate,
  {
    readonly required: (user: Types.User) => Effect.Effect<boolean, Errors.AuthError>;
    readonly begin: (user: Types.User) => Effect.Effect<SecondFactorChallenge, Errors.AuthError>;
  }
>()("@effect-auth/SecondFactorGate") {}

/**
 * The sign-in methods that issue a session and so consult the
 * {@link SecondFactorGate}: password sign-in by email (`"email-password"`) or
 * username (`"username"`), the magic link, the email and SMS one-time codes,
 * `redeemOneTimeTokenForSession` (`"one-time-token"`), the sign-in that
 * follows an email verification (`"email-verification"`), OAuth, SSO (OIDC
 * and SAML), Google One Tap and passkeys (`"passkey"`, for a host that issues
 * the session itself after `WebAuthnService.verifyAuthentication`).
 */
export type SignInMethod =
  | "email-password"
  | "username"
  | "magic-link"
  | "email-otp"
  | "phone-otp"
  | "one-time-token"
  | "email-verification"
  | "oauth"
  | "sso"
  | "google-one-tap"
  | "passkey";

/**
 * The sign-in methods the {@link SecondFactorGate} lets through on their
 * own: a user enrolled in a second factor who signs in with one of them gets
 * a session, not a challenge. Empty by default, so every method is gated.
 * Provide it with {@link exemptFromSecondFactor}, for instance to treat an IdP
 * that enforces its own multi-factor policy as sufficient.
 */
export const SecondFactorExemptMethods: Context.Reference<ReadonlyArray<SignInMethod>> =
  Context.Reference<ReadonlyArray<SignInMethod>>("@effect-auth/SecondFactorExemptMethods", {
    defaultValue: () => [],
  });

/**
 * Exempt `methods` from the {@link SecondFactorGate}: provide the layer
 * beside the sign-in services.
 *
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect } from "effect"
 * import {
 *   SecondFactorExemptMethods,
 *   exemptFromSecondFactor,
 * } from "@thomasfosterau/effect-auth/email"
 *
 * const program = Effect.gen(function* () {
 *   assert.deepEqual(yield* SecondFactorExemptMethods, ["sso", "passkey"])
 * })
 *
 * await Effect.runPromise(program.pipe(Effect.provide(exemptFromSecondFactor("sso", "passkey"))))
 * ```
 */
export const exemptFromSecondFactor = (
  ...methods: ReadonlyArray<SignInMethod>
): Layer.Layer<never> => Layer.succeed(SecondFactorExemptMethods, methods);

/**
 * Consult the {@link SecondFactorGate} for `user` signing in with `method`,
 * after the first factor succeeded and before a session is created. Answers
 * the challenge to return instead of a session, or `undefined` when there is
 * no gate, the method is exempt ({@link SecondFactorExemptMethods}) or the
 * gate does not require a second factor for this user.
 *
 * Every session-issuing sign-in in the core calls it; a host that issues a
 * session itself (a passkey sign-in, say) calls it too.
 */
export const secondFactorChallenge = (
  user: Types.User,
  method: SignInMethod,
): Effect.Effect<SecondFactorChallenge | undefined, Errors.AuthError> =>
  Effect.gen(function* () {
    const gate = yield* Effect.serviceOption(SecondFactorGate);
    if (Option.isNone(gate)) return undefined;
    if ((yield* SecondFactorExemptMethods).includes(method)) return undefined;
    if (!(yield* gate.value.required(user))) return undefined;
    return yield* gate.value.begin(user);
  });

/**
 * What a gated sign-in answers: the new session and its raw token, or, when
 * the {@link SecondFactorGate} requires a second factor, the challenge to
 * redeem for one instead.
 */
export type SessionOrChallenge =
  | {
      readonly session: Types.Session;
      /** The raw session token, the credential the client presents; `session.id` is its digest. */
      readonly token: string;
      readonly secondFactor?: never;
    }
  | {
      readonly session?: never;
      readonly token?: never;
      /** The challenge to redeem with the second factor for a session. */
      readonly secondFactor: SecondFactorChallenge;
    };

/**
 * Sign `user` in with `method`: the challenge {@link secondFactorChallenge}
 * answers when the gate requires one, else a new session.
 */
export const sessionOrChallenge = (
  sessions: typeof SessionService.Service,
  user: Types.User,
  method: SignInMethod,
  attributes?: Types.Attributes,
): Effect.Effect<SessionOrChallenge, Errors.AuthError | HookError> =>
  Effect.flatMap(
    secondFactorChallenge(user, method),
    (secondFactor): Effect.Effect<SessionOrChallenge, Errors.AuthError | HookError> =>
      secondFactor === undefined
        ? sessions.createSession(user.id, attributes)
        : Effect.succeed({ secondFactor }),
  );

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
  /** The raw session token, present with `session`: the credential the client presents; `session.id` is its digest. */
  readonly token?: string;
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
    const holder = yield* lookupIdentifier(
      identifiers,
      "email",
      result.identifier?.value ?? normalizeEmail(email),
    );
    return Option.isSome(holder)
      ? holder.value.userId !== result.user.id
      : Option.isNone(yield* users.get(result.user.id));
  });

/** Input to {@link EmailPasswordService.changePassword}. */
export interface ChangePasswordInput {
  readonly userId: string;
  readonly currentPassword: string;
  readonly newPassword: string;
  /**
   * Revoke the user's other sessions (keeping `currentSessionId`) and every
   * trusted device after the change. Default `true`; `false` keeps them.
   */
  readonly revokeOtherSessions?: boolean;
  /** The stored id (`session.id`) of the session to keep when `revokeOtherSessions` is on; omit to revoke all. */
  readonly currentSessionId?: string;
}

/**
 * Email-and-password sign-up, sign-in and password changes. Sign-in does constant work whether or not the account exists, and honours the multi-factor gate.
 *
 * Requires `EmailPasswordStore`, `PasswordHasher`, `UserStore`, `IdentifierStore`, `SessionService` and `Hooks`.
 * Reads `UserService`'s `serverOnlyAttributes` when it is in context as the
 * layer is built (else the default `["role"]`): `signUp` never stores those,
 * nor the ban, SCIM and anonymous-user keys, from its input (see
 * {@link SignUpInput.attributes}).
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
     * password first (through `MultiAlgorithmVerifier` when present, so a hash
     * written by a previous hasher verifies), then runs the
     * `beforeChangePassword` hooks on the new one. By default it then revokes the user's other sessions and
     * every trusted device (`TrustedDeviceStore`, when present), so a session
     * or device cookie an attacker holds stops working; `revokeOtherSessions:
     * false` keeps them.
     */
    readonly changePassword: (
      input: ChangePasswordInput,
    ) => Effect.Effect<
      void,
      | Errors.InvalidCredentialsError
      | Errors.HashingError
      | Errors.AuthError
      | Errors.PasswordPolicyError
      | HookError
    >;

    /**
     * Set a password for a user that does not have one yet (e.g. an account
     * created via OAuth), after the `beforeSetPassword` hooks. Fails if a
     * password is already set.
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
      | HookError
    >;

    /**
     * Remove the user's password, if it has one. Afterwards password sign-in
     * fails for the account until a password is set again, through
     * {@link setPassword} or a password reset. Revokes no sessions.
     */
    readonly clearPassword: (userId: string) => Effect.Effect<void, Errors.AuthError>;
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
    return yield* Effect.void;
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
    const verifyStoredPassword = yield* storedPasswordVerifier(passwordHasher);
    const trustedDevices = Option.getOrUndefined(yield* Effect.serviceOption(TrustedDeviceStore));
    // The attributes a sign-up never stores from its input: the
    // configured server-only ones (the `UserService`'s when it is in context
    // as this layer is built, else the default `["role"]`) and the ban, SCIM
    // and anonymous-user keys.
    const serverOnly = Option.match(yield* Effect.serviceOption(UserService), {
      onNone: () => DEFAULT_SERVER_ONLY_ATTRIBUTES,
      onSome: (users) => users.serverOnlyAttributes ?? DEFAULT_SERVER_ONLY_ATTRIBUTES,
    });

    // Cached decoy hash — computed on first signIn call so that unknown-user
    // attempts always perform the same hashing work as known-user ones.
    const getDecoyHash = lazyDecoyHash(passwordHasher, "getDecoyHash");

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
            email,
          });
        }
        yield* passwordHasher.hash(input.password);
        const id =
          store.newUserId === undefined ? globalThis.crypto.randomUUID() : yield* store.newUserId();
        const now = yield* DateTime.nowAsDate;
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
          const hooked = yield* hooks.beforeSignUp(rawInput);
          // Strip after the hooks, so no input (the caller's or a hook's)
          // presets a role, a ban or a SCIM key. Those are set through
          // their privileged door once the user exists.
          const input: SignUpInput =
            hooked.attributes === undefined
              ? hooked
              : {
                  ...hooked,
                  attributes: withoutSignUpProtectedAttributes(hooked.attributes, serverOnly),
                };

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

          const taken = yield* lookupIdentifier(identifiers, "email", email);
          if (Option.isSome(taken)) return yield* addressTaken(input, email);

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

          const { session, token } = yield* sessionManager.createSession(
            user.id,
            input.sessionAttributes,
          );
          const signUpResult = {
            user,
            session,
            token,
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
          yield* hooks.beforeAuthenticate(
            definedKeys({
              method: "email-password",
              identifier: { type: "email", value: email },
              userId: Option.getOrUndefined(Option.map(resolvedUser, (found) => found.user.id)),
              captchaToken: input.captchaToken,
            }),
          );
          const passwordHash = Option.isSome(resolvedUser)
            ? yield* store.getPasswordHash(resolvedUser.value.user.id)
            : Option.none<string>();
          // Always verify against a real or decoy hash so timing is constant
          // regardless of whether the account exists.
          const isValid = yield* verifyPasswordOrDecoy(
            passwordHasher,
            input.password,
            passwordHash,
            getDecoyHash,
          );
          if (Option.isNone(resolvedUser) || Option.isNone(passwordHash) || !isValid) {
            return yield* new Errors.InvalidCredentialsError({
              message: "Invalid email or password",
            });
          }
          const { user, identifier: signInIdentifier } = resolvedUser.value;

          // Silently upgrade the stored hash when the current hasher considers
          // it outdated (e.g. iteration count raised, algorithm switched).  A
          // failure here must never abort sign-in — the user is already
          // authenticated at this point.
          if (passwordHasher.needsRehash?.(passwordHash.value)) {
            yield* passwordHasher.hash(input.password).pipe(
              Effect.flatMap((newHash) => store.setPasswordHash(user.id, newHash.hash)),
              Effect.ignore,
            );
          }

          if (resolved.requireEmailVerification && !signInIdentifier.verified) {
            return yield* new Errors.EmailNotVerifiedError({
              message: "Email must be verified before sign-in",
              email,
            });
          }

          const handle = { type: "email" as const, value: signInIdentifier.value };

          // Second factor: when a gate is present and required for this user,
          // return a challenge instead of a session.
          const secondFactor = yield* secondFactorChallenge(user, "email-password");
          if (secondFactor !== undefined) {
            return yield* hooks.afterSignIn({
              user,
              secondFactor,
              identifier: handle,
              method: "email-password",
            });
          }

          const { session, token } = yield* sessionManager.createSession(
            user.id,
            input.sessionAttributes,
          );
          const signInResult = {
            user,
            session,
            token,
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

        const foundCurrentHash = yield* store.getPasswordHash(input.userId);
        if (Option.isNone(foundCurrentHash)) {
          return yield* new Errors.InvalidCredentialsError({
            message: "Invalid password",
          });
        }
        const currentHash = foundCurrentHash.value;

        const isValid = yield* verifyStoredPassword(input.currentPassword, currentHash);
        if (!isValid) {
          return yield* new Errors.InvalidCredentialsError({
            message: "Invalid password",
          });
        }

        // After the current password, so a plugin that calls out (the breach
        // check) runs only for the account holder.
        const { newPassword } = yield* hooks.beforeChangePassword({
          userId: input.userId,
          newPassword: input.newPassword,
        });
        yield* validatePasswordLength(newPassword, {
          minPasswordLength: resolved.minPasswordLength,
          maxPasswordLength: resolved.maxPasswordLength,
        });

        const hashedPassword = yield* passwordHasher.hash(newPassword);
        yield* store.setPasswordHash(input.userId, hashedPassword.hash);

        if (input.revokeOtherSessions ?? true) {
          if (input.currentSessionId !== undefined) {
            yield* sessionManager.revokeOtherSessions(input.userId, input.currentSessionId);
          } else {
            yield* sessionManager.invalidateUserSessions(input.userId);
          }
          if (trustedDevices !== undefined) yield* trustedDevices.deleteByUserId(input.userId);
        }
        return yield* Effect.void;
      }),

      setPassword: Effect.fn("EmailPasswordService.setPassword")(function* (
        userId: string,
        rawNewPassword: string,
      ) {
        const currentHash = yield* store.getPasswordHash(userId);
        if (Option.isSome(currentHash)) {
          return yield* new Errors.PasswordAlreadySetError({
            message: "User already has a password; use changePassword instead",
          });
        }

        const { newPassword } = yield* hooks.beforeSetPassword({
          userId,
          newPassword: rawNewPassword,
        });
        yield* validatePasswordLength(newPassword, {
          minPasswordLength: resolved.minPasswordLength,
          maxPasswordLength: resolved.maxPasswordLength,
        });

        const hashedPassword = yield* passwordHasher.hash(newPassword);
        return yield* store.setPasswordHash(userId, hashedPassword.hash);
      }),

      clearPassword: Effect.fn("EmailPasswordService.clearPassword")(function* (userId: string) {
        yield* store.clearPasswordHash(userId);
      }),
    };
  });
