import { Context, Effect, Layer, Option } from "effect";
import * as Errors from "../Errors.ts";
import { Hooks, type HookError } from "../Hooks.ts";
import {
  claimIdentifier,
  IdentifierStore,
  makeIdentifier,
  resolveUserByIdentifier,
  type IdentifierType,
} from "../Identifier.ts";
import { MultiAlgorithmVerifier, PasswordHasher } from "../password/Password.ts";
import type * as Types from "../Types.ts";
import { normalizeEmail } from "../utils.ts";
import { SessionService } from "../SessionService.ts";
import { UserStore } from "../UserStore.ts";
import * as Obs from "../Observability.ts";

/**
 * Profile fields for a new user record. The login handle (email/username/
 * phone) is NOT part of this input — services record it as an `Identifier`
 * after the user row exists.
 */
export interface CreateUserInput {
  readonly name?: string;
  readonly image?: string;
  readonly attributes?: Record<string, unknown>;
}

export class EmailPasswordStore extends Context.Service<
  EmailPasswordStore,
  {
    readonly createUser: (input: CreateUserInput) => Effect.Effect<Types.User, Errors.AuthError>;

    readonly getPasswordHash: (userId: string) => Effect.Effect<string | null, Errors.AuthError>;

    readonly setPasswordHash: (
      userId: string,
      hash: string,
    ) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/EmailPasswordStore") {}

export interface EmailPasswordConfig {
  readonly disableSignUp?: boolean;
  readonly requireEmailVerification?: boolean;
  readonly minPasswordLength?: number;
  readonly maxPasswordLength?: number;
  readonly autoSignIn?: boolean;
}

export interface SignUpInput {
  readonly email: string;
  readonly password: string;
  readonly name?: string;
  readonly attributes?: Record<string, unknown>;
  readonly sessionAttributes?: Record<string, unknown>;
  /** Optional captcha token, consumed by the `CaptchaPlugin` `beforeSignUp` hook. */
  readonly captchaToken?: string;
}

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

export interface ChangePasswordInput {
  readonly userId: string;
  readonly currentPassword: string;
  readonly newPassword: string;
  /** Revoke the user's other sessions after the change (keeps `currentSessionId`). */
  readonly revokeOtherSessions?: boolean;
  /** The session to keep when `revokeOtherSessions` is set; omit to revoke all. */
  readonly currentSessionId?: string;
}

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
      return yield* Effect.fail(
        new Errors.PasswordPolicyError({
          code: Errors.ErrorCode.PASSWORD_TOO_SHORT,
          message: `Password must be at least ${config.minPasswordLength} characters`,
          params: { minLength: config.minPasswordLength },
        }),
      );
    }

    if (password.length > config.maxPasswordLength) {
      return yield* Effect.fail(
        new Errors.PasswordPolicyError({
          code: Errors.ErrorCode.PASSWORD_TOO_LONG,
          message: `Password must be at most ${config.maxPasswordLength} characters`,
          params: { maxLength: config.maxPasswordLength },
        }),
      );
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

    return {
      signUp: Effect.fn("EmailPasswordService.signUp")((rawInput: SignUpInput) =>
        Effect.gen(function* () {
          const input = yield* hooks.beforeSignUp(rawInput);

          if (resolved.disableSignUp) {
            return yield* Effect.fail(
              new Errors.SignUpDisabledError({
                message: "Email/password sign-up is disabled",
              }),
            );
          }

          const email = normalizeEmail(input.email);
          if (!email) {
            return yield* Effect.fail(
              new Errors.InvalidInputError({
                message: "Email is required",
                field: "email",
              }),
            );
          }

          yield* validatePasswordLength(input.password, {
            minPasswordLength: resolved.minPasswordLength,
            maxPasswordLength: resolved.maxPasswordLength,
          });

          const taken = yield* identifiers.getByValue("email", email);
          if (taken) {
            return yield* new Errors.EmailInUseError({
              message: "A user with this email already exists",
            });
          }

          const user = yield* store.createUser({
            ...(input.name !== undefined && { name: input.name }),
            ...(input.attributes !== undefined && { attributes: input.attributes }),
          });

          // The identifier's unique (type, value) index is the real claim; a
          // lost race surfaces as EmailInUseError. The just-created user row
          // is then orphaned (no identifiers, no password) — harmless but
          // worth a periodic sweep in high-contention deployments.
          const emailIdentifier = yield* claimIdentifier(
            identifiers,
            makeIdentifier({ userId: user.id, type: "email", value: email }),
          ).pipe(
            Effect.catchTag("IdentifierTakenError", () =>
              Effect.fail(
                new Errors.EmailInUseError({
                  message: "A user with this email already exists",
                }),
              ),
            ),
          );

          const hashedPassword = yield* passwordHasher.hash(input.password);
          yield* store.setPasswordHash(user.id, hashedPassword.hash);

          const handle = { type: "email" as const, value: emailIdentifier.value };

          if (!resolved.autoSignIn) {
            return yield* hooks.afterSignUp({ user, identifier: handle, method: "email-password" });
          }

          if (resolved.requireEmailVerification) {
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
          Effect.withSpan("effect-auth.sign-up", { attributes: { method: "email-password" } }),
          Effect.tap(() => Obs.recordSignUp("email-password", "success")),
          Effect.tapError(() => Obs.recordSignUp("email-password", "failure")),
        ),
      ),

      signIn: Effect.fn("EmailPasswordService.signIn")((rawInput: SignInInput) =>
        Effect.gen(function* () {
          const input = yield* hooks.beforeSignIn(rawInput);

          const email = normalizeEmail(input.email);
          if (!email) {
            return yield* Effect.fail(
              new Errors.InvalidCredentialsError({
                message: "Invalid email or password",
              }),
            );
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
            return yield* Effect.fail(
              new Errors.InvalidCredentialsError({
                message: "Invalid email or password",
              }),
            );
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
            return yield* Effect.fail(
              new Errors.EmailNotVerifiedError({
                message: "Email must be verified before sign-in",
                email,
              }),
            );
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
          Effect.withSpan("effect-auth.sign-in", { attributes: { method: "email-password" } }),
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
