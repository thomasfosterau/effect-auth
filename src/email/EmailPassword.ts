import { Context, Effect, Layer, Option } from "effect";
import * as Errors from "../Errors.ts";
import { Hooks, type HookError } from "../Hooks.ts";
import { MultiAlgorithmVerifier, PasswordHasher } from "../password/Password.ts";
import type * as Types from "../Types.ts";
import { normalizeEmail } from "../utils.ts";
import { SessionService } from "../session/SessionService.ts";
import * as Obs from "../Observability.ts";

export interface CreateUserInput {
  readonly email: string;
  readonly name?: string;
  readonly image?: string;
  readonly attributes?: Record<string, unknown>;
}

export interface EmailPasswordStoreShape {
  readonly getUserByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

  readonly createUser: (input: CreateUserInput) => Effect.Effect<Types.User, Errors.AuthError>;

  readonly getPasswordHash: (userId: string) => Effect.Effect<string | null, Errors.AuthError>;

  readonly setPasswordHash: (userId: string, hash: string) => Effect.Effect<void, Errors.AuthError>;
}

export class EmailPasswordStore extends Context.Service<
  EmailPasswordStore,
  EmailPasswordStoreShape
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
 * succeeds. When present in context (see `TwoFactorGateLayer` in the
 * TwoFactor module) and `required` reports true, sign-in returns a
 * {@link SecondFactorChallenge} instead of a session.
 */
export interface SecondFactorGateShape {
  readonly required: (user: Types.User) => Effect.Effect<boolean, Errors.AuthError>;
  readonly begin: (user: Types.User) => Effect.Effect<SecondFactorChallenge, Errors.AuthError>;
}

export class SecondFactorGate extends Context.Service<SecondFactorGate, SecondFactorGateShape>()(
  "@effect-auth/SecondFactorGate",
) {}

export interface AuthResult {
  readonly user: Types.User;
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

export interface EmailPasswordServiceShape {
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
    | HookError,
    EmailPasswordStore | PasswordHasher | SessionService | Hooks
  >;

  readonly signIn: (
    input: SignInInput,
  ) => Effect.Effect<
    AuthResult,
    | Errors.InvalidCredentialsError
    | Errors.HashingError
    | Errors.AuthError
    | Errors.EmailNotVerifiedError
    | HookError,
    EmailPasswordStore | PasswordHasher | SessionService | Hooks
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
    | Errors.PasswordPolicyError,
    EmailPasswordStore | PasswordHasher | SessionService
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
    | Errors.PasswordAlreadySetError,
    EmailPasswordStore | PasswordHasher
  >;
}

export class EmailPasswordService extends Context.Service<
  EmailPasswordService,
  EmailPasswordServiceShape
>()("@effect-auth/EmailPasswordService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: EmailPasswordConfig = {}) =>
    Layer.effect(EmailPasswordService, makeEmailPasswordService(config));
}

export const isEmailVerified = (user: Types.User): boolean => user.emailVerified;

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

export const makeEmailPasswordService = (
  config: EmailPasswordConfig = {},
): Effect.Effect<EmailPasswordServiceShape, never> => {
  const resolved = {
    disableSignUp: config.disableSignUp ?? false,
    requireEmailVerification: config.requireEmailVerification ?? false,
    minPasswordLength: config.minPasswordLength ?? 8,
    maxPasswordLength: config.maxPasswordLength ?? 128,
    autoSignIn: config.autoSignIn ?? true,
  };

  // Cached decoy hash — computed on first signIn call so that unknown-user
  // attempts always perform the same hashing work as known-user ones.
  let cachedDecoyHash: string | undefined;
  const getDecoyHash: Effect.Effect<string, Errors.HashingError, PasswordHasher> = Effect.gen(
    function* () {
      if (cachedDecoyHash !== undefined) return cachedDecoyHash;
      const hasher = yield* PasswordHasher;
      const result = yield* hasher.hash("effect-auth-decoy");
      cachedDecoyHash = result.hash;
      return cachedDecoyHash;
    },
  );

  return Effect.sync(
    (): EmailPasswordServiceShape => ({
      signUp: (rawInput) =>
        Effect.gen(function* () {
          const hooks = yield* Hooks;
          const input = yield* hooks.beforeSignUp(rawInput);

          if (resolved.disableSignUp) {
            return yield* Effect.fail(
              new Errors.SignUpDisabledError({
                message: "Email/password sign-up is disabled",
              }),
            );
          }

          const store = yield* EmailPasswordStore;
          const passwordHasher = yield* PasswordHasher;
          const sessionManager = yield* SessionService;

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

          const existing = yield* store.getUserByEmail(email);
          if (existing) {
            return yield* new Errors.EmailInUseError({
              message: "A user with this email already exists",
            });
          }

          const user = yield* store.createUser({
            email,
            ...(input.name !== undefined && { name: input.name }),
            ...(input.attributes !== undefined && { attributes: input.attributes }),
          });

          const hashedPassword = yield* passwordHasher.hash(input.password);
          yield* store.setPasswordHash(user.id, hashedPassword.hash);

          if (!resolved.autoSignIn) {
            return yield* hooks.afterSignUp({ user, method: "email-password" });
          }

          if (resolved.requireEmailVerification && !isEmailVerified(user)) {
            return yield* hooks.afterSignUp({ user, method: "email-password" });
          }

          const session = yield* sessionManager.createSession(user.id, input.sessionAttributes);
          const signUpResult = { user, session, method: "email-password" as const };

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

      signIn: (rawInput) =>
        Effect.gen(function* () {
          const hooks = yield* Hooks;
          const input = yield* hooks.beforeSignIn(rawInput);

          const store = yield* EmailPasswordStore;
          const passwordHasher = yield* PasswordHasher;
          const sessionManager = yield* SessionService;

          const email = normalizeEmail(input.email);
          if (!email) {
            return yield* Effect.fail(
              new Errors.InvalidCredentialsError({
                message: "Invalid email or password",
              }),
            );
          }

          const user = yield* store.getUserByEmail(email);
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

          if (resolved.requireEmailVerification && !isEmailVerified(user)) {
            return yield* Effect.fail(
              new Errors.EmailNotVerifiedError({
                message: "Email must be verified before sign-in",
                email,
              }),
            );
          }

          // Second factor: when a gate is present and required for this user,
          // return a challenge instead of a session.
          const gate = yield* Effect.serviceOption(SecondFactorGate);
          if (Option.isSome(gate) && (yield* gate.value.required(user))) {
            const secondFactor = yield* gate.value.begin(user);
            return yield* hooks.afterSignIn({ user, secondFactor, method: "email-password" });
          }

          const session = yield* sessionManager.createSession(user.id, input.sessionAttributes);
          const signInResult = {
            user,
            session,
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

      changePassword: (input) =>
        Effect.gen(function* () {
          const store = yield* EmailPasswordStore;
          const passwordHasher = yield* PasswordHasher;
          const sessionManager = yield* SessionService;

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

      setPassword: (userId, newPassword) =>
        Effect.gen(function* () {
          const store = yield* EmailPasswordStore;
          const passwordHasher = yield* PasswordHasher;

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
    }),
  );
};
