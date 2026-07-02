import { Context, Effect, Layer, Option } from "effect";
import * as Errors from "./Errors.js";
import { Hooks, type HookError } from "./Hooks.js";
import { PasswordHasherTag } from "./Password.js";
import type * as Types from "./Types.js";
import { SessionManagerTag } from "./Session.js";

export interface CreateUserInput {
  readonly email: string;
  readonly name?: string;
  readonly image?: string;
  readonly attributes?: Record<string, unknown>;
}

export interface EmailPasswordStore {
  readonly getUserByEmail: (email: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

  readonly createUser: (input: CreateUserInput) => Effect.Effect<Types.User, Errors.AuthError>;

  readonly getPasswordHash: (userId: string) => Effect.Effect<string | null, Errors.AuthError>;

  readonly setPasswordHash: (userId: string, hash: string) => Effect.Effect<void, Errors.AuthError>;
}

export class EmailPasswordStoreTag extends Context.Service<
  EmailPasswordStoreTag,
  EmailPasswordStore
>()("@effect-auth/EmailPasswordStore") {}

export const EmailPasswordStore = EmailPasswordStoreTag;

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
}

export interface SignInInput {
  readonly email: string;
  readonly password: string;
  readonly sessionAttributes?: Record<string, unknown>;
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
export interface SecondFactorGate {
  readonly required: (user: Types.User) => Effect.Effect<boolean, Errors.AuthError>;
  readonly begin: (user: Types.User) => Effect.Effect<SecondFactorChallenge, Errors.AuthError>;
}

export class SecondFactorGateTag extends Context.Service<SecondFactorGateTag, SecondFactorGate>()(
  "@effect-auth/SecondFactorGate",
) {}

export const SecondFactorGate = SecondFactorGateTag;

export interface AuthResult {
  readonly user: Types.User;
  readonly session?: Types.Session;
  /** Present when a second factor is required to complete sign-in. */
  readonly secondFactor?: SecondFactorChallenge;
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

export interface EmailPasswordService {
  readonly signUp: (
    input: SignUpInput,
  ) => Effect.Effect<
    AuthResult,
    Errors.AuthError | Errors.HashingError | Errors.EmailNotVerifiedError | HookError,
    EmailPasswordStoreTag | PasswordHasherTag | SessionManagerTag | Hooks
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
    EmailPasswordStoreTag | PasswordHasherTag | SessionManagerTag | Hooks
  >;

  /**
   * Change the password of a user that already has one, verifying the current
   * password first. Optionally revokes the user's other sessions.
   */
  readonly changePassword: (
    input: ChangePasswordInput,
  ) => Effect.Effect<
    void,
    Errors.InvalidCredentialsError | Errors.HashingError | Errors.AuthError,
    EmailPasswordStoreTag | PasswordHasherTag | SessionManagerTag
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
    Errors.HashingError | Errors.AuthError,
    EmailPasswordStoreTag | PasswordHasherTag
  >;
}

export class EmailPasswordServiceTag extends Context.Service<
  EmailPasswordServiceTag,
  EmailPasswordService
>()("@effect-auth/EmailPasswordService") {}

export const EmailPasswordService = EmailPasswordServiceTag;

const isEmailVerified = (user: Types.User): boolean => user.emailVerified;

const normalizeEmail = (email: string): string => email.trim().toLowerCase();

const validatePasswordLength = (
  password: string,
  config: Required<Pick<EmailPasswordConfig, "minPasswordLength" | "maxPasswordLength">>,
): Effect.Effect<void, Errors.AuthError> =>
  Effect.gen(function* () {
    if (password.length < config.minPasswordLength) {
      return yield* Effect.fail(
        new Errors.AuthError({
          message: `Password must be at least ${config.minPasswordLength} characters`,
        }),
      );
    }

    if (password.length > config.maxPasswordLength) {
      return yield* Effect.fail(
        new Errors.AuthError({
          message: `Password must be at most ${config.maxPasswordLength} characters`,
        }),
      );
    }
  });

export const makeEmailPasswordService = (
  config: EmailPasswordConfig = {},
): Effect.Effect<EmailPasswordService, never> => {
  const resolved = {
    disableSignUp: config.disableSignUp ?? false,
    requireEmailVerification: config.requireEmailVerification ?? false,
    minPasswordLength: config.minPasswordLength ?? 8,
    maxPasswordLength: config.maxPasswordLength ?? 128,
    autoSignIn: config.autoSignIn ?? true,
  };

  return Effect.sync(
    (): EmailPasswordService => ({
      signUp: (rawInput) =>
        Effect.gen(function* () {
          const hooks = yield* Hooks;
          const input = yield* hooks.beforeSignUp(rawInput);

          if (resolved.disableSignUp) {
            return yield* Effect.fail(
              new Errors.AuthError({
                message: "Email/password sign-up is disabled",
              }),
            );
          }

          const store = yield* EmailPasswordStoreTag;
          const passwordHasher = yield* PasswordHasherTag;
          const sessionManager = yield* SessionManagerTag;

          const email = normalizeEmail(input.email);
          if (!email) {
            return yield* Effect.fail(
              new Errors.AuthError({
                message: "Email is required",
              }),
            );
          }

          yield* validatePasswordLength(input.password, {
            minPasswordLength: resolved.minPasswordLength,
            maxPasswordLength: resolved.maxPasswordLength,
          });

          const existing = yield* store.getUserByEmail(email);
          if (existing) {
            return yield* Effect.fail(
              new Errors.AuthError({
                message: "A user with this email already exists",
              }),
            );
          }

          const user = yield* store.createUser({
            email,
            ...(input.name !== undefined && { name: input.name }),
            ...(input.attributes !== undefined && { attributes: input.attributes }),
          });

          const hashedPassword = yield* passwordHasher.hash(input.password);
          yield* store.setPasswordHash(user.id, hashedPassword.hash);

          if (!resolved.autoSignIn) {
            return yield* hooks.afterSignUp({ user });
          }

          if (resolved.requireEmailVerification && !isEmailVerified(user)) {
            return yield* hooks.afterSignUp({ user });
          }

          const session = yield* sessionManager.createSession(user.id, input.sessionAttributes);

          return yield* hooks.afterSignUp({ user, session });
        }),

      signIn: (rawInput) =>
        Effect.gen(function* () {
          const hooks = yield* Hooks;
          const input = yield* hooks.beforeSignIn(rawInput);

          const store = yield* EmailPasswordStoreTag;
          const passwordHasher = yield* PasswordHasherTag;
          const sessionManager = yield* SessionManagerTag;

          const email = normalizeEmail(input.email);
          if (!email) {
            return yield* Effect.fail(
              new Errors.InvalidCredentialsError({
                message: "Invalid email or password",
              }),
            );
          }

          const user = yield* store.getUserByEmail(email);
          if (!user) {
            return yield* Effect.fail(
              new Errors.InvalidCredentialsError({
                message: "Invalid email or password",
              }),
            );
          }

          const passwordHash = yield* store.getPasswordHash(user.id);
          if (!passwordHash) {
            return yield* Effect.fail(
              new Errors.InvalidCredentialsError({
                message: "Invalid email or password",
              }),
            );
          }

          const isValid = yield* passwordHasher.verify(input.password, passwordHash);
          if (!isValid) {
            return yield* Effect.fail(
              new Errors.InvalidCredentialsError({
                message: "Invalid email or password",
              }),
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
          const gate = yield* Effect.serviceOption(SecondFactorGateTag);
          if (Option.isSome(gate) && (yield* gate.value.required(user))) {
            const secondFactor = yield* gate.value.begin(user);
            return yield* hooks.afterSignIn({ user, secondFactor });
          }

          const session = yield* sessionManager.createSession(user.id, input.sessionAttributes);

          return yield* hooks.afterSignIn({ user, session });
        }),

      changePassword: (input) =>
        Effect.gen(function* () {
          const store = yield* EmailPasswordStoreTag;
          const passwordHasher = yield* PasswordHasherTag;
          const sessionManager = yield* SessionManagerTag;

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
          const store = yield* EmailPasswordStoreTag;
          const passwordHasher = yield* PasswordHasherTag;

          yield* validatePasswordLength(newPassword, {
            minPasswordLength: resolved.minPasswordLength,
            maxPasswordLength: resolved.maxPasswordLength,
          });

          const currentHash = yield* store.getPasswordHash(userId);
          if (currentHash) {
            return yield* new Errors.AuthError({
              message: "User already has a password; use changePassword instead",
            });
          }

          const hashedPassword = yield* passwordHasher.hash(newPassword);
          yield* store.setPasswordHash(userId, hashedPassword.hash);
        }),
    }),
  );
};

export const EmailPasswordServiceLayer = (config: EmailPasswordConfig = {}) =>
  Layer.effect(EmailPasswordServiceTag, makeEmailPasswordService(config));
