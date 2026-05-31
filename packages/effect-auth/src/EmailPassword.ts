import { Context, Effect, Layer } from "effect";
import * as Errors from "./Errors.js";
import { Hooks, type HookError } from "./Hooks.js";
import { PasswordHasherTag } from "./Password.js";
import type * as Types from "./Types.js";
import { SessionManagerTag } from "./Session.js";

export interface CreateUserInput {
  readonly email: string;
  readonly name?: string;
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

export interface AuthResult {
  readonly user: Types.User;
  readonly session?: Types.Session;
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
}

export class EmailPasswordServiceTag extends Context.Service<
  EmailPasswordServiceTag,
  EmailPasswordService
>()("@effect-auth/EmailPasswordService") {}

export const EmailPasswordService = EmailPasswordServiceTag;

const isEmailVerified = (user: Types.User): boolean => user.attributes.emailVerified === true;

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
            attributes: {
              email,
              ...(input.name !== undefined && { name: input.name }),
              ...input.attributes,
            },
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

          const session = yield* sessionManager.createSession(user.id, input.sessionAttributes);

          return yield* hooks.afterSignIn({ user, session });
        }),
    }),
  );
};

export const EmailPasswordServiceLayer = (config: EmailPasswordConfig = {}) =>
  Layer.effect(EmailPasswordServiceTag, makeEmailPasswordService(config));
