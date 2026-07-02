/**
 * Username authentication: sign in with a username + password instead of an
 * email.
 *
 * Username is a first-class *lookup key* but not a first-class `User` field —
 * implementers store it in `attributes.username` (normalized lowercase for
 * case-insensitive uniqueness). Sign-up validates + reserves the username then
 * delegates credential creation to {@link EmailPasswordServiceTag}; sign-in
 * resolves the user by username and verifies the password with the same
 * anti-enumeration error and the same `SecondFactorGate` seam as email/password
 * sign-in.
 */
import { Context, Data, Effect, Layer, Option } from "effect";
import * as Errors from "./Errors.js";
import type * as Types from "./Types.js";
import {
  EmailPasswordServiceTag,
  EmailPasswordStoreTag,
  SecondFactorGateTag,
  type AuthResult,
} from "./EmailPassword.js";
import { PasswordHasherTag } from "./Password.js";
import { SessionManagerTag } from "./Session.js";
import { Hooks, type HookError } from "./Hooks.js";

/** Raised for invalid or already-taken usernames. */
export class UsernameError extends Data.TaggedError("UsernameError")<{
  readonly message: string;
}> {}

/**
 * Username lookup / reservation. Keys are the normalized (trimmed, lowercased)
 * username; implementers persist it in `attributes.username`.
 */
export interface UsernameStore {
  readonly getUserByUsername: (
    username: string,
  ) => Effect.Effect<Types.User | null, Errors.AuthError>;
  readonly isUsernameTaken: (username: string) => Effect.Effect<boolean, Errors.AuthError>;
  readonly setUsername: (userId: string, username: string) => Effect.Effect<void, Errors.AuthError>;
}

export class UsernameStoreTag extends Context.Service<UsernameStoreTag, UsernameStore>()(
  "@effect-auth/UsernameStore",
) {}

export const UsernameStore = UsernameStoreTag;

export interface UsernameConfig {
  /** Minimum username length. Default 3. */
  readonly minUsernameLength?: number;
  /** Maximum username length. Default 30. */
  readonly maxUsernameLength?: number;
  /**
   * Extra validation beyond the default charset (`[a-zA-Z0-9_.]`) and length.
   * Runs on the raw (pre-normalized) username.
   */
  readonly usernameValidator?: (username: string) => Effect.Effect<void, UsernameError>;
}

export interface UsernameSignUpInput {
  readonly username: string;
  readonly email: string;
  readonly password: string;
  readonly name?: string;
  readonly attributes?: Record<string, unknown>;
  readonly sessionAttributes?: Record<string, unknown>;
}

export interface UsernameSignInInput {
  readonly username: string;
  readonly password: string;
  readonly sessionAttributes?: Record<string, unknown>;
}

export interface UsernameService {
  readonly signUp: (
    input: UsernameSignUpInput,
  ) => Effect.Effect<
    AuthResult,
    | UsernameError
    | Errors.AuthError
    | Errors.HashingError
    | Errors.EmailNotVerifiedError
    | HookError,
    | UsernameStoreTag
    | EmailPasswordServiceTag
    | EmailPasswordStoreTag
    | PasswordHasherTag
    | SessionManagerTag
    | Hooks
  >;

  readonly signIn: (
    input: UsernameSignInInput,
  ) => Effect.Effect<
    AuthResult,
    | UsernameError
    | Errors.InvalidCredentialsError
    | Errors.HashingError
    | Errors.AuthError
    | HookError,
    UsernameStoreTag | EmailPasswordStoreTag | PasswordHasherTag | SessionManagerTag | Hooks
  >;

  readonly updateUsername: (
    userId: string,
    username: string,
  ) => Effect.Effect<void, UsernameError | Errors.AuthError, UsernameStoreTag>;
}

export class UsernameServiceTag extends Context.Service<UsernameServiceTag, UsernameService>()(
  "@effect-auth/UsernameService",
) {}

export const UsernameService = UsernameServiceTag;

const normalizeUsername = (username: string): string => username.trim().toLowerCase();

const DEFAULT_CHARSET = /^[a-zA-Z0-9_.]+$/;

export const makeUsernameService = (
  config: UsernameConfig = {},
): Effect.Effect<UsernameService, never> =>
  Effect.sync((): UsernameService => {
    const minLength = config.minUsernameLength ?? 3;
    const maxLength = config.maxUsernameLength ?? 30;

    const validate = (raw: string): Effect.Effect<string, UsernameError> =>
      Effect.gen(function* () {
        const trimmed = raw.trim();
        if (trimmed.length < minLength || trimmed.length > maxLength) {
          return yield* new UsernameError({
            message: `Username must be between ${minLength} and ${maxLength} characters`,
          });
        }
        if (!DEFAULT_CHARSET.test(trimmed)) {
          return yield* new UsernameError({
            message: "Username may only contain letters, numbers, '_' and '.'",
          });
        }
        if (config.usernameValidator !== undefined) {
          yield* config.usernameValidator(trimmed);
        }
        return normalizeUsername(trimmed);
      });

    return {
      signUp: (input) =>
        Effect.gen(function* () {
          const store = yield* UsernameStoreTag;
          const emailPassword = yield* EmailPasswordServiceTag;

          const username = yield* validate(input.username);

          if (yield* store.isUsernameTaken(username)) {
            return yield* new UsernameError({ message: "Username is already taken" });
          }

          const result = yield* emailPassword.signUp({
            email: input.email,
            password: input.password,
            ...(input.name !== undefined && { name: input.name }),
            ...(input.attributes !== undefined && { attributes: input.attributes }),
            ...(input.sessionAttributes !== undefined && {
              sessionAttributes: input.sessionAttributes,
            }),
          });

          yield* store.setUsername(result.user.id, username);

          // Reflect the reserved username on the returned user.
          return {
            ...result,
            user: {
              ...result.user,
              attributes: { ...result.user.attributes, username },
            },
          };
        }),

      signIn: (input) =>
        Effect.gen(function* () {
          const hooks = yield* Hooks;
          const store = yield* UsernameStoreTag;
          const emailPasswordStore = yield* EmailPasswordStoreTag;
          const passwordHasher = yield* PasswordHasherTag;
          const sessionManager = yield* SessionManagerTag;

          const invalid = () =>
            Effect.fail(
              new Errors.InvalidCredentialsError({ message: "Invalid username or password" }),
            );

          const username = normalizeUsername(input.username);
          if (!username) {
            return yield* invalid();
          }

          const user = yield* store.getUserByUsername(username);
          if (!user) {
            return yield* invalid();
          }

          const passwordHash = yield* emailPasswordStore.getPasswordHash(user.id);
          if (!passwordHash) {
            return yield* invalid();
          }

          const isValid = yield* passwordHasher.verify(input.password, passwordHash);
          if (!isValid) {
            return yield* invalid();
          }

          // Same second-factor seam as email/password sign-in.
          const gate = yield* Effect.serviceOption(SecondFactorGateTag);
          if (Option.isSome(gate) && (yield* gate.value.required(user))) {
            const secondFactor = yield* gate.value.begin(user);
            return yield* hooks.afterSignIn({ user, secondFactor, method: "username" });
          }

          const session = yield* sessionManager.createSession(user.id, input.sessionAttributes);
          return yield* hooks.afterSignIn({ user, session, method: "username" });
        }),

      updateUsername: (userId, rawUsername) =>
        Effect.gen(function* () {
          const store = yield* UsernameStoreTag;
          const username = yield* validate(rawUsername);

          const existing = yield* store.getUserByUsername(username);
          if (existing !== null && existing.id !== userId) {
            return yield* new UsernameError({ message: "Username is already taken" });
          }

          yield* store.setUsername(userId, username);
        }),
    };
  });

export const UsernameServiceLayer = (config?: UsernameConfig) =>
  Layer.effect(UsernameServiceTag, makeUsernameService(config));
