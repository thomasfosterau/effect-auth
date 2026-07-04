/**
 * Username authentication: sign in with a username + password instead of an
 * email.
 *
 * Username is a first-class *lookup key* but not a first-class `User` field —
 * implementers store it in `attributes.username` (normalized lowercase for
 * case-insensitive uniqueness). Sign-up validates + reserves the username then
 * delegates credential creation to {@link EmailPasswordService}; sign-in
 * resolves the user by username and verifies the password with the same
 * anti-enumeration error and the same `SecondFactorGate` seam as email/password
 * sign-in.
 */
import { Context, Data, Effect, Layer, Option } from "effect";
import * as Errors from "./Errors.js";
import type * as Types from "./Types.js";
import {
  EmailPasswordService,
  EmailPasswordStore,
  SecondFactorGate,
  isEmailVerified,
  type AuthResult,
} from "./EmailPassword.js";
import { MultiAlgorithmVerifier, PasswordHasher } from "./Password.js";
import { SessionManager } from "./Session.js";
import { Hooks, type HookError } from "./Hooks.js";

/** Raised for invalid or already-taken usernames. */
export class UsernameError extends Data.TaggedError("UsernameError")<{
  readonly message: string;
}> {}

/**
 * Username lookup / reservation. Keys are the normalized (trimmed, lowercased)
 * username; implementers persist it in `attributes.username`.
 */
export interface UsernameStoreShape {
  readonly getUserByUsername: (
    username: string,
  ) => Effect.Effect<Types.User | null, Errors.AuthError>;
  readonly isUsernameTaken: (username: string) => Effect.Effect<boolean, Errors.AuthError>;
  readonly setUsername: (userId: string, username: string) => Effect.Effect<void, Errors.AuthError>;
}

export class UsernameStore extends Context.Service<UsernameStore, UsernameStoreShape>()(
  "@effect-auth/UsernameStore",
) {}

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
  /**
   * When true, sign-in is blocked until the user's email address has been
   * verified. Mirrors the same policy on EmailPasswordConfig. Default false.
   */
  readonly requireEmailVerification?: boolean;
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

export interface UsernameServiceShape {
  readonly signUp: (
    input: UsernameSignUpInput,
  ) => Effect.Effect<
    AuthResult,
    | UsernameError
    | Errors.AuthError
    | Errors.EmailInUseError
    | Errors.HashingError
    | Errors.EmailNotVerifiedError
    | Errors.PasswordPolicyError
    | Errors.SignUpDisabledError
    | Errors.InvalidInputError
    | HookError,
    | UsernameStore
    | EmailPasswordService
    | EmailPasswordStore
    | PasswordHasher
    | SessionManager
    | Hooks
  >;

  readonly signIn: (
    input: UsernameSignInInput,
  ) => Effect.Effect<
    AuthResult,
    | UsernameError
    | Errors.InvalidCredentialsError
    | Errors.EmailNotVerifiedError
    | Errors.HashingError
    | Errors.AuthError
    | HookError,
    UsernameStore | EmailPasswordStore | PasswordHasher | SessionManager | Hooks
  >;

  readonly updateUsername: (
    userId: string,
    username: string,
  ) => Effect.Effect<void, UsernameError | Errors.AuthError, UsernameStore>;
}

export class UsernameService extends Context.Service<UsernameService, UsernameServiceShape>()(
  "@effect-auth/UsernameService",
) {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: UsernameConfig = {}) =>
    Layer.effect(UsernameService, makeUsernameService(config));
}

const normalizeUsername = (username: string): string => username.trim().toLowerCase();

const DEFAULT_CHARSET = /^[a-zA-Z0-9_.]+$/;

export const makeUsernameService = (
  config: UsernameConfig = {},
): Effect.Effect<UsernameServiceShape, never> =>
  Effect.sync((): UsernameServiceShape => {
    const minLength = config.minUsernameLength ?? 3;
    const maxLength = config.maxUsernameLength ?? 30;
    const requireEmailVerification = config.requireEmailVerification ?? false;

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
          const store = yield* UsernameStore;
          const emailPassword = yield* EmailPasswordService;

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
          const store = yield* UsernameStore;
          const emailPasswordStore = yield* EmailPasswordStore;
          const passwordHasher = yield* PasswordHasher;
          const sessionManager = yield* SessionManager;

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

          // Route through MultiAlgorithmVerifier when present (migration support).
          // Convert HashingError (format/algorithm mismatch) → invalid credentials.
          const multiVerifier = yield* Effect.serviceOption(MultiAlgorithmVerifier);
          const verifyEffect = Option.isSome(multiVerifier)
            ? multiVerifier.value.verify(input.password, passwordHash)
            : passwordHasher.verify(input.password, passwordHash);
          const isValid = yield* verifyEffect.pipe(
            Effect.catchTag("HashingError", () => Effect.succeed(false)),
          );
          if (!isValid) {
            return yield* invalid();
          }

          if (requireEmailVerification && !isEmailVerified(user)) {
            return yield* Effect.fail(
              new Errors.EmailNotVerifiedError({
                message: "Email must be verified before sign-in",
                email: user.email,
              }),
            );
          }

          // Silently upgrade the stored hash when the current hasher considers it outdated.
          if (passwordHasher.needsRehash?.(passwordHash)) {
            yield* passwordHasher.hash(input.password).pipe(
              Effect.flatMap((newHash) =>
                emailPasswordStore.setPasswordHash(user.id, newHash.hash),
              ),
              Effect.ignore,
            );
          }

          // Same second-factor seam as email/password sign-in.
          const gate = yield* Effect.serviceOption(SecondFactorGate);
          if (Option.isSome(gate) && (yield* gate.value.required(user))) {
            const secondFactor = yield* gate.value.begin(user);
            return yield* hooks.afterSignIn({ user, secondFactor, method: "username" });
          }

          const session = yield* sessionManager.createSession(user.id, input.sessionAttributes);
          return yield* hooks.afterSignIn({ user, session, method: "username" });
        }),

      updateUsername: (userId, rawUsername) =>
        Effect.gen(function* () {
          const store = yield* UsernameStore;
          const username = yield* validate(rawUsername);

          const existing = yield* store.getUserByUsername(username);
          if (existing !== null && existing.id !== userId) {
            return yield* new UsernameError({ message: "Username is already taken" });
          }

          yield* store.setUsername(userId, username);
        }),
    };
  });
