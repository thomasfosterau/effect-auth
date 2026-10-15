/**
 * Username authentication: sign in with a username + password instead of an
 * email.
 *
 * Usernames are `Identifier` records (`type: "username"`, normalized lowercase
 * for case-insensitive uniqueness) — there is no bespoke username store.
 * Sign-up validates + reserves the username then delegates credential
 * creation to {@link EmailPasswordService}; sign-in resolves the user by
 * username identifier and verifies the password with the same
 * anti-enumeration error and the same `SecondFactorGate` seam as
 * email/password sign-in.
 */
import { Context, Data, Effect, Layer, Option } from "effect";
import * as Errors from "./Errors.ts";
import {
  answeredByStandIn,
  EmailPasswordService,
  EmailPasswordStore,
  SecondFactorGate,
  type AuthResult,
} from "./email/EmailPassword.ts";
import {
  anyEmailValue,
  claimIdentifier,
  IdentifierStore,
  makeIdentifier,
  primaryEmail,
} from "./Identifier.ts";
import { UserStore } from "./UserStore.ts";
import { MultiAlgorithmVerifier, PasswordHasher } from "./password/Password.ts";
import { SessionService } from "./SessionService.ts";
import { Hooks, type HookError } from "./Hooks.ts";

/** Raised for invalid or already-taken usernames. */
export class UsernameError extends Data.TaggedError("UsernameError")<{
  readonly message: string;
}> {}

/** Configuration for {@link UsernameService}. */
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

/** Input to {@link UsernameService.signUp}. */
export interface UsernameSignUpInput {
  readonly username: string;
  readonly email: string;
  readonly password: string;
  readonly name?: string;
  readonly attributes?: Record<string, unknown>;
  readonly sessionAttributes?: Record<string, unknown>;
}

/** Input to {@link UsernameService.signIn}. */
export interface UsernameSignInInput {
  readonly username: string;
  readonly password: string;
  readonly sessionAttributes?: Record<string, unknown>;
  /**
   * When `false`, the session cookie is emitted without `Max-Age`/`Expires`
   * (a browser-session cookie). See `SignInInput.rememberMe` for details.
   */
  readonly rememberMe?: boolean;
}

/**
 * Sign-up and sign-in by username and password. Usernames are unique case-insensitively, and sign-in honours the multi-factor gate.
 *
 * Requires `EmailPasswordService`, `EmailPasswordStore`, `PasswordHasher`, `UserStore`, `IdentifierStore`, `SessionService` and `Hooks`.
 */
export class UsernameService extends Context.Service<
  UsernameService,
  {
    /**
     * Sign up with a username, email and password. A username already taken
     * fails with `UsernameError` before anything else runs, so a username's
     * availability is public. The rest is {@link EmailPasswordService}
     * `signUp`, and the username is then claimed for the new user.
     *
     * Under `antiEnumeration` (on `EmailPasswordConfig`), a sign-up whose email
     * another user holds gets the same answer as a fresh one, but its
     * username is not claimed: the answer's user is a stand-in that no row
     * backs, so the username stays free for a real sign-up rather than being
     * held by a user that doesn't exist. It still fails with `UsernameError`
     * if someone holds the username by then, as the claim would. A later
     * request can tell the two apart, since only a fresh sign-up's username
     * is taken afterwards.
     */
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
      | HookError
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
      | HookError
    >;

    readonly updateUsername: (
      userId: string,
      username: string,
    ) => Effect.Effect<void, UsernameError | Errors.AuthError>;
  }
>()("@effect-auth/UsernameService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: UsernameConfig = {}) =>
    Layer.effect(UsernameService, make(config));
}

const normalizeUsername = (username: string): string => username.trim().toLowerCase();

const DEFAULT_CHARSET = /^[a-zA-Z0-9_.]+$/;

export const make = (
  config: UsernameConfig = {},
): Effect.Effect<
  typeof UsernameService.Service,
  never,
  | IdentifierStore
  | UserStore
  | EmailPasswordService
  | EmailPasswordStore
  | PasswordHasher
  | SessionService
  | Hooks
> =>
  Effect.gen(function* () {
    const minLength = config.minUsernameLength ?? 3;
    const maxLength = config.maxUsernameLength ?? 30;
    const requireEmailVerification = config.requireEmailVerification ?? false;

    const identifiers = yield* IdentifierStore;
    const users = yield* UserStore;
    const emailPassword = yield* EmailPasswordService;
    const emailPasswordStore = yield* EmailPasswordStore;
    const passwordHasher = yield* PasswordHasher;
    const sessionManager = yield* SessionService;
    const hooks = yield* Hooks;

    // Cached decoy hash — computed on first signIn call so that unknown-username
    // attempts always perform the same hashing work as known-username ones.
    let cachedDecoyHash: string | undefined;
    const getDecoyHash: Effect.Effect<string, Errors.HashingError> = Effect.gen(function* () {
      if (cachedDecoyHash !== undefined) return cachedDecoyHash;
      const result = yield* passwordHasher.hash("effect-auth-decoy");
      cachedDecoyHash = result.hash;
      return cachedDecoyHash;
    });

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
      signUp: Effect.fn("UsernameService.signUp")(function* (input: UsernameSignUpInput) {
        const username = yield* validate(input.username);

        if ((yield* identifiers.getByValue("username", username)) !== null) {
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

        // Under anti-enumeration, an address another user holds gets a
        // stand-in user no row backs. Claiming the username for it would squat
        // the username on a user that doesn't exist, so the claim is skipped;
        // the availability check stands in for the claim's own failure.
        // `answeredByStandIn` asks the stores which answer this is; without
        // its user-store fallback, an identifier store whose reads lag would
        // silently leave a fresh sign-up's username unclaimed.
        const standIn = yield* answeredByStandIn(identifiers, users, result, input.email);
        if (standIn) {
          if ((yield* identifiers.getByValue("username", username)) !== null) {
            return yield* new UsernameError({ message: "Username is already taken" });
          }
          return result;
        }

        // Usernames carry no external proof-of-ownership, so the identifier
        // is created verified.
        yield* claimIdentifier(
          identifiers,
          makeIdentifier({
            userId: result.user.id,
            type: "username",
            value: username,
            verified: true,
          }),
        ).pipe(
          Effect.catchTag("IdentifierTakenError", () =>
            Effect.fail(new UsernameError({ message: "Username is already taken" })),
          ),
        );

        return result;
      }),

      signIn: Effect.fn("UsernameService.signIn")(function* (input: UsernameSignInInput) {
        const invalid = () =>
          Effect.fail(
            new Errors.InvalidCredentialsError({ message: "Invalid username or password" }),
          );

        const username = normalizeUsername(input.username);
        if (!username) {
          return yield* invalid();
        }

        const identifier = yield* identifiers.getByValue("username", username);
        const user = identifier === null ? null : yield* users.get(identifier.userId);
        const passwordHash =
          user !== null ? yield* emailPasswordStore.getPasswordHash(user.id) : null;
        // Always verify against a real or decoy hash so timing is constant
        // regardless of whether the account exists.  Route through
        // MultiAlgorithmVerifier when present so that a hasher switch does not
        // lock out existing users.
        const hashToVerify = passwordHash ?? (yield* getDecoyHash);
        const multiVerifier = yield* Effect.serviceOption(MultiAlgorithmVerifier);
        const verifyEffect = Option.isSome(multiVerifier)
          ? multiVerifier.value.verify(input.password, hashToVerify)
          : passwordHasher.verify(input.password, hashToVerify);
        const isValid = yield* verifyEffect.pipe(
          Effect.catchTag("HashingError", () => Effect.succeed(false)),
        );
        if (user === null || passwordHash === null || !isValid) {
          return yield* invalid();
        }

        if (requireEmailVerification) {
          const userIdentifiers = yield* identifiers.listByUser(user.id);
          if (primaryEmail(userIdentifiers) === null) {
            return yield* new Errors.EmailNotVerifiedError({
              message: "Email must be verified before sign-in",
              email: anyEmailValue(userIdentifiers) ?? "",
            });
          }
        }

        const handle = { type: "username" as const, value: username };

        // Silently upgrade the stored hash when the current hasher considers it outdated.
        if (passwordHasher.needsRehash?.(passwordHash!)) {
          yield* passwordHasher.hash(input.password).pipe(
            Effect.flatMap((newHash) => emailPasswordStore.setPasswordHash(user.id, newHash.hash)),
            Effect.ignore,
          );
        }

        // Same second-factor seam as email/password sign-in.
        const gate = yield* Effect.serviceOption(SecondFactorGate);
        if (Option.isSome(gate) && (yield* gate.value.required(user))) {
          const secondFactor = yield* gate.value.begin(user);
          return yield* hooks.afterSignIn({
            user,
            secondFactor,
            identifier: handle,
            method: "username",
          });
        }

        const session = yield* sessionManager.createSession(user.id, input.sessionAttributes);
        return yield* hooks.afterSignIn({
          user,
          session,
          identifier: handle,
          method: "username",
          ...(input.rememberMe !== undefined && { rememberMe: input.rememberMe }),
        });
      }),

      updateUsername: Effect.fn("UsernameService.updateUsername")(function* (
        userId: string,
        rawUsername: string,
      ) {
        const username = yield* validate(rawUsername);

        const existing = yield* identifiers.getByValue("username", username);
        if (existing !== null && existing.userId !== userId) {
          return yield* new UsernameError({ message: "Username is already taken" });
        }
        if (existing !== null) {
          return; // Already this user's username.
        }

        // Replace any previous username identifier, then claim the new one.
        const current = yield* identifiers.listByUser(userId);
        for (const id of current) {
          if (id.type === "username") {
            yield* identifiers.delete(id.id);
          }
        }
        yield* claimIdentifier(
          identifiers,
          makeIdentifier({ userId, type: "username", value: username, verified: true }),
        ).pipe(
          Effect.catchTag("IdentifierTakenError", () =>
            Effect.fail(new UsernameError({ message: "Username is already taken" })),
          ),
        );
      }),
    };
  });
