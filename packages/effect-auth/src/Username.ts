/**
 * Username sign-in: usernames are `username` identifiers, normalized to
 * lowercase. Sign-up reserves one, then delegates to {@link
 * EmailPasswordService}; sign-in resolves it and verifies the password with
 * email sign-in's error, `beforeAuthenticate` hook and `SecondFactorGate`.
 */
import * as Context from "effect/Context";
import * as Schema from "effect/Schema";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import { guardCurrentSession } from "./Impersonation.ts";
import * as Option from "effect/Option";
import * as Arr from "effect/Array";
import * as Errors from "./Errors.ts";
import {
  answeredByStandIn,
  EmailPasswordService,
  EmailPasswordStore,
  secondFactorChallenge,
  type AuthResult,
} from "./email/EmailPassword.ts";
import * as Identifier from "./Identifier.ts";
import { UserStore } from "./UserStore.ts";
import { PasswordHasher } from "./password/Password.ts";
import { lazyDecoyHash, verifyPasswordOrDecoy } from "./password/DecoyVerify.ts";
import { normalizeUsername } from "./Normalize.ts";
import { SessionService } from "./SessionService.ts";
import { Hooks, type HookError } from "./Hooks.ts";
import type * as Types from "./Types.ts";
import { definedKeys } from "./DefinedKeys.ts";

/** Raised for invalid or already-taken usernames. */
export class UsernameError extends Schema.TaggedError<
  UsernameError,
  { readonly brand: unique symbol }
>()("UsernameError", {
  message: Schema.String,
}) {}

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
  readonly attributes?: Types.Attributes;
  readonly sessionAttributes?: Types.Attributes;
}

/** Input to {@link UsernameService.signIn}. */
export interface UsernameSignInInput {
  readonly username: string;
  readonly password: string;
  readonly sessionAttributes?: Types.Attributes;
  /** Optional captcha token, consumed by the `CaptchaPlugin` on the `beforeAuthenticate` hook. */
  readonly captchaToken?: string;
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
    ) => Effect.Effect<void, UsernameError | Errors.AuthError | Errors.ImpersonationForbiddenError>;
  }
>()("@effect-auth/UsernameService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (config: UsernameConfig = {}) =>
    Layer.effect(UsernameService, make(config));
}

const DEFAULT_CHARSET = /^[a-zA-Z0-9_.]+$/;

const invalid = () =>
  Effect.fail(new Errors.InvalidCredentialsError({ message: "Invalid username or password" }));

const make = (
  config: UsernameConfig = {},
): Effect.Effect<
  typeof UsernameService.Service,
  never,
  | Identifier.IdentifierStore
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

    const identifiers = yield* Identifier.IdentifierStore;
    const users = yield* UserStore;
    const emailPassword = yield* EmailPasswordService;
    const emailPasswordStore = yield* EmailPasswordStore;
    const passwordHasher = yield* PasswordHasher;
    const sessionManager = yield* SessionService;
    const hooks = yield* Hooks;

    // Cached decoy hash — computed on first signIn call so that unknown-username
    // attempts always perform the same hashing work as known-username ones.
    const getDecoyHash = lazyDecoyHash(passwordHasher, "UsernameService.getDecoyHash");

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

        if (Option.isSome(yield* Identifier.lookupIdentifier(identifiers, "username", username))) {
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
          if (
            Option.isSome(yield* Identifier.lookupIdentifier(identifiers, "username", username))
          ) {
            return yield* new UsernameError({ message: "Username is already taken" });
          }
          return result;
        }

        // Usernames carry no external proof-of-ownership, so the identifier
        // is created verified.
        const now = yield* DateTime.nowAsDate;
        yield* Identifier.claimIdentifier(
          identifiers,
          Identifier.makeIdentifier({
            userId: result.user.id,
            type: "username",
            value: username,
            verified: true,
            now,
          }),
        ).pipe(
          Effect.catchTags({
            IdentifierTakenError: () =>
              Effect.fail(new UsernameError({ message: "Username is already taken" })),
            IdentifierRefusedError: (error) => Effect.fail(Identifier.refusalAuthError(error)),
          }),
        );

        return result;
      }),

      signIn: Effect.fn("UsernameService.signIn")(function* (input: UsernameSignInInput) {
        const username = normalizeUsername(input.username);
        if (!username) {
          return yield* invalid();
        }

        const identifier = yield* Identifier.lookupIdentifier(identifiers, "username", username);
        const found = Option.isNone(identifier)
          ? Option.none<Types.User>()
          : yield* users.get(identifier.value.userId);
        // The same gate as email and password sign-in: lockout, rate limits
        // and captcha key on the resolved user.
        yield* hooks.beforeAuthenticate(
          definedKeys({
            method: "username",
            identifier: { type: "username", value: username },
            userId: Option.getOrUndefined(Option.map(found, (user) => user.id)),
            captchaToken: input.captchaToken,
          }),
        );
        const passwordHash = Option.isSome(found)
          ? yield* emailPasswordStore.getPasswordHash(found.value.id)
          : Option.none<string>();
        // Always verify against a real or decoy hash so timing is constant
        // regardless of whether the account exists.
        const isValid = yield* verifyPasswordOrDecoy(
          passwordHasher,
          input.password,
          passwordHash,
          getDecoyHash,
        );
        if (Option.isNone(found) || Option.isNone(passwordHash) || !isValid) {
          return yield* invalid();
        }
        const user = found.value;

        if (requireEmailVerification) {
          const userIdentifiers = yield* identifiers.listByUser(user.id);
          if (Option.isNone(Identifier.primaryEmail(userIdentifiers))) {
            return yield* new Errors.EmailNotVerifiedError({
              message: "Email must be verified before sign-in",
              email: Option.getOrElse(Identifier.anyEmailValue(userIdentifiers), () => ""),
            });
          }
        }

        const handle = { type: "username" as const, value: username };

        // Silently upgrade the stored hash when the current hasher considers it outdated.
        if (passwordHasher.needsRehash?.(passwordHash.value)) {
          yield* passwordHasher.hash(input.password).pipe(
            Effect.flatMap((newHash) => emailPasswordStore.setPasswordHash(user.id, newHash.hash)),
            Effect.ignore,
          );
        }

        // Same second-factor seam as email/password sign-in.
        const secondFactor = yield* secondFactorChallenge(user, "username");
        if (secondFactor !== undefined) {
          return yield* hooks.afterSignIn({
            user,
            secondFactor,
            identifier: handle,
            method: "username",
          });
        }

        const { session, token } = yield* sessionManager.createSession(
          user.id,
          input.sessionAttributes,
        );
        return yield* hooks.afterSignIn({
          user,
          session,
          token,
          identifier: handle,
          method: "username",
          ...(input.rememberMe !== undefined && { rememberMe: input.rememberMe }),
        });
      }),

      updateUsername: Effect.fn("UsernameService.updateUsername")(function* (
        userId: string,
        rawUsername: string,
      ) {
        yield* guardCurrentSession;
        const username = yield* validate(rawUsername);

        const existing = yield* Identifier.lookupIdentifier(identifiers, "username", username);
        if (Option.exists(existing, (held) => held.userId !== userId)) {
          return yield* new UsernameError({ message: "Username is already taken" });
        }
        if (Option.isSome(existing)) {
          return yield* Effect.void; // Already this user's username.
        }

        // Replace any previous username identifier, then claim the new one.
        const current = yield* identifiers.listByUser(userId);
        yield* Effect.forEach(
          Arr.filter(current, (id) => id.type === "username"),
          (id) => identifiers.delete(id.id),
          { concurrency: 1, discard: true },
        );
        const now = yield* DateTime.nowAsDate;
        return yield* Identifier.claimIdentifier(
          identifiers,
          Identifier.makeIdentifier({
            userId,
            type: "username",
            value: username,
            verified: true,
            now,
          }),
        ).pipe(
          Effect.catchTags({
            IdentifierTakenError: () =>
              Effect.fail(new UsernameError({ message: "Username is already taken" })),
            IdentifierRefusedError: (error) => Effect.fail(Identifier.refusalAuthError(error)),
          }),
          Effect.asVoid,
        );
      }),
    };
  });
