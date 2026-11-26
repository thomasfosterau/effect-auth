/**
 * Email and password over WorkOS: sign-up creates the WorkOS user, sign-in is
 * the `password` grant, and the session is the sealed cookie
 * (`WorkOSSessions.issue`). The core's hooks run at the core's points, so the
 * abuse plugins keep guarding sign-in. Also the `AuthLifecycleService` the
 * HTTP tier signs in through, and the `PasswordHasher` it requires, which
 * refuses: WorkOS holds every password.
 *
 * @since 0.1.0
 */
import { Effect, Layer } from "effect";
import * as HashSet from "effect/HashSet";
import * as Option from "effect/Option";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import { Base64Url } from "effect/encoding";
import * as Auth from "@thomasfosterau/effect-auth";
import { WorkOSAuthenticate, WorkOSSessions } from "./Session.ts";
import { WireUser } from "./Schemas.ts";
import { toUser } from "./Users.ts";
import { toAuthError, unsupported, WorkOSClient, path, type WorkOSError } from "./WorkOS.ts";

/** The WorkOS `code`s a password sign-in can stop at, which v1 does not continue. */
const UNSUPPORTED_STEPS = HashSet.make(
  "mfa_enrollment",
  "mfa_challenge",
  "mfa_verification",
  "organization_selection_required",
  "sso_required",
  "radar_email_challenge",
  "radar_sms_challenge",
);

/**
 * The error a refused password grant maps to.
 *
 * @internal
 */
export const passwordGrantError = (
  email: string,
  error: WorkOSError,
): Auth.InvalidCredentialsError | Auth.EmailNotVerifiedError | Auth.AuthError => {
  if (error.code === "email_verification_required") {
    return new Auth.EmailNotVerifiedError({ message: "Email not verified", email });
  }
  if (error.code !== undefined && HashSet.has(UNSUPPORTED_STEPS, error.code)) {
    // TODO(#900): WorkOS MFA, organization selection and Radar challenges are
    // phase 2; until then the app keeps them off in the WorkOS dashboard.
    return new Auth.AuthError({
      message: `WorkOS asked for a step this backend does not support (${error.code})`,
      cause: error,
    });
  }
  if (error.status >= 400 && error.status < 500 && error.status !== 429) {
    return new Auth.InvalidCredentialsError({ message: "Invalid email or password" });
  }
  return toAuthError(error);
};

const splitName = (name: string | undefined) => {
  if (name === undefined) return {};
  const [first, ...rest] = name.trim().split(/\s+/);
  return { first_name: first ?? "", last_name: rest.join(" ") };
};

/** The error a refused user creation maps to. */
const signUpError = (
  error: WorkOSError,
): Auth.EmailInUseError | Auth.InvalidInputError | Auth.AuthError => {
  const code = error.code ?? "";
  // TODO(#900): these codes are not in the WorkOS SDK's source; check them
  // against the API's answers before the package is published.
  if (error.status === 409 || code.includes("email_not_available") || code.includes("exist")) {
    return new Auth.EmailInUseError({ message: "Email already in use" });
  }
  if (code.includes("password")) {
    return new Auth.InvalidInputError({
      message: "The password does not meet the WorkOS password policy",
      field: "password",
    });
  }
  if (error.status === 400 || error.status === 422) {
    return new Auth.InvalidInputError({ message: "WorkOS refused the sign-up", field: "email" });
  }
  return toAuthError(error);
};

/** Read the `sid` of an access token without verifying it: only to revoke a session we just made. */
const decodeSid = Schema.decodeUnknownOption(
  Schema.fromJsonString(Schema.Struct({ sid: Schema.String })),
);
const unverifiedSessionId = (accessToken: string): string | undefined => {
  const bytes = Result.getOrUndefined(Base64Url.decode(accessToken.split(".")[1] ?? ""));
  if (bytes === undefined) return undefined;
  return Option.getOrUndefined(decodeSid(new TextDecoder().decode(bytes)))?.sid;
};

/**
 * The core `EmailPasswordService` over WorkOS.
 *
 * `setPassword` and `clearPassword` are refused: WorkOS does not tell
 * whether a user has a password, so neither could keep the core's rule that
 * an existing password is changed only with the current one. A sign-up's
 * `attributes` are not stored (WorkOS has no attribute bag; write `metadata`
 * through `UserService.updateUserAttributes`).
 *
 * @since 0.1.0
 * @category layers
 */
export const emailPasswordLayer: Layer.Layer<
  Auth.Email.EmailPasswordService,
  never,
  WorkOSClient | WorkOSSessions | WorkOSAuthenticate | Auth.SessionService | Auth.Hooks
> = Layer.effect(
  Auth.Email.EmailPasswordService,
  Effect.gen(function* () {
    const workos = yield* WorkOSClient;
    const sessions = yield* WorkOSSessions;
    const { authenticate, revoke } = yield* WorkOSAuthenticate;
    const sessionService = yield* Auth.SessionService;
    const hooks = yield* Auth.Hooks;

    const passwordGrant = (email: string, password: string) =>
      authenticate({ grant_type: "password", email, password }).pipe(
        Effect.mapError((error) => passwordGrantError(email, error)),
      );

    const signIn = Effect.fn("WorkOS.EmailPassword.signIn")(function* (
      raw: Auth.Email.SignInInput,
    ) {
      const input = yield* hooks.beforeSignIn(raw);
      const email = Auth.normalizeEmail(input.email);
      yield* hooks.beforeAuthenticate({
        method: "email-password",
        identifier: { type: "email", value: email },
        captchaToken: input.captchaToken,
      });
      const auth = yield* passwordGrant(email, input.password);
      const issued = yield* sessions.issue(auth, input.sessionAttributes);
      return yield* hooks.afterSignIn({
        user: issued.user,
        identifier: { type: "email", value: email },
        session: issued.session,
        token: issued.token,
        method: "email-password",
        ...(input.rememberMe !== undefined && { rememberMe: input.rememberMe }),
      });
    });

    const signUp = Effect.fn("WorkOS.EmailPassword.signUp")(function* (
      raw: Auth.Email.SignUpInput,
    ) {
      const input = yield* hooks.beforeSignUp(raw);
      const email = Auth.normalizeEmail(input.email);
      if (email === "") {
        return yield* new Auth.InvalidInputError({ message: "Email is required", field: "email" });
      }
      const created = yield* workos
        .request({
          method: "POST",
          path: "/user_management/users",
          route: "/user_management/users",
          body: { email, password: input.password, ...splitName(input.name) },
          schema: WireUser,
        })
        .pipe(Effect.mapError(signUpError));
      const identifier = { type: "email" as const, value: email };
      const auth = yield* authenticate({
        grant_type: "password",
        email,
        password: input.password,
      }).pipe(
        Effect.map(Option.some),
        // A sign-up that still needs its address verified is a success without
        // a session; WorkOS has emailed the code.
        Effect.catchTag("WorkOSError", (error) =>
          error.code === "email_verification_required"
            ? Effect.succeedNone
            : Effect.fail(toAuthError(error)),
        ),
      );
      if (Option.isNone(auth)) {
        return yield* hooks.afterSignUp({
          user: toUser(created),
          identifier,
          method: "email-password",
        });
      }
      const issued = yield* sessions.issue(auth.value, input.sessionAttributes);
      return yield* hooks.afterSignUp({
        user: issued.user,
        identifier,
        session: issued.session,
        token: issued.token,
        method: "email-password",
      });
    });

    return Auth.Email.EmailPasswordService.of({
      signIn,
      signUp,
      changePassword: Effect.fn("WorkOS.EmailPassword.changePassword")(function* (
        input: Auth.Email.ChangePasswordInput,
      ) {
        const user = yield* workos
          .request({
            method: "GET",
            path: path`/user_management/users/${input.userId}`,
            route: "/user_management/users/{id}",
            schema: WireUser,
          })
          .pipe(Effect.mapError(toAuthError));
        // Proving the current password signs in once; that session is ended
        // straight away.
        const probe = yield* passwordGrant(user.email, input.currentPassword).pipe(
          Effect.catchTag("EmailNotVerifiedError", () =>
            Effect.fail(new Auth.InvalidCredentialsError({ message: "Invalid password" })),
          ),
        );
        const probeId = unverifiedSessionId(probe.access_token);
        if (probeId !== undefined) yield* revoke(probeId);
        const { newPassword } = yield* hooks.beforeChangePassword({
          userId: input.userId,
          newPassword: input.newPassword,
        });
        yield* workos
          .request({
            method: "PUT",
            path: path`/user_management/users/${input.userId}`,
            route: "/user_management/users/{id}",
            body: { password: newPassword },
          })
          .pipe(Effect.mapError(toAuthError));
        if (input.revokeOtherSessions !== false) {
          yield* input.currentSessionId === undefined
            ? sessionService.invalidateUserSessions(input.userId)
            : sessionService.revokeOtherSessions(input.userId, input.currentSessionId);
        }
      }),
      setPassword: () => Effect.fail(unsupported("EmailPasswordService.setPassword")),
      clearPassword: () => Effect.fail(unsupported("EmailPasswordService.clearPassword")),
    });
  }),
);

/**
 * The core `AuthLifecycleService` over this package's email and password and
 * email verification. A sign-up whose address WorkOS requires verified
 * answers `needsEmailVerification: true` and no session; WorkOS has emailed
 * the code. `verifyEmail` takes `<userId>:<code>` (see
 * {@link EmailVerification}) and signs nobody in: the user signs in again.
 *
 * @since 0.1.0
 * @category layers
 */
export const authLifecycleLayer: Layer.Layer<
  Auth.AuthLifecycleService,
  never,
  Auth.Email.EmailPasswordService | Auth.Email.EmailVerificationService | Auth.UserStore
> = Layer.effect(
  Auth.AuthLifecycleService,
  Effect.gen(function* () {
    const emailPassword = yield* Auth.Email.EmailPasswordService;
    const verification = yield* Auth.Email.EmailVerificationService;
    const users = yield* Auth.UserStore;
    const answer = (result: Auth.Email.AuthResult): Auth.AuthLifecycleResult => ({
      user: result.user,
      ...(result.identifier !== undefined && { identifier: result.identifier }),
      ...(result.session !== undefined && { session: result.session, token: result.token }),
      ...(result.rememberMe !== undefined && { rememberMe: result.rememberMe }),
      needsEmailVerification: result.session === undefined,
    });
    return Auth.AuthLifecycleService.of({
      signUp: (input) => Effect.map(emailPassword.signUp(input), answer),
      signIn: (input) =>
        emailPassword.signIn(input).pipe(
          Effect.map(answer),
          Effect.catchTag("EmailNotVerifiedError", () =>
            Effect.fail(
              new Auth.EmailVerificationError({
                message: "Verify your email address, then sign in",
              }),
            ),
          ),
        ),
      verifyEmail: Effect.fn("WorkOS.AuthLifecycle.verifyEmail")(function* (
        input: Auth.VerifyEmailInput,
      ) {
        const result = yield* verification.verifyToken(input.token);
        const user = yield* users.get(result.userId);
        if (user === null) {
          return yield* new Auth.UserNotFoundError({
            message: "User not found",
            userId: result.userId,
          });
        }
        return { user, needsEmailVerification: false };
      }),
    });
  }),
);

/**
 * The `PasswordHasher` the HTTP tier requires. WorkOS hashes and checks every
 * password, so nothing here should reach it; a call fails rather than hash a
 * password the backend would never read.
 *
 * @since 0.1.0
 * @category layers
 */
export const refusingHasherLayer: Layer.Layer<Auth.Password.PasswordHasher> = Layer.succeed(
  Auth.Password.PasswordHasher,
  {
    algorithm: "workos",
    hash: () => Effect.fail(new Auth.HashingError({ message: "Passwords are held by WorkOS" })),
    verify: () => Effect.fail(new Auth.HashingError({ message: "Passwords are held by WorkOS" })),
  },
);
