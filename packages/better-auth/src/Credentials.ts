/**
 * A thin Effect wrapper over BetterAuth's own sign-up, sign-in and sign-out.
 * It promises nothing of the core's `AuthLifecycleService`: verification,
 * second factors and hooks are BetterAuth's.
 *
 * @since 0.1.0
 */
import { Context, Effect, Layer } from "effect";
import * as P from "effect/Predicate";
import * as Auth from "@thomasfosterau/effect-auth";
import { BetterAuthInstance, type SignInAnswer, type WithHeaders } from "./BetterAuth.ts";
import { type CredentialError, fromApiError, toUser } from "./Convert.ts";

/**
 * A sign-in or sign-up's answer, with the `Set-Cookie` lines BetterAuth set
 * (its signed session cookie, or the two-factor cookie) for the response:
 *
 * - `signed-in`: BetterAuth issued a session.
 * - `pending-verification`: a sign-up that issued no session, because
 *   BetterAuth waits for the email to be verified. Under
 *   `requireEmailVerification` BetterAuth answers a sign-up for a taken
 *   address the same way, so the answer reveals nothing.
 * - `second-factor`: a sign-in that BetterAuth's `twoFactor()` plugin holds
 *   for the second factor (`{ twoFactorRedirect: true }`); it carries no user.
 *
 * @since 0.1.0
 * @category models
 */
export type CredentialResult =
  | {
      readonly status: "signed-in" | "pending-verification";
      readonly user: Auth.User;
      readonly setCookie: ReadonlyArray<string>;
    }
  | { readonly status: "second-factor"; readonly setCookie: ReadonlyArray<string> };

/**
 * The inputs every call takes: the incoming request's headers, which
 * BetterAuth reads for the client's address, its rate limits and, on
 * sign-out, the session cookie.
 *
 * @since 0.1.0
 * @category models
 */
export interface RequestInput {
  readonly headers: Headers;
}

/**
 * BetterAuth's sign-up, sign-in and sign-out as Effects, with `APIError`
 * mapped into the typed error channel (`InvalidCredentialsError`,
 * `EmailInUseError`, `EmailNotVerifiedError`, else `AuthError`).
 *
 * @since 0.1.0
 * @category services
 */
export class BetterAuthCredentials extends Context.Service<
  BetterAuthCredentials,
  {
    readonly signUpEmail: (
      input: RequestInput & {
        readonly email: string;
        readonly password: string;
        readonly name: string;
      },
    ) => Effect.Effect<CredentialResult, CredentialError>;
    readonly signInEmail: (
      input: RequestInput & {
        readonly email: string;
        readonly password: string;
        readonly rememberMe?: boolean;
      },
    ) => Effect.Effect<CredentialResult, CredentialError>;
    /** Fails with `AuthError` when the instance has no `username()` plugin. */
    readonly signInUsername: (
      input: RequestInput & {
        readonly username: string;
        readonly password: string;
        readonly rememberMe?: boolean;
      },
    ) => Effect.Effect<CredentialResult, CredentialError>;
    /** Sign the request's session out; answers the lines that clear the cookies. */
    readonly signOut: (
      input: RequestInput,
    ) => Effect.Effect<ReadonlyArray<string>, CredentialError>;
  }
>()("@effect-auth/better-auth/BetterAuthCredentials") {
  static readonly layer: Layer.Layer<BetterAuthCredentials, never, BetterAuthInstance> =
    Layer.effect(
      BetterAuthCredentials,
      Effect.map(Effect.service(BetterAuthInstance), ({ api }) => {
        const call = <A>(run: () => Promise<A>, email?: string) =>
          Effect.tryPromise({ try: run, catch: (error) => fromApiError(error, email) });

        const signedIn = (
          answer: WithHeaders<SignInAnswer | null>,
        ): Effect.Effect<CredentialResult, Auth.AuthError> => {
          const setCookie = answer.headers.getSetCookie();
          const response: SignInAnswer | null = answer.response;
          if (response !== null && "twoFactorRedirect" in response) {
            return Effect.succeed({ status: "second-factor", setCookie });
          }
          if (response === null || !P.isObject(response.user)) {
            return Effect.fail(new Auth.AuthError({ message: "BetterAuth answered no user" }));
          }
          return Effect.succeed({
            status: response.token === null ? "pending-verification" : "signed-in",
            user: toUser(response.user),
            setCookie,
          });
        };

        return {
          signUpEmail: ({ headers, email, password, name }) =>
            Effect.flatMap(
              call(
                () =>
                  api.signUpEmail({
                    body: { email, password, name },
                    headers,
                    returnHeaders: true,
                  }),
                email,
              ),
              signedIn,
            ),

          signInEmail: ({ headers, email, password, rememberMe }) =>
            Effect.flatMap(
              call(
                () =>
                  api.signInEmail({
                    body: { email, password, ...(rememberMe !== undefined && { rememberMe }) },
                    headers,
                    returnHeaders: true,
                  }),
                email,
              ),
              signedIn,
            ),

          signInUsername: ({ headers, username, password, rememberMe }) => {
            const signIn = api.signInUsername?.bind(api);
            if (signIn === undefined) {
              return Effect.fail(
                new Auth.AuthError({
                  message: "signInUsername needs BetterAuth's username() plugin",
                }),
              );
            }
            return Effect.flatMap(
              call(() =>
                signIn({
                  body: { username, password, ...(rememberMe !== undefined && { rememberMe }) },
                  headers,
                  returnHeaders: true,
                }),
              ),
              signedIn,
            );
          },

          signOut: ({ headers }) =>
            Effect.map(
              call(() => api.signOut({ headers, returnHeaders: true })),
              (answer) => answer.headers.getSetCookie(),
            ),
        };
      }),
    );
}
