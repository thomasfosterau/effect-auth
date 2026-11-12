/**
 * Captcha plugin (transform hook with short-circuit).
 *
 * Verifies a captcha token against the provider's siteverify endpoint on
 * `beforeSignUp` and on `beforeAuthenticate` for the password sign-in
 * methods (`"email-password"` and `"username"`), and short-circuits with
 * `CaptchaError` when the token is missing or verification fails. The token
 * is read from the optional `captchaToken` field on `SignUpInput`,
 * `SignInInput` and `UsernameSignInInput` (wired through the `SignUpPayload`
 * HTTP schema and the `password` and `username` sign-in credentials). The
 * one-time-code, magic-link and second-factor flows carry no captcha token,
 * so the `"signIn"` endpoint does not guard them.
 *
 * Supports Cloudflare Turnstile, Google reCAPTCHA and hCaptcha (all expose a
 * compatible `{ secret, response }` siteverify returning `{ success }`).
 *
 * @module plugins/captcha
 */
import { Effect, Redacted } from "effect";
import * as Arr from "effect/Array";
import * as P from "effect/Predicate";
import { HttpClient, HttpClientRequest } from "effect/http";
import type { SignUpInput } from "../email/EmailPassword.ts";
import { type AuthenticateAttempt, makePlugin, type PluginImpls } from "../Hooks.ts";
import { CaptchaError } from "../Errors.ts";

/** The captcha services {@link CaptchaPlugin} can verify tokens with. */
export type CaptchaProvider = "cloudflare-turnstile" | "google-recaptcha" | "hcaptcha";

/**
 * Which auth endpoints the captcha guards: `"signUp"` (`beforeSignUp`) and
 * `"signIn"` (`beforeAuthenticate` for the password methods, by email or by
 * username).
 */
export type CaptchaEndpoint = "signUp" | "signIn";

/** Whether an attempt is a password sign-in, the attempts a captcha token rides on. */
const isPasswordSignIn = (attempt: AuthenticateAttempt): boolean =>
  attempt.method === "email-password" || attempt.method === "username";

const VERIFY_URLS: Record<CaptchaProvider, string> = {
  "cloudflare-turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
  "google-recaptcha": "https://www.google.com/recaptcha/api/siteverify",
  hcaptcha: "https://hcaptcha.com/siteverify",
};

/** Configuration for {@link CaptchaPlugin}. */
export interface CaptchaConfig {
  readonly provider: CaptchaProvider;
  readonly secretKey: Redacted.Redacted;
  /** Endpoints to guard. Default `["signUp", "signIn"]`. */
  readonly endpoints?: readonly CaptchaEndpoint[];
}

/**
 * Build the captcha plugin. The resulting layer is
 * `Layer<Hooks, never, Hooks | HttpClient>` — provide `FetchHttpClient.layer`
 * (or a stub) to satisfy the client.
 */
export const CaptchaPlugin = (config: CaptchaConfig) => {
  const endpoints: readonly CaptchaEndpoint[] = config.endpoints ?? ["signUp", "signIn"];
  const url = VERIFY_URLS[config.provider];

  return makePlugin(
    Effect.gen(function* () {
      const client = yield* HttpClient.HttpClient;

      const verify = (token: string | undefined): Effect.Effect<void, CaptchaError> =>
        Effect.gen(function* () {
          if (token === undefined || token === "") {
            return yield* new CaptchaError({ message: "Captcha verification failed" });
          }
          const success = yield* client
            .execute(
              HttpClientRequest.post(url).pipe(
                HttpClientRequest.bodyUrlParams({
                  secret: Redacted.value(config.secretKey),
                  response: token,
                }),
              ),
            )
            .pipe(
              Effect.flatMap((response) => response.json),
              Effect.map((body) => P.hasProperty(body, "success") && body.success === true),
              Effect.catch(() => Effect.succeed(false)),
            );
          if (!success) {
            return yield* new CaptchaError({ message: "Captcha verification failed" });
          }
          return yield* Effect.void;
        });

      const impls: PluginImpls = {
        ...(Arr.contains(endpoints, "signUp") && {
          beforeSignUp: (input: SignUpInput) => verify(input.captchaToken).pipe(Effect.as(input)),
        }),
        ...(Arr.contains(endpoints, "signIn") && {
          beforeAuthenticate: (attempt: AuthenticateAttempt) =>
            isPasswordSignIn(attempt)
              ? verify(attempt.captchaToken).pipe(Effect.as(attempt))
              : Effect.succeed(attempt),
        }),
      };
      return impls;
    }),
  );
};
