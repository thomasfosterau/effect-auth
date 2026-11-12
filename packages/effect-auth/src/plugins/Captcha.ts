/**
 * Captcha plugin (transform hook with short-circuit).
 *
 * Verifies a captcha token against the provider's siteverify endpoint and
 * short-circuits with `CaptchaError` when the token is missing or
 * verification fails, on three endpoints:
 *
 * - `"signUp"`: `beforeSignUp`, the token from `SignUpInput.captchaToken`
 *   (the `SignUpPayload` HTTP schema).
 * - `"signIn"`: `beforeAuthenticate` for the password sign-in methods
 *   (`"email-password"` and `"username"`), the token from
 *   `SignInInput.captchaToken` / `UsernameSignInInput.captchaToken` (the
 *   `password` and `username` sign-in credentials).
 * - `"sendCode"` (#678): `beforeSendCode`, every send of an email or SMS
 *   one-time code and of a magic link, the token from the send's
 *   `SendCodeOptions.captchaToken` (the `captchaToken` attribute of
 *   `POST /otp-challenges`). A send is the step that costs money, so it is
 *   where the captcha guards the passwordless flows; verifying a code or a
 *   link carries no token.
 *
 * Second-factor redemption carries no token: only someone who passed the
 * first factor reaches it.
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
import {
  type AuthenticateAttempt,
  makePlugin,
  type PluginImpls,
  type SendCodeAttempt,
} from "../Hooks.ts";
import { CaptchaError } from "../Errors.ts";

/** The captcha services {@link CaptchaPlugin} can verify tokens with. */
export type CaptchaProvider = "cloudflare-turnstile" | "google-recaptcha" | "hcaptcha";

/**
 * Which auth endpoints the captcha guards: `"signUp"` (`beforeSignUp`),
 * `"signIn"` (`beforeAuthenticate` for the password methods, by email or by
 * username) and `"sendCode"` (`beforeSendCode`: every one-time-code and
 * magic-link send).
 */
export type CaptchaEndpoint = "signUp" | "signIn" | "sendCode";

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
  /** Endpoints to guard. Default `["signUp", "signIn", "sendCode"]`. */
  readonly endpoints?: readonly CaptchaEndpoint[];
}

/**
 * Build the captcha plugin. The resulting layer is
 * `Layer<Hooks, never, Hooks | HttpClient>` — provide `FetchHttpClient.layer`
 * (or a stub) to satisfy the client.
 */
export const CaptchaPlugin = (config: CaptchaConfig) => {
  const endpoints: readonly CaptchaEndpoint[] = config.endpoints ?? [
    "signUp",
    "signIn",
    "sendCode",
  ];
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
        ...(Arr.contains(endpoints, "sendCode") && {
          beforeSendCode: (attempt: SendCodeAttempt) =>
            verify(attempt.captchaToken).pipe(Effect.as(attempt)),
        }),
      };
      return impls;
    }),
  );
};
