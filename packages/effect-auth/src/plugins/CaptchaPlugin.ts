/**
 * Captcha plugin (transform hook with short-circuit).
 *
 * Verifies a captcha token against the provider's siteverify endpoint on
 * `beforeSignUp` / `beforeSignIn` and short-circuits with `AuthError` when the
 * token is missing or verification fails. The token is read from the optional
 * `captchaToken` field on `SignUpInput` / `SignInInput` (wired through the
 * `SignUpPayload` / `SignInPayload` HTTP schemas).
 *
 * Supports Cloudflare Turnstile, Google reCAPTCHA and hCaptcha (all expose a
 * compatible `{ secret, response }` siteverify returning `{ success }`).
 *
 * @module plugins/captcha
 */
import { Effect, Redacted } from "effect";
import { HttpClient, HttpClientRequest } from "effect/unstable/http";
import type { SignInInput, SignUpInput } from "../EmailPassword.js";
import { makePlugin, type PluginImpls } from "../Hooks.js";
import { AuthError } from "../Errors.js";

export type CaptchaProvider = "cloudflare-turnstile" | "google-recaptcha" | "hcaptcha";

/** Which auth endpoints the captcha guards. */
export type CaptchaEndpoint = "signUp" | "signIn";

const VERIFY_URLS: Record<CaptchaProvider, string> = {
  "cloudflare-turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
  "google-recaptcha": "https://www.google.com/recaptcha/api/siteverify",
  hcaptcha: "https://hcaptcha.com/siteverify",
};

export interface CaptchaConfig {
  readonly provider: CaptchaProvider;
  readonly secretKey: Redacted.Redacted<string>;
  /** Endpoints to guard. Default `["signUp", "signIn"]`. */
  readonly endpoints?: readonly CaptchaEndpoint[];
}

/**
 * Build the captcha plugin. The resulting layer is
 * `Layer<Hooks, never, Hooks | HttpClient>` — provide `FetchHttpClient.layer`
 * (or a stub) to satisfy the client.
 */
export const CaptchaPlugin = (config: CaptchaConfig) => {
  const endpoints = new Set<CaptchaEndpoint>(config.endpoints ?? ["signUp", "signIn"]);
  const url = VERIFY_URLS[config.provider];

  return makePlugin(
    Effect.gen(function* () {
      const client = yield* HttpClient.HttpClient;

      const verify = (token: string | undefined): Effect.Effect<void, AuthError> =>
        Effect.gen(function* () {
          if (token === undefined || token === "") {
            return yield* Effect.fail(new AuthError({ message: "captcha verification failed" }));
          }
          const success = yield* client
            .execute(
              HttpClientRequest.post(url, {
                urlParams: { secret: Redacted.value(config.secretKey), response: token },
              }),
            )
            .pipe(
              Effect.flatMap((response) => response.json),
              Effect.map((body) => (body as { success?: boolean }).success === true),
              Effect.catch(() => Effect.succeed(false)),
            );
          if (!success) {
            return yield* Effect.fail(new AuthError({ message: "captcha verification failed" }));
          }
        });

      const impls: PluginImpls = {
        ...(endpoints.has("signUp") && {
          beforeSignUp: (input: SignUpInput) => verify(input.captchaToken).pipe(Effect.as(input)),
        }),
        ...(endpoints.has("signIn") && {
          beforeSignIn: (input: SignInInput) => verify(input.captchaToken).pipe(Effect.as(input)),
        }),
      };
      return impls;
    }),
  );
};
