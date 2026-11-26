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
 * - `"sendCode"`: `beforeSendCode`, every send of an email or SMS
 *   one-time code, of a magic link and of a password-reset link, the token
 *   from the send's `SendCodeOptions.captchaToken` (the `captchaToken`
 *   attribute of `POST /otp-challenges` and `POST /password-resets`). A send
 *   is the step that costs money, so it is where the captcha guards the
 *   passwordless flows; verifying a code or a link carries no token.
 *
 * Second-factor redemption carries no token: only someone who passed the
 * first factor reaches it.
 *
 * Supports Cloudflare Turnstile, Google reCAPTCHA and hCaptcha (all expose a
 * compatible `{ secret, response }` siteverify returning `{ success }`). The
 * client address, when the request has one, goes along as `remoteip`.
 *
 * `success: true` only says the token is genuine, so the plugin can also
 * check what the token was minted for: `expectedHostname`, `expectedAction`
 * and `minScore`. reCAPTCHA v3 answers `success: true` for every genuine
 * token, bots included, and leaves the verdict to `score`, so a
 * `recaptchaVersion: 3` configuration without `minScore` is refused when the
 * layer is built, and a token carrying a `score` that no `minScore` judges is
 * refused at verification.
 *
 * @module plugins/captcha
 */
import { Data, Effect, Redacted } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import { HttpClient, HttpClientRequest } from "effect/http";
import { ClientIP } from "../ClientIP.ts";
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
 * username) and `"sendCode"` (`beforeSendCode`: every one-time-code,
 * magic-link and password-reset send).
 */
export type CaptchaEndpoint = "signUp" | "signIn" | "sendCode";

/**
 * A `CaptchaPlugin` configuration that cannot protect anything: reCAPTCHA v3
 * with no `minScore`, or a `minScore` outside 0 to 1. The layer build dies
 * with it, so the app fails to start.
 *
 * @since 0.9.0
 */
export class CaptchaConfigError extends Data.TaggedError("CaptchaConfigError")<{
  readonly message: string;
}> {}

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
  /**
   * The reCAPTCHA version the site key is for (`provider: "google-recaptcha"`
   * only). Version `3` requires {@link minScore}. Default `2`.
   */
  readonly recaptchaVersion?: 2 | 3 | undefined;
  /**
   * The lowest `score` (0 to 1) a token may carry. A token whose answer has
   * no numeric `score` is refused. Required for reCAPTCHA v3; for hCaptcha
   * it needs an Enterprise account, which returns a score.
   */
  readonly minScore?: number | undefined;
  /**
   * The hostname (or hostnames) the token must have been solved on: the
   * answer's `hostname`. Set it when other sites share the site key.
   */
  readonly expectedHostname?: string | ReadonlyArray<string> | undefined;
  /**
   * The action the token must have been minted for: the answer's `action`
   * (Turnstile's `action`, reCAPTCHA v3's `action`). One string for every
   * guarded endpoint, or one per endpoint; an endpoint with none is not
   * checked.
   */
  readonly expectedAction?: string | Partial<Record<CaptchaEndpoint, string>> | undefined;
}

/** Why `config` cannot protect anything, or `undefined` when it can. */
const configProblem = (config: CaptchaConfig): string | undefined => {
  if (
    config.minScore !== undefined &&
    !(Number.isFinite(config.minScore) && config.minScore >= 0 && config.minScore <= 1)
  ) {
    return `CaptchaPlugin: minScore must be a number from 0 to 1, got ${String(config.minScore)}`;
  }
  if (
    config.provider === "google-recaptcha" &&
    config.recaptchaVersion === 3 &&
    config.minScore === undefined
  ) {
    return (
      "CaptchaPlugin: reCAPTCHA v3 answers success: true for every genuine token, bots included, " +
      "so it needs a minScore (for example 0.5) to refuse anything"
    );
  }
  return undefined;
};

/** The action `endpoint`'s tokens must carry, if one is configured. */
const actionFor = (config: CaptchaConfig, endpoint: CaptchaEndpoint): string | undefined =>
  P.isString(config.expectedAction) ? config.expectedAction : config.expectedAction?.[endpoint];

/**
 * The siteverify answer fields the checks read. Every provider answers
 * `success`; `hostname`, `action` and `score` are there when the provider
 * and the key type carry them. Other fields are ignored.
 */
const SiteverifyAnswer = Schema.Struct({
  success: Schema.Boolean,
  hostname: Schema.optional(Schema.String),
  action: Schema.optional(Schema.String),
  score: Schema.optional(Schema.Number),
});

const decodeAnswer = Schema.decodeUnknownEffect(SiteverifyAnswer);

/**
 * Whether a decoded siteverify answer passes every configured check:
 * `success`, then the hostname, the action and the score. A `score` with no
 * `minScore` to judge it fails, since it means a score-based token
 * (reCAPTCHA v3) whose `success` alone proves nothing.
 */
const accepts = (
  config: CaptchaConfig,
  endpoint: CaptchaEndpoint,
  answer: typeof SiteverifyAnswer.Type,
): boolean => {
  if (!answer.success) return false;
  if (config.expectedHostname !== undefined) {
    const hostnames = Arr.ensure(config.expectedHostname);
    if (answer.hostname === undefined || !Arr.contains(hostnames, answer.hostname)) return false;
  }
  const action = actionFor(config, endpoint);
  if (action !== undefined && answer.action !== action) return false;
  return config.minScore === undefined
    ? answer.score === undefined
    : answer.score !== undefined && answer.score >= config.minScore;
};

/**
 * Build the captcha plugin. The resulting layer is
 * `Layer<Hooks, never, Hooks | HttpClient>` — provide `FetchHttpClient.layer`
 * (or a stub) to satisfy the client. Its build dies with
 * {@link CaptchaConfigError} for a configuration that cannot protect anything.
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
      const problem = configProblem(config);
      if (problem !== undefined) {
        return yield* Effect.die(new CaptchaConfigError({ message: problem }));
      }
      const client = yield* HttpClient.HttpClient;

      const verify = (
        endpoint: CaptchaEndpoint,
        token: string | undefined,
      ): Effect.Effect<void, CaptchaError> =>
        Effect.gen(function* () {
          if (token === undefined || token === "") {
            return yield* new CaptchaError({ message: "Captcha verification failed" });
          }
          const clientIp = yield* Effect.serviceOption(ClientIP);
          const remoteip = Option.isSome(clientIp) ? clientIp.value.ip : undefined;
          const passed = yield* client
            .execute(
              HttpClientRequest.post(url).pipe(
                HttpClientRequest.bodyUrlParams({
                  secret: Redacted.value(config.secretKey),
                  response: token,
                  ...(remoteip !== undefined && { remoteip }),
                }),
              ),
            )
            .pipe(
              Effect.flatMap((response) => response.json),
              // An answer that does not decode fails, like any other failure.
              Effect.flatMap(decodeAnswer),
              Effect.map((answer) => accepts(config, endpoint, answer)),
              Effect.catch(() => Effect.succeed(false)),
            );
          if (!passed) {
            return yield* new CaptchaError({ message: "Captcha verification failed" });
          }
          return yield* Effect.void;
        });

      const impls: PluginImpls = {
        ...(Arr.contains(endpoints, "signUp") && {
          beforeSignUp: (input: SignUpInput) =>
            verify("signUp", input.captchaToken).pipe(Effect.as(input)),
        }),
        ...(Arr.contains(endpoints, "signIn") && {
          beforeAuthenticate: (attempt: AuthenticateAttempt) =>
            isPasswordSignIn(attempt)
              ? verify("signIn", attempt.captchaToken).pipe(Effect.as(attempt))
              : Effect.succeed(attempt),
        }),
        ...(Arr.contains(endpoints, "sendCode") && {
          beforeSendCode: (attempt: SendCodeAttempt) =>
            verify("sendCode", attempt.captchaToken).pipe(Effect.as(attempt)),
        }),
      };
      return impls;
    }),
  );
};
