/**
 * Have I Been Pwned plugin: refuses a new password found in Pwned Passwords on
 * sign-up, reset, change and set, sending only the first five hex digits of its
 * SHA-1, with padding. When the API cannot answer, the password is allowed
 * unless `failClosed: true`.
 *
 * @module plugins/hibp
 */
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import { Digest } from "effect/crypto";
import { Hex } from "effect/encoding";
import { HttpClientRequest } from "effect/http";
import * as OutboundHttp from "../OutboundHttp.ts";
import type { SignUpInput } from "../email/EmailPassword.ts";
import {
  type ChangePasswordArgs,
  makePlugin,
  type ResetPasswordArgs,
  type SetPasswordArgs,
} from "../Hooks.ts";
import { AuthError, PwnedPasswordError } from "../Errors.ts";

/** Configuration for {@link HaveIBeenPwnedPlugin}. */
export interface HibpConfig {
  /** Reject when the breach count is at least this. Default 1. */
  readonly threshold?: number;
  /**
   * Reject (rather than allow) when the API cannot answer: a network error, a
   * non-2xx status, or no answer within `timeout`. Default false.
   */
  readonly failClosed?: boolean;
  /** How long to wait for the API before treating it as unavailable. Default 5 seconds. */
  readonly timeout?: Duration.Input;
}

const RANGE_URL = "https://api.pwnedpasswords.com/range";

/**
 * Build the HIBP plugin. The resulting layer is
 * `Layer<Hooks, never, Hooks | HttpClient | Digest.Digest>` — provide
 * `FetchHttpClient.layer` (or a stub) and a `Digest.Digest` layer to satisfy
 * the dependencies.
 */
export const HaveIBeenPwnedPlugin = (config: HibpConfig = {}) => {
  const threshold = config.threshold ?? 1;
  const failClosed = config.failClosed ?? false;
  const timeout = config.timeout ?? Duration.seconds(5);

  return makePlugin(
    Effect.gen(function* () {
      const outbound = yield* OutboundHttp.resolve();
      const digest = yield* Digest.Digest;

      const sha1Upper = (password: string): Effect.Effect<string> =>
        digest
          .digest(Digest.sha1, new TextEncoder().encode(password))
          .pipe(Effect.map((bytes) => Hex.encode(bytes).toUpperCase()));

      const breachCount = (password: string): Effect.Effect<number, AuthError> =>
        Effect.gen(function* () {
          const hash = yield* sha1Upper(password);
          const prefix = hash.slice(0, 5);
          const suffix = hash.slice(5);
          const request = HttpClientRequest.get(`${RANGE_URL}/${prefix}`).pipe(
            HttpClientRequest.setHeader("Add-Padding", "true"),
          );
          return yield* OutboundHttp.send(outbound.client, request, outbound.limits).pipe(
            // A 429, a 5xx or a challenge page has no suffix lines: read as
            // a count of 0 it would allow every password.
            Effect.filterOrFail(OutboundHttp.isOk),
            Effect.map((response) => response.body),
            Effect.timeout(timeout),
            Effect.map((body) =>
              Arr.findFirst(body.split("\n"), (line) => {
                const [suf, count] = line.trim().split(":");
                return suf === suffix ? Option.some(Number(count) || 0) : Option.none();
              }).pipe(Option.getOrElse(() => 0)),
            ),
            Effect.catch(() =>
              failClosed
                ? Effect.fail(new AuthError({ message: "Password breach check is unavailable" }))
                : Effect.succeed(0),
            ),
          );
        });

      const check = (password: string): Effect.Effect<void, AuthError | PwnedPasswordError> =>
        Effect.gen(function* () {
          const count = yield* breachCount(password);
          if (count >= threshold) {
            return yield* new PwnedPasswordError({
              message: "This password has appeared in a data breach; please choose another",
            });
          }
          return yield* Effect.void;
        });

      return {
        beforeSignUp: (input: SignUpInput) => check(input.password).pipe(Effect.as(input)),
        beforeResetPassword: (args: ResetPasswordArgs) =>
          check(args.newPassword).pipe(Effect.as(args)),
        beforeChangePassword: (args: ChangePasswordArgs) =>
          check(args.newPassword).pipe(Effect.as(args)),
        beforeSetPassword: (args: SetPasswordArgs) => check(args.newPassword).pipe(Effect.as(args)),
      };
    }),
  );
};
