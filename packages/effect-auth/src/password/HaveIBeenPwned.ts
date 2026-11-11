/**
 * Have I Been Pwned plugin (transform hook with short-circuit).
 *
 * Rejects passwords that appear in the Pwned Passwords dataset using the
 * k-anonymity range API: the password is SHA-1 hashed, only the first 5 hex
 * characters are sent, and the returned suffix list is checked locally (the
 * full password/hash never leaves the process). Covers `beforeSignUp` and
 * `beforeResetPassword` (both carry the plaintext new password).
 *
 * Availability over strictness: on an API/network failure the password is
 * allowed by default (`failClosed: false`).
 *
 * @module plugins/hibp
 */
import { Effect } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import { Digest } from "effect/crypto";
import { Hex } from "effect/encoding";
import { HttpClient, HttpClientRequest } from "effect/http";
import type { SignUpInput } from "../email/EmailPassword.ts";
import { makePlugin, type ResetPasswordArgs } from "../Hooks.ts";
import { AuthError, PwnedPasswordError } from "../Errors.ts";

/** Configuration for {@link HaveIBeenPwnedPlugin}. */
export interface HibpConfig {
  /** Reject when the breach count is at least this. Default 1. */
  readonly threshold?: number;
  /** Reject (rather than allow) when the API is unavailable. Default false. */
  readonly failClosed?: boolean;
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

  return makePlugin(
    Effect.gen(function* () {
      const client = yield* HttpClient.HttpClient;
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
          return yield* client.execute(HttpClientRequest.get(`${RANGE_URL}/${prefix}`)).pipe(
            Effect.flatMap((response) => response.text),
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
      };
    }),
  );
};
