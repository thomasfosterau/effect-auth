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
import { HttpClient, HttpClientRequest } from "effect/unstable/http";
import * as crypto from "node:crypto";
import type { SignUpInput } from "../EmailPassword.js";
import { makePlugin, type ResetPasswordArgs } from "../Hooks.js";
import { AuthError } from "../Errors.js";

export interface HibpConfig {
  /** Reject when the breach count is at least this. Default 1. */
  readonly threshold?: number;
  /** Reject (rather than allow) when the API is unavailable. Default false. */
  readonly failClosed?: boolean;
}

const RANGE_URL = "https://api.pwnedpasswords.com/range";

const sha1Upper = (password: string): string =>
  crypto.createHash("sha1").update(password).digest("hex").toUpperCase();

/**
 * Build the HIBP plugin. The resulting layer is
 * `Layer<Hooks, never, Hooks | HttpClient>` — provide `FetchHttpClient.layer`
 * (or a stub) to satisfy the client.
 */
export const HaveIBeenPwnedPlugin = (config: HibpConfig = {}) => {
  const threshold = config.threshold ?? 1;
  const failClosed = config.failClosed ?? false;

  return makePlugin(
    Effect.gen(function* () {
      const client = yield* HttpClient.HttpClient;

      const breachCount = (password: string): Effect.Effect<number, AuthError> => {
        const hash = sha1Upper(password);
        const prefix = hash.slice(0, 5);
        const suffix = hash.slice(5);
        return client.execute(HttpClientRequest.get(`${RANGE_URL}/${prefix}`)).pipe(
          Effect.flatMap((response) => response.text),
          Effect.map((body) => {
            for (const line of body.split("\n")) {
              const [suf, count] = line.trim().split(":");
              if (suf === suffix) return Number(count) || 0;
            }
            return 0;
          }),
          Effect.catch(() =>
            failClosed
              ? Effect.fail(new AuthError({ message: "Password breach check is unavailable" }))
              : Effect.succeed(0),
          ),
        );
      };

      const check = (password: string): Effect.Effect<void, AuthError> =>
        Effect.gen(function* () {
          const count = yield* breachCount(password);
          if (count >= threshold) {
            return yield* Effect.fail(
              new AuthError({
                message: "This password has appeared in a data breach; please choose another",
              }),
            );
          }
        });

      return {
        beforeSignUp: (input: SignUpInput) => check(input.password).pipe(Effect.as(input)),
        beforeResetPassword: (args: ResetPasswordArgs) =>
          check(args.newPassword).pipe(Effect.as(args)),
      };
    }),
  );
};
