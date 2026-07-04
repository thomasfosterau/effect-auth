/**
 * Rate limiting plugin (transform hook with short-circuit).
 *
 * Consumes a rate-limit token on `beforeSignIn`, keyed by email. When the limit
 * is exceeded the hook *fails* with `RateLimitError`, which propagates through
 * the auth error channel and short-circuits the sign-in - demonstrating the
 * "deny" pattern within a transform hook.
 *
 * Demonstrates a plugin that declares its own service dependencies: the
 * resulting Layer is `Layer<Hooks, never, Hooks | RateLimiter | RateLimitStore>`.
 *
 * @module plugins/rate-limit
 */
import { Effect } from "effect";
import type { SignInInput } from "./EmailPassword.ts";
import { makePlugin } from "./Hooks.ts";
import { RateLimitPresets, RateLimitStore, RateLimiter } from "./RateLimit.ts";

const normalize = (email: string): string => email.trim().toLowerCase();

/**
 * Rate-limits sign-in attempts per email using {@link RateLimitPresets.login}.
 *
 * `Layer<Hooks, never, Hooks | RateLimiterTag | RateLimitStoreTag>` - the
 * limiter and its store are acquired when the layer is built.
 */
export const RateLimitPlugin = makePlugin(
  Effect.gen(function* () {
    const rateLimiter = yield* RateLimiter;
    const store = yield* RateLimitStore;

    return {
      beforeSignIn: (input: SignInInput) =>
        rateLimiter
          .consumeToken(`signin:${normalize(input.email)}`, RateLimitPresets.login)
          .pipe(Effect.provideService(RateLimitStore, store), Effect.as(input)),
    };
  }),
);
