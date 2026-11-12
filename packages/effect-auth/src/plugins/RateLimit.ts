/**
 * Rate limiting plugin (transform hook with short-circuit).
 *
 * Consumes a rate-limit token on `beforeAuthenticate`, which every
 * credential-verifying flow fires, keyed on the account (the resolved user,
 * else the handle; see `authenticationSubject`). When the limit is exceeded
 * the hook *fails* with `RateLimitError`, which propagates through the auth
 * error channel and short-circuits the attempt - demonstrating the "deny"
 * pattern within a transform hook.
 *
 * Demonstrates a plugin that declares its own service dependencies: the
 * resulting Layer is `Layer<Hooks, never, Hooks | RateLimiter | RateLimitStore>`.
 *
 * @module plugins/rate-limit
 */
import { Effect } from "effect";
import { type AuthenticateAttempt, authenticationSubject, makePlugin } from "../Hooks.ts";
import { RateLimitPresets, RateLimitStore, RateLimiter } from "../RateLimit.ts";

/**
 * Rate-limits authentication attempts per account: first-factor attempts
 * (every method but `"second-factor"`) share one bucket per account under
 * {@link RateLimitPresets.login} (`signin:<subject>`), and second-factor
 * redemptions draw on a bucket of their own under
 * {@link RateLimitPresets.totpVerification} (`second-factor:<subject>`). An
 * unkeyed attempt (an unknown challenge or token, which names no account)
 * passes: `IPRateLimitPlugin` is what counts it.
 *
 * `Layer<Hooks, never, Hooks | RateLimiterTag | RateLimitStoreTag>` - the
 * limiter and its store are acquired when the layer is built.
 */
export const RateLimitPlugin = makePlugin(
  Effect.gen(function* () {
    const rateLimiter = yield* RateLimiter;
    const store = yield* RateLimitStore;

    return {
      beforeAuthenticate: (attempt: AuthenticateAttempt) => {
        const subject = authenticationSubject(attempt);
        if (subject === undefined) return Effect.succeed(attempt);
        return (
          attempt.method === "second-factor"
            ? rateLimiter.consumeToken(
                `second-factor:${subject}`,
                RateLimitPresets.totpVerification,
              )
            : rateLimiter.consumeToken(`signin:${subject}`, RateLimitPresets.login)
        ).pipe(Effect.provideService(RateLimitStore, store), Effect.as(attempt));
      },
    };
  }),
);
