/**
 * Per-account rate limiting on `beforeAuthenticate`, keyed by
 * `authenticationSubject` (the resolved user, else the handle): past the limit
 * the hook fails with `RateLimitError`. Its layer requires `RateLimiter` and
 * `RateLimitStore`.
 *
 * @module plugins/rate-limit
 */
import * as Effect from "effect/Effect";
import * as Hooks from "../Hooks.ts";
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
export const RateLimitPlugin = Hooks.makePlugin(
  Effect.gen(function* () {
    const rateLimiter = yield* RateLimiter;
    const store = yield* RateLimitStore;

    return {
      beforeAuthenticate: (attempt: Hooks.AuthenticateAttempt) => {
        const subject = Hooks.authenticationSubject(attempt);
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
