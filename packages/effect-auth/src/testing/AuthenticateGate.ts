/**
 * A `beforeAuthenticate` probe for the flows' tests (#592): it records every
 * attempt a flow hands the hook and, when told to, refuses it with a
 * `RateLimitError`, so a test can see both that a flow runs the gate and that
 * a refusal stops the flow before it checks or spends the credential.
 *
 * Internal test support: the `./testing` barrel does not export it.
 */
import { Effect, Layer } from "effect";
import { DeliveryScheduler } from "../DeliveryScheduler.ts";
import { RateLimitError } from "../Errors.ts";
import { type AuthenticateAttempt, Hooks, makePlugin } from "../Hooks.ts";
import { inlineDeliveryScheduler } from "./Delivery.ts";

/**
 * `Hooks` (over `Hooks.Default`) whose `beforeAuthenticate` pushes each
 * attempt onto `seen` and fails it when `refuse` is set, merged with the
 * inline delivery scheduler the passwordless suites run their sends on.
 */
export const authenticateGate = (
  seen: Array<AuthenticateAttempt>,
  refuse: boolean,
): Layer.Layer<Hooks | DeliveryScheduler> =>
  Layer.merge(
    makePlugin({
      beforeAuthenticate: (attempt) =>
        Effect.suspend(() => {
          seen.push(attempt);
          return refuse
            ? Effect.fail(new RateLimitError({ message: "refused by the gate", key: "gate" }))
            : Effect.succeed(attempt);
        }),
    }).pipe(Layer.provide(Hooks.Default)),
    inlineDeliveryScheduler,
  );
