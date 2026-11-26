/**
 * A `beforeAuthenticate` probe for flow tests: it records every attempt and,
 * when told to, refuses with `RateLimitError`, to show that a flow runs the
 * gate and stops before checking the credential. Internal; not in the
 * `./testing` barrel.
 */
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import { DeliveryScheduler } from "../DeliveryScheduler.ts";
import { RateLimitError } from "../Errors.ts";
import * as Hooks from "../Hooks.ts";
import { inlineDeliveryScheduler } from "./Delivery.ts";

/**
 * `Hooks` (over `Hooks.Default`) whose `beforeAuthenticate` pushes each
 * attempt onto `seen` and fails it when `refuse` is set, merged with the
 * inline delivery scheduler the passwordless suites run their sends on.
 */
export const authenticateGate = (
  seen: Array<Hooks.AuthenticateAttempt>,
  refuse: boolean,
): Layer.Layer<Hooks.Hooks | DeliveryScheduler> =>
  Layer.merge(
    Hooks.makePlugin({
      beforeAuthenticate: (attempt) =>
        Effect.suspend(() => {
          seen.push(attempt);
          return refuse
            ? Effect.fail(new RateLimitError({ message: "refused by the gate", key: "gate" }))
            : Effect.succeed(attempt);
        }),
    }).pipe(Layer.provide(Hooks.Hooks.Default)),
    inlineDeliveryScheduler,
  );
