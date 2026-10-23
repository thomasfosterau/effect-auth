/**
 * A {@link DeliveryScheduler} for tests: runs each detached send in place, so
 * a test reads the message (or the failure hook) as soon as the call returns.
 *
 * Never use it in production: it puts the send back on the response path,
 * which is exactly what the scheduler exists to avoid in the flows that hide
 * whether an account exists.
 */
import { Layer } from "effect";
import { DeliveryScheduler } from "../DeliveryScheduler.ts";

/**
 * Provide around a test program to run the flows' detached sends inline.
 *
 * @since 1.0.0
 */
export const inlineDeliveryScheduler: Layer.Layer<DeliveryScheduler> = Layer.succeed(
  DeliveryScheduler,
  { schedule: (task) => task },
);
