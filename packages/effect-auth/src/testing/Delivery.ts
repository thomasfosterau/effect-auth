/**
 * A {@link DeliveryScheduler} for tests that runs each detached send in place.
 * Never use it in production: it puts the send back on the response path.
 */
import * as Layer from "effect/Layer";
import { DeliveryScheduler } from "../DeliveryScheduler.ts";

/**
 * Provide around a test program to run the flows' detached sends inline.
 *
 * @since 0.1.0
 */
export const inlineDeliveryScheduler: Layer.Layer<DeliveryScheduler> = Layer.succeed(
  DeliveryScheduler,
  { schedule: (task) => task },
);
