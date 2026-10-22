/**
 * The host scheduler seam for sends that must not sit on the response path
 * ({@link DeliveryScheduler}), and the detached send the flows build on it
 * ({@link makeDetachedSend}).
 *
 * A flow awaits its send inline unless the configuration hides whether an
 * account exists: there only a known address gets a message, so an inline send
 * would answer that address later than an unknown one, and fail it when the
 * vendor fails. Those sends are handed to the scheduler instead, and their
 * failures go to the `afterDeliveryFailure` hook and the
 * `effect_auth_delivery_sends_total` metric (#196).
 *
 * @module deliveryScheduler
 */
import { Context, Effect, Layer, Option } from "effect";
import type { DeliveryPurpose } from "./Delivery.ts";
import { Hooks } from "./Hooks.ts";
import * as Obs from "./Observability.ts";

// ---------------------------------------------------------------------------
// Off-response-path scheduling
// ---------------------------------------------------------------------------

/**
 * The host's way to run work after the response: `ExecutionContext.waitUntil`
 * on Cloudflare Workers, a queue producer, or a daemon fiber on a long-lived
 * server.
 *
 * Only the sends that must not sit on the response path use it: the ones in
 * configurations that hide whether an account exists, where an inline send
 * would put a vendor round-trip (and any vendor failure) on the known-address
 * branch only. Every other send is awaited inline, so its failure reaches the
 * caller. Which flows detach is listed in the package README ("Delivery").
 *
 * `schedule` receives a task that never fails and needs no services; it must
 * return once the task is handed off, not when it finishes. Without this
 * service the detached sends fork a detached fiber ({@link DeliveryScheduler.forkDetach}),
 * which a long-lived server runs to completion but which Workers can drop
 * once the response is returned: on Workers, provide
 * {@link DeliveryScheduler.waitUntil}.
 */
/**
 * `forkDetach` rather than `forkChild`: a child fiber is interrupted when its
 * parent (the request's fiber) completes, which can happen before the send has
 * even started; a detached fiber outlives the request and finishes the send.
 */
const forkDetachSchedule = (task: Effect.Effect<void>): Effect.Effect<void> =>
  Effect.asVoid(Effect.forkDetach(task));

export class DeliveryScheduler extends Context.Service<
  DeliveryScheduler,
  {
    readonly schedule: (task: Effect.Effect<void>) => Effect.Effect<void>;
  }
>()("@effect-auth/DeliveryScheduler") {
  /** Run each task on a detached fiber: the default, for long-lived servers. */
  static readonly forkDetach: Layer.Layer<DeliveryScheduler> = Layer.succeed(DeliveryScheduler, {
    schedule: forkDetachSchedule,
  });

  /**
   * Hand each task to a `waitUntil`-style function as a promise, as Workers'
   * `ExecutionContext.waitUntil` takes one, so the runtime keeps the isolate
   * alive until the send finishes. Build it per request from that request's
   * context.
   */
  static readonly waitUntil = (
    waitUntil: (promise: Promise<unknown>) => void,
  ): Layer.Layer<DeliveryScheduler> =>
    Layer.succeed(DeliveryScheduler, {
      // The task runs on a detached fiber, as without a scheduler; the promise
      // only tells the runtime when that fiber is done.
      schedule: (task) =>
        Effect.flatMap(Effect.forkDetach(task), (fiber) =>
          Effect.sync(() =>
            waitUntil(new Promise<void>((resolve) => void fiber.addObserver(() => resolve()))),
          ),
        ),
    });
}

/**
 * A send run off the response path: the flow carries on without waiting, and
 * the send's outcome never reaches the caller.
 */
export type DetachedSend = <E>(
  purpose: DeliveryPurpose,
  send: Effect.Effect<void, E>,
) => Effect.Effect<void>;

/**
 * Build a {@link DetachedSend} over {@link Hooks} (no hook when none is
 * provided). Each send reads the {@link DeliveryScheduler} from the calling
 * fiber, so a scheduler provided per request (Workers' `waitUntil`) is the one
 * used even when the services were built once; with none, the send runs on a
 * detached fiber. Both are optional, so a flow that detaches gains no
 * requirement.
 *
 * A detached send cannot fail the request that triggered it, so its failure is
 * observed here instead: logged, counted on `effect_auth_delivery_sends_total`
 * (which counts every detached send by purpose and outcome) and passed to the
 * `afterDeliveryFailure` hook, which `AuditPlugin` logs. The logged failure
 * carries the purpose and the sender's error, never the message's parameters,
 * since those hold the token or code.
 */
export const makeDetachedSend: Effect.Effect<DetachedSend> = Effect.map(
  Effect.serviceOption(Hooks),
  (hooks): DetachedSend => {
    const observed = <E>(purpose: DeliveryPurpose, send: Effect.Effect<void, E>) =>
      send.pipe(
        Effect.tap(() => Obs.recordDeliverySend(purpose, "success")),
        Effect.tapError((cause) =>
          Effect.logError("[effect-auth] delivery send failed", { purpose, cause }).pipe(
            Effect.andThen(Obs.recordDeliverySend(purpose, "failure")),
            Effect.andThen(
              Option.match(hooks, {
                onNone: () => Effect.void,
                onSome: (h) => Effect.ignore(h.afterDeliveryFailure({ purpose, cause })),
              }),
            ),
          ),
        ),
        Effect.ignore,
      );
    return (purpose, send) =>
      Effect.flatMap(Effect.serviceOption(DeliveryScheduler), (scheduler) => {
        const task = observed(purpose, send);
        return Option.isSome(scheduler) ? scheduler.value.schedule(task) : forkDetachSchedule(task);
      });
  },
);
