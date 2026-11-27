/**
 * The WorkOS Events API: the same events as the webhooks, read in order, for
 * an app that polls rather than receives (`GET /events`).
 *
 * @since 0.1.0
 */
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import { List, WireEvent } from "./Schemas.ts";
import { WorkOSClient, type WorkOSError } from "./WorkOS.ts";
import { typeEvent, type WorkOSEvent } from "./Webhook.ts";

/**
 * Options for {@link list}.
 *
 * @since 0.1.0
 * @category models
 */
export interface ListOptions {
  /** The event names to read (`["session.revoked", "user.deleted"]`). */
  readonly events: ReadonlyArray<string>;
  /** The cursor the previous page answered, to read on from it. */
  readonly after?: string;
  readonly organizationId?: string;
  readonly limit?: number;
}

/**
 * One page of events and the cursor to read the next from (`None` when there
 * is none yet: poll again later with the same cursor).
 *
 * @since 0.1.0
 * @category reading
 */
export const list = (
  options: ListOptions,
): Effect.Effect<
  { readonly events: ReadonlyArray<WorkOSEvent>; readonly after: Option.Option<string> },
  WorkOSError,
  WorkOSClient
> =>
  Effect.gen(function* () {
    const workos = yield* WorkOSClient;
    const page = yield* workos.request({
      method: "GET",
      path: "/events",
      route: "/events",
      query: R.getSomes({
        // The WorkOS SDK sends a list as one comma-separated value.
        events: Option.some(options.events.join(",")),
        after: Option.fromUndefinedOr(options.after),
        organization_id: Option.fromUndefinedOr(options.organizationId),
        limit: Option.map(Option.fromUndefinedOr(options.limit), String),
      }),
      schema: List(WireEvent),
    });
    return {
      events: page.data.map(typeEvent),
      after: Option.fromNullishOr(page.list_metadata?.after ?? options.after),
    };
  });
