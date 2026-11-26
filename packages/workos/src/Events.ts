/**
 * The WorkOS Events API: the same events as the webhooks, read in order, for
 * an app that polls rather than receives (`GET /events`).
 *
 * @since 0.1.0
 */
import { Effect } from "effect";
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
  readonly after?: string | undefined;
  readonly organizationId?: string | undefined;
  readonly limit?: number | undefined;
}

/**
 * One page of events and the cursor to read the next from (`undefined` when
 * there is none yet: poll again later with the same cursor).
 *
 * @since 0.1.0
 * @category reading
 */
export const list = (
  options: ListOptions,
): Effect.Effect<
  { readonly events: ReadonlyArray<WorkOSEvent>; readonly after: string | undefined },
  WorkOSError,
  WorkOSClient
> =>
  Effect.gen(function* () {
    const workos = yield* WorkOSClient;
    const page = yield* workos.request({
      method: "GET",
      path: "/events",
      route: "/events",
      query: {
        // The WorkOS SDK sends a list as one comma-separated value.
        events: options.events.join(","),
        after: options.after,
        organization_id: options.organizationId,
        limit: options.limit === undefined ? undefined : `${options.limit}`,
      },
      schema: List(WireEvent),
    });
    return {
      events: page.data.map(typeEvent),
      after: page.list_metadata?.after ?? options.after,
    };
  });
