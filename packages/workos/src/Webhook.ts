/**
 * WorkOS webhooks: the `WorkOS-Signature` header (`t=<ms>,v1=<hex>`, an
 * HMAC-SHA256 of `<t>.<raw body>` under the endpoint's secret) is checked in
 * constant time and within a tolerance before the body is parsed. Verify the
 * raw body as received: a body parsed and re-serialized no longer matches.
 *
 * @since 0.1.0
 */
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import * as Option from "effect/Option";
import * as Result from "effect/Result";
import { type Mac } from "effect/crypto";
import { Hex } from "effect/encoding";
import * as Auth from "@thomasfosterau/effect-auth";
import { WireEvent, WireSession, WireUser } from "./Schemas.ts";
import { RevokedSessions } from "./Session.ts";

/**
 * The header WorkOS signs a webhook in.
 *
 * @since 0.1.0
 * @category constants
 */
// TODO(#900): the header name is from the WorkOS docs, not the SDK's source;
// confirm it on a delivered webhook.
export const SIGNATURE_HEADER = "workos-signature";

/**
 * How far a signature's timestamp may be from now, in milliseconds (the WorkOS
 * SDK's default).
 *
 * @since 0.1.0
 * @category constants
 */
export const DEFAULT_TOLERANCE_MS = 180_000;

/**
 * A webhook that failed verification. `reason` is for the server log; answer
 * the request `400` whatever it is.
 *
 * @since 0.1.0
 * @category errors
 */
export class WebhookVerificationError extends Schema.TaggedError<
  WebhookVerificationError,
  { readonly brand: unique symbol }
>()("WebhookVerificationError", {
  message: Schema.String,
  reason: Schema.Literals([
    "missing-header",
    "malformed-header",
    "stale",
    "bad-signature",
    "bad-body",
  ]),
}) {}

/**
 * A verified WorkOS event. The events this package acts on are decoded
 * (`known: true`); every other event, or one whose `data` did not decode,
 * keeps its `data` as it came (`known: false`).
 *
 * @since 0.1.0
 * @category models
 */
export type WorkOSEvent =
  | {
      readonly id: string;
      readonly event: "session.created" | "session.revoked";
      readonly data: WireSession;
      readonly createdAt: string;
      readonly known: true;
    }
  | {
      readonly id: string;
      readonly event: "user.created" | "user.updated" | "user.deleted";
      readonly data: WireUser;
      readonly createdAt: string;
      readonly known: true;
    }
  | {
      readonly id: string;
      readonly event: string;
      readonly data: unknown;
      readonly createdAt: string;
      readonly known: false;
    };

/** How long a webhook's revocation is remembered: past any access token's lifetime. */
const REVOCATION_TTL_MS = 60 * 60 * 1000;

const decodeEvent = Schema.decodeUnknownOption(Schema.fromJsonString(WireEvent));
const decodeSession = Schema.decodeUnknownOption(WireSession);
const decodeUser = Schema.decodeUnknownOption(WireUser);

/**
 * Type a decoded event by its name, keeping an event whose `data` does not
 * decode as unknown rather than refusing it.
 *
 * @since 0.1.0
 * @category utils
 */
export const typeEvent = (event: WireEvent): WorkOSEvent => {
  const base = { id: event.id, createdAt: event.created_at, known: true as const };
  const name = event.event;
  const typed: Option.Option<WorkOSEvent> =
    name === "session.created" || name === "session.revoked"
      ? Option.map(decodeSession(event.data), (data) => ({ ...base, event: name, data }))
      : name === "user.created" || name === "user.updated" || name === "user.deleted"
        ? Option.map(decodeUser(event.data), (data) => ({ ...base, event: name, data }))
        : Option.none();
  return Option.getOrElse(typed, () => ({ ...base, event: name, data: event.data, known: false }));
};

const SIGNATURE = /^t=(\d+),\s*v1=([0-9a-fA-F]+)$/;

const parseHeader = (header: string) => {
  const match = SIGNATURE.exec(header.trim());
  if (match === null) return undefined;
  const [, t = "", v1 = ""] = match;
  const timestamp = Number(t);
  if (!Number.isSafeInteger(timestamp)) return undefined;
  const signature = Result.getOrUndefined(Hex.decode(v1.toLowerCase()));
  return signature === undefined ? undefined : { t, timestamp, signature };
};

/**
 * Verify a webhook and decode its event. `header` is the `WorkOS-Signature`
 * value (`None` when absent), `rawBody` the body exactly as received.
 *
 * @since 0.1.0
 * @category verification
 */
export const verify = (
  rawBody: string,
  header: Option.Option<string>,
  secret: Redacted.Redacted,
  tolerance: number = DEFAULT_TOLERANCE_MS,
): Effect.Effect<WorkOSEvent, WebhookVerificationError | Auth.AuthError, Mac.Mac> =>
  Effect.gen(function* () {
    const present = Option.filter(header, (value) => value !== "");
    if (Option.isNone(present)) {
      return yield* new WebhookVerificationError({
        message: "The webhook has no signature",
        reason: "missing-header",
      });
    }
    const parsed = parseHeader(present.value);
    if (parsed === undefined) {
      return yield* new WebhookVerificationError({
        message: "The webhook signature is malformed",
        reason: "malformed-header",
      });
    }
    const now = yield* Clock.currentTimeMillis;
    if (Math.abs(now - parsed.timestamp) > tolerance) {
      return yield* new WebhookVerificationError({
        message: "The webhook signature is outside the tolerance",
        reason: "stale",
      });
    }
    const expected = yield* Auth.hmac(
      "sha256",
      Redacted.value<string>(secret),
      `${parsed.t}.${rawBody}`,
    );
    if (!Auth.timingSafeEqualBytes(expected, parsed.signature)) {
      return yield* new WebhookVerificationError({
        message: "The webhook signature does not match",
        reason: "bad-signature",
      });
    }
    const event = decodeEvent(rawBody);
    if (Option.isNone(event)) {
      return yield* new WebhookVerificationError({
        message: "The webhook body is not a WorkOS event",
        reason: "bad-body",
      });
    }
    return typeEvent(event.value);
  });

/**
 * What a verified event does here. `session.revoked` records the session as
 * revoked, so its sealed cookie stops validating before its access token
 * expires; `onUserDeleted` runs for `user.deleted` (the app removes what it
 * keeps for the user). Every event is handed to `onEvent`.
 *
 * @since 0.1.0
 * @category models
 */
export interface EventHandlers {
  readonly onUserDeleted?: (userId: string) => Effect.Effect<void, Auth.AuthError>;
  readonly onEvent?: (event: WorkOSEvent) => Effect.Effect<void, Auth.AuthError>;
}

/**
 * Acts on verified WorkOS events.
 *
 * @since 0.1.0
 * @category services
 */
export class WorkOSEvents extends Context.Service<
  WorkOSEvents,
  { readonly handle: (event: WorkOSEvent) => Effect.Effect<void, Auth.AuthError> }
>()("@effect-auth/workos/WorkOSEvents") {
  /** The handler over `RevokedSessions` and `handlers`. */
  static readonly layer = (
    handlers: EventHandlers = {},
  ): Layer.Layer<WorkOSEvents, never, RevokedSessions> =>
    Layer.effect(
      WorkOSEvents,
      Effect.gen(function* () {
        const revoked = yield* RevokedSessions;
        return {
          handle: Effect.fn("WorkOS.WorkOSEvents.handle")(function* (event: WorkOSEvent) {
            if (event.known && event.event === "session.revoked") {
              yield* revoked.revoke(event.data.id, REVOCATION_TTL_MS);
            }
            if (event.known && event.event === "user.deleted" && handlers.onUserDeleted) {
              yield* handlers.onUserDeleted(event.data.id);
            }
            if (handlers.onEvent) yield* handlers.onEvent(event);
          }),
        };
      }),
    );
}
