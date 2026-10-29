/**
 * The JSON:API error documents of the included HTTP API (#205).
 *
 * Each class is an effect-jsonapi `ApiError.make` declaration: a tagged error
 * on the Effect side whose wire encoding is a JSON:API error document with the
 * declared status. They carry the same information as the `{ message, code }`
 * bodies of `HttpApiSchema.ts`: `detail` is the message, and `meta` carries
 * `message` and, when the failure has one, the stable domain `code`
 * (`EMAIL_NOT_VERIFIED`, `RESEND_TOO_SOON`, …) a client branches on.
 *
 * The externally specified endpoints (OAuth / OIDC, SCIM, the device flow)
 * keep their own error bodies; these classes serve only the JSON:API
 * endpoints. {@link fromHttpError} maps the `HttpApiSchema.ts` errors the
 * shared handler helpers fail with onto them.
 *
 * @module http/JsonApiErrors
 */
import { Effect, Match, Schema } from "effect";
import { ApiError } from "@thomasfosterau/effect-jsonapi";
import * as S from "./HttpApiSchema.ts";

const fields = {
  message: Schema.String,
  code: Schema.optionalKey(Schema.String),
};

const detail = (error: { readonly message: string }): string => error.message;

/**
 * `401`: no session, or credentials that do not authenticate.
 *
 * @since 0.2.0
 * @category errors
 */
export class Unauthorized extends ApiError.make<Unauthorized>("JsonApiUnauthorized")(
  "Unauthorized",
  {
    status: 401,
    code: "unauthorized",
    title: "Unauthorized",
    fields,
    detail,
  },
) {}

/**
 * `403`: authenticated, but not allowed (an unverified email, a ban, a
 * resource that is not the caller's).
 *
 * @since 0.2.0
 * @category errors
 */
export class Forbidden extends ApiError.make<Forbidden>("JsonApiForbidden")("Forbidden", {
  status: 403,
  code: "forbidden",
  title: "Forbidden",
  fields,
  detail,
}) {}

/**
 * `404`: the resource does not exist, or is not the caller's to see (the same
 * answer for both, so the status discloses nothing).
 *
 * @since 0.2.0
 * @category errors
 */
export class NotFound extends ApiError.make<NotFound>("JsonApiNotFound")("NotFound", {
  status: 404,
  code: "not_found",
  title: "Not Found",
  fields,
  detail,
}) {}

/**
 * `400`: a request the server will not act on as written.
 *
 * @since 0.2.0
 * @category errors
 */
export class BadRequest extends ApiError.make<BadRequest>("JsonApiBadRequest")("BadRequest", {
  status: 400,
  code: "bad_request",
  title: "Bad Request",
  fields,
  detail,
}) {}

/**
 * `409`: the request conflicts with the current state (a handle already held).
 *
 * @since 0.2.0
 * @category errors
 */
export class Conflict extends ApiError.make<Conflict>("JsonApiConflict")("Conflict", {
  status: 409,
  code: "conflict",
  title: "Conflict",
  fields,
  detail,
}) {}

/**
 * `429`: rate limited; retry later.
 *
 * @since 0.2.0
 * @category errors
 */
export class TooManyRequests extends ApiError.make<TooManyRequests>("JsonApiTooManyRequests")(
  "TooManyRequests",
  {
    status: 429,
    code: "too_many_requests",
    title: "Too Many Requests",
    fields,
    detail,
  },
) {}

/**
 * `500`: an unexpected server failure. The detail is generic; the cause is
 * logged, never sent.
 *
 * @since 0.2.0
 * @category errors
 */
export class InternalServerError extends ApiError.make<InternalServerError>(
  "JsonApiInternalServerError",
)("InternalServerError", {
  status: 500,
  code: "internal_server_error",
  title: "Internal Server Error",
  fields: { message: Schema.String },
  detail,
}) {}

/**
 * Any of the JSON:API errors above.
 *
 * @since 0.2.0
 * @category errors
 */
export type JsonApiError =
  | Unauthorized
  | Forbidden
  | NotFound
  | BadRequest
  | Conflict
  | TooManyRequests
  | InternalServerError;

/**
 * The JSON:API counterpart of an `HttpApiSchema.ts` error, by tag, so a
 * handler's error channel names exactly the documents it can answer with.
 *
 * @since 0.2.0
 * @category type-level
 */
export type FromHttpError<E> = E extends { readonly _tag: "Unauthorized" }
  ? Unauthorized
  : E extends { readonly _tag: "Forbidden" }
    ? Forbidden
    : E extends { readonly _tag: "NotFound" }
      ? NotFound
      : E extends { readonly _tag: "BadRequest" }
        ? BadRequest
        : E extends { readonly _tag: "Conflict" }
          ? Conflict
          : E extends { readonly _tag: "TooManyRequests" }
            ? TooManyRequests
            : E extends { readonly _tag: "InternalServerError" }
              ? InternalServerError
              : never;

/** The `HttpApiSchema.ts` errors the shared handler helpers fail with. */
type HttpError =
  | S.Unauthorized
  | S.Forbidden
  | S.NotFound
  | S.BadRequest
  | S.Conflict
  | S.TooManyRequests
  | S.InternalServerError;

const carry = (error: {
  readonly message: string;
  readonly code?: string | undefined;
}): { readonly message: string; readonly code?: string } => ({
  message: error.message,
  ...(error.code !== undefined && { code: error.code }),
});

/**
 * The JSON:API error carrying the same status and information as one of the
 * `HttpApiSchema.ts` errors.
 *
 * @example
 * ```ts
 * import { strictEqual } from "node:assert";
 * import * as Http from "@thomasfosterau/effect-auth/http";
 *
 * const error = Http.JsonApiErrors.fromHttpError(
 *   new Http.Unauthorized({ message: "Not authenticated" }),
 * );
 * strictEqual(error._tag, "Unauthorized");
 * strictEqual(error.message, "Not authenticated");
 * ```
 *
 * @since 0.2.0
 * @category conversions
 */
export const fromHttpError = <E extends HttpError>(error: E): FromHttpError<E> =>
  // SAFETY: each arm builds the class `FromHttpError` names for its tag.
  Match.valueTags(error as HttpError, {
    Unauthorized: (e) => new Unauthorized(carry(e)),
    Forbidden: (e) => new Forbidden(carry(e)),
    NotFound: (e) => new NotFound(carry(e)),
    BadRequest: (e) => new BadRequest(carry(e)),
    Conflict: (e) => new Conflict(carry(e)),
    TooManyRequests: (e) => new TooManyRequests(carry(e)),
    InternalServerError: (e) => new InternalServerError({ message: e.message }),
  }) as FromHttpError<E>;

/**
 * Re-type an effect that fails with `HttpApiSchema.ts` errors so it fails with
 * their JSON:API counterparts instead.
 *
 * @since 0.2.0
 * @category combinators
 */
export const mapHttpErrors = <A, E extends HttpError, R>(
  self: Effect.Effect<A, E, R>,
): Effect.Effect<A, FromHttpError<E>, R> => Effect.mapError(self, fromHttpError);
