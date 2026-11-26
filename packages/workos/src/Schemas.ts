/**
 * The WorkOS User Management wire shapes this package reads, as `Schema`s.
 * Fields are snake_case, as WorkOS sends them; unknown fields are ignored, so
 * a field WorkOS adds never fails a decode.
 *
 * @since 0.1.0
 */
import { DateTime } from "effect";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";

/**
 * A WorkOS timestamp (ISO 8601, or epoch milliseconds) as a `Date`; one that
 * does not parse reads as the epoch rather than failing a whole answer.
 *
 * @since 0.1.0
 * @category utils
 */
export const instant = (value: string | number): Date =>
  DateTime.toDateUtc(Option.getOrElse(DateTime.make(value), () => DateTime.makeUnsafe(0)));

const Nullable = <S extends Schema.Top>(schema: S) => Schema.optional(Schema.NullOr(schema));

/**
 * A WorkOS user (`object: "user"`).
 *
 * @since 0.1.0
 * @category schemas
 */
export const WireUser = Schema.Struct({
  id: Schema.String,
  email: Schema.String,
  email_verified: Schema.Boolean,
  first_name: Nullable(Schema.String),
  last_name: Nullable(Schema.String),
  name: Nullable(Schema.String),
  profile_picture_url: Nullable(Schema.String),
  last_sign_in_at: Nullable(Schema.String),
  external_id: Nullable(Schema.String),
  metadata: Nullable(Schema.Record(Schema.String, Schema.String)),
  created_at: Schema.String,
  updated_at: Schema.String,
});

/** @since 0.1.0 */
export type WireUser = typeof WireUser.Type;

/**
 * The admin impersonating a user, when the session is an impersonation.
 *
 * @since 0.1.0
 * @category schemas
 */
export const Impersonator = Schema.Struct({
  email: Schema.String,
  reason: Nullable(Schema.String),
});

/** @since 0.1.0 */
export type Impersonator = typeof Impersonator.Type;

/**
 * What `POST /user_management/authenticate` answers on success.
 *
 * @since 0.1.0
 * @category schemas
 */
export const AuthenticationResponse = Schema.Struct({
  user: WireUser,
  organization_id: Nullable(Schema.String),
  access_token: Schema.String,
  refresh_token: Schema.String,
  authentication_method: Nullable(Schema.String),
  impersonator: Nullable(Impersonator),
});

/** @since 0.1.0 */
export type AuthenticationResponse = typeof AuthenticationResponse.Type;

/**
 * A WorkOS session, as `GET /user_management/users/:id/sessions` lists it.
 *
 * @since 0.1.0
 * @category schemas
 */
export const WireSession = Schema.Struct({
  id: Schema.String,
  user_id: Schema.String,
  organization_id: Nullable(Schema.String),
  status: Schema.String,
  auth_method: Nullable(Schema.String),
  ip_address: Nullable(Schema.String),
  user_agent: Nullable(Schema.String),
  impersonator: Nullable(Impersonator),
  expires_at: Schema.String,
  ended_at: Nullable(Schema.String),
  created_at: Schema.String,
  updated_at: Schema.String,
});

/** @since 0.1.0 */
export type WireSession = typeof WireSession.Type;

/**
 * A page of a WorkOS list endpoint.
 *
 * @since 0.1.0
 * @category schemas
 */
export const List = <S extends Schema.Top>(item: S) =>
  Schema.Struct({
    data: Schema.Array(item),
    list_metadata: Schema.optional(
      Schema.Struct({ before: Nullable(Schema.String), after: Nullable(Schema.String) }),
    ),
  });

/**
 * A Magic Auth code record. `code` is present only in the answer to its
 * creation.
 *
 * @since 0.1.0
 * @category schemas
 */
export const MagicAuth = Schema.Struct({
  id: Schema.String,
  user_id: Schema.String,
  email: Schema.String,
  expires_at: Schema.String,
  code: Nullable(Schema.String),
});

/** @since 0.1.0 */
export type MagicAuth = typeof MagicAuth.Type;

/**
 * A password reset. The token and URL are present only in the answer to its
 * creation.
 *
 * @since 0.1.0
 * @category schemas
 */
export const PasswordReset = Schema.Struct({
  id: Schema.String,
  user_id: Schema.String,
  email: Schema.String,
  password_reset_token: Nullable(Schema.String),
  password_reset_url: Nullable(Schema.String),
  expires_at: Schema.String,
});

/** @since 0.1.0 */
export type PasswordReset = typeof PasswordReset.Type;

/**
 * An answer that carries a user (`password_reset/confirm`,
 * `email_verification/confirm`).
 *
 * @since 0.1.0
 * @category schemas
 */
export const UserEnvelope = Schema.Struct({ user: WireUser });

/** @since 0.1.0 */
export type UserEnvelope = typeof UserEnvelope.Type;

/**
 * A WorkOS identity: a provider account linked to a user.
 *
 * @since 0.1.0
 * @category schemas
 */
export const Identity = Schema.Struct({
  idp_id: Schema.String,
  type: Schema.String,
  provider: Schema.String,
});

/** @since 0.1.0 */
export type Identity = typeof Identity.Type;

/**
 * A WorkOS error body. `code` names the failure (`invalid_credentials`,
 * `email_verification_required`, …); older endpoints put it in `error`.
 *
 * @since 0.1.0
 * @category schemas
 */
export const ErrorBody = Schema.Struct({
  code: Nullable(Schema.String),
  error: Nullable(Schema.String),
  message: Nullable(Schema.String),
  error_description: Nullable(Schema.String),
  pending_authentication_token: Nullable(Schema.String),
  errors: Nullable(Schema.Array(Schema.Struct({ code: Nullable(Schema.String) }))),
});

/** @since 0.1.0 */
export type ErrorBody = typeof ErrorBody.Type;

/**
 * A WorkOS event, from a webhook or `GET /events`. `data` is the event's
 * object, decoded further by the event type.
 *
 * @since 0.1.0
 * @category schemas
 */
export const WireEvent = Schema.Struct({
  id: Schema.String,
  event: Schema.String,
  data: Schema.Unknown,
  created_at: Schema.String,
});

/** @since 0.1.0 */
export type WireEvent = typeof WireEvent.Type;
