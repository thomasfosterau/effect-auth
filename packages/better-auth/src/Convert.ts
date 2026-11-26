/**
 * BetterAuth rows as effect-auth domain values, and BetterAuth's `APIError`
 * as effect-auth's typed errors.
 *
 * @since 0.1.0
 */
import { Clock, Effect, Result } from "effect";
import * as Arr from "effect/Array";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import * as Auth from "@thomasfosterau/effect-auth";
import type { BetterAuthSession, BetterAuthUser, ColumnValue } from "./BetterAuth.ts";

/** The user columns that map onto `Types.User` fields or derived identifiers. */
const USER_FIELD_COLUMNS: ReadonlyArray<string> = [
  "id",
  "name",
  "image",
  "createdAt",
  "updatedAt",
  "email",
  "emailVerified",
  "username",
  "displayUsername",
  "phoneNumber",
  "phoneNumberVerified",
];

/**
 * The session columns that map onto `Types.Session` fields. `token` is the
 * bearer credential and never reaches a domain value.
 */
const SESSION_FIELD_COLUMNS: ReadonlyArray<string> = [
  "id",
  "token",
  "userId",
  "expiresAt",
  "createdAt",
  "updatedAt",
];

/**
 * A column value as JSON: a `Date` becomes epoch milliseconds (how the core
 * reads `banExpires`), `undefined` is dropped, anything not JSON is dropped.
 */
const toJson = (value: ColumnValue): Auth.Json | undefined => {
  if (value === undefined) return undefined;
  if (value === null || P.isString(value) || P.isBoolean(value)) return value;
  if (P.isNumber(value)) return Number.isFinite(value) ? value : undefined;
  if (P.isDate(value)) return value.getTime();
  if (Array.isArray(value)) return Arr.filterMap(value, (item) => toJsonResult(item));
  if (P.isObject(value)) return toAttributes(value, []);
  return undefined;
};

const toJsonResult = (value: ColumnValue) => {
  const json = toJson(value);
  return json === undefined ? Result.failVoid : Result.succeed(json);
};

/** Every column but `skip`, as an attribute bag. */
const toAttributes = (
  row: Readonly<Record<string, ColumnValue>>,
  skip: ReadonlyArray<string>,
): Auth.Attributes =>
  R.filterMap(row, (value, key) => {
    if (skip.includes(key)) return Result.failVoid;
    return toJsonResult(value);
  });

const optionalString = (value: ColumnValue): string | undefined =>
  P.isString(value) ? value : undefined;

/**
 * A BetterAuth user as a `Types.User`. `email`, `username` and `phoneNumber`
 * stay off it, as in the core, and are reached through the derived identifiers.
 *
 * @since 0.1.0
 * @category conversions
 */
export const toUser = (user: BetterAuthUser): Auth.User => {
  const name = optionalString(user.name);
  const image = optionalString(user.image);
  return {
    id: user.id,
    ...(name !== undefined && { name }),
    ...(image !== undefined && { image }),
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    attributes: toAttributes(user, USER_FIELD_COLUMNS),
  };
};

/**
 * A BetterAuth session as a `Types.Session`, named by its stored id.
 * `lastActivityAt` is BetterAuth's `updatedAt`.
 *
 * @since 0.1.0
 * @category conversions
 */
export const toSession = (session: BetterAuthSession): Auth.Session => ({
  id: session.id,
  userId: session.userId,
  expiresAt: session.expiresAt,
  createdAt: session.createdAt,
  lastActivityAt: session.updatedAt,
  attributes: toAttributes(session, SESSION_FIELD_COLUMNS),
});

/**
 * The identifiers a BetterAuth user holds, each with a deterministic id
 * (`${userId}:email`, `:username`, `:phone`): the email, the `username()`
 * plugin's username and the `phoneNumber()` plugin's number.
 *
 * @since 0.1.0
 * @category conversions
 */
export const identifiersOf = (user: BetterAuthUser): ReadonlyArray<Auth.Identifier> => {
  const derive = (
    type: Auth.IdentifierType,
    value: ColumnValue,
    verified: ColumnValue,
  ): ReadonlyArray<Auth.Identifier> =>
    P.isString(value) && value !== ""
      ? [
          {
            id: identifierId(user.id, type),
            userId: user.id,
            type,
            value,
            verified: verified === true,
            createdAt: user.createdAt,
          },
        ]
      : [];
  return [
    ...derive("email", user.email, user.emailVerified),
    // BetterAuth's username plugin holds no verification flag: the handle is its own proof.
    ...derive("username", user["username"], true),
    ...derive("phone", user["phoneNumber"], user["phoneNumberVerified"]),
  ];
};

/**
 * The deterministic id of a derived identifier.
 *
 * @since 0.1.0
 * @category conversions
 */
export const identifierId = (userId: string, type: Auth.IdentifierType): string =>
  `${userId}:${type}`;

/**
 * Split an identifier id back into user id and type, or `undefined` for an id
 * this package never derived.
 *
 * @internal
 */
export const parseIdentifierId = (
  id: string,
): { readonly userId: string; readonly type: Auth.IdentifierType } | undefined => {
  const at = id.lastIndexOf(":");
  if (at <= 0) return undefined;
  const type = id.slice(at + 1);
  return type === "email" || type === "username" || type === "phone"
    ? { userId: id.slice(0, at), type }
    : undefined;
};

/**
 * Roles from the admin plugin's `role` column, which holds several roles
 * comma-separated (`"admin,user"`).
 *
 * @since 0.1.0
 * @category conversions
 */
export const rolesOf = (user: Auth.User): ReadonlyArray<string> => {
  const role = user.attributes["role"];
  return P.isString(role)
    ? Arr.filter(
        Arr.map(role.split(","), (part) => part.trim()),
        (part) => part !== "",
      )
    : [];
};

/**
 * Refuse a user BetterAuth's admin plugin has banned (`banned`, until
 * `banExpires` when set) or SCIM has deactivated, as the core's
 * `SessionService` does.
 *
 * @internal
 */
export const requireGoodStanding = (user: Auth.User): Effect.Effect<void, Auth.UserBannedError> =>
  Effect.gen(function* () {
    if (user.attributes["scimDeactivated"] === true) {
      return yield* new Auth.UserBannedError({ message: "Your account has been deactivated" });
    }
    if (user.attributes["banned"] !== true) return yield* Effect.void;
    const banExpires = user.attributes["banExpires"];
    if (P.isNumber(banExpires) && banExpires <= (yield* Clock.currentTimeMillis)) {
      return yield* Effect.void;
    }
    return yield* new Auth.UserBannedError({ message: "Your account has been suspended" });
  });

/**
 * What an `APIError` from BetterAuth's server API becomes.
 *
 * @since 0.1.0
 * @category errors
 */
export type CredentialError =
  | Auth.AuthError
  | Auth.InvalidCredentialsError
  | Auth.EmailInUseError
  | Auth.EmailNotVerifiedError;

interface ApiErrorShape {
  readonly statusCode: number;
  readonly body?: { readonly code?: unknown; readonly message?: unknown } | undefined;
}

const isApiError = (error: unknown): error is ApiErrorShape =>
  P.isObject(error) && P.isNumber(error["statusCode"]);

/**
 * Map a rejection from `auth.api.*` by status and `body.code`. Anything else,
 * including a thrown non-`APIError`, is `AuthError` with the cause kept; a
 * `429` keeps BetterAuth's error (and its `X-Retry-After`) as the cause.
 *
 * @since 0.1.0
 * @category errors
 */
export const fromApiError = (error: unknown, email?: string): CredentialError => {
  if (!isApiError(error)) {
    return new Auth.AuthError({ message: "BetterAuth call failed", cause: error });
  }
  const code = P.isString(error.body?.code) ? error.body.code : "";
  if (error.statusCode === 401 && code === "INVALID_EMAIL_OR_PASSWORD") {
    return new Auth.InvalidCredentialsError({ message: "Invalid email or password" });
  }
  if (error.statusCode === 401 && code === "INVALID_USERNAME_OR_PASSWORD") {
    return new Auth.InvalidCredentialsError({ message: "Invalid username or password" });
  }
  if (error.statusCode === 422 && code.startsWith("USER_ALREADY_EXISTS")) {
    return new Auth.EmailInUseError({
      message: "This email is already in use",
      ...(email !== undefined && { email }),
    });
  }
  if (error.statusCode === 403 && code === "EMAIL_NOT_VERIFIED") {
    return new Auth.EmailNotVerifiedError({ message: "Email not verified", email: email ?? "" });
  }
  const message =
    error.statusCode === 429
      ? "BetterAuth rate limit exceeded"
      : `BetterAuth answered ${error.statusCode}${code === "" ? "" : ` ${code}`}`;
  return new Auth.AuthError({ message, cause: error });
};
