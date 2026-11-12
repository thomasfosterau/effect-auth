import * as Schema from "effect/Schema";
import { HttpApi, HttpApiEndpoint, HttpApiGroup, HttpApiSchema, OpenApi } from "effect/http-api";
import {
  Document,
  Endpoint,
  Group,
  MediaType,
  Middleware,
  Query,
} from "@thomasfosterau/effect-jsonapi";
import * as S from "./HttpApiSchema.ts";
import * as E from "./JsonApiErrors.ts";
import * as R from "./Resources.ts";

/**
 * The auth HTTP contract.
 *
 * This is the single source of truth for the protocol: it derives the server
 * (see `HttpServer.ts`), a typed Effect-native client (see `HttpClient.ts`),
 * and an OpenAPI document. Mounted under a configurable prefix (default
 * `/api/auth`).
 */

// -----------------------------------------------------------------------------
// JSON:API resource groups (#205)
// -----------------------------------------------------------------------------

/**
 * The document `GET /sessions/:id` answers: one `sessions` resource, with the
 * `users` resource it names in `included` when the request asks for
 * `?include=user`.
 */
export const SessionDocument = Document.DataDocument(R.Session, {
  included: Schema.Union([R.User]),
});

/**
 * A JSON:API write document: one resource object of `type` carrying
 * `attributes`, the shape every command endpoint below accepts.
 */
const writeDocument = <const T extends string, A extends Schema.Top>(type: T, attributes: A) =>
  Schema.Struct({ data: Schema.Struct({ type: Schema.Literal(type), attributes }) });

/** A JSON:API body accepted as `application/vnd.api+json`. */
const jsonApiPayload = <S extends Schema.Top>(schema: S) =>
  MediaType.asMediaType(schema, "application/vnd.api+json");

/** The `meta` of a sign-in or sign-up answer. */
const SignInMeta = Schema.Struct({
  /** Whether the user's email address still awaits verification. */
  needsEmailVerification: Schema.Boolean,
});

/**
 * How a `POST /sessions` proves who the caller is: the `credential` attribute,
 * a union tagged by `method`. It is write-only: no answer carries it back.
 *
 * - `password`: email and password (`captchaToken` for the captcha plugin).
 * - `username`: username and password (`captchaToken` for the captcha plugin).
 * - `email-otp` / `phone-otp`: a one-time code sent through
 *   `POST /otp-challenges`.
 * - `magic-link`: the token from a magic-link email.
 * - `anonymous`: a guest user, created on the spot.
 * - `google-one-tap`: a Google-signed id token and the nonce from
 *   `POST /google-one-tap-nonces`.
 */
export const SignInCredential = Schema.Union([
  Schema.Struct({
    method: Schema.Literal("password"),
    email: Schema.String,
    password: Schema.String,
    captchaToken: Schema.optional(Schema.String),
  }),
  Schema.Struct({
    method: Schema.Literal("username"),
    username: Schema.String,
    password: Schema.String,
    captchaToken: Schema.optional(Schema.String),
  }),
  Schema.Struct({ method: Schema.Literal("email-otp"), email: Schema.String, otp: Schema.String }),
  Schema.Struct({
    method: Schema.Literal("phone-otp"),
    phoneNumber: Schema.String,
    otp: Schema.String,
  }),
  Schema.Struct({ method: Schema.Literal("magic-link"), token: Schema.String }),
  Schema.Struct({ method: Schema.Literal("anonymous") }),
  Schema.Struct({
    method: Schema.Literal("google-one-tap"),
    idToken: Schema.String,
    nonce: Schema.String,
  }),
]);
export type SignInCredential = typeof SignInCredential.Type;

/** The body of `POST /sessions`: a `sessions` write document carrying the credential. */
export const SignInDocument = writeDocument(
  "sessions",
  Schema.Struct({
    credential: SignInCredential,
    /**
     * When `false`, the session cookie lasts until the browser closes; omit or
     * pass `true` for a cookie that matches the session's expiry.
     */
    rememberMe: Schema.optional(Schema.Boolean),
  }),
);
export type SignInDocument = typeof SignInDocument.Type;

/**
 * A new session, answered with `201` by every endpoint that signs someone in:
 * the `sessions` resource, its user in `included`, and whether the address
 * still awaits verification in `meta`.
 */
export const SignedInDocument = Document.DataDocument(R.Session, {
  included: Schema.Union([R.User]),
  meta: SignInMeta,
});

/**
 * A sign-in or sign-up accepted without a session, answered with `202`. Either
 * `data` is the `second-factor-challenges` resource to redeem, or there is no
 * primary data and `meta.needsEmailVerification` says the address must be
 * verified first (a sign-up under `antiEnumeration` answers this way for a
 * fresh address and a held one alike).
 */
export const PendingDocument = Schema.Struct({
  data: Schema.optionalKey(R.SecondFactorChallenge),
  meta: SignInMeta,
});
export type PendingDocument = typeof PendingDocument.Type;

/** The body of `POST /users`: a `users` write document with the sign-up fields. */
export const SignUpDocument = writeDocument("users", S.SignUpPayload);
export type SignUpDocument = typeof SignUpDocument.Type;

/**
 * The body of `PATCH /users/me/password`: the current password, the new one,
 * and whether to revoke the user's other sessions.
 */
export const PasswordChangeDocument = Schema.Struct({
  data: Schema.Struct({
    type: Schema.Literal("user-passwords"),
    id: Schema.Literal("me"),
    attributes: S.ChangePasswordPayload,
  }),
});
export type PasswordChangeDocument = typeof PasswordChangeDocument.Type;

/**
 * The body of `POST /second-factor-challenges/verifications`: a TOTP code or a
 * single-use backup code, and the challenge it redeems as the `challenge`
 * relationship. The challenge token travels in the body, never in the URL, so
 * no access log or `Referer` carries it, and one rate-limit bucket covers every
 * challenge.
 */
export const SecondFactorVerificationDocument = Schema.Struct({
  data: Schema.Struct({
    type: Schema.Literal("second-factor-verifications"),
    attributes: Schema.Struct({
      method: Schema.Literals(["totp", "backup-code"]),
      code: Schema.String,
    }),
    relationships: Schema.Struct({
      /** The challenge to redeem: its id is the challenge token. */
      challenge: Schema.Struct({
        data: Schema.Struct({
          type: Schema.Literal("second-factor-challenges"),
          id: Schema.String,
        }),
      }),
    }),
  }),
});
export type SecondFactorVerificationDocument = typeof SecondFactorVerificationDocument.Type;

/**
 * The body of `POST /otp-challenges`: which channel to send a one-time code or
 * link through, and to whom, with an optional `captchaToken` for the captcha
 * plugin's `"sendCode"` endpoint (#678).
 */
export const OtpChallengeDocument = writeDocument(
  "otp-challenges",
  Schema.Union([
    Schema.Struct({
      channel: Schema.Literal("email"),
      email: Schema.String,
      purpose: S.EmailOtpPurpose,
      captchaToken: Schema.optional(Schema.String),
    }),
    Schema.Struct({
      channel: Schema.Literal("phone"),
      phoneNumber: Schema.String,
      purpose: S.PhoneOtpPurpose,
      captchaToken: Schema.optional(Schema.String),
    }),
    Schema.Struct({
      channel: Schema.Literal("magic-link"),
      email: Schema.String,
      captchaToken: Schema.optional(Schema.String),
    }),
  ]),
);
export type OtpChallengeDocument = typeof OtpChallengeDocument.Type;

/** The body of `POST /email-verifications`: the address to (re)send a link to. */
export const EmailVerificationRequestDocument = writeDocument(
  "email-verifications",
  Schema.Struct({ email: Schema.String }),
);
export type EmailVerificationRequestDocument = typeof EmailVerificationRequestDocument.Type;

/** The body of `POST /password-resets`: the address to send a reset link to. */
export const PasswordResetRequestDocument = writeDocument(
  "password-resets",
  Schema.Struct({ email: Schema.String }),
);
export type PasswordResetRequestDocument = typeof PasswordResetRequestDocument.Type;

/**
 * The body of `POST /email-verifications/redemptions`: the token from a
 * verification link. It travels in the body, never in the URL.
 */
export const EmailVerificationRedemptionDocument = writeDocument(
  "email-verification-redemptions",
  Schema.Struct({ token: Schema.String }),
);
export type EmailVerificationRedemptionDocument = typeof EmailVerificationRedemptionDocument.Type;

/**
 * The body of `POST /password-resets/redemptions`: the token from a reset link
 * and the new password. The token travels in the body, never in the URL.
 */
export const PasswordResetRedemptionDocument = writeDocument(
  "password-reset-redemptions",
  Schema.Struct({ token: Schema.String, newPassword: Schema.String }),
);
export type PasswordResetRedemptionDocument = typeof PasswordResetRedemptionDocument.Type;

/** `202 Accepted` with no body: the request is taken, and the answer says nothing more. */
const Accepted = HttpApiSchema.NoContent.pipe(HttpApiSchema.status(202));

/**
 * The errors a sign-in can answer with: `401` for credentials that do not
 * authenticate, `403` for a locked or banned account, `404` for a method that
 * is not configured, `400` for a refused code or captcha.
 */
const signInErrors = [
  E.BadRequest.wire,
  E.Unauthorized.wire,
  E.Forbidden.wire,
  E.NotFound.wire,
  E.TooManyRequests.wire,
  E.InternalServerError.wire,
];

/**
 * The errors a sign-up can answer with: `409` for an address held verified,
 * `403` when sign-up is disabled, `400` for a refused password or input.
 */
const signUpErrors = [
  E.BadRequest.wire,
  E.Forbidden.wire,
  E.Conflict.wire,
  E.TooManyRequests.wire,
  E.InternalServerError.wire,
];

/** The errors a send (a verification or reset link) can answer with. */
const sendErrors = [
  E.BadRequest.wire,
  E.Forbidden.wire,
  E.TooManyRequests.wire,
  E.InternalServerError.wire,
];

/**
 * `sessions`: the signed-in user's sessions.
 *
 * - `GET /sessions`: every unexpired session of the caller.
 * - `GET /sessions/:id`: one of them; `current` names the session the request
 *   carries, and `?include=user` adds its user.
 * - `DELETE /sessions/:id`: revoke one; `DELETE /sessions/current` signs out,
 *   clearing the session cookies.
 * - `DELETE /sessions?filter[current]=false`: revoke every session but the
 *   current one.
 *
 * An id is the stored id (the hash of the session token), so a listed session
 * can be revoked by the id the list gave.
 */
export const sessionsGroup = Group.make(
  R.Session,
  Endpoint.list(R.Session, {
    errors: [E.Unauthorized, E.InternalServerError],
  }),
  Endpoint.get(R.Session, {
    include: true,
    success: SessionDocument,
    errors: [E.Unauthorized, E.NotFound, E.InternalServerError],
  }),
  Endpoint.delete(R.Session, {
    errors: [E.Unauthorized, E.NotFound, E.InternalServerError],
  }),
  HttpApiEndpoint.delete("deleteOthers", "/sessions", {
    query: { "filter[current]": Schema.Literal("false") },
    success: HttpApiSchema.NoContent,
    error: [E.Unauthorized.wire, E.InternalServerError.wire],
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
  HttpApiEndpoint.post("create", "/sessions", {
    payload: jsonApiPayload(SignInDocument),
    success: [
      MediaType.asJsonApi(SignedInDocument, 201),
      MediaType.asJsonApi(PendingDocument, 202),
    ],
    error: signInErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * `second-factor-challenges`: redeem the challenge a sign-in answered with.
 *
 * - `POST /second-factor-challenges/verifications`: a TOTP or backup code for
 *   the challenge its `challenge` relationship names; `201` with the new
 *   session. A wrong code or an unknown, expired or spent challenge answers
 *   `401`.
 */
export const secondFactorChallengesGroup = Group.make(
  R.SecondFactorChallenge,
  HttpApiEndpoint.post("verify", "/second-factor-challenges/verifications", {
    payload: jsonApiPayload(SecondFactorVerificationDocument),
    success: MediaType.asJsonApi(SignedInDocument, 201),
    error: signInErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * `otp-challenges`: send a one-time code (`email`, `phone`) or a magic link.
 * Answers `202` whether or not the address or number has an account; `400`
 * when a `beforeSendCode` plugin refuses the send (a captcha that does not
 * verify).
 */
export const otpChallengesGroup = Group.make(
  "otp-challenges",
  HttpApiEndpoint.post("create", "/otp-challenges", {
    payload: jsonApiPayload(OtpChallengeDocument),
    success: Accepted,
    error: [
      E.BadRequest.wire,
      E.Forbidden.wire,
      E.NotFound.wire,
      E.TooManyRequests.wire,
      E.InternalServerError.wire,
    ],
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * `email-verifications`: prove an email address.
 *
 * - `POST /email-verifications`: (re)send a verification link; `202` whether or
 *   not the address has an account.
 * - `POST /email-verifications/redemptions`: verify with the link's token.
 *   Answers `201` with the new session when verification signs the user in,
 *   else `204`.
 */
export const emailVerificationsGroup = Group.make(
  "email-verifications",
  HttpApiEndpoint.post("create", "/email-verifications", {
    payload: jsonApiPayload(EmailVerificationRequestDocument),
    success: Accepted,
    error: sendErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
  HttpApiEndpoint.post("redeem", "/email-verifications/redemptions", {
    payload: jsonApiPayload(EmailVerificationRedemptionDocument),
    success: [MediaType.asJsonApi(SignedInDocument, 201), HttpApiSchema.NoContent],
    error: sendErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * `password-resets`: reset a forgotten password.
 *
 * - `POST /password-resets`: send a reset link; `202` whether or not the address
 *   has an account.
 * - `POST /password-resets/redemptions`: set the new password with the link's
 *   token; `204`.
 */
export const passwordResetsGroup = Group.make(
  "password-resets",
  HttpApiEndpoint.post("create", "/password-resets", {
    payload: jsonApiPayload(PasswordResetRequestDocument),
    success: Accepted,
    error: sendErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
  HttpApiEndpoint.post("redeem", "/password-resets/redemptions", {
    payload: jsonApiPayload(PasswordResetRedemptionDocument),
    success: HttpApiSchema.NoContent,
    error: sendErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * `google-one-tap-nonces`: `POST /google-one-tap-nonces` mints the nonce to
 * hand to Google's One Tap library; `404` when One Tap is not configured.
 */
export const googleOneTapNoncesGroup = Group.make(
  R.GoogleOneTapNonce,
  HttpApiEndpoint.post("create", "/google-one-tap-nonces", {
    success: MediaType.asJsonApi(Document.DataDocument(R.GoogleOneTapNonce), 201),
    error: [E.NotFound.wire, E.InternalServerError.wire],
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * `identifiers`: the signed-in user's login handles.
 *
 * - `GET /identifiers`: every identifier the caller holds.
 * - `DELETE /identifiers/:id`: remove one. A foreign or unknown id answers
 *   `404`, and the last identifier on an account cannot be removed (`403`).
 */
export const identifiersGroup = Group.make(
  R.Identifier,
  Endpoint.list(R.Identifier, {
    errors: [E.Unauthorized, E.InternalServerError],
  }),
  Endpoint.delete(R.Identifier, {
    errors: [E.Unauthorized, E.NotFound, E.Forbidden, E.InternalServerError],
  }),
);

/**
 * `users`: the signed-in user's own profile.
 *
 * - `PATCH /users/:id`: update `name` / `image`. `:id` is `me` or the caller's
 *   own id; any other id answers `404`. No other attribute is writable (#193).
 */
export const usersGroup = Group.make(
  R.User,
  Endpoint.update(R.User, {
    errors: [E.Unauthorized, E.NotFound, E.InternalServerError],
  }),
  HttpApiEndpoint.patch("changePassword", "/users/me/password", {
    payload: jsonApiPayload(PasswordChangeDocument),
    success: HttpApiSchema.NoContent,
    error: [E.BadRequest.wire, E.Unauthorized.wire, E.InternalServerError.wire],
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
  HttpApiEndpoint.post("create", "/users", {
    payload: jsonApiPayload(SignUpDocument),
    success: [
      MediaType.asJsonApi(SignedInDocument, 201),
      MediaType.asJsonApi(PendingDocument, 202),
    ],
    error: signUpErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

// -----------------------------------------------------------------------------
// Account management (#205): password, email change, deletion, multi-factor
// -----------------------------------------------------------------------------

/** The body of `POST /email-changes`: the address to move the account to. */
export const EmailChangeDocument = writeDocument("email-changes", S.ChangeEmailRequestPayload);
export type EmailChangeDocument = typeof EmailChangeDocument.Type;

/**
 * The body of `POST /email-changes/redemptions`: the token from the
 * confirmation link. It travels in the body, never in the URL.
 */
export const EmailChangeRedemptionDocument = writeDocument(
  "email-change-redemptions",
  S.ChangeEmailConfirmPayload,
);
export type EmailChangeRedemptionDocument = typeof EmailChangeRedemptionDocument.Type;

/** The body of `POST /account-deletions`: a request, with nothing to say. */
export const AccountDeletionDocument = Schema.Struct({
  data: Schema.Struct({ type: Schema.Literal("account-deletions") }),
});
export type AccountDeletionDocument = typeof AccountDeletionDocument.Type;

/**
 * The body of `POST /account-deletions/redemptions`: the token from the
 * confirmation link. It travels in the body, never in the URL.
 */
export const AccountDeletionRedemptionDocument = writeDocument(
  "account-deletion-redemptions",
  S.DeleteUserConfirmPayload,
);
export type AccountDeletionRedemptionDocument = typeof AccountDeletionRedemptionDocument.Type;

/** The body of `POST /multi-factor-enrollments`: the password, re-proved. */
export const MultiFactorEnrollmentDocument = writeDocument(
  "multi-factor-enrollments",
  S.MultiFactorPasswordPayload,
);
export type MultiFactorEnrollmentDocument = typeof MultiFactorEnrollmentDocument.Type;

/**
 * What `POST /multi-factor-enrollments` answers: the unverified enrolment, and
 * in `meta` the TOTP secret, its `otpauth://` URI and the backup codes, shown
 * this once.
 */
export const EnrolledDocument = Document.DataDocument(R.MultiFactorEnrollment, {
  meta: S.MultiFactorEnableView,
});

/**
 * The body of `PATCH /multi-factor-enrollments/current`: a TOTP code from the
 * new authenticator, which confirms the enrolment.
 */
export const MultiFactorConfirmationDocument = Schema.Struct({
  data: Schema.Struct({
    type: Schema.Literal("multi-factor-enrollments"),
    id: Schema.Literal("current"),
    attributes: S.MultiFactorConfirmPayload,
  }),
});
export type MultiFactorConfirmationDocument = typeof MultiFactorConfirmationDocument.Type;

/**
 * The body of `DELETE /multi-factor-enrollments/current`: the password,
 * re-proved, in `meta` (a deletion carries no resource).
 */
export const MultiFactorRemovalDocument = Schema.Struct({ meta: S.MultiFactorPasswordPayload });
export type MultiFactorRemovalDocument = typeof MultiFactorRemovalDocument.Type;

/** The body of `POST /backup-code-sets`: the password, re-proved. */
export const BackupCodeSetDocument = writeDocument(
  "backup-code-sets",
  S.MultiFactorPasswordPayload,
);
export type BackupCodeSetDocument = typeof BackupCodeSetDocument.Type;

/** What `POST /backup-code-sets` answers: the new set, its codes in `meta`. */
export const BackupCodesDocument = Document.DataDocument(R.BackupCodeSet, {
  meta: S.BackupCodesView,
});

/** The errors an account-management request can answer with. */
const accountErrors = [
  E.BadRequest.wire,
  E.Unauthorized.wire,
  E.NotFound.wire,
  E.InternalServerError.wire,
];

/**
 * `email-changes`: move the account to a new address, proved by a link sent
 * there.
 *
 * - `POST /email-changes`: signed in; `202` whether or not the new address is
 *   taken (anti-enumeration).
 * - `POST /email-changes/redemptions`: the link's token; `204`.
 *
 * `404` when account management is not configured.
 */
export const emailChangesGroup = Group.make(
  "email-changes",
  HttpApiEndpoint.post("create", "/email-changes", {
    payload: jsonApiPayload(EmailChangeDocument),
    success: Accepted,
    error: accountErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
  HttpApiEndpoint.post("redeem", "/email-changes/redemptions", {
    payload: jsonApiPayload(EmailChangeRedemptionDocument),
    success: HttpApiSchema.NoContent,
    error: accountErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * `account-deletions`: delete the account, confirmed by a link sent to its
 * address.
 *
 * - `POST /account-deletions`: signed in; `202`.
 * - `POST /account-deletions/redemptions`: the link's token; `204` once the
 *   account and its sessions are gone.
 *
 * `404` when account management is not configured.
 */
export const accountDeletionsGroup = Group.make(
  "account-deletions",
  HttpApiEndpoint.post("create", "/account-deletions", {
    payload: jsonApiPayload(AccountDeletionDocument),
    success: Accepted,
    error: accountErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
  HttpApiEndpoint.post("redeem", "/account-deletions/redemptions", {
    payload: jsonApiPayload(AccountDeletionRedemptionDocument),
    success: HttpApiSchema.NoContent,
    error: accountErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * `multi-factor-enrollments`: the signed-in user's TOTP enrolment.
 *
 * - `POST /multi-factor-enrollments`: start one with the password; `201`, the
 *   secret and backup codes in `meta`.
 * - `PATCH /multi-factor-enrollments/current`: confirm it with a TOTP code;
 *   `200`, now `verified`.
 * - `DELETE /multi-factor-enrollments/current`: remove it with the password
 *   (in the document's `meta`); `204`.
 *
 * A wrong password or code answers `400`; `404` when multi-factor is not
 * configured.
 */
export const multiFactorEnrollmentsGroup = Group.make(
  R.MultiFactorEnrollment,
  HttpApiEndpoint.post("create", "/multi-factor-enrollments", {
    payload: jsonApiPayload(MultiFactorEnrollmentDocument),
    success: MediaType.asJsonApi(EnrolledDocument, 201),
    error: accountErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
  HttpApiEndpoint.patch("confirm", "/multi-factor-enrollments/current", {
    payload: jsonApiPayload(MultiFactorConfirmationDocument),
    success: MediaType.asJsonApi(Document.DataDocument(R.MultiFactorEnrollment), 200),
    error: accountErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
  HttpApiEndpoint.delete("remove", "/multi-factor-enrollments/current", {
    payload: jsonApiPayload(MultiFactorRemovalDocument),
    success: HttpApiSchema.NoContent,
    error: accountErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * `backup-code-sets`: `POST /backup-code-sets` with the password replaces the
 * user's backup codes; `201`, the new codes in `meta`. A wrong password, or no
 * enrolment, answers `400`.
 */
export const backupCodeSetsGroup = Group.make(
  R.BackupCodeSet,
  HttpApiEndpoint.post("create", "/backup-code-sets", {
    payload: jsonApiPayload(BackupCodeSetDocument),
    success: MediaType.asJsonApi(BackupCodesDocument, 201),
    error: accountErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

// -----------------------------------------------------------------------------
// Device sessions and organizations: members, invitations, domains, roles and
// teams (#205, slice 4)
// -----------------------------------------------------------------------------

/**
 * A JSON:API resource linkage to `type`, or `null`: the body of a `PATCH` that
 * points a singleton (`/organizations/active`, `/device-sessions/active`) at
 * one resource.
 */
const linkageDocument = <const T extends string>(type: T) =>
  Schema.Struct({
    data: Schema.NullOr(Schema.Struct({ type: Schema.Literal(type), id: Schema.String })),
  });

/** What `GET /device-sessions` answers: the device's accounts, their users included. */
export const DeviceSessionsDocument = Document.CollectionDocument(R.DeviceSession, {
  included: Schema.Union([R.User]),
});

/**
 * The body of `PATCH /device-sessions/active`: the listed id of the device
 * session to switch to. `null` is refused (`400`): signing out is
 * `DELETE /sessions/current`.
 */
export const ActiveDeviceSessionDocument = linkageDocument("device-sessions");
export type ActiveDeviceSessionDocument = typeof ActiveDeviceSessionDocument.Type;

/**
 * `device-sessions`: the accounts signed in on this device (multi-session).
 *
 * - `GET /device-sessions`: every still-valid session the device holds, with
 *   its user included and `active` marking the one requests now carry.
 * - `PATCH /device-sessions/active`: switch the active account to the device
 *   session the linkage names; `204`, the session cookie rewritten.
 * - `DELETE /device-sessions/:id`: sign one of them out; `204`. Signing out the
 *   active one clears the session cookie too.
 *
 * Ids are the stored ids (the hash of each session token), never the tokens
 * the device's cookies hold. An id the device does not hold answers `404` (or
 * `400` for the switch); `404` when multi-session is not enabled.
 */
export const deviceSessionsGroup = Group.make(
  R.DeviceSession,
  Endpoint.list(R.DeviceSession, {
    success: DeviceSessionsDocument,
    errors: [E.NotFound, E.InternalServerError],
  }),
  HttpApiEndpoint.patch("setActive", "/device-sessions/active", {
    payload: jsonApiPayload(ActiveDeviceSessionDocument),
    success: HttpApiSchema.NoContent,
    error: [E.BadRequest.wire, E.NotFound.wire, E.InternalServerError.wire],
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
  Endpoint.delete(R.DeviceSession, {
    errors: [E.NotFound, E.InternalServerError],
  }),
);

/** The errors a request on a signed-in resource (an organization, an admin action, a key) can answer with. */
const resourceErrors = [
  E.BadRequest,
  E.Unauthorized,
  E.Forbidden,
  E.NotFound,
  E.InternalServerError,
] as const;

/** The same errors, as the wire schemas a hand-built endpoint declares. */
const resourceErrorWires = [
  E.BadRequest.wire,
  E.Unauthorized.wire,
  E.Forbidden.wire,
  E.NotFound.wire,
  E.InternalServerError.wire,
];

/** Those errors and a `409` (`POST /organizations/:id/roles` of a defined role). */
const resourceConflictErrorWires = [...resourceErrorWires, E.Conflict.wire];

/**
 * `GET <path>`, the `:id` in it naming the parent: a JSON:API collection of
 * `resource`, answering the resource errors.
 */
const childCollection = <
  const Name extends string,
  const Path extends `/${string}/:id/${string}`,
  Resource extends Schema.Top,
>(
  name: Name,
  path: Path,
  resource: Resource,
) =>
  HttpApiEndpoint.get(name, path, {
    params: { id: Schema.String },
    success: MediaType.asJsonApi(Document.CollectionDocument(resource), 200),
    error: resourceErrorWires,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors);

/**
 * `POST <path>`, the `:id` in it naming the parent: create one `resource` from
 * the `payload` document; `201` with it.
 */
const childCreate = <
  const Name extends string,
  const Path extends `/${string}/:id/${string}`,
  Payload extends Schema.Top,
  Resource extends Schema.Top,
>(
  name: Name,
  path: Path,
  payload: Payload,
  resource: Resource,
  errors: ReadonlyArray<(typeof resourceConflictErrorWires)[number]>,
) =>
  HttpApiEndpoint.post(name, path, {
    params: { id: Schema.String },
    payload: jsonApiPayload(payload),
    success: MediaType.asJsonApi(Document.DataDocument(resource), 201),
    error: errors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors);

/**
 * `POST <path>` with no body, the `:id` in it naming the resource it acts on
 * (a re-delivery, a verification): the resource afterwards, with `status`.
 */
const itemAction = <
  const Name extends string,
  const Path extends `/${string}/:id/${string}`,
  Resource extends Schema.Top,
>(
  name: Name,
  path: Path,
  resource: Resource,
  status: number,
) =>
  HttpApiEndpoint.post(name, path, {
    params: { id: Schema.String },
    success: MediaType.asJsonApi(Document.DataDocument(resource), status),
    error: resourceErrorWires,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors);

/**
 * A write document of `type` whose `user` relationship names the user to add,
 * with `attributes` optional.
 */
const userLinkDocument = <const T extends string, A extends Schema.Top>(type: T, attributes: A) =>
  Schema.Struct({
    data: Schema.Struct({
      type: Schema.Literal(type),
      attributes: Schema.optionalKey(attributes),
      relationships: Schema.Struct({
        user: Schema.Struct({
          data: Schema.Struct({ type: Schema.Literal("users"), id: Schema.String }),
        }),
      }),
    }),
  });

/** The body of `PATCH /organizations/active`: the organization, or `null` to clear it. */
export const ActiveOrganizationDocument = linkageDocument("organizations");
export type ActiveOrganizationDocument = typeof ActiveOrganizationDocument.Type;

/**
 * The body of `POST /organizations/:id/members`: the user to add, as the
 * `user` relationship, and optionally the `role` (omitted, the organization's
 * `defaultRole`).
 */
export const MemberCreateDocument = userLinkDocument(
  "organization-members",
  Schema.Struct({ role: Schema.optional(Schema.String) }),
);
export type MemberCreateDocument = typeof MemberCreateDocument.Type;

/** The body of `POST /organizations/:id/invitations`: the invitee's email and role. */
export const InvitationCreateDocument = writeDocument("invitations", S.InviteMemberPayload);
export type InvitationCreateDocument = typeof InvitationCreateDocument.Type;

/**
 * The body of `POST /organizations/:id/domains`: the domain to claim. Its
 * `verificationStrategy` may only be `dns` (the default); `manual` answers
 * `400`, since manual attestation is the operator's (#598).
 */
export const DomainCreateDocument = writeDocument(
  "organization-domains",
  S.AddOrganizationDomainPayload,
);
export type DomainCreateDocument = typeof DomainCreateDocument.Type;

/** The body of `POST /organizations/:id/roles`: the role's name and its permissions. */
export const RoleCreateDocument = writeDocument("organization-roles", S.CreateOrgRolePayload);
export type RoleCreateDocument = typeof RoleCreateDocument.Type;

/** The body of `POST /organizations/:id/teams`: the team's name. */
export const TeamCreateDocument = writeDocument("teams", S.CreateTeamPayload);
export type TeamCreateDocument = typeof TeamCreateDocument.Type;

/** The body of `POST /teams/:id/members`: the user to add, as the `user` relationship. */
export const TeamMemberCreateDocument = userLinkDocument("team-members", Schema.Struct({}));
export type TeamMemberCreateDocument = typeof TeamMemberCreateDocument.Type;

/** One `organization-members` resource. */
export const MemberDocument = Document.DataDocument(R.OrganizationMember);

/** One `invitations` resource. */
export const InvitationDocument = Document.DataDocument(R.Invitation);

/**
 * What `PATCH /invitations/:id` answers: the invitation in its new status and,
 * for an acceptance, the membership it created as `meta.membership` (the
 * stored invitation links to no membership, so the membership cannot be an
 * `included` resource: JSON:API requires full linkage).
 */
export const InvitationTransitionDocument = Document.DataDocument(R.Invitation, {
  meta: Schema.Struct({ membership: Schema.optionalKey(R.OrganizationMember) }),
});

/**
 * `organizations`: the organizations the signed-in user belongs to.
 *
 * - `GET /organizations`: every organization the caller is an active member
 *   of (#717).
 * - `POST /organizations`: create one; the caller becomes its owner. `201`.
 * - `GET /organizations/:id`: one organization (any member; a non-member
 *   and an unknown id get the same `403`, #717).
 * - `PATCH /organizations/:id`: `name`, `slug`, `logo`, `metadata` and
 *   `jitProvisioning` (`organization:update`) and `defaultRole`
 *   (`role:manage`).
 * - `DELETE /organizations/:id`: `organization:delete`; `204`.
 * - `PATCH /organizations/active`: record the session's active organization
 *   (a linkage to it, or `null` to clear it); `204`. Only an organization
 *   the caller is an active member of: a non-member and an unknown id get
 *   the same `403` (#576).
 * - `GET /organizations/:id/members` · `POST /organizations/:id/members`: its
 *   memberships (any member, refused as `GET /organizations/:id` is, #717),
 *   and add one directly (`member:create`).
 * - `GET /organizations/:id/invitations` · `POST /organizations/:id/invitations`:
 *   its invitations, and invite someone by email (both `invitation:create`;
 *   a non-member and an unknown id get the same `403` as a member without
 *   it, #715).
 * - `GET /organizations/:id/domains` · `POST /organizations/:id/domains`: its
 *   email-domain claims (any member), and claim one (`domain:manage`).
 * - `GET /organizations/:id/roles` · `POST /organizations/:id/roles`: its
 *   custom role definitions (any member), and define one (`role:manage`); a
 *   role it already defines answers `409`.
 * - `GET /organizations/:id/teams` · `POST /organizations/:id/teams`: its
 *   teams (any member), and create one (`team:create`).
 *
 * `404` when organizations are not enabled; `403` when the actor is not a
 * member, when the actor's role lacks the permission, when the organization
 * does not exist (so the answer reveals no ids), or (for a domain request)
 * when the server has no `OrganizationDomainStore`.
 */
export const organizationsGroup = Group.make(
  R.Organization,
  Endpoint.list(R.Organization, {
    errors: [E.Unauthorized, E.NotFound, E.InternalServerError],
  }),
  Endpoint.create(R.Organization, { errors: resourceErrors }),
  HttpApiEndpoint.patch("setActive", "/organizations/active", {
    payload: jsonApiPayload(ActiveOrganizationDocument),
    success: HttpApiSchema.NoContent,
    error: resourceErrorWires,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
  Endpoint.get(R.Organization, {
    errors: [E.Unauthorized, E.Forbidden, E.NotFound, E.InternalServerError],
  }),
  Endpoint.update(R.Organization, { errors: resourceErrors }),
  Endpoint.delete(R.Organization, { errors: resourceErrors }),
  childCollection("listMembers", "/organizations/:id/members", R.OrganizationMember),
  childCreate(
    "addMember",
    "/organizations/:id/members",
    MemberCreateDocument,
    R.OrganizationMember,
    resourceErrorWires,
  ),
  childCollection("listInvitations", "/organizations/:id/invitations", R.Invitation),
  childCreate(
    "invite",
    "/organizations/:id/invitations",
    InvitationCreateDocument,
    R.Invitation,
    resourceErrorWires,
  ),
  childCollection("listDomains", "/organizations/:id/domains", R.OrganizationDomain),
  childCreate(
    "addDomain",
    "/organizations/:id/domains",
    DomainCreateDocument,
    R.OrganizationDomain,
    resourceErrorWires,
  ),
  childCollection("listRoles", "/organizations/:id/roles", R.OrganizationRole),
  childCreate(
    "createRole",
    "/organizations/:id/roles",
    RoleCreateDocument,
    R.OrganizationRole,
    resourceConflictErrorWires,
  ),
  childCollection("listTeams", "/organizations/:id/teams", R.Team),
  childCreate(
    "createTeam",
    "/organizations/:id/teams",
    TeamCreateDocument,
    R.Team,
    resourceErrorWires,
  ),
);

/**
 * `organization-members`: one membership, by its stored id.
 *
 * - `PATCH /organization-members/:id`: change the `role`, or the `status`
 *   (`inactive` deactivates the membership, `active` restores its previous
 *   role), with `member:update`. The last active owner can be neither
 *   demoted nor deactivated.
 * - `DELETE /organization-members/:id`: remove it, with `member:delete`; `204`.
 * - `GET /organization-members/:id/teams`: the teams of its organization the
 *   member belongs to (any member of that organization).
 *
 * An unknown id answers `404`, a refused change `403`.
 */
export const organizationMembersGroup = Group.make(
  R.OrganizationMember,
  Endpoint.update(R.OrganizationMember, { errors: resourceErrors }),
  Endpoint.delete(R.OrganizationMember, { errors: resourceErrors }),
  childCollection("listTeams", "/organization-members/:id/teams", R.Team),
);

/**
 * `invitations`: the signed-in user's own invitations, and one invitation by id.
 *
 * - `GET /invitations`: the pending, unexpired invitations addressed to the
 *   caller's verified email identifiers (#706), the ones they may answer by
 *   id; `401` without a session. Like `GET /organizations`, the top-level
 *   collection is scoped to the caller, never every invitation; an
 *   organization's own list is `GET /organizations/:id/invitations`.
 * - `PATCH /invitations/:id` with a `status`: `accepted` or `rejected` by the
 *   invitee, with the invitation email's secret as the `token` attribute,
 *   which an invitee whose matching email is verified may omit (#673) (an
 *   acceptance includes the new membership), `canceled` by a member
 *   holding `invitation:cancel`. A refused acceptance or rejection answers
 *   `400`, a refused cancellation `403`.
 * - `POST /invitations/:id/deliveries`: send a pending invitation again, with
 *   a fresh expiry (`invitation:create`); `202` with the invitation.
 */
export const invitationsGroup = Group.make(
  R.Invitation,
  Endpoint.list(R.Invitation, {
    errors: [E.Unauthorized, E.NotFound, E.InternalServerError],
  }),
  Endpoint.update(R.Invitation, {
    success: InvitationTransitionDocument,
    errors: resourceErrors,
  }),
  itemAction("deliver", "/invitations/:id/deliveries", R.Invitation, 202),
);

/**
 * The body of `POST /admin/organization-domains`: the domain the operator
 * attests, and the organization it is attested for as the `organization`
 * relationship.
 */
export const DomainAttestationDocument = Schema.Struct({
  data: Schema.Struct({
    type: Schema.Literal("organization-domains"),
    attributes: Schema.Struct({ domain: Schema.String }),
    relationships: Schema.Struct({
      organization: Schema.Struct({
        data: Schema.Struct({ type: Schema.Literal("organizations"), id: Schema.String }),
      }),
    }),
  }),
});
export type DomainAttestationDocument = typeof DomainAttestationDocument.Type;

/**
 * `organization-domains`: email-domain claims.
 *
 * - `DELETE /organization-domains/:id`: release the claim (`domain:manage` in
 *   its organization); `204`.
 * - `POST /organization-domains/:id/verifications`: check the DNS TXT record
 *   through the server's `DomainVerifier` (`domain:manage`); `200` with the
 *   claim, now `verified` or `failed`. The permission is never the proof: an
 *   unverified `manual` claim is refused (#598).
 * - `POST /admin/organization-domains`: the operator's attestation, after
 *   checking ownership out of band, that the `organization` relationship
 *   controls `domain` (`OrganizationService.attestDomain`). Needs the
 *   server's admin rule (the mounted `AdminService`'s `AdminConfig`, else
 *   role `admin`), never an organization permission; `201` with the
 *   organization's claim, now `verified` with the `manual` strategy and the
 *   admin as its `attester`. A refusal (an unknown organization, an invalid
 *   domain, a domain verified for another organization) answers `400`.
 * - `DELETE /admin/organization-domains/:id`: the operator's release of any
 *   organization's claim, whatever its state, for disputes
 *   (`OrganizationService.releaseDomain`, #680). Gated as the attestation is;
 *   `204`.
 *
 * An unknown id answers `404`; a tenant's refusal, or a server with no
 * `OrganizationDomainStore`, `403`.
 */
export const organizationDomainsGroup = Group.make(
  R.OrganizationDomain,
  Endpoint.delete(R.OrganizationDomain, { errors: resourceErrors }),
  itemAction("verify", "/organization-domains/:id/verifications", R.OrganizationDomain, 200),
  Endpoint.create(R.OrganizationDomain, {
    name: "attest",
    path: "/admin/organization-domains",
    payload: DomainAttestationDocument,
    errors: resourceErrors,
  }),
  Endpoint.delete(R.OrganizationDomain, {
    name: "release",
    path: "/admin/organization-domains/:id",
    errors: resourceErrors,
  }),
);

/**
 * `organization-roles`: one custom role definition, by its stored id. Both
 * need `role:manage` (owner-only by default); the protected owner role can be
 * neither defined nor removed.
 *
 * - `PATCH /organization-roles/:id`: replace its `permissions`.
 * - `DELETE /organization-roles/:id`: remove it, so the static role of that
 *   name (if any) applies again; `204`.
 *
 * An unknown id answers `404`, a refusal `403`.
 */
export const organizationRolesGroup = Group.make(
  R.OrganizationRole,
  Endpoint.update(R.OrganizationRole, { errors: resourceErrors }),
  Endpoint.delete(R.OrganizationRole, { errors: resourceErrors }),
);

/**
 * `teams`: one team, by id. The `team:*` permissions that gate them are
 * organization-scoped, resolved through the team's organization.
 *
 * - `PATCH /teams/:id`: rename it (`team:update`).
 * - `DELETE /teams/:id`: delete it and its memberships (`team:delete`); `204`.
 * - `GET /teams/:id/members` · `POST /teams/:id/members`: its memberships (any
 *   member of the organization), and add a member of the organization to it,
 *   as the `user` relationship (`team:manage-members`).
 *
 * An unknown team answers `403`, as every refusal does.
 */
export const teamsGroup = Group.make(
  R.Team,
  Endpoint.update(R.Team, { errors: resourceErrors }),
  Endpoint.delete(R.Team, { errors: resourceErrors }),
  childCollection("listMembers", "/teams/:id/members", R.TeamMember),
  childCreate(
    "addMember",
    "/teams/:id/members",
    TeamMemberCreateDocument,
    R.TeamMember,
    resourceErrorWires,
  ),
);

/**
 * `team-members`: one team membership, by its stored id.
 * `DELETE /team-members/:id` removes it (`team:manage-members`); `204`. An
 * unknown id answers `404`, a refusal `403`.
 */
export const teamMembersGroup = Group.make(
  R.TeamMember,
  Endpoint.delete(R.TeamMember, { errors: resourceErrors }),
);

// -----------------------------------------------------------------------------
// Admin, impersonation, API keys, OAuth clients, SSO, JWTs and device approval
// (#205, slice 5)
// -----------------------------------------------------------------------------

/** The `meta` of `GET /admin/users`: how many users match, before paging. */
const AdminUsersMeta = Schema.Struct({ total: Schema.Finite });

/** The body of `PATCH /admin/users/:id`: the user's new `role`. */
export const AdminUserUpdateDocument = Schema.Struct({
  data: Schema.Struct({
    type: Schema.Literal("users"),
    id: Schema.String,
    attributes: Schema.Struct({ role: Schema.String }),
  }),
});
export type AdminUserUpdateDocument = typeof AdminUserUpdateDocument.Type;

/**
 * `admin-users`: user administration. Every call needs the server's `isAdmin`
 * (`403` otherwise); `404` when admin is not enabled.
 *
 * - `GET /admin/users?filter[email]=…&page[offset]=…&page[limit]=…`: the
 *   users, filtered by a case-insensitive substring of an email address,
 *   `meta.total` counting every match.
 * - `PATCH /admin/users/:id`: set the user's `role`.
 * - `DELETE /admin/users/:id`: delete the user and revoke their sessions; `204`.
 * - `DELETE /admin/users/:id/sessions`: revoke every session of the user; `204`.
 *
 * An unknown user answers `400`, as it always has.
 */
export const adminUsersGroup = Group.make(
  "admin-users",
  Endpoint.list(R.User, {
    path: "/admin/users",
    page: Query.Page.Offset,
    filter: { email: Schema.optionalKey(Schema.String) },
    meta: AdminUsersMeta,
    errors: resourceErrors,
  }),
  Endpoint.update(R.User, {
    path: "/admin/users/:id",
    payload: AdminUserUpdateDocument,
    errors: resourceErrors,
  }),
  Endpoint.delete(R.User, { path: "/admin/users/:id", errors: resourceErrors }),
  HttpApiEndpoint.delete("deleteSessions", "/admin/users/:id/sessions", {
    params: { id: Schema.String },
    success: HttpApiSchema.NoContent,
    error: resourceErrorWires,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * The body of `POST /user-bans`: the user to ban, as the `user` relationship,
 * and optionally the `reason` and how long the ban lasts (`expiresIn`, in
 * milliseconds; omitted, the server's default, else permanent).
 */
export const UserBanCreateDocument = userLinkDocument(
  "user-bans",
  Schema.Struct({
    reason: Schema.optional(Schema.String),
    expiresIn: Schema.optional(Schema.Finite),
  }),
);
export type UserBanCreateDocument = typeof UserBanCreateDocument.Type;

/** A resource of `R` with the user it names in `included`. */
const withUserDocument = <S extends Schema.Top>(resource: S) =>
  Document.DataDocument(resource, { included: Schema.Union([R.User]) });

/**
 * `user-bans`: bans, keyed by the banned user's id. Both need `isAdmin`.
 *
 * - `POST /user-bans`: ban the user the `user` relationship names, revoking
 *   their sessions; `201` with the ban, the updated user included. An
 *   administrator can be banned by nobody, and nobody can ban themselves
 *   (`403`).
 * - `DELETE /user-bans/:id`: lift the ban on user `:id`; `204`.
 */
export const userBansGroup = Group.make(
  R.UserBan,
  Endpoint.create(R.UserBan, {
    payload: UserBanCreateDocument,
    success: withUserDocument(R.UserBan),
    errors: resourceErrors,
  }),
  Endpoint.delete(R.UserBan, { errors: resourceErrors }),
);

/** The body of `POST /impersonations`: the user to act as, as the `user` relationship. */
export const ImpersonationCreateDocument = userLinkDocument("impersonations", Schema.Struct({}));
export type ImpersonationCreateDocument = typeof ImpersonationCreateDocument.Type;

/**
 * `impersonations`: an administrator signed in as another user.
 *
 * - `POST /impersonations`: start one (`isAdmin`); `201` with the
 *   impersonation, the impersonated user included, and the session cookie now
 *   the impersonation's session.
 * - `DELETE /impersonations/current`: end the impersonation the request
 *   carries, signing its session out and clearing the session cookies; `204`.
 *   A session that is not an impersonation answers `404`.
 */
export const impersonationsGroup = Group.make(
  R.Impersonation,
  Endpoint.create(R.Impersonation, {
    payload: ImpersonationCreateDocument,
    success: withUserDocument(R.Impersonation),
    errors: [...resourceErrors, E.TooManyRequests],
  }),
  Endpoint.delete(R.Impersonation, {
    errors: [E.Unauthorized, E.NotFound, E.InternalServerError],
  }),
);

/** The body of `POST /api-keys`: the new key's settings, all optional. */
export const ApiKeyCreateDocument = writeDocument("api-keys", S.ApiKeyCreatePayload);
export type ApiKeyCreateDocument = typeof ApiKeyCreateDocument.Type;

/** The errors a request on one of the caller's own keys can answer with. */
const apiKeyErrors = [E.BadRequest, E.Unauthorized, E.NotFound, E.InternalServerError] as const;

/**
 * `api-keys`: the signed-in user's API keys. `404` when API keys are not
 * enabled.
 *
 * - `GET /api-keys`: every key the caller owns.
 * - `POST /api-keys`: mint one; `201` with the key and, in `meta.key`, the
 *   plaintext key, shown this once. Minting needs an interactive credential
 *   (the session cookie): over a bearer credential it answers `403`.
 * - `PATCH /api-keys/:id`: change its `name`, `enabled`, `expiresAt`,
 *   `permissions`, `metadata`, `remaining` or `rateLimit`.
 * - `DELETE /api-keys/:id`: delete it; `204`.
 *
 * A key the caller does not own answers `400`, as an unknown one does.
 */
export const apiKeysGroup = Group.make(
  R.ApiKey,
  Endpoint.list(R.ApiKey, { errors: [E.Unauthorized, E.NotFound, E.InternalServerError] }),
  Endpoint.create(R.ApiKey, {
    payload: ApiKeyCreateDocument,
    meta: Schema.Struct({ key: Schema.String }),
    errors: resourceErrors,
  }),
  Endpoint.update(R.ApiKey, { errors: apiKeyErrors }),
  Endpoint.delete(R.ApiKey, { errors: apiKeyErrors }),
);

/**
 * `oauth-clients`: the OIDC provider's registered clients. Every call needs
 * the server's admin rule (the mounted `AdminService`'s `AdminConfig`, else
 * role `admin`; `403` otherwise); `404` when the provider is not enabled.
 *
 * - `GET /oauth-clients`: every store-registered client.
 * - `POST /oauth-clients`: register one; `201` with the client and, for a
 *   confidential (`web`) client, its secret in `meta.clientSecret`, shown this
 *   once.
 * - `PATCH /oauth-clients/:id` · `DELETE /oauth-clients/:id`: change or delete
 *   one.
 *
 * A refused change (an unknown or statically configured client) answers `400`.
 * RFC 7591 dynamic registration stays at `/register`.
 */
export const oauthClientsGroup = Group.make(
  R.OAuthClient,
  Endpoint.list(R.OAuthClient, { errors: resourceErrors }),
  Endpoint.create(R.OAuthClient, {
    meta: Schema.Struct({ clientSecret: Schema.optionalKey(Schema.String) }),
    errors: resourceErrors,
  }),
  Endpoint.update(R.OAuthClient, { errors: resourceErrors }),
  Endpoint.delete(R.OAuthClient, { errors: resourceErrors }),
);

/**
 * The body of `POST /sso-providers`: one protocol's registration fields,
 * discriminated by `protocol` (omitted, `oidc`), and the connection's
 * organization as the optional `organization` relationship (absent or
 * `data: null` for none), as the answer carries it (#642).
 */
export const SsoProviderCreateDocument = Schema.Struct({
  data: Schema.Struct({
    type: Schema.Literal("sso-providers"),
    attributes: S.SsoRegisterAttributes,
    relationships: Schema.optionalKey(
      Schema.Struct({
        organization: Schema.optionalKey(
          Schema.Struct({
            data: Schema.NullOr(
              Schema.Struct({ type: Schema.Literal("organizations"), id: Schema.String }),
            ),
          }),
        ),
      }),
    ),
  }),
});
export type SsoProviderCreateDocument = typeof SsoProviderCreateDocument.Type;

/**
 * `sso-providers`: `POST /sso-providers` registers an enterprise SSO
 * connection (OIDC or SAML); `201` with it. Needs the server's admin rule,
 * as `oauth-clients` does (`403` otherwise); a refused registration answers `400`, and `404` means SSO
 * is not enabled.
 */
export const ssoProvidersGroup = Group.make(
  R.SsoProvider,
  Endpoint.create(R.SsoProvider, {
    payload: SsoProviderCreateDocument,
    errors: resourceErrors,
  }),
);

/**
 * The body of `POST /sso-authorizations`: how to find the connection, by any
 * one of `email` (its domain), `domain` or `providerId`.
 */
export const SsoAuthorizationCreateDocument = writeDocument(
  "sso-authorizations",
  S.SsoSignInPayload,
);
export type SsoAuthorizationCreateDocument = typeof SsoAuthorizationCreateDocument.Type;

/**
 * `sso-authorizations`: `POST /sso-authorizations` starts an SSO sign-in;
 * `201` with the IdP `url` to send the browser to, the round-trip state as the
 * id. No connection for the selector answers `400`; `404` means SSO is not
 * enabled.
 */
export const ssoAuthorizationsGroup = Group.make(
  R.SsoAuthorization,
  Endpoint.create(R.SsoAuthorization, {
    payload: SsoAuthorizationCreateDocument,
    errors: [E.BadRequest, E.NotFound, E.InternalServerError],
  }),
);

/**
 * `tokens`: `POST /tokens` signs a JWT for the signed-in user; `201` with it.
 * `404` when JWT is not enabled. The keys that verify it are at `GET /jwks`.
 */
export const tokensGroup = Group.make(
  R.Token,
  HttpApiEndpoint.post("create", "/tokens", {
    success: MediaType.asJsonApi(Document.DataDocument(R.Token), 201),
    error: [E.Unauthorized.wire, E.NotFound.wire, E.InternalServerError.wire],
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * The body of `POST /device-authorizations/decisions`: the user code the
 * device showed, and the decision. The code travels in the body, never in the
 * URL, so no access log or `Referer` carries it.
 */
export const DeviceAuthorizationDecisionDocument = writeDocument(
  "device-authorization-decisions",
  Schema.Struct({
    userCode: Schema.String,
    decision: Schema.Literals(["approved", "denied"]),
  }),
);
export type DeviceAuthorizationDecisionDocument = typeof DeviceAuthorizationDecisionDocument.Type;

/**
 * `device-authorizations`: the verification page's side of the device grant
 * (RFC 8628 §3.3, which leaves its shape to the server).
 *
 * - `POST /device-authorizations/decisions`: approve (signed in: the device
 *   is granted the caller's session) or deny (no session needed) the pending
 *   authorization a user code names; `204`. An unknown or settled code
 *   answers `400`; each code allows 5 attempts per 15 minutes (`429`).
 *
 * The device's own endpoints (`/device/code`, `/device/token`) keep RFC
 * 8628's wire format. `404` when device authorization is not enabled.
 */
export const deviceAuthorizationsGroup = Group.make(
  "device-authorizations",
  HttpApiEndpoint.post("decide", "/device-authorizations/decisions", {
    payload: jsonApiPayload(DeviceAuthorizationDecisionDocument),
    success: HttpApiSchema.NoContent,
    error: [
      E.BadRequest.wire,
      E.Unauthorized.wire,
      E.NotFound.wire,
      E.TooManyRequests.wire,
      E.InternalServerError.wire,
    ],
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * The externally specified endpoints: the RFC 8628 device grant
 * (`/device/code`, `/device/token`), the SSO callbacks, the JWKS, and the OIDC
 * provider's OAuth 2.0 / OIDC / RFC 7591 / RFC 8414 surface. Their wire
 * formats are fixed by those specifications, so they are not JSON:API.
 */
export const authGroup = HttpApiGroup.make("auth").add(
  // Device authorization grant (RFC 8628). 404 when unconfigured.
  HttpApiEndpoint.post("deviceCode", "/device/code", {
    payload: S.DeviceCodePayload,
    success: S.DeviceCodeView,
    error: [S.NotFoundError, S.InternalError],
  }),
  // Poll: RFC error codes (authorization_pending/slow_down/...) -> 400.
  HttpApiEndpoint.post("deviceToken", "/device/token", {
    payload: S.DeviceTokenPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.BadRequestError,
      S.ForbiddenError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  // --- Enterprise SSO callbacks (relying party). 404 when the module is
  // --- absent. The IdP sends the browser back here, so they keep their
  // --- binding's wire format.
  // Completes the OIDC callback and issues a session (cookie).
  HttpApiEndpoint.post("ssoCallback", "/sso/callback", {
    payload: S.SsoCallbackPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.BadRequestError,
      S.ForbiddenError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  // SAML assertion consumer service: the form POST the IdP makes on the user's
  // behalf. Same session-issuing tail as `ssoCallback`.
  HttpApiEndpoint.post("samlAcs", "/sso/saml/acs/:providerId", {
    params: { providerId: Schema.String },
    payload: S.SamlAcsPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.BadRequestError,
      S.ForbiddenError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  // This SP's `EntityDescriptor` for a SAML connection, as XML.
  HttpApiEndpoint.get("samlMetadata", "/sso/saml/metadata/:providerId", {
    params: { providerId: Schema.String },
    success: S.SamlMetadataView,
    error: [S.NotFoundError, S.BadRequestError, S.InternalError],
  }),
  // --- JWT: the JWKS (RFC 7517) that verifies the tokens `POST /tokens` signs.
  HttpApiEndpoint.get("jwtJwks", "/jwks", {
    success: S.JwksView,
    error: [S.NotFoundError, S.InternalError],
  }),
  // --- OIDC provider (this server as an OpenID Connect IdP). 404 when the
  // --- module is absent. Client administration is `oauth-clients`.
  // Authorization endpoint: answers 302 (to the client's redirect_uri, the
  // login page, or the consent page). Declared NoContent — handlers return
  // raw redirect responses.
  HttpApiEndpoint.get("oidcAuthorize", "/oauth2/authorize", {
    query: {
      response_type: Schema.optional(Schema.String),
      client_id: Schema.optional(Schema.String),
      redirect_uri: Schema.optional(Schema.String),
      scope: Schema.optional(Schema.String),
      state: Schema.optional(Schema.String),
      code_challenge: Schema.optional(Schema.String),
      code_challenge_method: Schema.optional(Schema.String),
      nonce: Schema.optional(Schema.String),
      prompt: Schema.optional(Schema.String),
    },
    success: HttpApiSchema.NoContent,
    error: [S.NotFoundError, S.BadRequestError, S.InternalError],
  }),
  // Consent decision (session-authenticated; posted by the consent page).
  HttpApiEndpoint.post("oidcConsent", "/oauth2/consent", {
    payload: S.OidcConsentPayload,
    success: S.OidcRedirectView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  // Token endpoint: authorization_code + refresh_token grants. Accepts JSON
  // or form encoding; errors carry the RFC 6749 error code as the message.
  HttpApiEndpoint.post("oidcToken", "/oauth2/token", {
    payload: [S.OidcTokenPayload, S.OidcTokenPayload.pipe(HttpApiSchema.asFormUrlEncoded())],
    success: S.OidcTokenView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  // UserInfo endpoint: bearer access token -> standard claims.
  HttpApiEndpoint.get("oidcUserInfo", "/oauth2/userinfo", {
    success: S.ClaimsView,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  // --- RFC 7591 dynamic client registration. 404 unless the provider is
  // --- configured with `dynamicRegistration`. Open to anonymous callers
  // --- (optionally gated by an initial access token), so it is rate limited
  // --- and errors use the RFC's `{ error, error_description }` body.
  HttpApiEndpoint.post("oidcDynamicRegister", "/register", {
    payload: S.OidcRegistrationPayload,
    success: S.OidcRegistrationView.pipe(HttpApiSchema.status(201)),
    error: [
      S.OAuthBadRequestError,
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.TooManyRequestsError,
      S.InternalError,
    ],
  }),
  // --- RFC 7592 registration management, guarded by the registration access
  // --- token issued at registration (`Authorization: Bearer`).
  HttpApiEndpoint.get("oidcReadRegistration", "/register/:clientId", {
    params: { clientId: Schema.String },
    success: S.OidcRegistrationView,
    error: [
      S.OAuthBadRequestError,
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.put("oidcUpdateRegistration", "/register/:clientId", {
    params: { clientId: Schema.String },
    payload: S.OidcRegistrationPayload,
    success: S.OidcRegistrationView,
    error: [
      S.OAuthBadRequestError,
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("oidcDeleteRegistration", "/register/:clientId", {
    params: { clientId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.OAuthBadRequestError,
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.InternalError,
    ],
  }),
  // OIDC discovery + JWKS (shared with the JWT module's signing keys).
  HttpApiEndpoint.get("oidcDiscovery", "/.well-known/openid-configuration", {
    success: S.ClaimsView,
    error: [S.NotFoundError, S.InternalError],
  }),
  // RFC 8414 authorization server metadata — the document MCP clients fetch.
  HttpApiEndpoint.get(
    "oauthAuthorizationServerMetadata",
    "/.well-known/oauth-authorization-server",
    {
      success: S.ClaimsView,
      error: [S.NotFoundError, S.InternalError],
    },
  ),
  HttpApiEndpoint.get("oidcJwks", "/.well-known/jwks.json", {
    success: S.JwksView,
    error: [S.NotFoundError, S.InternalError],
  }),
);

/**
 * SCIM 2.0 provisioning (RFC 7644), mounted under `/scim/v2`.
 *
 * A group of its own rather than more endpoints on `authGroup`, because SCIM
 * is a different protocol with a different audience: every route here is
 * authenticated by an organization's bearer provisioning token instead of a
 * session cookie, speaks `application/scim+json`, and reports failures in
 * SCIM's own error shape. Keeping it separate means none of that leaks into
 * the session API — and an app that never provisions simply gets `404`s.
 *
 * Resource names are capitalized (`/Users`, `/Groups`) because SCIM says so and
 * IdPs build the paths literally.
 */
export const scimGroup = HttpApiGroup.make("scim")
  .add(
    HttpApiEndpoint.post("scimCreateUser", "/Users", {
      payload: S.ScimUserPayload.pipe(S.asScimJson),
      success: S.ScimUserView.pipe(HttpApiSchema.status(201), S.asScimJson),
      error: S.ScimErrors,
    }),
  )
  .add(
    HttpApiEndpoint.get("scimListUsers", "/Users", {
      query: {
        filter: Schema.optional(Schema.String),
        startIndex: Schema.optional(Schema.String),
        count: Schema.optional(Schema.String),
      },
      success: S.ScimUserListView.pipe(S.asScimJson),
      error: S.ScimErrors,
    }),
  )
  .add(
    HttpApiEndpoint.get("scimGetUser", "/Users/:id", {
      params: { id: Schema.String },
      success: S.ScimUserView.pipe(S.asScimJson),
      error: S.ScimErrors,
    }),
  )
  .add(
    HttpApiEndpoint.put("scimReplaceUser", "/Users/:id", {
      params: { id: Schema.String },
      payload: S.ScimUserPayload.pipe(S.asScimJson),
      success: S.ScimUserView.pipe(S.asScimJson),
      error: S.ScimErrors,
    }),
  )
  .add(
    HttpApiEndpoint.patch("scimPatchUser", "/Users/:id", {
      params: { id: Schema.String },
      payload: S.ScimPatchPayload.pipe(S.asScimJson),
      success: S.ScimUserView.pipe(S.asScimJson),
      error: S.ScimErrors,
    }),
  )
  // A soft disable, not a hard delete — see `ScimService.deactivateUser`.
  .add(
    HttpApiEndpoint.delete("scimDeleteUser", "/Users/:id", {
      params: { id: Schema.String },
      success: HttpApiSchema.NoContent,
      error: S.ScimErrors,
    }),
  )
  .add(
    HttpApiEndpoint.post("scimCreateGroup", "/Groups", {
      payload: S.ScimGroupPayload.pipe(S.asScimJson),
      success: S.ScimGroupView.pipe(HttpApiSchema.status(201), S.asScimJson),
      error: S.ScimErrors,
    }),
  )
  .add(
    HttpApiEndpoint.get("scimListGroups", "/Groups", {
      query: {
        filter: Schema.optional(Schema.String),
        startIndex: Schema.optional(Schema.String),
        count: Schema.optional(Schema.String),
      },
      success: S.ScimGroupListView.pipe(S.asScimJson),
      error: S.ScimErrors,
    }),
  )
  .add(
    HttpApiEndpoint.get("scimGetGroup", "/Groups/:id", {
      params: { id: Schema.String },
      success: S.ScimGroupView.pipe(S.asScimJson),
      error: S.ScimErrors,
    }),
  )
  .add(
    HttpApiEndpoint.put("scimReplaceGroup", "/Groups/:id", {
      params: { id: Schema.String },
      payload: S.ScimGroupPayload.pipe(S.asScimJson),
      success: S.ScimGroupView.pipe(S.asScimJson),
      error: S.ScimErrors,
    }),
  )
  .add(
    HttpApiEndpoint.patch("scimPatchGroup", "/Groups/:id", {
      params: { id: Schema.String },
      payload: S.ScimPatchPayload.pipe(S.asScimJson),
      success: S.ScimGroupView.pipe(S.asScimJson),
      error: S.ScimErrors,
    }),
  )
  .add(
    HttpApiEndpoint.delete("scimDeleteGroup", "/Groups/:id", {
      params: { id: Schema.String },
      success: HttpApiSchema.NoContent,
      error: S.ScimErrors,
    }),
  )
  // Discovery (RFC 7644 §4). An IdP reads these before it provisions anything
  // to learn which optional features to use; they are unauthenticated because
  // they describe the server, not any tenant's data.
  .add(
    HttpApiEndpoint.get("scimServiceProviderConfig", "/ServiceProviderConfig", {
      success: S.ScimDocumentView.pipe(S.asScimJson),
      error: S.ScimErrors,
    }),
  )
  .add(
    HttpApiEndpoint.get("scimResourceTypes", "/ResourceTypes", {
      success: S.ScimDocumentView.pipe(S.asScimJson),
      error: S.ScimErrors,
    }),
  )
  .add(
    HttpApiEndpoint.get("scimSchemas", "/Schemas", {
      success: S.ScimDocumentView.pipe(S.asScimJson),
      error: S.ScimErrors,
    }),
  )
  .prefix("/scim/v2");

/** The complete auth API, annotated with OpenAPI document metadata. */
export const AuthApi = HttpApi.make("AuthApi")
  .add(authGroup)
  .add(sessionsGroup)
  .add(identifiersGroup)
  .add(usersGroup)
  .add(secondFactorChallengesGroup)
  .add(otpChallengesGroup)
  .add(emailVerificationsGroup)
  .add(passwordResetsGroup)
  .add(googleOneTapNoncesGroup)
  .add(emailChangesGroup)
  .add(accountDeletionsGroup)
  .add(multiFactorEnrollmentsGroup)
  .add(backupCodeSetsGroup)
  .add(deviceSessionsGroup)
  .add(organizationsGroup)
  .add(organizationMembersGroup)
  .add(invitationsGroup)
  .add(organizationDomainsGroup)
  .add(organizationRolesGroup)
  .add(teamsGroup)
  .add(teamMembersGroup)
  .add(adminUsersGroup)
  .add(userBansGroup)
  .add(impersonationsGroup)
  .add(apiKeysGroup)
  .add(oauthClientsGroup)
  .add(ssoProvidersGroup)
  .add(ssoAuthorizationsGroup)
  .add(tokensGroup)
  .add(deviceAuthorizationsGroup)
  .add(scimGroup)
  .annotateMerge(
    OpenApi.annotations({
      title: "effect-auth",
      version: "1.0.0",
      description:
        "HTTP protocol for effect-auth: email/password, sessions, email verification and " +
        "password reset, magic link, email OTP, multi-factor authentication, and SCIM 2.0 " +
        "provisioning.",
    }),
  );

/**
 * Derive the OpenAPI 3.1 document for the auth API from the {@link AuthApi}
 * contract. The document describes every endpoint path together with its
 * request/response and error schemas (each carrying its HTTP status code).
 *
 * Served at `GET {prefix}/openapi.json` when `HttpServer.make` is created
 * with `{ docs: true }`, and consumable by any OpenAPI tooling.
 */
export const getOpenApiSpec = (): OpenApi.OpenAPISpec => OpenApi.fromApi(AuthApi);
