import { Schema } from "effect";
import { HttpApi, HttpApiEndpoint, HttpApiGroup, HttpApiSchema, OpenApi } from "effect/http-api";
import { Document, Endpoint, Group, MediaType, Middleware } from "@thomasfosterau/effect-jsonapi";
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
 * - `username`: username and password.
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
 * The body of `POST /second-factor-challenges/:id/verifications`: a TOTP code
 * or a single-use backup code.
 */
export const SecondFactorVerificationDocument = writeDocument(
  "second-factor-verifications",
  Schema.Struct({
    method: Schema.Literals(["totp", "backup-code"]),
    code: Schema.String,
  }),
);
export type SecondFactorVerificationDocument = typeof SecondFactorVerificationDocument.Type;

/**
 * The body of `POST /otp-challenges`: which channel to send a one-time code or
 * link through, and to whom.
 */
export const OtpChallengeDocument = writeDocument(
  "otp-challenges",
  Schema.Union([
    Schema.Struct({
      channel: Schema.Literal("email"),
      email: Schema.String,
      purpose: S.EmailOtpPurpose,
    }),
    Schema.Struct({
      channel: Schema.Literal("phone"),
      phoneNumber: Schema.String,
      purpose: S.PhoneOtpPurpose,
    }),
    Schema.Struct({ channel: Schema.Literal("magic-link"), email: Schema.String }),
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
 * The body of `PATCH /email-verifications/:id`: the verification named by its
 * token, which must equal the path's.
 */
export const EmailVerificationDocument = Schema.Struct({
  data: Schema.Struct({ type: Schema.Literal("email-verifications"), id: Schema.String }),
});
export type EmailVerificationDocument = typeof EmailVerificationDocument.Type;

/**
 * The body of `PATCH /password-resets/:id`: the reset named by its token, which
 * must equal the path's, and the new password.
 */
export const PasswordResetDocument = Schema.Struct({
  data: Schema.Struct({
    type: Schema.Literal("password-resets"),
    id: Schema.String,
    attributes: Schema.Struct({ newPassword: Schema.String }),
  }),
});
export type PasswordResetDocument = typeof PasswordResetDocument.Type;

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

/** The errors redeeming a token can answer with: {@link sendErrors}, and `409` for an id mismatch. */
const redeemErrors = [...sendErrors, E.Conflict.wire];

/**
 * `sessions`: the signed-in user's sessions.
 *
 * - `GET /sessions`: every unexpired session of the caller.
 * - `GET /sessions/:id`: one of them; `current` names the session the request
 *   carries, and `?include=user` adds its user (what `GET /session` answered).
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
 * - `POST /second-factor-challenges/:id/verifications`: a TOTP or backup code
 *   for the challenge `:id`; `201` with the new session. A wrong code or an
 *   unknown, expired or spent challenge answers `401`.
 */
export const secondFactorChallengesGroup = Group.make(
  R.SecondFactorChallenge,
  HttpApiEndpoint.post("verify", "/second-factor-challenges/:id/verifications", {
    params: { id: Schema.String },
    payload: jsonApiPayload(SecondFactorVerificationDocument),
    success: MediaType.asJsonApi(SignedInDocument, 201),
    error: signInErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * `otp-challenges`: send a one-time code (`email`, `phone`) or a magic link.
 * Answers `202` whether or not the address or number has an account.
 */
export const otpChallengesGroup = Group.make(
  "otp-challenges",
  HttpApiEndpoint.post("create", "/otp-challenges", {
    payload: jsonApiPayload(OtpChallengeDocument),
    success: Accepted,
    error: [E.NotFound.wire, E.TooManyRequests.wire, E.InternalServerError.wire],
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * `email-verifications`: prove an email address.
 *
 * - `POST /email-verifications`: (re)send a verification link; `202` whether or
 *   not the address has an account.
 * - `PATCH /email-verifications/:id`: verify with the link's token. Answers
 *   `200` with the new session when verification signs the user in, else `204`.
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
  HttpApiEndpoint.patch("update", "/email-verifications/:id", {
    params: { id: Schema.String },
    payload: jsonApiPayload(EmailVerificationDocument),
    success: [MediaType.asJsonApi(SignedInDocument, 200), HttpApiSchema.NoContent],
    error: redeemErrors,
  })
    .middleware(Middleware.ContentNegotiation)
    .middleware(Middleware.SchemaErrors),
);

/**
 * `password-resets`: reset a forgotten password.
 *
 * - `POST /password-resets`: send a reset link; `202` whether or not the address
 *   has an account.
 * - `PATCH /password-resets/:id`: set the new password with the link's token;
 *   `204`.
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
  HttpApiEndpoint.patch("update", "/password-resets/:id", {
    params: { id: Schema.String },
    payload: jsonApiPayload(PasswordResetDocument),
    success: HttpApiSchema.NoContent,
    error: redeemErrors,
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

/** Email/password + session endpoints. */
export const authGroup = HttpApiGroup.make("auth").add(
  HttpApiEndpoint.post("changePassword", "/change-password", {
    payload: S.ChangePasswordPayload,
    success: HttpApiSchema.NoContent,
    error: [S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  // Account management: verification-gated email change & self-service deletion.
  // Request endpoints are session-authenticated; confirm endpoints are by token.
  // Anti-enumeration: request endpoints always answer `{ status: true }`.
  HttpApiEndpoint.post("changeEmailRequest", "/change-email/request", {
    payload: S.ChangeEmailRequestPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.post("changeEmailConfirm", "/change-email/confirm", {
    payload: S.ChangeEmailConfirmPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("deleteUserRequest", "/delete-user/request", {
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.post("deleteUserConfirm", "/delete-user/confirm", {
    payload: S.DeleteUserConfirmPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.BadRequestError, S.InternalError],
  }),
  // Multi-session (several accounts per device). 404 when not enabled.
  HttpApiEndpoint.get("multiSessionList", "/multi-session/list", {
    success: S.MultiSessionListView,
    error: [S.NotFoundError, S.InternalError],
  }),
  HttpApiEndpoint.post("multiSessionSetActive", "/multi-session/set-active", {
    payload: S.MultiSessionActionPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("multiSessionRevoke", "/multi-session/revoke", {
    payload: S.MultiSessionActionPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.InternalError],
  }),
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
  HttpApiEndpoint.post("deviceApprove", "/device/approve", {
    payload: S.DeviceUserCodePayload,
    success: S.StatusResponse,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.BadRequestError,
      S.TooManyRequestsError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("deviceDeny", "/device/deny", {
    payload: S.DeviceUserCodePayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.BadRequestError, S.TooManyRequestsError, S.InternalError],
  }),
  // Authenticated; wrong password -> 400 BadRequest (mirrors change-password).
  HttpApiEndpoint.post("multiFactorEnable", "/multi-factor/enable", {
    payload: S.MultiFactorPasswordPayload,
    success: S.MultiFactorEnableView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  // Authenticated; invalid TOTP code or no pending enrollment -> 400 BadRequest.
  HttpApiEndpoint.post("multiFactorConfirm", "/multi-factor/confirm", {
    payload: S.MultiFactorConfirmPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  // Authenticated; wrong password -> 400 BadRequest.
  HttpApiEndpoint.post("multiFactorDisable", "/multi-factor/disable", {
    payload: S.MultiFactorPasswordPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  // Authenticated; wrong password or multi-factor not enabled -> 400 BadRequest.
  HttpApiEndpoint.post(
    "multiFactorRegenerateBackupCodes",
    "/multi-factor/regenerate-backup-codes",
    {
      payload: S.MultiFactorPasswordPayload,
      success: S.BackupCodesView,
      error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
    },
  ),
  // --- Organization (session-authenticated). 404 when the module is absent;
  // --- 403 when the actor's role lacks the required permission.
  HttpApiEndpoint.post("orgCreate", "/organization/create", {
    payload: S.CreateOrganizationPayload,
    success: S.OrganizationView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get("orgList", "/organizations", {
    success: S.OrganizationListView,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.get("orgGet", "/organization/:organizationId", {
    params: { organizationId: Schema.String },
    success: S.FullOrganizationView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.patch("orgUpdate", "/organization/:organizationId", {
    params: { organizationId: Schema.String },
    payload: S.UpdateOrganizationPayload,
    success: S.OrganizationView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("orgDelete", "/organization/:organizationId", {
    params: { organizationId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("orgSetActive", "/organization/set-active", {
    payload: S.SetActiveOrganizationPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.post("orgInvite", "/organization/:organizationId/invitations", {
    params: { organizationId: Schema.String },
    payload: S.InviteMemberPayload,
    success: S.InvitationView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get("orgListInvitations", "/organization/:organizationId/invitations", {
    params: { organizationId: Schema.String },
    success: S.InvitationListView,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.post("orgAcceptInvitation", "/invitations/:invitationId/accept", {
    params: { invitationId: Schema.String },
    success: S.MemberView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("orgRejectInvitation", "/invitations/:invitationId/reject", {
    params: { invitationId: Schema.String },
    success: S.InvitationView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.post("orgCancelInvitation", "/invitations/:invitationId/cancel", {
    params: { invitationId: Schema.String },
    success: S.InvitationView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  // Same row, same id, a fresh expiry and another delivery attempt.
  HttpApiEndpoint.post("orgResendInvitation", "/invitations/:invitationId/resend", {
    params: { invitationId: Schema.String },
    success: S.InvitationView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("orgAddMember", "/organization/:organizationId/members", {
    params: { organizationId: Schema.String },
    payload: S.AddMemberPayload,
    success: S.MemberView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.patch("orgUpdateMemberRole", "/organization/:organizationId/members", {
    params: { organizationId: Schema.String },
    payload: S.UpdateMemberRolePayload,
    success: S.MemberView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("orgRemoveMember", "/organization/:organizationId/members/:userId", {
    params: { organizationId: Schema.String, userId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  // Member lifecycle: deactivation suspends a membership without deleting it,
  // gated on `member:update` like a role change. The last active owner can be
  // neither.
  HttpApiEndpoint.post(
    "orgDeactivateMember",
    "/organization/:organizationId/members/:userId/deactivate",
    {
      params: { organizationId: Schema.String, userId: Schema.String },
      success: S.MemberView,
      error: [
        S.NotFoundError,
        S.UnauthorizedError,
        S.ForbiddenError,
        S.BadRequestError,
        S.InternalError,
      ],
    },
  ),
  HttpApiEndpoint.post(
    "orgReactivateMember",
    "/organization/:organizationId/members/:userId/reactivate",
    {
      params: { organizationId: Schema.String, userId: Schema.String },
      success: S.MemberView,
      error: [
        S.NotFoundError,
        S.UnauthorizedError,
        S.ForbiddenError,
        S.BadRequestError,
        S.InternalError,
      ],
    },
  ),
  // The role new members get when none is named: `role:manage`, i.e. owners.
  HttpApiEndpoint.put("orgSetDefaultRole", "/organization/:organizationId/default-role", {
    params: { organizationId: Schema.String },
    payload: S.SetDefaultRolePayload,
    success: S.OrganizationView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  // Email-domain claims. Writes need `domain:manage`; any member may list.
  // 404 means the organization module itself is absent; a server with no
  // `OrganizationDomainStore` wired answers 403 like any other refusal.
  HttpApiEndpoint.get("orgListDomains", "/organization/:organizationId/domains", {
    params: { organizationId: Schema.String },
    success: S.OrganizationDomainListView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("orgAddDomain", "/organization/:organizationId/domains", {
    params: { organizationId: Schema.String },
    payload: S.AddOrganizationDomainPayload,
    success: S.OrganizationDomainView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("orgRemoveDomain", "/organization/:organizationId/domains/:domainId", {
    params: { organizationId: Schema.String, domainId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post(
    "orgVerifyDomain",
    "/organization/:organizationId/domains/:domainId/verify",
    {
      params: { organizationId: Schema.String, domainId: Schema.String },
      success: S.OrganizationDomainView,
      error: [
        S.NotFoundError,
        S.UnauthorizedError,
        S.ForbiddenError,
        S.BadRequestError,
        S.InternalError,
      ],
    },
  ),
  // Dynamic access control: per-organization role definitions. Writes need the
  // `role:manage` permission (owner-only by default); any member may list.
  HttpApiEndpoint.put("orgUpsertRole", "/organization/:organizationId/roles/:role", {
    params: { organizationId: Schema.String, role: Schema.String },
    payload: S.UpsertOrgRolePayload,
    success: S.OrgRoleView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get("orgListRoles", "/organization/:organizationId/roles", {
    params: { organizationId: Schema.String },
    success: S.OrgRoleListView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("orgDeleteRole", "/organization/:organizationId/roles/:role", {
    params: { organizationId: Schema.String, role: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  // Teams are organization sub-groups; the `team:*` permissions that gate them
  // are organization-scoped, so team-scoped routes resolve the organization
  // through the team id.
  HttpApiEndpoint.post("orgCreateTeam", "/organization/:organizationId/teams", {
    params: { organizationId: Schema.String },
    payload: S.CreateTeamPayload,
    success: S.TeamView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get("orgListTeams", "/organization/:organizationId/teams", {
    params: { organizationId: Schema.String },
    success: S.TeamListView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get(
    "orgListTeamsForMember",
    "/organization/:organizationId/members/:userId/teams",
    {
      params: { organizationId: Schema.String, userId: Schema.String },
      success: S.TeamListView,
      error: [
        S.NotFoundError,
        S.UnauthorizedError,
        S.ForbiddenError,
        S.BadRequestError,
        S.InternalError,
      ],
    },
  ),
  HttpApiEndpoint.patch("orgUpdateTeam", "/teams/:teamId", {
    params: { teamId: Schema.String },
    payload: S.UpdateTeamPayload,
    success: S.TeamView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("orgDeleteTeam", "/teams/:teamId", {
    params: { teamId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("orgAddTeamMember", "/teams/:teamId/members", {
    params: { teamId: Schema.String },
    payload: S.AddTeamMemberPayload,
    success: S.TeamMemberView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get("orgListTeamMembers", "/teams/:teamId/members", {
    params: { teamId: Schema.String },
    success: S.TeamMemberListView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("orgRemoveTeamMember", "/teams/:teamId/members/:userId", {
    params: { teamId: Schema.String, userId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  // --- Admin (session-authenticated; the actor must satisfy `isAdmin`).
  // --- Authorization failures answer 403.
  HttpApiEndpoint.post("adminListUsers", "/admin/users/list", {
    payload: S.AdminListUsersPayload,
    success: S.AdminUserListView,
    error: [S.NotFoundError, S.UnauthorizedError, S.ForbiddenError, S.InternalError],
  }),
  HttpApiEndpoint.post("adminSetRole", "/admin/users/set-role", {
    payload: S.AdminSetRolePayload,
    success: S.UserView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("adminBanUser", "/admin/users/ban", {
    payload: S.AdminBanUserPayload,
    success: S.UserView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("adminUnbanUser", "/admin/users/unban", {
    payload: S.AdminUserActionPayload,
    success: S.UserView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.post("adminRemoveUser", "/admin/users/remove", {
    payload: S.AdminUserActionPayload,
    success: HttpApiSchema.NoContent,
    error: [S.NotFoundError, S.UnauthorizedError, S.ForbiddenError, S.InternalError],
  }),
  HttpApiEndpoint.post("adminRevokeSessions", "/admin/users/revoke-sessions", {
    payload: S.AdminUserActionPayload,
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.ForbiddenError, S.InternalError],
  }),
  HttpApiEndpoint.post("adminImpersonate", "/admin/impersonate", {
    payload: S.AdminUserActionPayload,
    success: S.AuthSuccess,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
      S.TooManyRequestsError,
    ],
  }),
  HttpApiEndpoint.post("adminStopImpersonating", "/admin/stop-impersonating", {
    success: S.StatusResponse,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  // --- API keys (session-authenticated management; `apiKeyCreate` additionally
  // requires an interactive credential — see `requireInteractiveCredential`).
  HttpApiEndpoint.post("apiKeyCreate", "/api-keys", {
    payload: S.ApiKeyCreatePayload,
    success: S.ApiKeyCreatedView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get("apiKeyList", "/api-keys", {
    success: S.ApiKeyListView,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.patch("apiKeyUpdate", "/api-keys/:keyId", {
    params: { keyId: Schema.String },
    payload: S.ApiKeyUpdatePayload,
    success: S.ApiKeyView,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  HttpApiEndpoint.delete("apiKeyDelete", "/api-keys/:keyId", {
    params: { keyId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [S.NotFoundError, S.UnauthorizedError, S.BadRequestError, S.InternalError],
  }),
  // --- Enterprise SSO (OIDC relying party). 404 when the module is absent.
  // Register is admin-gated (403 for non-admins).
  HttpApiEndpoint.post("ssoRegister", "/sso/register", {
    payload: S.SsoRegisterPayload,
    success: S.SsoProviderView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  // Returns the IdP authorization URL; unknown domain/provider -> 400.
  HttpApiEndpoint.post("signInSso", "/sign-in/sso", {
    payload: S.SsoSignInPayload,
    success: S.SsoUrlView,
    error: [S.NotFoundError, S.BadRequestError, S.InternalError],
  }),
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
  // --- JWT: issue a token for the session (`/token`) and serve the JWKS.
  HttpApiEndpoint.get("jwtToken", "/token", {
    success: S.JwtTokenView,
    error: [S.NotFoundError, S.UnauthorizedError, S.InternalError],
  }),
  HttpApiEndpoint.get("jwtJwks", "/jwks", {
    success: S.JwksView,
    error: [S.NotFoundError, S.InternalError],
  }),
  // --- OIDC provider (this server as an OpenID Connect IdP). 404 when the
  // --- module is absent. Client management is admin-gated.
  HttpApiEndpoint.post("oidcRegisterClient", "/oauth2/register", {
    payload: S.OidcRegisterClientPayload,
    success: S.OidcClientCreatedView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.get("oidcListClients", "/oauth2/clients", {
    success: S.OidcClientListView,
    error: [S.NotFoundError, S.UnauthorizedError, S.ForbiddenError, S.InternalError],
  }),
  HttpApiEndpoint.patch("oidcUpdateClient", "/oauth2/clients/:clientId", {
    params: { clientId: Schema.String },
    payload: S.OidcClientUpdatePayload,
    success: S.OidcClientView,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
  HttpApiEndpoint.delete("oidcDeleteClient", "/oauth2/clients/:clientId", {
    params: { clientId: Schema.String },
    success: HttpApiSchema.NoContent,
    error: [
      S.NotFoundError,
      S.UnauthorizedError,
      S.ForbiddenError,
      S.BadRequestError,
      S.InternalError,
    ],
  }),
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
