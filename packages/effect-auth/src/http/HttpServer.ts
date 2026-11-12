import {
  Cause,
  Clock,
  Context,
  DateTime,
  Duration,
  Effect,
  Exit,
  Fiber,
  FileSystem,
  Layer,
  Match,
  Path,
  Result,
  Scheduler,
  Scope,
} from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import * as Str from "effect/String";
import { Base64 } from "effect/encoding";
import { resolveMessage } from "../Messages.ts";
import type { AuthError, UserNotFoundError } from "../Errors.ts";
import { HttpApiBuilder } from "effect/http-api";
import {
  Etag,
  HttpEffect,
  HttpPlatform,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/http";
import { Handlers, Middleware as JsonApiMiddleware } from "@thomasfosterau/effect-jsonapi";
import {
  AuthApi,
  getOpenApiSpec,
  type PendingDocument,
  type SecondFactorVerificationDocument,
  type SignedInDocument,
  type SignInDocument,
} from "./HttpApi.ts";
import * as SessionCookies from "../SessionCookies.ts";
import { ClientIP, resolveClientIP, type TrustedProxyConfig } from "../ClientIP.ts";
import { RateLimiter, type RateLimitConfig } from "../RateLimit.ts";
import { isRecipientSendCapped } from "../RecipientSendLimit.ts";
import { mergeNoStore, noStoreWithSetCookie } from "./CacheControl.ts";
import * as S from "./HttpApiSchema.ts";
import * as JsonApiErrors from "./JsonApiErrors.ts";
import * as R from "./Resources.ts";
import { AuthLifecycleService } from "../AuthLifecycle.ts";
import { Hooks } from "../Hooks.ts";
import { clientAddressKeyedPlugins } from "../HooksClientAddress.ts";
import { SessionService } from "../SessionService.ts";
import { EmailPasswordService } from "../email/EmailPassword.ts";
import * as EmailPassword from "../email/EmailPassword.ts";
import { IdentifierStore, lookupIdentifier, type Identifier } from "../Identifier.ts";
import { MagicLinkService } from "../MagicLink.ts";
import { AccountManagementService } from "../AccountManagement.ts";
import { AnonymousService } from "../Anonymous.ts";
import { PhoneOtpService } from "../PhoneOtp.ts";
import { UsernameService } from "../Username.ts";
import {
  type DeviceCodeError,
  DeviceAuthorizationService,
  normalizeUserCode,
} from "../DeviceAuthorization.ts";
import { EmailOtpService } from "../email/EmailOtp.ts";
import { MultiFactorService } from "../multifactor/MultiFactor.ts";
import { PasswordHasher } from "../password/Password.ts";
import { EmailVerificationService } from "../email/EmailVerification.ts";
import { PasswordResetService } from "../password/PasswordReset.ts";
import { onlyAttributes, UserService } from "../User.ts";
import {
  missingPermission,
  notAMember,
  OrganizationError,
  OrganizationService,
  type Organization,
  type Member,
  type Invitation,
  type Team,
  type TeamMember,
  type OrgRole,
  type OrganizationDomain,
} from "../Organization.ts";
import {
  type AdminError,
  AdminService,
  type BanUserOptions,
  isAdmin,
  type ListUsersQuery,
} from "../Admin.ts";
import {
  ApiKeyService,
  type ApiKey,
  type ApiKeyCreateOptions,
  type ApiKeyError,
  type ApiKeyUpdate,
} from "../ApiKey.ts";
import { type CredentialClass } from "../Authorizer.ts";
import { extractApiKey, fromHeaders } from "../SessionResolution.ts";
import { JwtService } from "../Jwt.ts";
import {
  OidcProviderService,
  type OidcClient,
  type OidcClientMetadata,
  type OidcProviderError,
  type OidcRegistrationError,
  type RegisterOidcClientInput,
  type UpdateOidcClientInput,
} from "../OidcProvider.ts";
import {
  type RegisterProviderInput,
  type RegisterSamlProviderInput,
  SsoService,
  type SsoError,
  type SsoProvider,
  type SsoSignInSelector,
} from "../Sso.ts";
import {
  ScimService,
  type ScimError,
  type ScimGroupInput,
  type ScimGroupResource,
  type ScimListQuery,
  type ScimUserInput,
  type ScimUserResource,
} from "../Scim.ts";
import type * as Errors from "../Errors.ts";
import {
  ClientAddressConfigError,
  RateLimiterConfigError,
  ServicesBuildPendingError,
} from "../Errors.ts";
import { hashToken } from "../TokenHash.ts";
import { GoogleOneTapService } from "../GoogleOneTap.ts";
import {
  decodeSessionCacheCookie,
  sessionCacheGateAttributes,
  encodeSessionCacheCookie,
  resolveSessionCache,
  type ResolvedSessionCache,
  type SessionCacheConfig,
} from "../SessionCookieCache.ts";
import * as Types from "../Types.ts";

/**
 * The services the auth handlers require. Your `services` layer must provide
 * all of these (a superset is fine): the core orchestration services plus the
 * `Hooks` service (provide `Hooks.Default` for no-op hooks, or a
 * `composePlugins([...])` stack). Every service here resolves its own
 * stores at Layer-construction time (`R = never`); compose each store into
 * the corresponding service's own `.layer(config)` call rather than
 * providing it here — e.g.
 * `EmailPasswordService.layer(cfg).pipe(Layer.provide(emailPasswordStore))`.
 *
 * `IdentifierStore` is the one exception: some handlers (e.g.
 * `sendVerificationEmail`, `listIdentifiers`) read it directly.
 */
export type AuthServices =
  | AuthLifecycleService
  | SessionService
  | EmailPasswordService
  | IdentifierStore
  | PasswordHasher
  | EmailVerificationService
  | PasswordResetService
  | UserService
  | Hooks;

/**
 * Server implementation for the auth HTTP contract.
 *
 * `make` turns the contract + your service layer into a standard
 * Web `Request => Response` handler that any framework can mount. Handlers call
 * the existing Effect services; the session cookie and session resolution are
 * handled here so framework integrations no longer hand-roll them.
 */

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * Response header name used by bearer mode to deliver the raw session token.
 *
 * When `bearerMode` is enabled, every session-issuing response carries this
 * header so native/mobile/CLI clients can store the token and present it as
 * `Authorization: Bearer <token>` on subsequent requests.
 */
export const BEARER_TOKEN_HEADER = "set-auth-token" as const;

// -----------------------------------------------------------------------------
// Cookie configuration
// -----------------------------------------------------------------------------

/**
 * Session cookie settings for the HTTP API.
 */
export interface CookieConfig {
  /** Cookie name. Default `conduit_session`. */
  readonly name?: string;
  /** Mark the cookie `Secure`. Default `true` (set `false` for local http). */
  readonly secure?: boolean;
  /** Cookie path. Default `/`. */
  readonly path?: string;
  /**
   * Apply the `__Host-` cookie name prefix for added security. When active the
   * browser enforces that the cookie is `Secure`, has no `Domain` attribute,
   * and has `Path=/`. Defaults to `true` when `secure` is `true` and `path`
   * is `/` (or not set). Set to `false` to opt out.
   *
   * Note: enabling this when `path` is not `/` forces the cookie path to `/`
   * so the prefix constraint is satisfied.
   */
  readonly hostPrefix?: boolean;
  /**
   * Signed session-data cookie cache. When enabled, a short-lived HMAC-signed
   * copy of the session + user is stored in a `${name}_data` cookie so
   * authenticated requests can be served without a session-store read (up to
   * `maxAge`). See {@link SessionCacheConfig}.
   */
  readonly cache?: SessionCacheConfig;
  /**
   * Record the sign-in method in a NON-httpOnly `${name}_last_method` cookie
   * whenever a sign-in endpoint issues a session, so login pages can
   * highlight the user's previous method (`"email-password"`,
   * `"magic-link"`, `"sso"`, ...). Pass `true` for a 30-day cookie or an
   * object to tune the lifetime. Pair with `LastLoginMethodPlugin` to
   * also record the method into `session.attributes.method` server-side.
   */
  readonly lastLoginMethod?: boolean | { readonly maxAge?: number };
  /**
   * Issue the raw session token in a `set-auth-token` response header on
   * every session-issuing endpoint (sign-in, sign-up, magic-link verify,
   * OTP verify, OAuth callback, …) in addition to the normal `Set-Cookie`.
   *
   * Whatever the mode, no response body carries the token: every session
   * resource is named by its stored id, the token's digest (#581).
   *
   * - `false` (default): sessions are issued only via httpOnly cookies.
   *   The httpOnly flag prevents client-side JavaScript from reading the
   *   token — the strongest option for browser clients.
   *
   * - `true` / `"always"`: every session-issuing response also carries
   *   `set-auth-token: <raw-token>`. The client **must** store this token
   *   in secure platform storage (iOS Keychain,
   *   Android EncryptedSharedPreferences, OS credential store) and present
   *   it as `Authorization: Bearer <token>` on subsequent requests.
   *   ⚠ The token is exposed outside the httpOnly boundary — suitable for
   *   native mobile/desktop/CLI clients where httpOnly cookies are
   *   unavailable. Do not use for browser clients without understanding the
   *   XSS exposure.
   *
   * - `"opt-in"`: same as `"always"`, but only when the incoming request
   *   includes an `x-use-bearer: 1` header. A single server can serve both
   *   browser (cookie) and native (bearer) clients without a separate
   *   deployment.
   *
   * CSRF note: bearer-token clients that omit the `Origin` or `Referer`
   * header bypass the CSRF origin check and are implicitly allowed. This is
   * safe because bearer tokens are not vulnerable to CSRF — a cross-site
   * request cannot attach a custom `Authorization` header.
   *
   * CORS note: if you serve browser-based native clients (e.g. Electron or
   * Capacitor) across origins, add `Access-Control-Expose-Headers:
   * set-auth-token` in your CORS middleware so JavaScript can read the
   * header from cross-origin responses.
   */
  readonly bearerMode?: boolean | "always" | "opt-in";
  /**
   * The header names `GET /api-keys/current` reads a machine API key from, the
   * first non-empty one winning. Default `["x-api-key"]`. A key is never read
   * from the URL or the query. This is `SessionResolution.CredentialConfig`'s
   * `apiKeyHeaders`: pass the same value to `RemoteSession.make`'s
   * `credentials` so the edge and the auth service agree on where the key is.
   */
  readonly apiKeyHeaders?: ReadonlyArray<string> | undefined;
}

/** Multiple concurrent accounts per client (device-scoped session list). */
export interface MultiSessionConfig {
  /** Maximum concurrent sessions retained per device. Default 5. */
  readonly maximumSessions?: number;
}

/**
 * A {@link CookieConfig} with every default applied, as the handlers use it.
 *
 * @internal
 */
export interface ResolvedCookieConfig {
  readonly name: string;
  readonly secure: boolean;
  readonly path: string;
  readonly cache: ResolvedSessionCache | undefined;
  readonly multiSession: { readonly maximumSessions: number } | undefined;
  readonly lastLoginMethod: { readonly maxAge: number } | undefined;
  readonly bearerMode: "always" | "opt-in" | false;
  readonly apiKeyHeaders: ReadonlyArray<string> | undefined;
}

/**
 * Apply the defaults to a {@link CookieConfig} (and the multi-session settings).
 *
 * @internal
 */
export const resolveCookieConfig = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
): ResolvedCookieConfig => {
  // Name/path/secure derivation lives in `SessionCookies` so an app edge can
  // run the SAME derivation to learn which cookie to look for, without
  // restating the `__Host-` rule. There is deliberately only one copy.
  const naming = SessionCookies.resolveNaming(config);
  const bm = config?.bearerMode;
  return {
    name: naming.name,
    secure: naming.secure,
    path: naming.path,
    cache: resolveSessionCache(config?.cache),
    multiSession:
      multiSession === undefined
        ? undefined
        : { maximumSessions: multiSession.maximumSessions ?? 5 },
    lastLoginMethod:
      config?.lastLoginMethod === undefined || config.lastLoginMethod === false
        ? undefined
        : {
            maxAge:
              (config.lastLoginMethod === true ? undefined : config.lastLoginMethod.maxAge) ??
              30 * 24 * 60 * 60 * 1000,
          },
    bearerMode: bm === true || bm === "always" ? "always" : bm === "opt-in" ? "opt-in" : false,
    apiKeyHeaders: config?.apiKeyHeaders,
  };
};

/** Name of the non-httpOnly last-login-method hint cookie. */
const lastMethodCookieName = (cfg: ResolvedCookieConfig): string => `${cfg.name}_last_method`;

/** Options for the last-login-method hint cookie: readable by page scripts. */
const lastMethodCookieOptions = (cfg: ResolvedCookieConfig, maxAge: number) =>
  ({
    httpOnly: false,
    sameSite: "lax",
    secure: cfg.secure,
    path: cfg.path,
    maxAge: Math.floor(maxAge / 1000),
  }) as const;

/** Name of the device session-list cookie. */
const multiCookieName = (cfg: ResolvedCookieConfig): string => `${cfg.name}_multi`;

/** Parse the comma-separated device session-id list from the request. */
const readDeviceSessionIds = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): string[] => {
  const raw = request.cookies[multiCookieName(cfg)];
  if (raw === undefined || raw === "") return [];
  // "." separates ids: safe inside a cookie value (session ids are hex /
  // base64url) and, unlike ",", it doesn't confuse Set-Cookie parsing.
  return raw.split(".").filter(Str.isNonEmpty);
};

/**
 * Name of the companion session-data cache cookie (`<name>_data`).
 *
 * @internal
 */
export const dataCookieName = (cfg: ResolvedCookieConfig): string => `${cfg.name}_data`;

const dataCookieOptions = (cfg: ResolvedCookieConfig, cache: ResolvedSessionCache) =>
  ({
    httpOnly: true,
    sameSite: "lax",
    secure: cfg.secure,
    path: cfg.path,
    maxAge: Math.floor(cache.maxAge / 1000),
  }) as const;

const sessionCookieOptions = (cfg: ResolvedCookieConfig, expiresAt: Date) =>
  ({
    httpOnly: true,
    sameSite: "lax",
    secure: cfg.secure,
    path: cfg.path,
    expires: expiresAt,
  }) as const;

/** Options for a browser-session cookie (cleared on browser close, no Max-Age/Expires). */
const sessionOnlyCookieOptions = (cfg: ResolvedCookieConfig) =>
  ({
    httpOnly: true,
    sameSite: "lax",
    secure: cfg.secure,
    path: cfg.path,
  }) as const;

const clearCookieOptions = (cfg: ResolvedCookieConfig) =>
  ({
    httpOnly: true,
    sameSite: "lax",
    secure: cfg.secure,
    path: cfg.path,
    maxAge: 0,
  }) as const;

// -----------------------------------------------------------------------------
// Session resolution (Authorization header, then cookie)
// -----------------------------------------------------------------------------

/**
 * Read the raw session token from a request's `Authorization: Bearer` (or `Token`) header or session cookie.
 *
 * @internal
 */
export const sessionIdFromRequest = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): string | undefined => {
  const auth = request.headers["authorization"];
  if (auth) {
    const [scheme, value] = auth.split(" ");
    if ((scheme === "Token" || scheme === "Bearer") && value) return value;
  }
  return request.cookies[cfg.name];
};

/**
 * The {@link CredentialClass} implied by *how* the request carried its
 * credential: the session cookie only a browser sends automatically is
 * "interactive"; an `Authorization: Bearer/Token` header — copy-pasted into
 * a script, a CLI, or a machine caller, the same delivery mechanism a
 * consuming app's own API-key middleware uses — is "machine". Mirrors the
 * branch `sessionIdFromRequest` takes so the two never disagree about which
 * credential a request presented.
 */
export const credentialClassFromRequest = (
  request: HttpServerRequest.HttpServerRequest,
): CredentialClass => {
  const auth = request.headers["authorization"];
  if (auth) {
    const [scheme, value] = auth.split(" ");
    if ((scheme === "Token" || scheme === "Bearer") && value) return "machine";
  }
  return "interactive";
};

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

/**
 * The most the attributes a sign-up keeps (after the
 * {@link AuthWebHandlerOptions.signUpAttributes} allow-list) may take, as JSON
 * text in UTF-8: 4096 bytes (#580). A sign-up whose kept attributes are larger
 * is refused with `400`; keys the allow-list drops never count.
 *
 * @since 0.1.0
 * @category constants
 */
export const SIGN_UP_ATTRIBUTES_MAX_BYTES = 4096;

const encodeJsonText = Schema.encodeSync(Schema.fromJsonString(Schema.Json));
const utf8 = new TextEncoder();

/**
 * The sign-up input for a `POST /users` payload: of its `attributes`, only the
 * keys `allowed` names, and those within {@link SIGN_UP_ATTRIBUTES_MAX_BYTES}
 * (#580). Any other key is dropped without an error, so the answer does not
 * tell a caller which keys the server guards. The services strip the
 * server-only, ban and SCIM keys again, whatever `allowed` names.
 */
const signUpInput = (payload: S.SignUpPayload, allowed: ReadonlyArray<string>) =>
  Effect.gen(function* () {
    const attributes =
      payload.attributes === undefined ? undefined : onlyAttributes(payload.attributes, allowed);
    if (
      attributes !== undefined &&
      utf8.encode(encodeJsonText(attributes)).length > SIGN_UP_ATTRIBUTES_MAX_BYTES
    ) {
      return yield* new S.BadRequest({
        message: `Sign-up attributes must be at most ${SIGN_UP_ATTRIBUTES_MAX_BYTES} bytes as JSON`,
        code: "INVALID_INPUT",
      });
    }
    return {
      email: payload.email,
      password: payload.password,
      ...(payload.name !== undefined && { name: payload.name }),
      ...(attributes !== undefined && { attributes }),
      ...(payload.captchaToken !== undefined && { captchaToken: payload.captchaToken }),
    };
  });

// -----------------------------------------------------------------------------
// Optional feature resolution
//
// Magic link, email OTP and multi-factor are optional plugins: their services
// are NOT part of `AuthServices`. Handlers resolve them with
// `Effect.serviceOption` and answer 404 when absent. Because the service
// METHODS declare their store requirements in `R`, the store tags are
// resolved optionally too and provided into each method call, keeping the
// handlers' `R` inside `AuthServices`.
// -----------------------------------------------------------------------------

/**
 * Resolve an optional service, or fail with 404. Every orchestration service
 * resolves its own stores at Layer-construction time (R = never), so
 * presence of the top-level service tag is the only thing to check here —
 * there is nothing left to provide per-call.
 */
const resolveOptional = <I, S>(tag: Context.Key<I, S>, notEnabledMessage: string) =>
  Effect.gen(function* () {
    const service = yield* Effect.serviceOption(tag);
    if (Option.isNone(service)) {
      return yield* new S.NotFound({ message: notEnabledMessage });
    }
    return { service: service.value };
  });

/** Resolve the magic link service, or fail with 404. */
const resolveMagicLink = resolveOptional(MagicLinkService, "Magic link is not enabled");

/** Resolve the email OTP service, or fail with 404. */
const resolveEmailOtp = resolveOptional(EmailOtpService, "Email OTP is not enabled");

/** Resolve the multi-factor service, or fail with 404. */
const resolveMultiFactor = resolveOptional(
  MultiFactorService,
  "Two-factor authentication is not enabled",
);

/** Resolve the account-management service, or fail with 404. */
const resolveAccountManagement = resolveOptional(
  AccountManagementService,
  "Account management is not enabled",
);

/** Resolve the device-authorization service, or fail with 404. */
const resolveDevice = resolveOptional(
  DeviceAuthorizationService,
  "Device authorization is not enabled",
);

/** Resolve the username service, or fail with 404. */
const resolveUsername = resolveOptional(UsernameService, "Username sign-in is not enabled");

/** Resolve the phone OTP service, or fail with 404. */
const resolvePhoneOtp = resolveOptional(PhoneOtpService, "Phone OTP is not enabled");

/** Resolve the anonymous service, or fail with 404. */
const resolveAnonymous = resolveOptional(AnonymousService, "Anonymous sign-in is not enabled");

/** Resolve the organization service, or fail with 404. */
const resolveOrganization = resolveOptional(OrganizationService, "Organizations are not enabled");

/** Resolve the admin service, or fail with 404. */
const resolveAdmin = resolveOptional(AdminService, "Admin is not enabled");

/** Resolve the API-key service, or fail with 404. */
const resolveApiKey = resolveOptional(ApiKeyService, "API keys are not enabled");

/** Resolve the JWT service, or fail with 404. */
const resolveJwt = resolveOptional(JwtService, "JWT is not enabled");

/** Resolve the SSO service, or fail with 404. */
const resolveSso = resolveOptional(SsoService, "SSO is not enabled");

/** Resolve the Google One Tap service, or fail with 404. */
const resolveGoogleOneTap = resolveOptional(GoogleOneTapService, "Google One Tap is not enabled");

/** Resolve the OIDC provider service, or fail with 404. */
const resolveOidcProvider = resolveOptional(OidcProviderService, "OIDC provider is not enabled");

// --- Encoders for the organization / API-key domain types --------------------

// The stored record leaves the newer fields optional (rows written before they
// existed keep working); the wire view is total, so clients never branch on
// "absent means the default".
/** The `organizations` resource of a stored organization. */
const organizationResource = (o: Organization): R.Organization =>
  R.Organization.make({
    id: o.id,
    attributes: {
      name: o.name,
      slug: o.slug,
      ...(o.logo !== undefined && { logo: o.logo }),
      metadata: o.metadata,
      defaultRole: o.defaultRole ?? "member",
      jitProvisioning: o.jitProvisioning ?? false,
      createdAt: o.createdAt,
    },
  });

/** The `organization-members` resource of a stored membership. */
const memberResource = (m: Member): R.OrganizationMember =>
  R.OrganizationMember.make({
    id: m.id,
    attributes: {
      role: m.role,
      status: m.status ?? "active",
      ...(m.previousRole !== undefined && { previousRole: m.previousRole }),
      createdAt: m.createdAt,
    },
    relationships: {
      organization: { data: R.Organization.ref(m.organizationId) },
      user: { data: R.User.ref(m.userId) },
    },
  });

/** The `organization-domains` resource of a stored domain claim. */
const domainResource = (d: OrganizationDomain): R.OrganizationDomain =>
  R.OrganizationDomain.make({
    id: d.id,
    attributes: {
      domain: d.domain,
      verificationState: d.verificationState,
      verificationStrategy: d.verificationStrategy,
      ...(d.verificationToken !== undefined && { verificationToken: d.verificationToken }),
      createdAt: d.createdAt,
      ...(d.verifiedAt !== undefined && { verifiedAt: d.verifiedAt }),
    },
    relationships: {
      organization: { data: R.Organization.ref(d.organizationId) },
      attester: { data: d.attestedBy === undefined ? null : R.User.ref(d.attestedBy) },
    },
  });

/** The `invitations` resource of a stored invitation. */
const invitationResource = (i: Invitation): R.Invitation =>
  R.Invitation.make({
    id: i.id,
    attributes: {
      email: i.email,
      role: i.role,
      status: i.status,
      expiresAt: i.expiresAt,
      createdAt: i.createdAt,
    },
    relationships: {
      organization: { data: R.Organization.ref(i.organizationId) },
      inviter: { data: R.User.ref(i.inviterId) },
    },
  });

/** The `teams` resource of a stored team. */
const teamResource = (t: Team): R.Team =>
  R.Team.make({
    id: t.id,
    attributes: { name: t.name, createdAt: t.createdAt, updatedAt: t.updatedAt },
    relationships: { organization: { data: R.Organization.ref(t.organizationId) } },
  });

/** The `team-members` resource of a stored team membership. */
const teamMemberResource = (m: TeamMember): R.TeamMember =>
  R.TeamMember.make({
    id: m.id,
    attributes: { createdAt: m.createdAt },
    relationships: {
      team: { data: R.Team.ref(m.teamId) },
      user: { data: R.User.ref(m.userId) },
    },
  });

/** The `organization-roles` resource of a stored custom role definition. */
const orgRoleResource = (r: OrgRole): R.OrganizationRole =>
  R.OrganizationRole.make({
    id: r.id,
    attributes: {
      role: r.role,
      permissions: r.permissions,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    },
    relationships: { organization: { data: R.Organization.ref(r.organizationId) } },
  });

/**
 * The fields of a SAML connection that its registration and its stored record
 * share, each optional one left out when absent.
 */
const samlConnection = <Algorithm extends string>(p: {
  readonly domain: string;
  readonly entityId: string;
  readonly ssoUrl: string;
  readonly idpCertificates: ReadonlyArray<string>;
  readonly spEntityId: string;
  readonly acsUrl: string;
  readonly signatureAlgorithms?: ReadonlyArray<Algorithm> | undefined;
  readonly wantAssertionsSigned?: boolean | undefined;
  readonly wantAuthnResponseSigned?: boolean | undefined;
  readonly forceAuthn?: boolean | undefined;
}) => ({
  protocol: "saml" as const,
  domain: p.domain,
  entityId: p.entityId,
  ssoUrl: p.ssoUrl,
  idpCertificates: p.idpCertificates,
  spEntityId: p.spEntityId,
  acsUrl: p.acsUrl,
  ...(p.signatureAlgorithms !== undefined && { signatureAlgorithms: p.signatureAlgorithms }),
  ...(p.wantAssertionsSigned !== undefined && { wantAssertionsSigned: p.wantAssertionsSigned }),
  ...(p.wantAuthnResponseSigned !== undefined && {
    wantAuthnResponseSigned: p.wantAuthnResponseSigned,
  }),
  ...(p.forceAuthn !== undefined && { forceAuthn: p.forceAuthn }),
});

/**
 * The attributes of an SSO connection's `sso-providers` resource, one arm of
 * the `protocol` union at a time. Neither arm carries a secret: the OIDC arm
 * drops `clientSecret`, and both drop the registrar's `userId`.
 */
const ssoProviderAttributes = (p: SsoProvider): R.SsoProvider["attributes"] =>
  p.protocol === "saml"
    ? { ...samlConnection(p), createdAt: p.createdAt }
    : {
        issuer: p.issuer,
        domain: p.domain,
        protocol: p.protocol,
        clientId: p.clientId,
        redirectUri: p.redirectUri,
        authorizationEndpoint: p.authorizationEndpoint,
        tokenEndpoint: p.tokenEndpoint,
        ...(p.userInfoEndpoint !== undefined && { userInfoEndpoint: p.userInfoEndpoint }),
        ...(p.jwksEndpoint !== undefined && { jwksEndpoint: p.jwksEndpoint }),
        scopes: p.scopes,
        createdAt: p.createdAt,
      };

/** The `sso-providers` resource of a connection, its `organizationId` as a relationship. */
const ssoProviderResource = (provider: SsoProvider): R.SsoProvider =>
  R.SsoProvider.make({
    id: provider.id,
    attributes: ssoProviderAttributes(provider),
    relationships: {
      organization: {
        data:
          provider.organizationId === undefined
            ? null
            : R.Organization.ref(provider.organizationId),
      },
    },
  });

/**
 * The `oauth-clients` resource of a registered client: never the secret's
 * hash, the registration metadata or the registrar. JSON:API reserves `type`,
 * so the client's own type travels as `clientType`.
 */
const oauthClientResource = (c: OidcClient): R.OAuthClient =>
  R.OAuthClient.make({
    id: c.clientId,
    attributes: {
      name: c.name,
      redirectUris: c.redirectUris,
      clientType: c.type,
      skipConsent: c.skipConsent,
      disabled: c.disabled,
      metadata: c.metadata,
      createdAt: c.createdAt,
      updatedAt: c.updatedAt,
    },
  });

/**
 * Encode a client as an RFC 7591 §3.2.1 client information response. The
 * one-time `client_secret` / `registration_access_token` are added by the
 * registration handler; everything here is readable from the stored client.
 */
const encodeOidcRegistration = (
  c: OidcClient,
  registrationEndpoint: string,
): S.OidcRegistrationView => ({
  client_id: c.clientId,
  client_id_issued_at: Math.floor(c.createdAt / 1000),
  client_name: c.name,
  redirect_uris: c.redirectUris,
  grant_types: c.grantTypes ?? ["authorization_code"],
  response_types: c.responseTypes ?? ["code"],
  token_endpoint_auth_method:
    c.tokenEndpointAuthMethod ??
    (c.clientSecretHash === undefined ? "none" : "client_secret_basic"),
  scope: c.scope ?? "",
  registration_client_uri: `${registrationEndpoint}/${c.clientId}`,
});

/**
 * Map an `OidcRegistrationError` onto the HTTP contract: RFC 7591 §3.2.2 keeps
 * metadata failures at 400 with an `{ error, error_description }` body, while
 * `invalid_token` (RFC 7592 §2) is a 401 and `access_denied` a 403 — both in
 * this API's usual error shape, with the OAuth code carried in `code`.
 */
const registrationError = (
  e: OidcRegistrationError,
): Effect.Effect<never, S.OAuthError | S.Unauthorized | S.Forbidden> => {
  const message = e.description ?? e.error;
  if (e.error === "invalid_token") {
    return Effect.fail(new S.Unauthorized({ message, code: e.error }));
  }
  if (e.error === "access_denied") {
    return Effect.fail(new S.Forbidden({ message, code: e.error }));
  }
  return Effect.fail(
    new S.OAuthError({
      error: e.error,
      ...(e.description !== undefined && { error_description: e.description }),
    }),
  );
};

/** The `Authorization: Bearer` value of a request, if any. */
const bearerToken = (request: HttpServerRequest.HttpServerRequest): string | undefined => {
  const auth = request.headers["authorization"];
  return auth !== undefined && auth.startsWith("Bearer ") ? auth.slice(7) : undefined;
};

/**
 * The RFC 7591 registration endpoint the provider advertises (always a string
 * in its RFC 8414 metadata), for the `registration_client_uri` it echoes.
 */
const registrationEndpointOf = (service: typeof OidcProviderService.Service): string => {
  const endpoint = service.getAuthorizationServerMetadata()["registration_endpoint"];
  return P.isString(endpoint) ? endpoint : "";
};

/**
 * Guard the RFC 7592 management endpoints: 404 when management is switched
 * off, 401 when the caller presents no registration access token at all (the
 * token itself is verified by the service, in constant time).
 */
const requireRegistrationAccessToken = (
  service: typeof OidcProviderService.Service,
  request: HttpServerRequest.HttpServerRequest,
): Effect.Effect<string, S.NotFound | S.Unauthorized> =>
  Effect.gen(function* () {
    if (!service.dynamicRegistration.management) {
      return yield* new S.NotFound({
        message: "Dynamic client registration management is not enabled",
      });
    }
    const token = bearerToken(request);
    if (token === undefined) {
      return yield* new S.Unauthorized({
        message: "Missing registration access token",
        code: "invalid_token",
      });
    }
    return token;
  });

/** Decode an RFC 7591 registration body into the service's camelCase input. */
const registrationMetadata = (payload: S.OidcRegistrationPayload): OidcClientMetadata => ({
  redirectUris: payload.redirect_uris,
  ...(payload.token_endpoint_auth_method !== undefined && {
    tokenEndpointAuthMethod: payload.token_endpoint_auth_method,
  }),
  ...(payload.grant_types !== undefined && { grantTypes: payload.grant_types }),
  ...(payload.response_types !== undefined && { responseTypes: payload.response_types }),
  ...(payload.client_name !== undefined && { clientName: payload.client_name }),
  ...(payload.scope !== undefined && { scope: payload.scope }),
});

/**
 * The `api-keys` resource of a stored key, its owner as `user`: never the
 * key's hash or its refill bookkeeping.
 */
const apiKeyResource = (k: ApiKey): R.ApiKey =>
  R.ApiKey.make({
    id: k.id,
    attributes: {
      ...(k.name !== undefined && { name: k.name }),
      ...(k.prefix !== undefined && { prefix: k.prefix }),
      start: k.start,
      enabled: k.enabled,
      ...(k.expiresAt !== undefined && { expiresAt: k.expiresAt }),
      ...(k.lastUsedAt !== undefined && { lastUsedAt: k.lastUsedAt }),
      ...(k.permissions !== undefined && { permissions: k.permissions }),
      metadata: k.metadata,
      ...(k.remaining !== undefined && { remaining: k.remaining }),
      ...(k.rateLimit !== undefined && { rateLimit: k.rateLimit }),
      createdAt: k.createdAt,
      updatedAt: k.updatedAt,
    },
    relationships: { user: { data: R.User.ref(k.userId) } },
  });

/**
 * Log the real error server-side and return a generic 500 body so internal
 * implementation details are never exposed to clients.
 */
const internalServerError = (
  e: Cause.YieldableError,
): Effect.Effect<never, S.InternalServerError> =>
  Effect.logError("[effect-auth] internal error", e).pipe(
    Effect.flatMap(() =>
      Effect.fail(new S.InternalServerError({ message: "Internal server error" })),
    ),
  );

/**
 * An OIDC provider call's failures as the client sees them: a refusal is a
 * `400` carrying its message, an infrastructure failure a generic `500`.
 */
const oidcProviderFailures = <A, R>(
  effect: Effect.Effect<A, OidcProviderError | AuthError, R>,
): Effect.Effect<A, S.BadRequest | S.InternalServerError, R> =>
  effect.pipe(
    Effect.catchTags({
      OidcProviderError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
      AuthError: (e) => internalServerError(e),
    }),
  );

/**
 * Answer a lookup of the signed-in caller's own account: a user that has gone
 * since the session was resolved is `401`, a store failure a generic `500`.
 */
const asCaller = <A, R>(
  self: Effect.Effect<A, UserNotFoundError | AuthError, R>,
): Effect.Effect<A, S.Unauthorized | S.InternalServerError, R> =>
  Effect.catchTags(self, {
    UserNotFoundError: () => Effect.fail(new S.Unauthorized({ message: "Not authenticated" })),
    AuthError: (e) => internalServerError(e),
  });

/**
 * Answer an RFC 7591 / 7592 registration call: a registration refusal is the
 * RFC's error response (see `registrationError`), a store failure a generic
 * `500`.
 */
const asRegistration = <A, R>(
  self: Effect.Effect<A, OidcRegistrationError | AuthError, R>,
): Effect.Effect<A, S.OAuthError | S.Unauthorized | S.Forbidden | S.InternalServerError, R> =>
  Effect.catchTags(self, {
    OidcRegistrationError: registrationError,
    AuthError: (e) => internalServerError(e),
  });

/**
 * Per-user-code rate limit for device-authorization approve/deny endpoints
 * (RFC 8628 §5.2), through the `RateLimiter` in scope. `make` refuses to build
 * a handler whose `services` hold the device service and no `RateLimiter`
 * (#389). Outside `make` (the exported group layers composed by hand), a
 * request with no `RateLimiter` in scope is refused with `429`, unless the
 * device service was built with `allowMissingRateLimiter: true`.
 */
const USER_CODE_RATE_LIMIT: RateLimitConfig = {
  maxRequests: 5,
  windowMs: 15 * 60 * 1000,
  blockDurationMs: 30 * 60 * 1000,
};

/** The JWT service's public keys as a JWK Set (`/jwks` and the OIDC provider's). */
const jwksDocument = Effect.fn("HttpServer.jwksDocument")(function* () {
  const jwt = yield* resolveJwt;
  const jwks = yield* jwt.service
    .getJwks()
    .pipe(Effect.catchTags({ AuthError: (e) => internalServerError(e) }));
  return { keys: [...jwks.keys] };
});

/**
 * Consume one token from `key`'s bucket, answering `429` when the bucket is
 * spent and `500` when the limiter's store fails.
 */
const consumeRateLimitToken = (
  rateLimiter: typeof RateLimiter.Service,
  key: string,
  limit: RateLimitConfig,
): Effect.Effect<void, S.TooManyRequests | S.InternalServerError> =>
  rateLimiter.consumeToken(key, limit).pipe(
    Effect.catchTags({
      RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
      AuthError: (e) => internalServerError(e),
    }),
  );

const applyUserCodeRateLimit = (
  userCode: string,
  device: typeof DeviceAuthorizationService.Service,
): Effect.Effect<void, S.TooManyRequests | S.InternalServerError> =>
  Effect.gen(function* () {
    const rateLimiterOpt = yield* Effect.serviceOption(RateLimiter);
    if (Option.isNone(rateLimiterOpt)) {
      // The app opted out of the limit explicitly; nothing else skips it.
      if (device.allowMissingRateLimiter === true) return yield* Effect.void;
      return yield* refuseWithoutRateLimiter("the device user-code limit");
    }
    const key = `device-user-code:${normalizeUserCode(userCode)}`;
    return yield* consumeRateLimitToken(rateLimiterOpt.value, key, USER_CODE_RATE_LIMIT);
  });

/**
 * The refusal message when a request reaches a rate-limited endpoint with no
 * client address. The limiter cannot key such a request, so it is refused
 * rather than skipped or counted under a bucket that other callers share.
 */
const NO_CLIENT_ADDRESS = "Client address unavailable; this request cannot be rate limited";

/** The refusal message when a rate-limited request finds no `RateLimiter` in scope. */
const NO_RATE_LIMITER = "No RateLimiter in services; this request cannot be rate limited";

/**
 * Refuse a request whose limit has no `RateLimiter` to run on (#389). The
 * refusal is the same `429` as a request with no client address: the request
 * cannot be rate limited, so it is not served. The misconfiguration is logged.
 */
const refuseWithoutRateLimiter = (limit: string): Effect.Effect<never, S.TooManyRequests> =>
  Effect.logError(
    `[effect-auth] ${limit} is configured with no RateLimiter in services; the request is refused`,
  ).pipe(Effect.andThen(Effect.fail(new S.TooManyRequests({ message: NO_RATE_LIMITER }))));

/**
 * Per-IP rate limit for anonymous dynamic client registration, through the
 * `RateLimiter` in scope. The window comes from the provider's own
 * configuration. `make` refuses to build a handler whose `services` enable
 * registration with no `RateLimiter` (#389); outside `make`, a registration
 * with no `RateLimiter` in scope is refused with `429`.
 *
 * A caller with no resolvable client address (or no `ClientIP` service in
 * scope) is refused, never keyed under a shared bucket and never let through
 * uncounted (#358).
 */
const applyRegistrationRateLimit = (
  limit: RateLimitConfig,
): Effect.Effect<void, S.TooManyRequests | S.InternalServerError> =>
  Effect.gen(function* () {
    const rateLimiterOpt = yield* Effect.serviceOption(RateLimiter);
    if (Option.isNone(rateLimiterOpt)) {
      return yield* refuseWithoutRateLimiter("the dynamic client registration limit");
    }
    const clientIp = yield* Effect.serviceOption(ClientIP);
    const ip = Option.isSome(clientIp) ? clientIp.value.ip : undefined;
    if (ip === undefined) return yield* new S.TooManyRequests({ message: NO_CLIENT_ADDRESS });
    return yield* consumeRateLimitToken(rateLimiterOpt.value, `oidc-register:${ip}`, limit);
  });

/**
 * What a `ClientAddressConfigError` adds when `allowMissingClientIp: true` is
 * set (#682): the option is no address source. With no `trustedProxy`, a Web
 * `Request` under `Http.make` never has an address, so the limit would refuse
 * every request it covers with `429`; the handler refuses to start instead.
 */
const allowMissingClientIpNote = (options: AuthWebHandlerOptions): string =>
  options.allowMissingClientIp === true
    ? " allowMissingClientIp: true does not stand in for trustedProxy: with no proxy no request has an address, " +
      "so every request the limit covers would be refused with 429."
    : "";

/**
 * The `IPRateLimitPlugin` half of the client-address check (#389): the `Hooks`
 * include a plugin that keys on the client address and there is no
 * `trustedProxy`.
 */
const keyedPluginAddressError = (
  services: Context.Context<never>,
  options: AuthWebHandlerOptions,
): ClientAddressConfigError | undefined => {
  const hooks = Context.getOption(services, Hooks);
  const keyed = Option.isSome(hooks) ? clientAddressKeyedPlugins(hooks.value) : [];
  if (Arr.isReadonlyArrayEmpty(keyed)) return undefined;
  return new ClientAddressConfigError({
    message:
      `${keyed.join(", ")} keys its limits on the client address, and a Web Request has none under Http.make or Http.makeAsync. ` +
      "Set trustedProxy (for example ClientIP.cloudflare) to key the limits by the visitor's address." +
      allowMissingClientIpNote(options),
  });
};

/**
 * The dynamic client registration half of the client-address check: the
 * registration limit keys on the `ClientIP` this handler resolves from
 * `trustedProxy`, so registration needs the same address source (#388, #398).
 */
const registrationAddressError = (
  services: Context.Context<never>,
  options: AuthWebHandlerOptions,
): ClientAddressConfigError | undefined => {
  const oidc = Context.getOption(services, OidcProviderService);
  if (Option.isNone(oidc) || !oidc.value.dynamicRegistration.enabled) return undefined;
  return new ClientAddressConfigError({
    message:
      "Dynamic client registration (POST /register) is rate limited per client address, and a Web Request has none under Http.make or Http.makeAsync. " +
      "Set trustedProxy (for example ClientIP.cloudflare) to key the limit by the visitor's address." +
      allowMissingClientIpNote(options),
  });
};

/**
 * The limits configured with no `RateLimiter` in `services` (#389):
 * `ipRateLimit`, dynamic client registration, or the device user-code limit
 * (whenever the device service is present, unless it opted out with
 * `allowMissingRateLimiter`).
 */
const rateLimiterError = (
  services: Context.Context<never>,
  options: AuthWebHandlerOptions,
): RateLimiterConfigError | undefined => {
  if (Option.isSome(Context.getOption(services, RateLimiter))) return undefined;
  const oidc = Context.getOption(services, OidcProviderService);
  const device = Context.getOption(services, DeviceAuthorizationService);
  const configured = [
    ...(options.ipRateLimit === false ? [] : ["ipRateLimit (on by default)"]),
    ...(Option.isSome(oidc) && oidc.value.dynamicRegistration.enabled
      ? ["the dynamic client registration limit (POST /register)"]
      : []),
    ...(Option.isSome(device) && device.value.allowMissingRateLimiter !== true
      ? ["the device user-code limit (approve and deny)"]
      : []),
  ];
  if (Arr.isReadonlyArrayEmpty(configured)) return undefined;
  return new RateLimiterConfigError({
    message:
      `${configured.join(", ")} configured with no RateLimiter in services, so the limit could not run. ` +
      "Compose RateLimiter.layer() with its RateLimitStore into services, or remove the limit " +
      "(ipRateLimit: false; for the device user-code limit, DeviceAuthorizationConfig.allowMissingRateLimiter: true).",
  });
};

/**
 * The build-time check of `make`'s `services` (#389). Returns the error `make`
 * raises, or `undefined` when the services are consistent with the options:
 *
 * - The `Hooks` include a plugin that keys on the client address
 *   (`IPRateLimitPlugin`), or the OIDC provider enables dynamic client
 *   registration, and there is no `trustedProxy`. A Web `Request` has no
 *   socket address, and `allowMissingClientIp: true` is no address source
 *   (#682).
 * - A limit is configured with no `RateLimiter` ({@link rateLimiterError}).
 */
const servicesConfigError = (
  services: Context.Context<never>,
  options: AuthWebHandlerOptions,
): ClientAddressConfigError | RateLimiterConfigError | undefined =>
  (options.trustedProxy === undefined
    ? (keyedPluginAddressError(services, options) ?? registrationAddressError(services, options))
    : undefined) ?? rateLimiterError(services, options);

/**
 * The same check as a layer, for `services` that finish building only after
 * `make` returns (asynchronous work while building). `make` cannot throw then,
 * so the handler's build fails with the error and every request rejects with
 * it. When the services build synchronously, `make` has already thrown, and
 * `makeAsync` waits for the build, so it never needs this layer.
 */
const requireServicesConfig = (options: AuthWebHandlerOptions) =>
  Layer.effectDiscard(
    Effect.gen(function* () {
      const error = servicesConfigError(yield* Effect.context(), options);
      if (error === undefined) return yield* Effect.void;
      yield* Effect.logError(error.message);
      return yield* error;
    }),
  );

/**
 * A dispatcher that holds its tasks, by priority as Effect's own dispatcher
 * does, until `run` runs them or `handOver` moves them to another dispatcher.
 */
class HeldDispatcher implements Scheduler.SchedulerDispatcher {
  // Tasks by ascending priority, first in first out within a priority.
  private queued: Array<[priority: number, tasks: Array<() => void>]> = [];
  private target: Scheduler.SchedulerDispatcher | undefined;

  scheduleTask(task: () => void, priority: number): void {
    if (this.target !== undefined) return this.target.scheduleTask(task, priority);
    this.enqueue(task, priority, false);
  }

  flush(): void {
    // While held, only `run` runs the queue. A caller that flushes to finish
    // synchronously sees no exit and takes its asynchronous path.
    this.target?.flush();
  }

  /**
   * Run the queued tasks until `fiber` has an exit or nothing is queued. Like
   * Effect's dispatcher, it runs what is queued as one batch, so a task
   * scheduled while a batch runs waits for the next one. Returns whether it
   * ran a task.
   */
  run(fiber: Fiber.Fiber<unknown, unknown>): boolean {
    // `unfold` steps one batch at a time, so the batch count never grows the
    // stack.
    const batches = Arr.unfold(undefined, () =>
      this.target === undefined && fiber.pollUnsafe() === undefined
        ? Option.map(this.runBatch(fiber), (ran) => [ran, undefined] as const)
        : Option.none(),
    );
    return Arr.isReadonlyArrayNonEmpty(batches);
  }

  /** Run what is queued as one batch; `None` when nothing is queued. */
  private runBatch(fiber: Fiber.Fiber<unknown, unknown>): Option.Option<true> {
    const batch = this.queued.flatMap(([priority, tasks]) =>
      tasks.map((task) => [priority, task] as const),
    );
    if (Arr.isReadonlyArrayEmpty(batch)) return Option.none();
    this.queued = [];
    let next = 0;
    // `every` stops at the first task that finds `fiber` finished; a task
    // that throws stops the batch too, and the throw is rethrown below.
    const outcome = Result.try(() =>
      batch.every(([, task]) => {
        if (fiber.pollUnsafe() !== undefined) return false;
        next++;
        task();
        return true;
      }),
    );
    // The batch's unrun tasks go back ahead of those scheduled since.
    Arr.reverse(Arr.drop(batch, next)).forEach(([priority, task]) =>
      this.enqueue(task, priority, true),
    );
    if (Result.isFailure(outcome)) throw outcome.failure;
    return Option.some(true);
  }

  /** Move the queued tasks, and every task scheduled from now on, to `target`. */
  handOver(target: Scheduler.SchedulerDispatcher): void {
    if (this.target !== undefined) return;
    this.target = target;
    const queued = this.queued;
    this.queued = [];
    queued.forEach(([priority, tasks]) =>
      tasks.forEach((task) => target.scheduleTask(task, priority)),
    );
  }

  private enqueue(task: () => void, priority: number, first: boolean): void {
    // The first bucket at or above `priority`, or the end when there is none.
    const found = this.queued.findIndex(([bucketPriority]) => bucketPriority >= priority);
    const index = found === -1 ? this.queued.length : found;
    const bucket = this.queued[index];
    if (bucket !== undefined && bucket[0] === priority) {
      if (first) bucket[1].unshift(task);
      else bucket[1].push(task);
    } else {
      this.queued.splice(index, 0, [priority, [task]]);
    }
  }
}

/** An effect {@link runSynchronously} runs: its fiber, and how to drive it. */
interface SynchronousRun<A, E> {
  readonly fiber: Fiber.Fiber<A, E>;
  readonly run: () => boolean;
  readonly release: () => void;
}

/**
 * Run `effect` synchronously as far as it can go, the way `Effect.runSync`
 * does, without the fibers it forks staying on a synchronous scheduler (#389,
 * #402). `make` uses it to build `services` and to close them.
 *
 * Only the effect's own fiber runs synchronously: `run` runs the tasks it
 * schedules (yields, the start of a fiber it forks) until it has an exit, or
 * until it has nothing queued because it waits on asynchronous work or on
 * another fiber. Every other fiber runs on the default scheduler, so a
 * long-lived fiber a layer forks (a busy loop, a background job) cannot keep
 * `make` from returning, and does not starve the event loop as fibers forked
 * under `Effect.runSync` do (they run on microtasks).
 *
 * `run` returns whether it ran a task, so a caller driving two of these at
 * once can tell when neither makes progress. `release` hands what the effect's
 * fiber still has queued to the default scheduler, so whatever is left running
 * carries on as it would without this.
 */
const runSynchronously = <A, E>(effect: Effect.Effect<A, E>): SynchronousRun<A, E> => {
  const base = new Scheduler.MixedScheduler();
  // Dispatchers made before the fiber's own is known: one is its, and the rest
  // belong to fibers it forked while it started.
  const held: Array<HeldDispatcher> = [];
  let started = false;
  const scheduler: Scheduler.Scheduler = {
    executionMode: "async",
    shouldYield: (fiber) => base.shouldYield(fiber),
    makeDispatcher: () => {
      if (started) return base.makeDispatcher();
      const dispatcher = new HeldDispatcher();
      held.push(dispatcher);
      return dispatcher;
    },
  };
  const fiber = Effect.runFork(effect, { scheduler });
  // Reading it makes the fiber's dispatcher if it has none yet, so it is held.
  const own = fiber.currentDispatcher;
  started = true;
  held.forEach((dispatcher) => {
    if (dispatcher !== own) dispatcher.handOver(base.makeDispatcher());
  });
  return {
    fiber,
    run: () => own instanceof HeldDispatcher && own.run(fiber),
    release: () => {
      if (own instanceof HeldDispatcher) own.handOver(base.makeDispatcher());
    },
  };
};

// -----------------------------------------------------------------------------
// JSON:API resource groups (#205)
// -----------------------------------------------------------------------------

/**
 * `response` with `no-store` merged into its `Cache-Control` (#628): kept as
 * it is when it already has `no-store`, else with `no-store` appended.
 */
const withNoStore = (
  response: HttpServerResponse.HttpServerResponse,
): HttpServerResponse.HttpServerResponse =>
  HttpServerResponse.setHeader(
    response,
    "cache-control",
    mergeNoStore(response.headers["cache-control"]),
  );

/**
 * Mark the response a handler is about to send `no-store`, whatever it turns
 * out to be: for the bodies that hand a credential over (#628).
 */
const noStore: Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =
  HttpEffect.appendPreResponseHandler((_request, response) =>
    Effect.succeed(withNoStore(response)),
  );

/**
 * Set a cookie on the response a JSON:API handler is about to send, so the
 * handler can still answer with its typed document. The response is marked
 * `no-store` with it (#628), so a shared cache never replays the cookie.
 */
const setResponseCookie = (
  name: string,
  value: string,
  options: Parameters<typeof HttpServerResponse.setCookie>[3],
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =>
  HttpEffect.appendPreResponseHandler((_request, response) =>
    HttpServerResponse.setCookie(response, name, value, options).pipe(
      Effect.map(withNoStore),
      Effect.orDie,
    ),
  );

/** The `users` resource of a user, its `email` fields derived from `identifiers`. */
const userResource = (user: Types.User, identifiers?: ReadonlyArray<Identifier>): R.User => {
  const view = S.encodeUser(user, identifiers);
  return R.User.make({
    id: user.id,
    attributes: {
      ...(user.name !== undefined && { name: user.name }),
      ...(user.image !== undefined && { image: user.image }),
      ...(view.email !== undefined && { email: view.email }),
      ...(view.emailVerified !== undefined && { emailVerified: view.emailVerified }),
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      attributes: user.attributes,
    },
  });
};

/**
 * {@link userResource} with the user's identifiers read from the store. As in
 * {@link encodeUserView}, a failed lookup only leaves the `email` fields out.
 */
const loadUserResource = (user: Types.User): Effect.Effect<R.User, never, IdentifierStore> =>
  Effect.map(userIdentifiers(user), (list) => userResource(user, list));

/**
 * A user's identifiers, for the derived `email` fields of a user on the wire.
 * Fail-soft: a failed lookup logs a warning and reads as no identifiers.
 */
const userIdentifiers = (
  user: Types.User,
): Effect.Effect<ReadonlyArray<Identifier>, never, IdentifierStore> =>
  Effect.gen(function* () {
    const identifiers = yield* IdentifierStore;
    return yield* identifiers
      .listByUser(user.id)
      .pipe(
        Effect.catchTag("AuthError", (error) =>
          Effect.logWarning("Failed to resolve identifiers for user view", { error }).pipe(
            Effect.as<ReadonlyArray<Identifier>>([]),
          ),
        ),
      );
  });

/**
 * The `sessions` resource of a session. Its `id` is the stored id, the digest
 * of the token; every `Types.Session` the services answer carries that id, so
 * no response body ever holds the token itself (#581).
 */
const sessionResource = (session: Types.Session): R.Session =>
  R.Session.make({
    id: session.id,
    attributes: {
      expiresAt: session.expiresAt,
      createdAt: session.createdAt,
      lastActivityAt: session.lastActivityAt,
      attributes: session.attributes,
    },
    relationships: { user: { data: R.User.ref(session.userId) } },
  });

/** The `identifiers` resource of a stored identifier. */
const identifierResource = (identifier: Identifier): R.Identifier =>
  R.Identifier.make({
    id: identifier.id,
    attributes: {
      kind: identifier.type,
      value: identifier.value,
      verified: identifier.verified,
      ...(identifier.verifiedAt !== undefined && { verifiedAt: identifier.verifiedAt }),
      createdAt: identifier.createdAt,
    },
    relationships: { user: { data: R.User.ref(identifier.userId) } },
  });

/** The id that names the session the request carries. */
const CURRENT = "current";

/** The id that names the signed-in user. */
const ME = "me";

/**
 * Clear the session cookies the way signing out always has: the session
 * cookie, the session-data cache cookie, and (multi-session) the signed-out
 * session's entry in the device list, keeping the other accounts.
 */
const clearSessionCookies = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
  signedOut: string | undefined,
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =>
  Effect.gen(function* () {
    yield* setResponseCookie(cfg.name, "", clearCookieOptions(cfg));
    if (cfg.cache !== undefined) {
      yield* setResponseCookie(dataCookieName(cfg), "", clearCookieOptions(cfg));
    }
    if (cfg.multiSession !== undefined) {
      const remaining = readDeviceSessionIds(request, cfg).filter((id) => id !== signedOut);
      yield* setResponseCookie(
        multiCookieName(cfg),
        remaining.join("."),
        sessionCookieOptions(
          cfg,
          DateTime.toDateUtc(DateTime.add(yield* DateTime.now, { days: 30 })),
        ),
      );
    }
  });

/**
 * Layer implementing the `sessions` group: list, read and revoke the
 * signed-in user's sessions (see `sessionsGroup` in `HttpApi.ts`).
 */
export const sessionsGroupLayer = (config?: CookieConfig, multiSession?: MultiSessionConfig) => {
  const cfg = resolveCookieConfig(config, multiSession);

  return HttpApiBuilder.group(AuthApi, "sessions", (handlers) =>
    handlers
      .handle("list", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionService;
          const sessions = yield* sessionManager
            .listSessions(resolved.user.id)
            .pipe(Effect.catch(internalServerError));
          return Handlers.collection(sessions.map(sessionResource));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("get", ({ params, query, request }) =>
        Effect.gen(function* () {
          const { resolved, cacheHit } = yield* resolveSession(request, cfg);
          yield* noStore;
          const withUser = query.include?.includes("user") === true;
          if (params.id !== CURRENT && params.id !== resolved.session.id) {
            const sessionManager = yield* SessionService;
            const sessions = yield* sessionManager
              .listSessions(resolved.user.id)
              .pipe(Effect.catch(internalServerError));
            const session = sessions.find((candidate) => candidate.id === params.id);
            if (session === undefined) {
              return yield* new S.NotFound({ message: "Session not found" });
            }
            return withUser
              ? Handlers.data(sessionResource(session), {
                  included: [yield* loadUserResource(resolved.user)],
                })
              : Handlers.data(sessionResource(session));
          }
          // On a store validation (cache miss) refresh the signed cache cookie
          // so subsequent reads within `maxAge` skip the store.
          if (cfg.cache !== undefined && !cacheHit) {
            const value = encodeSessionCacheCookie(
              resolved,
              cfg.cache,
              yield* Clock.currentTimeMillis,
              resolved.session.id,
              yield* sessionCacheGateAttributes,
            );
            // A user holding a server-only attribute is never snapshotted.
            if (value !== undefined) {
              yield* setResponseCookie(
                dataCookieName(cfg),
                value,
                dataCookieOptions(cfg, cfg.cache),
              );
            }
          }
          // A cache-served answer deliberately skips the store round-trip, so
          // the derived email fields are omitted there.
          const user = cacheHit
            ? userResource(resolved.user)
            : yield* loadUserResource(resolved.user);
          return withUser
            ? Handlers.data(sessionResource(resolved.session), { included: [user] })
            : Handlers.data(sessionResource(resolved.session));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("delete", ({ params, request }) =>
        Effect.gen(function* () {
          const sessionManager = yield* SessionService;
          const presented = sessionIdFromRequest(request, cfg);
          const signsOut =
            params.id === CURRENT ||
            (presented !== undefined && hashToken(presented) === params.id);
          if (signsOut) {
            // Signing out answers 204 whether or not the session was still
            // valid: the cookies are cleared either way.
            if (presented !== undefined) {
              yield* Effect.ignore(sessionManager.invalidateSession(presented));
            }
            return yield* clearSessionCookies(request, cfg, presented);
          }
          const resolved = yield* requireSession(request, cfg);
          const revoked = yield* sessionManager
            .revokeSessionById(resolved.user.id, params.id)
            .pipe(Effect.catch(internalServerError));
          // A foreign or unknown id gets the same answer (anti-enumeration).
          if (!revoked) return yield* new S.NotFound({ message: "Session not found" });
          return yield* Effect.void;
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("deleteOthers", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionService;
          yield* sessionManager
            .revokeOtherSessions(resolved.user.id, resolved.session.id)
            .pipe(Effect.catch(internalServerError));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      // Sign in: `201` with the session, or `202` when it awaits a second
      // factor or a verified address.
      .handle("create", ({ payload }) =>
        signInWith(payload.data.attributes).pipe(
          Effect.flatMap((outcome) => answerSignIn(outcome, cfg)),
          JsonApiErrors.mapHttpErrors,
        ),
      ),
  );
};

/**
 * Layer implementing the `identifiers` group: list and remove the signed-in
 * user's login handles (see `identifiersGroup` in `HttpApi.ts`).
 */
export const identifiersGroupLayer = (config?: CookieConfig, multiSession?: MultiSessionConfig) => {
  const cfg = resolveCookieConfig(config, multiSession);

  return HttpApiBuilder.group(AuthApi, "identifiers", (handlers) =>
    handlers
      .handle("list", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const identifiers = yield* IdentifierStore;
          const list = yield* identifiers
            .listByUser(resolved.user.id)
            .pipe(Effect.catch(internalServerError));
          return Handlers.collection(list.map(identifierResource));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("delete", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const identifiers = yield* IdentifierStore;
          const list = yield* identifiers
            .listByUser(resolved.user.id)
            .pipe(Effect.catch(internalServerError));
          // Only the owner may delete an identifier, and only their own: a
          // foreign or unknown id gets the same answer (anti-enumeration).
          const target = list.find((identifier) => identifier.id === params.id);
          if (target === undefined) {
            return yield* new S.NotFound({ message: "Identifier not found" });
          }
          // Refuse to orphan the account: the last identifier is the user's
          // only login handle.
          if (list.length === 1) {
            return yield* new S.Forbidden({
              message: "Cannot delete the only identifier on an account",
            });
          }
          return yield* identifiers.delete(target.id).pipe(Effect.catch(internalServerError));
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

/**
 * Layer implementing the `users` group: the signed-in user's own profile
 * (see `usersGroup` in `HttpApi.ts`).
 */
export const usersGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
  signUpAttributes?: ReadonlyArray<string>,
) => {
  const cfg = resolveCookieConfig(config, multiSession);
  const allowedSignUpAttributes = signUpAttributes ?? [];

  return HttpApiBuilder.group(AuthApi, "users", (handlers) =>
    handlers
      .handle("changePassword", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const { currentPassword, newPassword, revokeOtherSessions } = payload.data.attributes;
          const emailPassword = yield* EmailPassword.make();
          yield* emailPassword
            .changePassword({
              userId: resolved.user.id,
              currentPassword,
              newPassword,
              ...(revokeOtherSessions !== undefined && { revokeOtherSessions }),
              currentSessionId: resolved.session.id,
            })
            .pipe(
              Effect.catchTags({
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.BadRequest({ message: e.message, code: e.code })),
                AuthError: (e) => internalServerError(e),
                HashingError: (e) => internalServerError(e),
                PasswordPolicyError: passwordPolicyFailure,
              }),
            );
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      // Sign up: `201` with the new session, or `202` when none was issued
      // (always, under `antiEnumeration`, so a held address answers alike).
      .handle("create", ({ payload }) =>
        signUpWith(payload.data.attributes, allowedSignUpAttributes).pipe(
          Effect.flatMap((outcome) => answerSignIn(outcome, cfg)),
          JsonApiErrors.mapHttpErrors,
        ),
      )
      .handle("update", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          // `me` or the caller's own id; any other user is not the caller's to
          // edit, and gets the answer an unknown id would.
          if (params.id !== ME && params.id !== resolved.user.id) {
            return yield* new S.NotFound({ message: "User not found" });
          }
          const attributes = payload.data.attributes ?? {};
          const userService = yield* UserService;
          const updated = yield* userService
            .updateUser(resolved.user.id, {
              ...(attributes.name !== undefined && { name: attributes.name }),
              ...(attributes.image !== undefined && { image: attributes.image }),
            })
            .pipe(asCaller);
          return Handlers.data(yield* loadUserResource(updated));
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

// -----------------------------------------------------------------------------
// Signing in and proving an address (#205)
// -----------------------------------------------------------------------------

/** Fail with `403`, the message resolved through the message catalogue. */
const forbiddenFor = (e: { readonly code: string; readonly message: string }) =>
  resolveMessage(e.code, e.message).pipe(
    Effect.flatMap((message) => Effect.fail(new S.Forbidden({ message, code: e.code }))),
  );

/** Fail with `400`, the message resolved through the message catalogue. */
const badRequestFor = (e: { readonly code: string; readonly message: string }) =>
  resolveMessage(e.code, e.message).pipe(
    Effect.flatMap((message) => Effect.fail(new S.BadRequest({ message, code: e.code }))),
  );

/** A password the policy refuses: `400`, the message resolved with its parameters. */
const passwordPolicyFailure = (e: {
  readonly code: string;
  readonly message: string;
  readonly params?: Readonly<Record<string, string | number>> | undefined;
}) =>
  resolveMessage(e.code, e.message, e.params).pipe(
    Effect.flatMap((message) => Effect.fail(new S.BadRequest({ message, code: e.code }))),
  );

/**
 * The failures every hook-guarded flow can meet, as `catchTags` cases: a rate
 * limit, a locked or banned account, and the captcha and pwned-password
 * plugins' refusals.
 */
const hookFailures = {
  RateLimitError: (e: { readonly code: string; readonly message: string }) =>
    Effect.fail(new S.TooManyRequests({ message: e.message, code: e.code })),
  AccountLockedError: forbiddenFor,
  UserBannedError: forbiddenFor,
  CaptchaError: badRequestFor,
  PwnedPasswordError: badRequestFor,
};

/** What a sign-in, sign-up or verification produced, before it is answered. */
interface SignInOutcome {
  readonly user: Types.User;
  readonly session?: Types.Session | undefined;
  /** The raw token of `session`: only ever set as a cookie or the bearer header. */
  readonly token?: string | undefined;
  readonly needsEmailVerification: boolean;
  readonly secondFactor?: { readonly token: string; readonly expiresAt: number } | undefined;
  readonly rememberMe?: boolean | undefined;
  /** The method the last-login-method hint records. */
  readonly method: string;
  /** The user as the answer shows it, when the flow builds it itself (sign-up). */
  readonly userResource?: R.User | undefined;
}

/** The `201` / `200` answer for a new session. */
type SignedIn = typeof SignedInDocument.Type;

/** The `202` answer for a sign-in or sign-up that issued no session. */
type Pending = typeof PendingDocument.Type;

/**
 * Attach a new session to the response a JSON:API handler is about to send:
 * the cookies and, in bearer mode, the `set-auth-token` header, as
 * {@link withSessionCookie} does for a JSON body. Those headers are the only
 * places the token goes; the body names the session by its stored id.
 */
const issueSession = (
  issued: Types.IssuedSession,
  cfg: ResolvedCookieConfig,
  method: string | undefined,
  rememberMe: boolean | undefined,
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =>
  HttpEffect.appendPreResponseHandler((request, response) =>
    decorateSessionResponse(response, issued, cfg, method, rememberMe).pipe(
      Effect.provideService(HttpServerRequest.HttpServerRequest, request),
    ),
  );

/** The `sessions` document a new session is answered with: its user included. */
const signedIn = (
  outcome: SignInOutcome & { readonly session: Types.Session },
): Effect.Effect<SignedIn, never, IdentifierStore> =>
  Effect.map(
    outcome.userResource === undefined
      ? loadUserResource(outcome.user)
      : Effect.succeed(outcome.userResource),
    (user) =>
      Handlers.data(sessionResource(outcome.session), {
        included: [user],
        meta: { needsEmailVerification: outcome.needsEmailVerification },
      }),
  );

/**
 * Answer a sign-in or sign-up: `201` with the session when one was issued,
 * else `202` with the second-factor challenge to redeem, or with only
 * `meta.needsEmailVerification` when the address must be verified first.
 */
const answerSignIn = (
  outcome: SignInOutcome,
  cfg: ResolvedCookieConfig,
): Effect.Effect<
  SignedIn | Pending,
  never,
  IdentifierStore | HttpServerRequest.HttpServerRequest
> =>
  Effect.gen(function* () {
    const meta = { needsEmailVerification: outcome.needsEmailVerification };
    const { session, token } = outcome;
    if (session !== undefined && token !== undefined) {
      yield* issueSession({ session, token }, cfg, outcome.method, outcome.rememberMe);
      return yield* signedIn({ ...outcome, session });
    }
    if (outcome.secondFactor !== undefined) {
      // The challenge's id is the token that redeems the second factor (#628).
      yield* noStore;
      return {
        data: R.SecondFactorChallenge.make({
          id: outcome.secondFactor.token,
          attributes: {
            expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(outcome.secondFactor.expiresAt)),
          },
        }),
        meta,
      };
    }
    return { meta };
  });

/** Sign in with an email address and password. */
const signInWithPassword = (
  credential: {
    readonly email: string;
    readonly password: string;
    readonly captchaToken?: string | undefined;
  },
  rememberMe: boolean | undefined,
) =>
  Effect.gen(function* () {
    const lifecycle = yield* AuthLifecycleService;
    const result = yield* lifecycle
      .signIn({
        email: credential.email,
        password: credential.password,
        ...(credential.captchaToken !== undefined && { captchaToken: credential.captchaToken }),
        ...(rememberMe !== undefined && { rememberMe }),
      })
      .pipe(
        Effect.catchTags({
          InvalidCredentialsError: (e) =>
            Effect.fail(new S.Unauthorized({ message: e.message, code: e.code })),
          AuthError: (e) => internalServerError(e),
          HashingError: (e) => internalServerError(e),
          EmailVerificationError: (e) => internalServerError(e),
          ...hookFailures,
        }),
      );
    return { ...result, method: "email-password" } satisfies SignInOutcome;
  });

/** Sign in with a username and password. */
const signInWithUsername = (
  credential: {
    readonly username: string;
    readonly password: string;
    readonly captchaToken?: string | undefined;
  },
  rememberMe: boolean | undefined,
) =>
  Effect.gen(function* () {
    const username = yield* resolveUsername;
    const result = yield* username.service
      .signIn({
        username: credential.username,
        password: credential.password,
        captchaToken: credential.captchaToken,
        ...(rememberMe !== undefined && { rememberMe }),
      })
      .pipe(
        Effect.catchTags({
          UsernameError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
          InvalidCredentialsError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
          EmailNotVerifiedError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
          HashingError: (e) => internalServerError(e),
          AuthError: (e) => internalServerError(e),
          ...hookFailures,
        }),
      );
    return {
      ...result,
      needsEmailVerification: false,
      method: "username",
    } satisfies SignInOutcome;
  });

/** A code or link that does not verify: `400`, uniformly (anti-enumeration). */
const invalidCode = (e: { readonly message: string }) =>
  Effect.fail(new S.BadRequest({ message: e.message }));

/** The outcome of a passwordless sign-in, which never awaits a verification. */
const passwordless =
  (method: string) =>
  (result: { readonly user: Types.User } & Types.IssuedSession): SignInOutcome => ({
    ...result,
    needsEmailVerification: false,
    method,
  });

/** Sign in with a one-time code sent by email. */
const signInWithEmailOtp = (credential: { readonly email: string; readonly otp: string }) =>
  Effect.flatMap(resolveEmailOtp, ({ service }) =>
    service.signIn(credential.email, credential.otp).pipe(
      Effect.catchTags({
        EmailOtpError: invalidCode,
        AuthError: internalServerError,
        ...hookFailures,
      }),
      Effect.map(passwordless("email-otp")),
    ),
  );

/** Sign in with a one-time code sent by SMS. */
const signInWithPhoneOtp = (credential: { readonly phoneNumber: string; readonly otp: string }) =>
  Effect.flatMap(resolvePhoneOtp, ({ service }) =>
    service.signIn(credential.phoneNumber, credential.otp).pipe(
      Effect.catchTags({
        PhoneOtpError: invalidCode,
        AuthError: internalServerError,
        ...hookFailures,
      }),
      Effect.map(passwordless("phone-otp")),
    ),
  );

/** Sign in with the token from a magic-link email. */
const signInWithMagicLink = (credential: { readonly token: string }) =>
  Effect.flatMap(resolveMagicLink, ({ service }) =>
    service.verify(credential.token).pipe(
      Effect.catchTags({
        MagicLinkError: invalidCode,
        AuthError: internalServerError,
        ...hookFailures,
      }),
      Effect.map(passwordless("magic-link")),
    ),
  );

/** Sign in as a new guest user. */
const signInAnonymously = Effect.fn("signInAnonymously")(function* () {
  const anonymous = yield* resolveAnonymous;
  const result = yield* anonymous.service.signInAnonymous().pipe(
    Effect.catchTags({
      AuthError: (e) => internalServerError(e),
      ...hookFailures,
    }),
  );
  return { ...result, needsEmailVerification: false, method: "anonymous" } satisfies SignInOutcome;
});

/** Sign in with a Google One Tap id token. */
const signInWithGoogleOneTap = (credential: { readonly idToken: string; readonly nonce: string }) =>
  Effect.gen(function* () {
    const oneTap = yield* resolveGoogleOneTap;
    const result = yield* oneTap.service.signIn(credential.idToken, credential.nonce).pipe(
      Effect.catchTags({
        GoogleOneTapError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
        AuthError: (e) => internalServerError(e),
        ...hookFailures,
      }),
    );
    return { ...result, needsEmailVerification: false, method: "google" } satisfies SignInOutcome;
  });

/** Sign in with the credential a `POST /sessions` carries. */
const signInWith = ({ credential, rememberMe }: typeof SignInDocument.Type.data.attributes) =>
  Match.value(credential).pipe(
    Match.discriminatorsExhaustive("method")({
      password: (password) => signInWithPassword(password, rememberMe),
      username: (username) => signInWithUsername(username, rememberMe),
      "email-otp": signInWithEmailOtp,
      "phone-otp": signInWithPhoneOtp,
      "magic-link": signInWithMagicLink,
      anonymous: () => signInAnonymously(),
      "google-one-tap": signInWithGoogleOneTap,
    }),
  );

/** Redeem a second-factor challenge with a TOTP or backup code. */
const verifySecondFactor = (
  token: string,
  attributes: typeof SecondFactorVerificationDocument.Type.data.attributes,
) =>
  Effect.gen(function* () {
    const multiFactor = yield* resolveMultiFactor;
    // A failed second factor is a failed authentication attempt: `401`.
    const rejected = (e: { readonly message: string }) =>
      Effect.fail(new S.Unauthorized({ message: e.message }));
    const result =
      attributes.method === "totp"
        ? yield* multiFactor.service.verifyTotp(token, attributes.code).pipe(
            Effect.catchTags({
              MultiFactorError: rejected,
              HashingError: (e) => internalServerError(e),
              AuthError: (e) => internalServerError(e),
              ...hookFailures,
            }),
          )
        : yield* multiFactor.service.verifyBackupCode(token, attributes.code).pipe(
            Effect.catchTags({
              MultiFactorError: rejected,
              AuthError: (e) => internalServerError(e),
              ...hookFailures,
            }),
          );
    const userService = yield* UserService;
    const user = yield* userService.getUser(result.userId).pipe(Effect.catch(internalServerError));
    return {
      user,
      session: result.session,
      token: result.token,
      needsEmailVerification: false,
      method: "multi-factor",
    } satisfies SignInOutcome & Types.IssuedSession;
  });

/**
 * The user a sign-up answers with, taking `email` from the address the sign-up
 * was made with (unverified, as every address is at sign-up) rather than from
 * the identifier store. For an address held unverified by another user (see
 * `AuthLifecycleResult.identifier`) the user is a stand-in no identifier names,
 * so a store lookup would leave its `email` fields out and give the address
 * away; this builds every answer the same way.
 */
const signUpUserResource = (user: Types.User, email: string): R.User => {
  const resource = userResource(user);
  return R.User.make({
    id: resource.id,
    attributes: { ...resource.attributes, email, emailVerified: false },
  });
};

/** Sign up with an email address and password. */
const signUpWith = (payload: S.SignUpPayload, allowedAttributes: ReadonlyArray<string>) =>
  Effect.gen(function* () {
    const lifecycle = yield* AuthLifecycleService;
    const input = yield* signUpInput(payload, allowedAttributes);
    const result = yield* lifecycle.signUp(input).pipe(
      Effect.catchTags({
        AuthError: (e) => internalServerError(e),
        EmailInUseError: (e) => Effect.fail(new S.Conflict({ message: e.message, code: e.code })),
        EmailNotVerifiedError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
        HashingError: (e) => internalServerError(e),
        EmailVerificationError: (e) => internalServerError(e),
        PasswordPolicyError: passwordPolicyFailure,
        SignUpDisabledError: forbiddenFor,
        InvalidInputError: badRequestFor,
        ...hookFailures,
      }),
    );
    return {
      ...result,
      method: "email-password",
      ...(result.identifier?.type === "email" && {
        userResource: signUpUserResource(result.user, result.identifier.value),
      }),
    } satisfies SignInOutcome;
  });

/**
 * Layer implementing `POST /sessions` (sign-in) and the
 * `second-factor-challenges` group.
 */
export const secondFactorChallengesGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);
  return HttpApiBuilder.group(AuthApi, "second-factor-challenges", (handlers) =>
    handlers.handle("verify", ({ payload }) =>
      verifySecondFactor(
        payload.data.relationships.challenge.data.id,
        payload.data.attributes,
      ).pipe(
        Effect.flatMap((outcome) =>
          Effect.flatMap(issueSession(outcome, cfg, outcome.method, undefined), () =>
            signedIn(outcome),
          ),
        ),
        JsonApiErrors.mapHttpErrors,
      ),
    ),
  );
};

/** Layer implementing the `otp-challenges` group: send a code or a magic link. */
export const otpChallengesGroupLayer = () =>
  HttpApiBuilder.group(AuthApi, "otp-challenges", (handlers) =>
    handlers.handle("create", ({ payload }) =>
      Effect.gen(function* () {
        // Anti-enumeration: each service succeeds silently for an unknown
        // address or number; only store and delivery failures surface (500).
        const challenge = payload.data.attributes;
        const resendTooSoon = (e: { readonly code: string; readonly message: string }) =>
          Effect.fail(new S.TooManyRequests({ message: e.message, code: e.code }));
        // The send gate (`beforeSendCode`, the captcha, #678).
        const options = { captchaToken: challenge.captchaToken };
        return yield* Match.value(challenge).pipe(
          Match.discriminatorsExhaustive("channel")({
            email: ({ email, purpose }) =>
              Effect.flatMap(resolveEmailOtp, ({ service }) =>
                service.send(email, purpose, options).pipe(
                  Effect.catchTags({
                    AuthError: (e) => internalServerError(e),
                    EmailOtpError: (e) => internalServerError(e),
                    ResendTooSoonError: resendTooSoon,
                    ...hookFailures,
                  }),
                ),
              ),
            phone: ({ phoneNumber, purpose }) =>
              Effect.flatMap(resolvePhoneOtp, ({ service }) =>
                service.send(phoneNumber, purpose, options).pipe(
                  Effect.catchTags({
                    PhoneOtpError: (e) => internalServerError(e),
                    AuthError: (e) => internalServerError(e),
                    ResendTooSoonError: resendTooSoon,
                    ...hookFailures,
                  }),
                ),
              ),
            "magic-link": ({ email }) =>
              Effect.flatMap(resolveMagicLink, ({ service }) =>
                service.send(email, options).pipe(
                  Effect.catchTags({
                    AuthError: (e) => internalServerError(e),
                    MagicLinkError: (e) => internalServerError(e),
                    ResendTooSoonError: resendTooSoon,
                    ...hookFailures,
                  }),
                ),
              ),
          }),
        );
      }).pipe(Effect.asVoid, JsonApiErrors.mapHttpErrors),
    ),
  );

/** Layer implementing the `email-verifications` group. */
export const emailVerificationsGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);
  return HttpApiBuilder.group(AuthApi, "email-verifications", (handlers) =>
    handlers
      .handle("create", ({ payload }) =>
        Effect.gen(function* () {
          const identifiers = yield* IdentifierStore;
          const verification = yield* EmailVerificationService;
          const email = payload.data.attributes.email.trim().toLowerCase();
          const identifier = yield* lookupIdentifier(identifiers, "email", email).pipe(
            Effect.catch(internalServerError),
          );
          // Anti-enumeration: the same answer whether or not the address has
          // an account, or is already verified, or is inside its resend
          // cooldown (#682) or past its send cap (#684): a 429 there alone
          // would name an unverified account.
          if (identifier !== null && !identifier.verified) {
            yield* verification.resendVerification(identifier.userId, identifier.value).pipe(
              Effect.catchIf(isRecipientSendCapped, () => Effect.void),
              Effect.catchTags({
                ResendTooSoonError: () => Effect.void,
                AuthError: (e) => internalServerError(e),
                EmailVerificationError: (e) => internalServerError(e),
                ...hookFailures,
              }),
            );
          }
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("redeem", ({ payload }) =>
        Effect.gen(function* () {
          const lifecycle = yield* AuthLifecycleService;
          const result = yield* lifecycle
            .verifyEmail({ token: payload.data.attributes.token })
            .pipe(
              Effect.catchTags({
                EmailVerificationError: (e) =>
                  Effect.fail(new S.BadRequest({ message: e.message })),
                UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
                ...hookFailures,
              }),
            );
          // `201` with the session when verification signs the user in.
          const { session, token } = result;
          if (session === undefined || token === undefined) return yield* Effect.void;
          yield* issueSession({ session, token }, cfg, "email-password", undefined);
          return yield* signedIn({ ...result, session, method: "email-password" });
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

/** Layer implementing the `password-resets` group. */
export const passwordResetsGroupLayer = () =>
  HttpApiBuilder.group(AuthApi, "password-resets", (handlers) =>
    handlers
      .handle("create", ({ payload }) =>
        Effect.gen(function* () {
          const passwordReset = yield* PasswordResetService;
          yield* passwordReset.requestPasswordReset(payload.data.attributes.email).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
              PasswordResetError: (e) => internalServerError(e),
              ...hookFailures,
            }),
          );
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("redeem", ({ payload }) =>
        Effect.gen(function* () {
          const { token, newPassword } = payload.data.attributes;
          const passwordReset = yield* PasswordResetService;
          yield* passwordReset.resetPassword(token, newPassword).pipe(
            Effect.catchTags({
              PasswordResetError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
              HashingError: (e) => internalServerError(e),
              ...hookFailures,
            }),
          );
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );

/** Layer implementing the `google-one-tap-nonces` group. */
export const googleOneTapNoncesGroupLayer = () =>
  HttpApiBuilder.group(AuthApi, "google-one-tap-nonces", (handlers) =>
    handlers.handle("create", () =>
      Effect.gen(function* () {
        const oneTap = yield* resolveGoogleOneTap;
        // The single-use nonce is this caller's alone: a cached answer would
        // hand it to the next caller (#628).
        yield* noStore;
        const nonce = yield* oneTap.service.createNonce().pipe(
          Effect.catchTags({
            GoogleOneTapError: (e) => internalServerError(e),
            AuthError: (e) => internalServerError(e),
          }),
        );
        return Handlers.data(R.GoogleOneTapNonce.make({ id: nonce, attributes: {} }));
      }).pipe(JsonApiErrors.mapHttpErrors),
    ),
  );

// -----------------------------------------------------------------------------
// Account management (#205)
// -----------------------------------------------------------------------------

/**
 * Clear the signed session-data cookie on the response: after an email change
 * or a deletion, a cached snapshot would describe a user who no longer exists
 * as it says.
 */
const clearDataCookie = (cfg: ResolvedCookieConfig) =>
  cfg.cache === undefined
    ? Effect.void
    : setResponseCookie(dataCookieName(cfg), "", clearCookieOptions(cfg));

/** A redeemed account token that does not verify: `400`. */
const accountTokenFailures = {
  AccountTokenError: (e: { readonly message: string }) =>
    Effect.fail(new S.BadRequest({ message: e.message })),
  UserNotFoundError: (e: { readonly message: string }) =>
    Effect.fail(new S.BadRequest({ message: e.message })),
};

/** Layer implementing the `email-changes` group. */
export const emailChangesGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);
  return HttpApiBuilder.group(AuthApi, "email-changes", (handlers) =>
    handlers
      .handle("create", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const account = yield* resolveAccountManagement;
          yield* account.service
            .requestEmailChange(resolved.user.id, payload.data.attributes.newEmail)
            .pipe(
              Effect.catchTags({
                // Anti-enumeration: never reveal whether the target address is taken.
                EmailInUseError: () => Effect.void,
                UserNotFoundError: () =>
                  Effect.fail(new S.Unauthorized({ message: "Not authenticated" })),
                AuthError: (e) => internalServerError(e),
              }),
            );
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("redeem", ({ payload }) =>
        Effect.gen(function* () {
          const account = yield* resolveAccountManagement;
          yield* account.service.confirmEmailChange(payload.data.attributes.token).pipe(
            Effect.catchTags({
              ...accountTokenFailures,
              AuthError: (e) => internalServerError(e),
            }),
          );
          yield* clearDataCookie(cfg);
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

/** Layer implementing the `account-deletions` group. */
export const accountDeletionsGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);
  return HttpApiBuilder.group(AuthApi, "account-deletions", (handlers) =>
    handlers
      .handle("create", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const account = yield* resolveAccountManagement;
          yield* account.service.requestAccountDeletion(resolved.user.id).pipe(asCaller);
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("redeem", ({ payload }) =>
        Effect.gen(function* () {
          const account = yield* resolveAccountManagement;
          yield* account.service.confirmAccountDeletion(payload.data.attributes.token).pipe(
            Effect.catchTags({
              ...accountTokenFailures,
              AuthError: (e) => internalServerError(e),
            }),
          );
          yield* clearDataCookie(cfg);
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

/** The `multi-factor-enrollments` resource: always `current`. */
const enrollmentResource = (verified: boolean): R.MultiFactorEnrollment =>
  R.MultiFactorEnrollment.make({ id: "current", attributes: { verified } });

/** Layer implementing the `multi-factor-enrollments` group. */
export const multiFactorEnrollmentsGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);
  return HttpApiBuilder.group(AuthApi, "multi-factor-enrollments", (handlers) =>
    handlers
      .handle("create", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const multiFactor = yield* resolveMultiFactor;
          // The answer carries the TOTP secret and backup codes (#628).
          yield* noStore;
          const enrolled = yield* multiFactor.service
            .enable(resolved.user.id, payload.data.attributes.password)
            .pipe(
              Effect.catchTags({
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.BadRequest({ message: e.message })),
                MultiFactorError: (e) => internalServerError(e),
                UserNotFoundError: (e) => internalServerError(e),
                HashingError: (e) => internalServerError(e),
                AuthError: (e) => internalServerError(e),
              }),
            );
          // The secret and backup codes are shown this once, in `meta`.
          return Handlers.data(enrollmentResource(false), {
            meta: {
              secret: enrolled.secret,
              totpUri: enrolled.totpUri,
              backupCodes: enrolled.backupCodes,
            },
          });
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("confirm", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const multiFactor = yield* resolveMultiFactor;
          yield* multiFactor.service
            .confirmEnable(resolved.user.id, payload.data.attributes.code)
            .pipe(
              Effect.catchTags({
                MultiFactorError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                HashingError: (e) => internalServerError(e),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return Handlers.data(enrollmentResource(true));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("remove", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const multiFactor = yield* resolveMultiFactor;
          yield* multiFactor.service.disable(resolved.user.id, payload.meta.password).pipe(
            Effect.catchTags({
              InvalidCredentialsError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              HashingError: (e) => internalServerError(e),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

/** Layer implementing the `backup-code-sets` group. */
export const backupCodeSetsGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);
  return HttpApiBuilder.group(AuthApi, "backup-code-sets", (handlers) =>
    handlers.handle("create", ({ payload, request }) =>
      Effect.gen(function* () {
        // The answer carries the new backup codes (#628).
        yield* noStore;
        const resolved = yield* requireSession(request, cfg);
        const multiFactor = yield* resolveMultiFactor;
        const backupCodes = yield* multiFactor.service
          .regenerateBackupCodes(resolved.user.id, payload.data.attributes.password)
          .pipe(
            Effect.catchTags({
              MultiFactorError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              InvalidCredentialsError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              HashingError: (e) => internalServerError(e),
              AuthError: (e) => internalServerError(e),
            }),
          );
        // The codes are shown this once, in `meta`.
        return Handlers.data(R.BackupCodeSet.make({ id: resolved.user.id, attributes: {} }), {
          meta: { backupCodes },
        });
      }).pipe(JsonApiErrors.mapHttpErrors),
    ),
  );
};

/**
 * Fail an organization operation the way its endpoint answers a refusal:
 * the service's `OrganizationError` as `refuse` builds it, an `AuthError` as
 * a `500`.
 */
const organizationRefusal =
  <F>(refuse: (message: string) => F) =>
  <A, R>(
    self: Effect.Effect<A, OrganizationError | AuthError, R>,
  ): Effect.Effect<A, F | S.InternalServerError, R> =>
    self.pipe(
      Effect.catchTags({
        OrganizationError: (e) => Effect.fail(refuse(e.message)),
        AuthError: (e) => internalServerError(e),
      }),
    );

/** A refused organization operation, answered `403`. */
const refusedForbidden = organizationRefusal((message) => new S.Forbidden({ message }));

/** A refused organization operation, answered `400`. */
const refusedBadRequest = organizationRefusal((message) => new S.BadRequest({ message }));

/** A store (or hook) failure, answered `500`. */
const storeFailure = <A, E extends Cause.YieldableError, R>(
  self: Effect.Effect<A, E, R>,
): Effect.Effect<A, S.InternalServerError, R> => Effect.catch(self, internalServerError);

/**
 * The organization service and the signed-in actor's id: `404` when
 * organizations are not enabled, `401` when the request carries no session.
 */
const organizationActor = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
) =>
  Effect.gen(function* () {
    const org = yield* resolveOrganization;
    const resolved = yield* requireSession(request, cfg);
    return { org: org.service, actorId: resolved.user.id, resolved };
  });

/** The organization service as the signed-in actor sees it, and the actor's id. */
type OrganizationOperation<A> = (
  org: typeof OrganizationService.Service,
  actorId: string,
) => Effect.Effect<A, OrganizationError | AuthError>;

/**
 * Run `operation` as the signed-in actor: `404` when organizations are not
 * enabled, `401` without a session, `403` when the service refuses.
 */
const asOrganizationActor = <A>(
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
  operation: OrganizationOperation<A>,
) =>
  Effect.flatMap(organizationActor(request, cfg), ({ org, actorId }) =>
    refusedForbidden(operation(org, actorId)),
  );

/**
 * How an item group reads its record by the URL's id: as the signed-in actor,
 * the service and the record `lookup` finds, `403` when the lookup is refused.
 * An id that names no record fails with `refusal`, the error the operation
 * gives a stranger (`missingPermission` of the permission it needs, or
 * `notAMember` for a member-only read), and the operation checks that
 * permission before anything else. So an unknown id, another tenant's record
 * and a member without the permission get the same `403` and body (#718).
 */
const organizationTarget =
  <A>(
    cfg: ResolvedCookieConfig,
    lookup: (
      org: typeof OrganizationService.Service,
      id: string,
    ) => Effect.Effect<A | null, OrganizationError | AuthError>,
  ) =>
  (request: HttpServerRequest.HttpServerRequest, id: string, refusal: OrganizationError) =>
    Effect.gen(function* () {
      const { org, actorId } = yield* organizationActor(request, cfg);
      const target = yield* refusedForbidden(
        Effect.filterOrFail(lookup(org, id), P.isNotNull, () => refusal),
      );
      return { org, actorId, target };
    });

/** The device's session token whose hash is the listed device-session `id`. */
const deviceTokenFor = (tokens: ReadonlyArray<string>, id: string): Option.Option<string> =>
  Arr.findFirst(tokens, (token) => hashToken(token) === id);

/**
 * Layer implementing the `device-sessions` group: the accounts signed in on
 * this device (see `deviceSessionsGroup` in `HttpApi.ts`). The device's
 * cookies hold the session tokens; the wire carries only their hashes.
 */
export const deviceSessionsGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);

  /**
   * The session tokens this device holds (its device list, then the active
   * session when the list lacks it), and the active one; `404` when
   * multi-session is off.
   */
  const deviceTokens = (request: HttpServerRequest.HttpServerRequest) =>
    Effect.gen(function* () {
      if (cfg.multiSession === undefined) {
        return yield* new S.NotFound({ message: "Multi-session is not enabled" });
      }
      const active = sessionIdFromRequest(request, cfg);
      const listed = readDeviceSessionIds(request, cfg);
      const tokens = Arr.dedupe(active === undefined ? listed : [...listed, active]);
      return { active, tokens };
    });

  return HttpApiBuilder.group(AuthApi, "device-sessions", (handlers) =>
    handlers
      .handle("list", ({ request }) =>
        Effect.gen(function* () {
          const { active, tokens } = yield* deviceTokens(request);
          const sessionManager = yield* SessionService;
          const valid = Arr.getSomes(
            yield* Effect.forEach(
              tokens,
              (token) => Effect.option(sessionManager.validateSession(token)),
              { concurrency: 1 },
            ),
          );
          const users = yield* Effect.forEach(
            Arr.dedupeWith(
              valid.map(({ user }) => user),
              (a, b) => a.id === b.id,
            ),
            loadUserResource,
            { concurrency: 1 },
          );
          return Handlers.collection(
            valid.map(({ session }) =>
              R.DeviceSession.make({
                id: session.id,
                attributes: {
                  active: active !== undefined && session.id === hashToken(active),
                  expiresAt: session.expiresAt,
                  createdAt: session.createdAt,
                  lastActivityAt: session.lastActivityAt,
                  attributes: session.attributes,
                },
                relationships: { user: { data: R.User.ref(session.userId) } },
              }),
            ),
            { included: users },
          );
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("setActive", ({ payload, request }) =>
        Effect.gen(function* () {
          const { tokens } = yield* deviceTokens(request);
          const target = payload.data;
          if (target === null) {
            return yield* new S.BadRequest({
              message:
                "Name the device session to switch to; sign out with DELETE /sessions/current",
            });
          }
          const token = deviceTokenFor(tokens, target.id);
          if (Option.isNone(token)) {
            return yield* new S.BadRequest({ message: "Session is not on this device" });
          }
          const sessionManager = yield* SessionService;
          const resolved = yield* sessionManager
            .validateSession(token.value)
            .pipe(
              Effect.mapError(() => new S.BadRequest({ message: "Invalid or expired session" })),
            );
          yield* setResponseCookie(
            cfg.name,
            token.value,
            sessionCookieOptions(cfg, resolved.session.expiresAt),
          );
          // The cached session data describes the previous account.
          return yield* cfg.cache === undefined
            ? Effect.void
            : setResponseCookie(dataCookieName(cfg), "", clearCookieOptions(cfg));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("delete", ({ params, request }) =>
        Effect.gen(function* () {
          const { active, tokens } = yield* deviceTokens(request);
          const token = deviceTokenFor(tokens, params.id);
          if (Option.isNone(token)) {
            return yield* new S.NotFound({ message: "Session is not on this device" });
          }
          const sessionManager = yield* SessionService;
          yield* storeFailure(sessionManager.invalidateSession(token.value));
          if (token.value === active) {
            // Signing out the active account clears the session cookies and
            // drops it from the device list.
            return yield* clearSessionCookies(request, cfg, token.value);
          }
          return yield* setResponseCookie(
            multiCookieName(cfg),
            readDeviceSessionIds(request, cfg)
              .filter((id) => id !== token.value)
              .join("."),
            sessionCookieOptions(
              cfg,
              DateTime.toDateUtc(DateTime.add(yield* DateTime.now, { days: 30 })),
            ),
          );
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

/**
 * Layer implementing the `organizations` group: the signed-in user's
 * organizations, the session's active one, and each organization's members
 * and invitations (see `organizationsGroup` in `HttpApi.ts`).
 */
export const organizationsGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);
  const actor = (request: HttpServerRequest.HttpServerRequest) => organizationActor(request, cfg);

  /**
   * The organization `id` names with its members, as the signed-in actor: a
   * member's read (#717). A stranger and an unknown id both answer the same
   * `403`, as the domain, role and team listings do.
   */
  const fullOrganization = (request: HttpServerRequest.HttpServerRequest, id: string) =>
    asOrganizationActor(request, cfg, (org, actorId) => org.getFullOrganization(actorId, id));

  return HttpApiBuilder.group(AuthApi, "organizations", (handlers) =>
    handlers
      .handle("list", ({ request }) =>
        Effect.gen(function* () {
          const { org, resolved } = yield* actor(request);
          const organizations = yield* storeFailure(org.listOrganizations(resolved.user.id));
          return Handlers.collection(organizations.map(organizationResource));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("create", ({ payload, request }) =>
        Effect.gen(function* () {
          const { org, resolved } = yield* actor(request);
          const { name, slug, logo, metadata } = payload.data.attributes;
          const created = yield* refusedBadRequest(
            org.createOrganization(resolved.user.id, {
              name,
              slug,
              ...(logo !== undefined && { logo }),
              ...(metadata !== undefined && { metadata }),
            }),
          );
          return Handlers.data(organizationResource(created));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("setActive", ({ payload, request }) =>
        Effect.gen(function* () {
          const { org, actorId, resolved } = yield* actor(request);
          const organizationId = payload.data?.id ?? null;
          // Only an organization the actor is an active member of (#576): a
          // stranger, a deactivated member and an unknown id get the same
          // `403`. Clearing it needs no check.
          if (organizationId !== null) {
            yield* refusedForbidden(org.requireMembership(actorId, organizationId));
          }
          const sessionManager = yield* SessionService;
          yield* sessionManager
            .setSessionAttributes(resolved.session.id, { activeOrganizationId: organizationId })
            .pipe(
              Effect.catchTags({
                SessionNotFoundError: (e) => internalServerError(e),
                AuthError: (e) => internalServerError(e),
              }),
            );
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("get", ({ params, request }) =>
        Effect.gen(function* () {
          const full = yield* fullOrganization(request, params.id);
          return Handlers.data(organizationResource(full.organization));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("update", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const { org, resolved } = yield* actor(request);
          const { defaultRole, ...fields } = payload.data.attributes ?? {};
          const updates = {
            ...(fields.name !== undefined && { name: fields.name }),
            ...(fields.slug !== undefined && { slug: fields.slug }),
            ...(fields.logo !== undefined && { logo: fields.logo }),
            ...(fields.metadata !== undefined && { metadata: fields.metadata }),
            ...(fields.jitProvisioning !== undefined && {
              jitProvisioning: fields.jitProvisioning,
            }),
          };
          // `defaultRole` alone needs only `role:manage`; anything else (or
          // nothing at all) goes through `organization:update` first.
          const updated =
            defaultRole === undefined ||
            Arr.some(
              [fields.name, fields.slug, fields.logo, fields.metadata, fields.jitProvisioning],
              P.isNotUndefined,
            )
              ? yield* refusedForbidden(
                  org.updateOrganization(resolved.user.id, params.id, updates),
                )
              : undefined;
          const organization =
            defaultRole === undefined
              ? updated
              : yield* refusedForbidden(
                  org.setDefaultRole(resolved.user.id, params.id, defaultRole),
                );
          if (organization === undefined) {
            return yield* new S.NotFound({ message: "Organization not found" });
          }
          return Handlers.data(organizationResource(organization));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("delete", ({ params, request }) =>
        Effect.gen(function* () {
          const { org, resolved } = yield* actor(request);
          yield* refusedForbidden(org.deleteOrganization(resolved.user.id, params.id));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("listMembers", ({ params, request }) =>
        Effect.gen(function* () {
          const full = yield* fullOrganization(request, params.id);
          return Handlers.collection(full.members.map(memberResource));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("addMember", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const { org, resolved } = yield* actor(request);
          const member = yield* refusedForbidden(
            org.addMember(
              resolved.user.id,
              params.id,
              payload.data.relationships.user.data.id,
              payload.data.attributes?.role,
            ),
          );
          return Handlers.data(memberResource(member));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("listInvitations", ({ params, request }) =>
        // `invitation:create`, as `invite` takes (#715): a stranger, a member
        // without it and an unknown id all answer the same `403`.
        asOrganizationActor(request, cfg, (org, actorId) =>
          org.listInvitations(actorId, params.id),
        ).pipe(
          Effect.map((invitations) => Handlers.collection(invitations.map(invitationResource))),
          JsonApiErrors.mapHttpErrors,
        ),
      )
      .handle("invite", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const { org, resolved } = yield* actor(request);
          const invitation = yield* refusedForbidden(
            org.inviteMember(resolved.user.id, params.id, payload.data.attributes),
          );
          return Handlers.data(invitationResource(invitation));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("listDomains", ({ params, request }) =>
        asOrganizationActor(request, cfg, (org, actorId) =>
          org.listDomains(actorId, params.id),
        ).pipe(
          Effect.map((domains) => Handlers.collection(domains.map(domainResource))),
          JsonApiErrors.mapHttpErrors,
        ),
      )
      .handle("addDomain", ({ params, payload, request }) =>
        // The payload admits only the `dns` strategy (#598), so the domain is
        // all there is to pass on.
        asOrganizationActor(request, cfg, (org, actorId) =>
          org.addDomain(actorId, params.id, { domain: payload.data.attributes.domain }),
        ).pipe(
          Effect.map((domain) => Handlers.data(domainResource(domain))),
          JsonApiErrors.mapHttpErrors,
        ),
      )
      .handle("listRoles", ({ params, request }) =>
        asOrganizationActor(request, cfg, (org, actorId) =>
          org.listOrgRoles(actorId, params.id),
        ).pipe(
          Effect.map((roles) => Handlers.collection(roles.map(orgRoleResource))),
          JsonApiErrors.mapHttpErrors,
        ),
      )
      .handle("createRole", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const { org, actorId } = yield* actor(request);
          const { role, permissions } = payload.data.attributes;
          yield* refusedForbidden(org.requirePermission(actorId, params.id, "role:manage"));
          // A create never replaces: an existing definition is changed through
          // its own resource.
          const defined = yield* refusedForbidden(org.listOrgRoles(actorId, params.id));
          if (Arr.some(defined, (definition) => definition.role === role)) {
            return yield* new S.Conflict({
              message: `Role '${role}' is already defined; change it with PATCH /organization-roles/:id`,
            });
          }
          const created = yield* refusedForbidden(
            org.upsertOrgRole(actorId, params.id, { role, permissions }),
          );
          return Handlers.data(orgRoleResource(created));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("listTeams", ({ params, request }) =>
        asOrganizationActor(request, cfg, (org, actorId) => org.listTeams(actorId, params.id)).pipe(
          Effect.map((teams) => Handlers.collection(teams.map(teamResource))),
          JsonApiErrors.mapHttpErrors,
        ),
      )
      .handle("createTeam", ({ params, payload, request }) =>
        asOrganizationActor(request, cfg, (org, actorId) =>
          org.createTeam(actorId, params.id, { name: payload.data.attributes.name }),
        ).pipe(
          Effect.map((team) => Handlers.data(teamResource(team))),
          JsonApiErrors.mapHttpErrors,
        ),
      ),
  );
};

/** Whether a membership is active (`status` absent reads as active). */
const memberStatus = (member: Member): "active" | "inactive" => member.status ?? "active";

/**
 * Layer implementing the `organization-members` group: one membership, by its
 * stored id (see `organizationMembersGroup` in `HttpApi.ts`).
 */
export const organizationMembersGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);

  const target = organizationTarget(cfg, (org, id) => org.getMemberById(id));

  return HttpApiBuilder.group(AuthApi, "organization-members", (handlers) =>
    handlers
      .handle("update", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const {
            org,
            actorId,
            target: member,
          } = yield* target(request, params.id, missingPermission("member:update"));
          const { role, status } = payload.data.attributes ?? {};
          const { organizationId, userId } = member;
          // Reactivate before a role change (an inactive member's role is not
          // editable), deactivate after one (so the new role is the one kept).
          const reactivated =
            status === "active" && memberStatus(member) === "inactive"
              ? yield* refusedForbidden(org.reactivateMember(actorId, organizationId, userId))
              : member;
          const reassigned =
            role === undefined
              ? reactivated
              : yield* refusedForbidden(
                  org.updateMemberRole(actorId, organizationId, userId, role),
                );
          const deactivates = status === "inactive" && memberStatus(reassigned) === "active";
          if (!deactivates && reassigned === member) {
            // Nothing changes; the answer still needs the permission a change would.
            yield* refusedForbidden(
              org.requirePermission(actorId, organizationId, "member:update"),
            );
          }
          const settled = deactivates
            ? yield* refusedForbidden(org.deactivateMember(actorId, organizationId, userId))
            : reassigned;
          return Handlers.data(memberResource(settled));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("delete", ({ params, request }) =>
        Effect.gen(function* () {
          const {
            org,
            actorId,
            target: member,
          } = yield* target(request, params.id, missingPermission("member:delete"));
          yield* refusedForbidden(org.removeMember(actorId, member.organizationId, member.userId));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("listTeams", ({ params, request }) =>
        Effect.gen(function* () {
          const { org, actorId, target: member } = yield* target(request, params.id, notAMember());
          const teams = yield* refusedForbidden(
            org.listTeamsForMember(actorId, member.organizationId, member.userId),
          );
          return Handlers.collection(teams.map(teamResource));
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

/**
 * Layer implementing the `organization-domains` group: one domain claim, by
 * id, and the operator's attestation and release (see
 * `organizationDomainsGroup` in `HttpApi.ts`).
 */
export const organizationDomainsGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);
  const target = organizationTarget(cfg, (org, id) => org.getDomainById(id));
  const manage = (request: HttpServerRequest.HttpServerRequest, id: string) =>
    target(request, id, missingPermission("domain:manage"));

  return HttpApiBuilder.group(AuthApi, "organization-domains", (handlers) =>
    handlers
      .handle("delete", ({ params, request }) =>
        Effect.gen(function* () {
          const { org, actorId, target: domain } = yield* manage(request, params.id);
          yield* refusedForbidden(org.removeDomain(actorId, domain.organizationId, domain.id));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("verify", ({ params, request }) =>
        Effect.gen(function* () {
          const { org, actorId, target: domain } = yield* manage(request, params.id);
          const verified = yield* refusedForbidden(
            org.verifyDomain(actorId, domain.organizationId, domain.id),
          );
          return Handlers.data(domainResource(verified));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      // The operator's attestation (#598): gated on `isAdmin`, never on an
      // organization permission, like SSO connection registration. The admin
      // is recorded as the claim's attester (#680).
      .handle("attest", ({ payload, request }) =>
        Effect.gen(function* () {
          const admin = yield* requireAdminCaller(request, cfg);
          const org = yield* resolveOrganization;
          const attested = yield* refusedBadRequest(
            org.service.attestDomain(
              payload.data.relationships.organization.data.id,
              payload.data.attributes.domain,
              { attestedBy: admin.id },
            ),
          );
          return Handlers.data(domainResource(attested));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      // The operator's release of any organization's claim (#680), gated as
      // the attestation is. The admin check comes first, so a non-admin never
      // learns whether an id names a claim.
      .handle("release", ({ params, request }) =>
        Effect.gen(function* () {
          yield* requireAdminCaller(request, cfg);
          const org = yield* resolveOrganization;
          const claim = yield* refusedBadRequest(org.service.getDomainById(params.id));
          if (claim === null) return yield* new S.NotFound({ message: "Domain not found" });
          return yield* refusedBadRequest(
            org.service.releaseDomain(claim.organizationId, claim.domain),
          ).pipe(Effect.asVoid);
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

/**
 * Layer implementing the `organization-roles` group: one custom role
 * definition, by its stored id (see `organizationRolesGroup` in `HttpApi.ts`).
 */
export const organizationRolesGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);
  const lookup = organizationTarget(cfg, (org, id) => org.getOrgRoleById(id));
  const target = (request: HttpServerRequest.HttpServerRequest, id: string) =>
    lookup(request, id, missingPermission("role:manage"));

  return HttpApiBuilder.group(AuthApi, "organization-roles", (handlers) =>
    handlers
      .handle("update", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const { org, actorId, target: definition } = yield* target(request, params.id);
          const permissions = payload.data.attributes?.permissions;
          if (permissions === undefined) {
            // Nothing changes; the answer still needs the permission a change would.
            yield* refusedForbidden(
              org.requirePermission(actorId, definition.organizationId, "role:manage"),
            );
            return Handlers.data(orgRoleResource(definition));
          }
          const updated = yield* refusedForbidden(
            org.upsertOrgRole(actorId, definition.organizationId, {
              role: definition.role,
              permissions,
            }),
          );
          return Handlers.data(orgRoleResource(updated));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("delete", ({ params, request }) =>
        Effect.gen(function* () {
          const { org, actorId, target: definition } = yield* target(request, params.id);
          yield* refusedForbidden(
            org.deleteOrgRole(actorId, definition.organizationId, definition.role),
          );
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

/**
 * Layer implementing the `teams` group: one team and its memberships (see
 * `teamsGroup` in `HttpApi.ts`).
 */
export const teamsGroupLayer = (config?: CookieConfig, multiSession?: MultiSessionConfig) => {
  const cfg = resolveCookieConfig(config, multiSession);

  return HttpApiBuilder.group(AuthApi, "teams", (handlers) =>
    handlers
      .handle("update", ({ params, payload, request }) =>
        asOrganizationActor(request, cfg, (org, actorId) => {
          const name = payload.data.attributes?.name;
          return org.updateTeam(actorId, params.id, { ...(name !== undefined && { name }) });
        }).pipe(
          Effect.map((team) => Handlers.data(teamResource(team))),
          JsonApiErrors.mapHttpErrors,
        ),
      )
      .handle("delete", ({ params, request }) =>
        asOrganizationActor(request, cfg, (org, actorId) =>
          org.deleteTeam(actorId, params.id),
        ).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("listMembers", ({ params, request }) =>
        asOrganizationActor(request, cfg, (org, actorId) =>
          org.listTeamMembers(actorId, params.id),
        ).pipe(
          Effect.map((members) => Handlers.collection(members.map(teamMemberResource))),
          JsonApiErrors.mapHttpErrors,
        ),
      )
      .handle("addMember", ({ params, payload, request }) =>
        asOrganizationActor(request, cfg, (org, actorId) =>
          org.addTeamMember(actorId, params.id, payload.data.relationships.user.data.id),
        ).pipe(
          Effect.map((member) => Handlers.data(teamMemberResource(member))),
          JsonApiErrors.mapHttpErrors,
        ),
      ),
  );
};

/**
 * Layer implementing the `team-members` group: one team membership, by its
 * stored id (see `teamMembersGroup` in `HttpApi.ts`).
 */
export const teamMembersGroupLayer = (config?: CookieConfig, multiSession?: MultiSessionConfig) => {
  const target = organizationTarget(resolveCookieConfig(config, multiSession), (org, id) =>
    org.getTeamMemberById(id),
  );

  return HttpApiBuilder.group(AuthApi, "team-members", (handlers) =>
    handlers.handle("delete", ({ params, request }) =>
      Effect.gen(function* () {
        const {
          org,
          actorId,
          target: member,
        } = yield* target(request, params.id, missingPermission("team:manage-members"));
        yield* refusedForbidden(org.removeTeamMember(actorId, member.teamId, member.userId));
      }).pipe(JsonApiErrors.mapHttpErrors),
    ),
  );
};

/**
 * Layer implementing the `invitations` group: the caller's own pending
 * invitations, an invitation's status transitions and re-deliveries (see
 * `invitationsGroup` in `HttpApi.ts`).
 */
export const invitationsGroupLayer = (config?: CookieConfig, multiSession?: MultiSessionConfig) => {
  const cfg = resolveCookieConfig(config, multiSession);
  const actor = (request: HttpServerRequest.HttpServerRequest) => organizationActor(request, cfg);

  return HttpApiBuilder.group(AuthApi, "invitations", (handlers) =>
    handlers
      .handle("list", ({ request }) =>
        Effect.gen(function* () {
          // Only the caller's own verified addresses (#706); `invitationResource`
          // never carries the token digest.
          const { org, actorId } = yield* actor(request);
          const invitations = yield* storeFailure(org.listInvitationsForUser(actorId));
          return Handlers.collection(invitations.map(invitationResource));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("update", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const { org, actorId, resolved } = yield* actor(request);
          // Without the emailed token, the service takes a verified matching
          // address as the proof (#673).
          const { status, token } = payload.data.attributes ?? {};
          const answer = { invitationId: params.id, token };
          if (status === "accepted") {
            const { member, invitation } = yield* refusedBadRequest(
              org.acceptInvitation(actorId, { ...answer, currentSessionId: resolved.session.id }),
            );
            return Handlers.data(invitationResource(invitation), {
              meta: { membership: memberResource(member) },
            });
          }
          if (status === "rejected") {
            const rejected = yield* refusedBadRequest(org.rejectInvitation(actorId, answer));
            return Handlers.data(invitationResource(rejected));
          }
          if (status === "canceled") {
            const canceled = yield* refusedForbidden(org.cancelInvitation(actorId, params.id));
            return Handlers.data(invitationResource(canceled));
          }
          return yield* new S.BadRequest({
            message: "An invitation's status can move only to accepted, rejected or canceled",
          });
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("deliver", ({ params, request }) =>
        Effect.gen(function* () {
          const { org, actorId } = yield* actor(request);
          const invitation = yield* refusedForbidden(org.resendInvitation(actorId, params.id));
          return Handlers.data(invitationResource(invitation));
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

// -----------------------------------------------------------------------------
// Admin, impersonation, API keys, OAuth clients, SSO, JWTs and device approval
// (#205, slice 5)
// -----------------------------------------------------------------------------

// The service inputs below leave an optional key out rather than set it to
// `undefined` (`exactOptionalPropertyTypes`), so each is built field by field.

/** `GET /admin/users`' query as the admin service's listing query. */
const listUsersQuery = (query: {
  readonly page?: { readonly offset?: number; readonly limit?: number } | undefined;
  readonly filter?: { readonly email?: string } | undefined;
}): ListUsersQuery => ({
  ...(query.page?.limit !== undefined && { limit: query.page.limit }),
  ...(query.page?.offset !== undefined && { offset: query.page.offset }),
  ...(query.filter?.email !== undefined && { searchEmail: query.filter.email }),
});

/** A ban's `reason` and `expiresIn`, as the admin service's ban options. */
const banOptions = (attributes: {
  readonly reason?: string | undefined;
  readonly expiresIn?: number | undefined;
}): BanUserOptions => ({
  ...(attributes.reason !== undefined && { reason: attributes.reason }),
  ...(attributes.expiresIn !== undefined && { expiresIn: attributes.expiresIn }),
});

/** The settings an API key's create and update share: its name, grants and limits. */
const apiKeySettings = (a: S.ApiKeyUpdatePayload) => ({
  ...(a.name !== undefined && { name: a.name }),
  ...(a.permissions !== undefined && { permissions: a.permissions }),
  ...(a.metadata !== undefined && { metadata: a.metadata }),
  ...(a.remaining !== undefined && { remaining: a.remaining }),
  ...(a.rateLimit !== undefined && { rateLimit: a.rateLimit }),
});

/** The settings of `POST /api-keys`, as the API-key service's create options. */
const apiKeyCreateOptions = (a: S.ApiKeyCreatePayload): ApiKeyCreateOptions => ({
  ...apiKeySettings(a),
  ...(a.prefix !== undefined && { prefix: a.prefix }),
  ...(a.expiresIn !== undefined && { expiresIn: a.expiresIn }),
});

/** The attributes of `PATCH /api-keys/:id`, as the API-key service's update. */
const apiKeyUpdate = (a: S.ApiKeyUpdatePayload): ApiKeyUpdate => ({
  ...apiKeySettings(a),
  ...(a.enabled !== undefined && { enabled: a.enabled }),
  ...(a.expiresAt !== undefined && { expiresAt: a.expiresAt }),
});

/** The attributes of `POST /oauth-clients`, as the provider's registration input. */
const oauthClientInput = (a: {
  readonly name: string;
  readonly redirectUris: ReadonlyArray<string>;
  readonly clientType?: "web" | "native" | undefined;
  readonly skipConsent?: boolean | undefined;
  readonly metadata?: Types.Attributes | undefined;
}): RegisterOidcClientInput => ({
  name: a.name,
  redirectUris: a.redirectUris,
  ...(a.clientType !== undefined && { type: a.clientType }),
  ...(a.skipConsent !== undefined && { skipConsent: a.skipConsent }),
  ...(a.metadata !== undefined && { metadata: a.metadata }),
});

/** The attributes of `PATCH /oauth-clients/:id`, as the provider's client update. */
const oauthClientUpdate = (a: S.OidcClientUpdatePayload): UpdateOidcClientInput => ({
  ...(a.name !== undefined && { name: a.name }),
  ...(a.redirectUris !== undefined && { redirectUris: a.redirectUris }),
  ...(a.skipConsent !== undefined && { skipConsent: a.skipConsent }),
  ...(a.disabled !== undefined && { disabled: a.disabled }),
  ...(a.metadata !== undefined && { metadata: a.metadata }),
});

/** A SAML registration document's attributes, as the SSO service's input. */
const samlRegistration = (
  p: S.SsoRegisterSamlAttributes,
  organizationId: string | undefined,
): RegisterSamlProviderInput => ({
  ...samlConnection(p),
  ...(organizationId !== undefined && { organizationId }),
});

/** An OIDC registration document's attributes, as the SSO service's input. */
const oidcRegistration = (
  p: S.SsoRegisterOidcAttributes,
  organizationId: string | undefined,
): RegisterProviderInput => ({
  issuer: p.issuer,
  domain: p.domain,
  clientId: p.clientId,
  clientSecret: p.clientSecret,
  redirectUri: p.redirectUri,
  ...(p.discover !== undefined && { discover: p.discover }),
  ...(p.authorizationEndpoint !== undefined && {
    authorizationEndpoint: p.authorizationEndpoint,
  }),
  ...(p.tokenEndpoint !== undefined && { tokenEndpoint: p.tokenEndpoint }),
  ...(p.userInfoEndpoint !== undefined && { userInfoEndpoint: p.userInfoEndpoint }),
  ...(p.jwksEndpoint !== undefined && { jwksEndpoint: p.jwksEndpoint }),
  ...(p.scopes !== undefined && { scopes: p.scopes }),
  ...(p.usePKCE !== undefined && { usePKCE: p.usePKCE }),
  ...(organizationId !== undefined && { organizationId }),
});

/** A sign-in document's selector (`email`, `domain` or `providerId`), as the SSO service's. */
const ssoSelector = (p: S.SsoSignInPayload): SsoSignInSelector => ({
  ...(p.email !== undefined && { email: p.email }),
  ...(p.domain !== undefined && { domain: p.domain }),
  ...(p.providerId !== undefined && { providerId: p.providerId }),
});

/**
 * An admin call's failures as the client sees them: a refusal (`isAdmin`
 * fails, or the target is protected) is `403`, an unknown user `400`, a store
 * failure `500`.
 */
const asAdmin = <A, R>(
  self: Effect.Effect<A, AdminError | UserNotFoundError | AuthError, R>,
): Effect.Effect<A, S.Forbidden | S.BadRequest | S.InternalServerError, R> =>
  Effect.catchTags(self, adminFailures);

/** The `catchTags` cases of {@link asAdmin}. */
const adminFailures = {
  AdminError: (e: AdminError) => Effect.fail(new S.Forbidden({ message: e.message })),
  UserNotFoundError: (e: UserNotFoundError) =>
    Effect.fail(new S.BadRequest({ message: e.message })),
  AuthError: (e: AuthError) => internalServerError(e),
};

/**
 * The signed-in actor and the admin service: `401` without a session, `404`
 * when admin is not enabled.
 */
const adminActor = (request: HttpServerRequest.HttpServerRequest, cfg: ResolvedCookieConfig) =>
  Effect.gen(function* () {
    const resolved = yield* requireSession(request, cfg);
    const admin = yield* resolveAdmin;
    return { admin: admin.service, actor: resolved.user };
  });

/**
 * The signed-in caller, when they are an administrator (what the OAuth-client,
 * SSO-provider and domain attestation and release endpoints gate on): `401`
 * without a session, `403` otherwise. The rule is the mounted
 * `AdminService`'s, so its `AdminConfig` (`adminRoles`, `adminUserIds`)
 * governs these endpoints as it does `/admin/users` (#680); without an
 * `AdminService`, the default `isAdmin` rule (role `admin`).
 */
const requireAdminCaller = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
) =>
  Effect.gen(function* () {
    const resolved = yield* requireSession(request, cfg);
    const admin = yield* Effect.serviceOption(AdminService);
    const allowed = Option.match(admin, {
      onNone: () => isAdmin(resolved.user),
      onSome: (service) => service.isAdmin(resolved.user),
    });
    if (!allowed) {
      return yield* new S.Forbidden({ message: "Admin privileges required" });
    }
    return resolved.user;
  });

/**
 * A bodiless admin call on the user the URL's `:id` names (a removal, a
 * revocation, a lifted ban), as the signed-in actor: `204` once it is done.
 */
const adminAction =
  (
    cfg: ResolvedCookieConfig,
    act: (
      admin: typeof AdminService.Service,
      actor: Types.User,
      userId: string,
    ) => Effect.Effect<unknown, AdminError | UserNotFoundError | AuthError>,
  ) =>
  ({
    params,
    request,
  }: {
    readonly params: { readonly id: string };
    readonly request: HttpServerRequest.HttpServerRequest;
  }) =>
    Effect.gen(function* () {
      const { admin, actor } = yield* adminActor(request, cfg);
      yield* asAdmin(act(admin, actor, params.id));
    }).pipe(JsonApiErrors.mapHttpErrors);

/**
 * Layer implementing the `admin-users` group: user administration (see
 * `adminUsersGroup` in `HttpApi.ts`).
 */
export const adminUsersGroupLayer = (config?: CookieConfig, multiSession?: MultiSessionConfig) => {
  const cfg = resolveCookieConfig(config, multiSession);

  return HttpApiBuilder.group(AuthApi, "admin-users", (handlers) =>
    handlers
      .handle("list", ({ query, request }) =>
        Effect.gen(function* () {
          const { admin, actor } = yield* adminActor(request, cfg);
          const result = yield* asAdmin(admin.listUsers(actor, listUsersQuery(query)));
          const users = yield* Effect.forEach(result.users, loadUserResource, { concurrency: 1 });
          return Handlers.collection(users, { meta: { total: result.total } });
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("update", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const { admin, actor } = yield* adminActor(request, cfg);
          const user = yield* asAdmin(
            admin.setRole(actor, params.id, payload.data.attributes.role),
          );
          return Handlers.data(yield* loadUserResource(user));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle(
        "delete",
        adminAction(cfg, (admin, actor, id) => admin.removeUser(actor, id)),
      )
      .handle(
        "deleteSessions",
        adminAction(cfg, (admin, actor, id) => admin.revokeUserSessions(actor, id)),
      ),
  );
};

/** The `user-bans` resource of a banned user: the ban fields of its `attributes`. */
const userBanResource = (user: Types.User): R.UserBan => {
  const reason = user.attributes["banReason"];
  const expiresAt = user.attributes["banExpires"];
  return R.UserBan.make({
    id: user.id,
    attributes: {
      reason: P.isString(reason) ? reason : "",
      ...(P.isNumber(expiresAt) && { expiresAt }),
    },
    relationships: { user: { data: R.User.ref(user.id) } },
  });
};

/**
 * Layer implementing the `user-bans` group: ban and unban users (see
 * `userBansGroup` in `HttpApi.ts`).
 */
export const userBansGroupLayer = (config?: CookieConfig, multiSession?: MultiSessionConfig) => {
  const cfg = resolveCookieConfig(config, multiSession);

  return HttpApiBuilder.group(AuthApi, "user-bans", (handlers) =>
    handlers
      .handle("create", ({ payload, request }) =>
        Effect.gen(function* () {
          const { admin, actor } = yield* adminActor(request, cfg);
          const banned = yield* asAdmin(
            admin.banUser(
              actor,
              payload.data.relationships.user.data.id,
              banOptions(payload.data.attributes ?? {}),
            ),
          );
          return Handlers.data(userBanResource(banned), {
            included: [yield* loadUserResource(banned)],
          });
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle(
        "delete",
        adminAction(cfg, (admin, actor, id) => admin.unbanUser(actor, id)),
      ),
  );
};

/**
 * Layer implementing the `impersonations` group: start and end an
 * administrator's impersonation of a user (see `impersonationsGroup` in
 * `HttpApi.ts`).
 */
export const impersonationsGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);

  return HttpApiBuilder.group(AuthApi, "impersonations", (handlers) =>
    handlers
      .handle("create", ({ payload, request }) =>
        Effect.gen(function* () {
          const { admin, actor } = yield* adminActor(request, cfg);
          const issued = yield* Effect.catchTags(
            admin.impersonateUser(actor, payload.data.relationships.user.data.id),
            { ...hookFailures, ...adminFailures },
          );
          const { session } = issued;
          const userService = yield* UserService;
          const user = yield* userService
            .getUser(session.userId)
            .pipe(Effect.catch(internalServerError));
          // The session cookie becomes the impersonation's session.
          yield* issueSession(issued, cfg, undefined, undefined);
          return Handlers.data(
            R.Impersonation.make({
              id: session.id,
              attributes: { expiresAt: session.expiresAt, createdAt: session.createdAt },
              relationships: {
                user: { data: R.User.ref(session.userId) },
                impersonator: { data: R.User.ref(actor.id) },
              },
            }),
            { included: [yield* loadUserResource(user)] },
          );
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("delete", ({ params, request }) =>
        Effect.gen(function* () {
          yield* resolveAdmin; // 404 when admin is not enabled
          if (params.id !== CURRENT) {
            return yield* new S.NotFound({ message: "Impersonation not found" });
          }
          const { resolved, token } = yield* resolveSession(request, cfg);
          if (!Types.isImpersonationSession(resolved.session)) {
            return yield* new S.NotFound({ message: "This session is not an impersonation" });
          }
          const sessionManager = yield* SessionService;
          yield* storeFailure(sessionManager.invalidateSession(token));
          return yield* clearSessionCookies(request, cfg, token);
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

/** An API-key call's failures: a refusal (or a key the caller does not own) is `400`. */
const asApiKeyOwner = <A, R>(
  self: Effect.Effect<A, ApiKeyError | AuthError, R>,
): Effect.Effect<A, S.BadRequest | S.InternalServerError, R> =>
  Effect.catchTags(self, {
    ApiKeyError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
    AuthError: (e) => internalServerError(e),
  });

/**
 * The one message every API key that does not resolve is answered with
 * (#730): unknown, disabled, expired, exhausted, missing or ownerless alike,
 * so the answer never tells them apart. The reason goes to the server log.
 */
const API_KEY_REFUSED = "Invalid API key";

/**
 * Refuse a key resolution with the identical `401`, logging only why (never
 * the key, which no log line or error ever carries).
 */
const refuseApiKey = (reason: string): Effect.Effect<never, S.Unauthorized> =>
  Effect.logInfo("[effect-auth] API key refused").pipe(
    Effect.annotateLogs({ reason }),
    Effect.andThen(Effect.fail(new S.Unauthorized({ message: API_KEY_REFUSED }))),
  );

/** Set `name: value` on whatever response the handler ends up sending, error or not. */
const setResponseHeader = (
  name: string,
  value: string,
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =>
  HttpEffect.appendPreResponseHandler((_request, response) =>
    Effect.succeed(HttpServerResponse.setHeader(response, name, value)),
  );

/**
 * The `429` of a real key over its own `rateLimit`, with `Retry-After` in
 * whole seconds (rounded up) when the limiter said how long.
 */
const apiKeyRateLimited = (
  retryAfter: Duration.Duration | undefined,
): Effect.Effect<never, S.TooManyRequests, HttpServerRequest.HttpServerRequest> =>
  Effect.gen(function* () {
    if (retryAfter !== undefined) {
      yield* setResponseHeader("retry-after", String(Math.ceil(Duration.toSeconds(retryAfter))));
    }
    return yield* new S.TooManyRequests({ message: "Too many requests" });
  });

/**
 * `GET /api-keys/current` (#730): the key the request carries in an API-key
 * header, verified with `verifyWithRateLimit` (no required permissions, so
 * the app checks those through the policy kernel), and the user it acts as.
 * The session cookie and bearer token are never read here, so a key always
 * wins over them. `404` before anything is read when API keys are off.
 */
const resolveCurrentApiKey = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
) =>
  Effect.gen(function* () {
    yield* setResponseHeader("cache-control", "no-store");
    const apiKey = yield* resolveApiKey; // 404 when API keys are not enabled
    const presented = extractApiKey(fromHeaders(request.headers), {
      ...(cfg.apiKeyHeaders !== undefined && { apiKeyHeaders: cfg.apiKeyHeaders }),
    });
    if (presented === undefined) return yield* refuseApiKey("no API key header");
    const result = yield* storeFailure(apiKey.service.verifyWithRateLimit(presented));
    if (result.reason === "rate-limited") return yield* apiKeyRateLimited(result.retryAfter);
    if (!result.valid || result.apiKey === undefined) {
      return yield* refuseApiKey(result.error ?? "API key refused");
    }
    const key = result.apiKey;
    const userService = yield* UserService;
    const user = yield* userService.getUser(key.userId).pipe(
      Effect.catchTags({
        // Owner existence, ban and SCIM deactivation are decided in `verify`, before
        // the limit and the spend (#755); this covers a delete racing the read.
        UserNotFoundError: () => refuseApiKey("API key owner not found"),
        AuthError: (e) => internalServerError(e),
      }),
    );
    return Handlers.data(apiKeyResource(key), { included: [yield* loadUserResource(user)] });
  });

/**
 * Layer implementing the `api-keys` group: the signed-in user's API keys, and
 * `GET /api-keys/current`, the resolution of a presented key (see
 * `apiKeysGroup` in `HttpApi.ts`).
 */
export const apiKeysGroupLayer = (config?: CookieConfig, multiSession?: MultiSessionConfig) => {
  const cfg = resolveCookieConfig(config, multiSession);

  /** The caller's id and the API-key service: `401` without a session, `404` when off. */
  const owner = (request: HttpServerRequest.HttpServerRequest) =>
    Effect.gen(function* () {
      const resolved = yield* requireSession(request, cfg);
      const apiKey = yield* resolveApiKey;
      return { apiKey: apiKey.service, userId: resolved.user.id };
    });

  return HttpApiBuilder.group(AuthApi, "api-keys", (handlers) =>
    handlers
      .handle("current", ({ request }) =>
        resolveCurrentApiKey(request, cfg).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("list", ({ request }) =>
        Effect.gen(function* () {
          const { apiKey, userId } = yield* owner(request);
          const keys = yield* storeFailure(apiKey.list(userId));
          return Handlers.collection(keys.map(apiKeyResource));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("create", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          // A key is never minted from a machine credential (a bearer token,
          // another key): only from the interactive session cookie.
          yield* requireInteractiveCredential(request);
          const apiKey = yield* resolveApiKey;
          // The answer carries the raw key, shown this once (#628).
          yield* noStore;
          const result = yield* asApiKeyOwner(
            apiKey.service.create(resolved.user.id, apiKeyCreateOptions(payload.data.attributes)),
          );
          // The plaintext key is shown this once, in `meta`.
          return Handlers.data(apiKeyResource(result.apiKey), { meta: { key: result.key } });
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("update", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const { apiKey, userId } = yield* owner(request);
          const updated = yield* asApiKeyOwner(
            apiKey.update(userId, params.id, apiKeyUpdate(payload.data.attributes ?? {})),
          );
          return Handlers.data(apiKeyResource(updated));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("delete", ({ params, request }) =>
        Effect.gen(function* () {
          const { apiKey, userId } = yield* owner(request);
          yield* asApiKeyOwner(apiKey.delete(userId, params.id));
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

/**
 * Layer implementing the `oauth-clients` group: the OIDC provider's client
 * registry, for administrators (see `oauthClientsGroup` in `HttpApi.ts`).
 */
export const oauthClientsGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);

  /** The administrator's id and the provider: `401`, `403`, or `404` when it is off. */
  const administrator = (request: HttpServerRequest.HttpServerRequest) =>
    Effect.gen(function* () {
      const user = yield* requireAdminCaller(request, cfg);
      const oidc = yield* resolveOidcProvider;
      return { oidc: oidc.service, userId: user.id };
    });

  return HttpApiBuilder.group(AuthApi, "oauth-clients", (handlers) =>
    handlers
      .handle("list", ({ request }) =>
        Effect.gen(function* () {
          const { oidc } = yield* administrator(request);
          const clients = yield* storeFailure(oidc.listClients());
          return Handlers.collection(clients.map(oauthClientResource));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("create", ({ payload, request }) =>
        Effect.gen(function* () {
          const { oidc, userId } = yield* administrator(request);
          // The answer may carry the client secret, shown this once (#628).
          yield* noStore;
          const result = yield* oidcProviderFailures(
            oidc.registerClient(oauthClientInput(payload.data.attributes), userId),
          );
          // A confidential client's secret is shown this once, in `meta`.
          return Handlers.data(oauthClientResource(result.client), {
            meta: result.clientSecret === undefined ? {} : { clientSecret: result.clientSecret },
          });
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("update", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const { oidc } = yield* administrator(request);
          const updated = yield* oidcProviderFailures(
            oidc.updateClient(params.id, oauthClientUpdate(payload.data.attributes ?? {})),
          );
          return Handlers.data(oauthClientResource(updated));
        }).pipe(JsonApiErrors.mapHttpErrors),
      )
      .handle("delete", ({ params, request }) =>
        Effect.gen(function* () {
          const { oidc } = yield* administrator(request);
          yield* oidcProviderFailures(oidc.deleteClient(params.id));
        }).pipe(JsonApiErrors.mapHttpErrors),
      ),
  );
};

/** An SSO call's failures: a refusal is `400`, a store failure `500`. */
const asSsoRequest = <A, R>(
  self: Effect.Effect<A, SsoError | AuthError, R>,
): Effect.Effect<A, S.BadRequest | S.InternalServerError, R> =>
  Effect.catchTags(self, {
    SsoError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
    AuthError: (e) => internalServerError(e),
  });

/**
 * Layer implementing the `sso-providers` group: register an enterprise SSO
 * connection (see `ssoProvidersGroup` in `HttpApi.ts`).
 */
export const ssoProvidersGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);

  return HttpApiBuilder.group(AuthApi, "sso-providers", (handlers) =>
    handlers.handle("create", ({ payload, request }) =>
      Effect.gen(function* () {
        const user = yield* requireAdminCaller(request, cfg);
        const sso = yield* resolveSso;
        // The attributes are a union discriminated on `protocol`; without one
        // they are an OIDC registration.
        const attributes = payload.data.attributes;
        const organizationId = payload.data.relationships?.organization?.data?.id;
        const provider =
          attributes.protocol === "saml"
            ? yield* asSsoRequest(
                sso.service.registerSamlProvider(
                  user.id,
                  samlRegistration(attributes, organizationId),
                ),
              )
            : yield* asSsoRequest(
                sso.service.registerProvider(user.id, oidcRegistration(attributes, organizationId)),
              );
        return Handlers.data(ssoProviderResource(provider));
      }).pipe(JsonApiErrors.mapHttpErrors),
    ),
  );
};

/**
 * Layer implementing the `sso-authorizations` group: start an SSO sign-in
 * (see `ssoAuthorizationsGroup` in `HttpApi.ts`).
 */
export const ssoAuthorizationsGroupLayer = HttpApiBuilder.group(
  AuthApi,
  "sso-authorizations",
  (handlers) =>
    handlers.handle("create", ({ payload }) =>
      Effect.gen(function* () {
        const sso = yield* resolveSso;
        // The single-use callback state is this caller's alone: a cached
        // answer would hand it to the next caller (#628).
        yield* noStore;
        const result = yield* asSsoRequest(
          sso.service.signIn(ssoSelector(payload.data.attributes)),
        );
        return Handlers.data(
          R.SsoAuthorization.make({ id: result.state, attributes: { url: result.url } }),
        );
      }).pipe(JsonApiErrors.mapHttpErrors),
    ),
);

/**
 * Layer implementing the `tokens` group: sign a JWT for the signed-in user
 * (see `tokensGroup` in `HttpApi.ts`).
 */
export const tokensGroupLayer = (config?: CookieConfig, multiSession?: MultiSessionConfig) => {
  const cfg = resolveCookieConfig(config, multiSession);

  return HttpApiBuilder.group(AuthApi, "tokens", (handlers) =>
    handlers.handle("create", ({ request }) =>
      Effect.gen(function* () {
        const resolved = yield* requireSession(request, cfg);
        const jwt = yield* resolveJwt;
        yield* noStore;
        const { token, expiresAt } = yield* storeFailure(jwt.service.sign(resolved.user));
        // A token is not stored: its id is its digest, never the token itself.
        return Handlers.data(
          R.Token.make({ id: hashToken(token), attributes: { token, expiresAt } }),
        );
      }).pipe(JsonApiErrors.mapHttpErrors),
    ),
  );
};

/**
 * Settle a device authorization: done, or an unknown or settled code as
 * `400`, a store failure as `500`.
 */
const deviceDecision = <R>(
  decision: Effect.Effect<void, DeviceCodeError | AuthError, R>,
): Effect.Effect<void, S.BadRequest | S.InternalServerError, R> =>
  Effect.catchTags(decision, {
    DeviceCodeError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
    AuthError: (e) => internalServerError(e),
  });

/**
 * Layer implementing the `device-authorizations` group: the verification
 * page's approval or denial of a device's user code (see
 * `deviceAuthorizationsGroup` in `HttpApi.ts`).
 */
export const deviceAuthorizationsGroupLayer = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
) => {
  const cfg = resolveCookieConfig(config, multiSession);

  return HttpApiBuilder.group(AuthApi, "device-authorizations", (handlers) =>
    handlers.handle("decide", ({ payload, request }) =>
      Effect.gen(function* () {
        const { userCode, decision } = payload.data.attributes;
        // Approving grants the device the caller's session, so it needs one;
        // denying needs none.
        const approver =
          decision === "approved" ? (yield* requireSession(request, cfg)).user.id : undefined;
        const device = yield* resolveDevice;
        // Rate-limit user_code attempts per RFC 8628 §5.2: user codes are ~39
        // bits, so without a per-code limit pending codes could be enumerated
        // (approve) or griefed at scale (deny, which is unauthenticated).
        yield* applyUserCodeRateLimit(userCode, device.service);
        return yield* deviceDecision(
          approver === undefined
            ? device.service.deny(userCode)
            : device.service.approve(userCode, approver),
        );
      }).pipe(JsonApiErrors.mapHttpErrors),
    ),
  );
};

/**
 * Every group of the {@link AuthApi} contract, with the JSON:API protocol
 * middleware its resource groups declare: what `HttpApiBuilder.layer(AuthApi)`
 * needs to build. `make` and `makeAsync` use it; compose it yourself to serve
 * the contract from your own `HttpApiBuilder` (the SCIM group is always
 * mounted and answers `404` until `ScimService` is provided).
 * `signUpAttributes` is {@link AuthWebHandlerOptions.signUpAttributes}: the
 * attribute keys `POST /users` accepts (default none).
 *
 * @since 0.1.0
 * @category layers
 */
export const groupLayers = (
  config?: CookieConfig,
  multiSession?: MultiSessionConfig,
  signUpAttributes?: ReadonlyArray<string>,
) =>
  Layer.mergeAll(
    authGroupLayer(config, multiSession),
    sessionsGroupLayer(config, multiSession),
    identifiersGroupLayer(config, multiSession),
    usersGroupLayer(config, multiSession, signUpAttributes),
    secondFactorChallengesGroupLayer(config, multiSession),
    otpChallengesGroupLayer(),
    emailVerificationsGroupLayer(config, multiSession),
    passwordResetsGroupLayer(),
    googleOneTapNoncesGroupLayer(),
    emailChangesGroupLayer(config, multiSession),
    accountDeletionsGroupLayer(config, multiSession),
    multiFactorEnrollmentsGroupLayer(config, multiSession),
    backupCodeSetsGroupLayer(config, multiSession),
    deviceSessionsGroupLayer(config, multiSession),
    organizationsGroupLayer(config, multiSession),
    organizationMembersGroupLayer(config, multiSession),
    invitationsGroupLayer(config, multiSession),
    organizationDomainsGroupLayer(config, multiSession),
    organizationRolesGroupLayer(config, multiSession),
    teamsGroupLayer(config, multiSession),
    teamMembersGroupLayer(config, multiSession),
    adminUsersGroupLayer(config, multiSession),
    userBansGroupLayer(config, multiSession),
    impersonationsGroupLayer(config, multiSession),
    apiKeysGroupLayer(config, multiSession),
    oauthClientsGroupLayer(config, multiSession),
    ssoProvidersGroupLayer(config, multiSession),
    ssoAuthorizationsGroupLayer,
    tokensGroupLayer(config, multiSession),
    deviceAuthorizationsGroupLayer(config, multiSession),
    scimGroupLayer(),
  ).pipe(
    // The protocol middleware the JSON:API endpoints declare: content
    // negotiation, schema errors as error documents, and the create's
    // `Location` header.
    Layer.provideMerge(JsonApiMiddleware.layer),
  );

/** Layer implementing the `auth` group handlers. */
export const authGroupLayer = (config?: CookieConfig, multiSession?: MultiSessionConfig) => {
  const cfg = resolveCookieConfig(config, multiSession);

  return HttpApiBuilder.group(AuthApi, "auth", (handlers) =>
    handlers
      .handle("deviceCode", ({ payload }) =>
        Effect.gen(function* () {
          const device = yield* resolveDevice;
          // RFC 8628 §3.2: the answer carries the device code, the secret
          // the device polls with (#628).
          yield* noStore;
          return yield* device.service
            .begin({
              ...(payload.clientId !== undefined && { clientId: payload.clientId }),
              ...(payload.scopes !== undefined && { scopes: payload.scopes }),
            })
            .pipe(
              Effect.catchTags({
                AuthError: (e) => internalServerError(e),
              }),
            );
        }),
      )
      .handle("deviceToken", ({ payload }) =>
        Effect.gen(function* () {
          const device = yield* resolveDevice;
          // A token response (RFC 8628 §3.5, RFC 6749 §5.1): never cached.
          yield* noStore;
          const result = yield* device.service.poll(payload.deviceCode).pipe(
            Effect.catchTags({
              // RFC 8628 poll errors -> 400 with the error code as message.
              DevicePollError: (e) => Effect.fail(new S.BadRequest({ message: e.error })),
              SessionNotFoundError: (e) => internalServerError(e),
              SessionExpiredError: (e) => internalServerError(e),
              UserNotFoundError: (e) => internalServerError(e),
              AuthError: (e) => internalServerError(e),
              RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
              AccountLockedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              UserBannedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              CaptchaError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
              PwnedPasswordError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
            }),
          );
          const body: S.AuthSuccess = {
            user: yield* encodeUserView(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result, cfg, "device");
        }),
      )
      .handle("ssoCallback", ({ payload }) =>
        Effect.gen(function* () {
          const sso = yield* resolveSso;
          const result = yield* sso.service.handleCallback(payload.state, payload.code).pipe(
            Effect.catchTags({
              SsoError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
              RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
              AccountLockedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              UserBannedError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              CaptchaError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
              PwnedPasswordError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
            }),
          );
          const body: S.AuthSuccess = {
            user: yield* encodeUserView(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result, cfg, "sso");
        }),
      )
      // SAML assertion consumer service. The IdP form-POSTs here through the
      // user's browser, so the tail is the same session-issuing one the OIDC
      // callback uses — cookie, last-login-method hint, bearer header and all.
      .handle("samlAcs", ({ params, payload }) =>
        Effect.gen(function* () {
          const sso = yield* resolveSso;
          const result = yield* sso.service
            .handleSamlCallback(params.providerId, payload.SAMLResponse, payload.RelayState)
            .pipe(
              Effect.catchTags({
                SsoError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
                RateLimitError: (e) => Effect.fail(new S.TooManyRequests({ message: e.message })),
                AccountLockedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                UserBannedError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                    ),
                  ),
                CaptchaError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
                PwnedPasswordError: (e) =>
                  resolveMessage(e.code, e.message).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
              }),
            );
          const body: S.AuthSuccess = {
            user: yield* encodeUserView(result.user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, result, cfg, "sso");
        }),
      )
      .handle("samlMetadata", ({ params }) =>
        Effect.gen(function* () {
          const sso = yield* resolveSso;
          return yield* sso.service.samlMetadata(params.providerId).pipe(
            Effect.catchTags({
              SsoError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }),
      )
      .handle("jwtJwks", () => jwksDocument())
      // --- OIDC provider ------------------------------------------------------
      .handle("oidcAuthorize", ({ query, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          // Unauthenticated: redirect to the login page carrying the original
          // authorize URL so the app can resume the flow after sign-in.
          const session = yield* resolveSession(request, cfg).pipe(
            Effect.catch(() => Effect.succeed(null)),
          );
          if (session === null || query.prompt === "login") {
            // prompt=none: must not show any UI — redirect back to the client with login_required.
            if (session === null && query.prompt === "none" && query.redirect_uri !== undefined) {
              const clientId = query.client_id;
              if (clientId !== undefined) {
                const client = yield* oidc.service
                  .getClient(clientId)
                  .pipe(Effect.catchTag("AuthError", () => Effect.succeed(null)));
                if (client !== null && client.redirectUris.includes(query.redirect_uri)) {
                  const errUrl = new URL(query.redirect_uri);
                  errUrl.searchParams.set("error", "login_required");
                  if (query.state !== undefined) errUrl.searchParams.set("state", query.state);
                  return HttpServerResponse.redirect(errUrl.toString(), { status: 302 });
                }
              }
            }
            return HttpServerResponse.redirect(oidc.service.loginRedirect(request.url), {
              status: 302,
            });
          }
          // Missing client/redirect_uri cannot be answered with a redirect
          // (there is nowhere trustworthy to send the user) -> 400.
          if (query.client_id === undefined || query.redirect_uri === undefined) {
            return yield* new S.BadRequest({
              message: "client_id and redirect_uri are required",
            });
          }
          const result = yield* oidc.service
            .authorize(session.resolved.user, {
              responseType: query.response_type ?? "",
              clientId: query.client_id,
              redirectUri: query.redirect_uri,
              ...(query.scope !== undefined && { scope: query.scope }),
              ...(query.state !== undefined && { state: query.state }),
              ...(query.code_challenge !== undefined && {
                codeChallenge: query.code_challenge,
              }),
              ...(query.code_challenge_method !== undefined && {
                codeChallengeMethod: query.code_challenge_method,
              }),
              ...(query.nonce !== undefined && { nonce: query.nonce }),
              ...(query.prompt !== undefined && { prompt: query.prompt }),
            })
            .pipe(oidcProviderFailures);
          return HttpServerResponse.redirect(result.redirectTo, { status: 302 });
        }),
      )
      .handle("oidcConsent", ({ payload, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          // The redirect carries the authorization code (#628).
          yield* noStore;
          const resolved = yield* requireSession(request, cfg);
          const result = yield* oidc.service
            .consent(resolved.user.id, payload.consentCode, payload.accept)
            .pipe(oidcProviderFailures);
          return { redirectTo: result.redirectTo };
        }),
      )
      .handle("oidcToken", ({ payload, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          // RFC 6749 §5.1: a token response is `no-store`.
          yield* noStore;
          // Client authentication: a Basic Authorization header takes
          // precedence over body credentials (RFC 6749 §2.3.1).
          let clientId = payload.client_id;
          let clientSecret = payload.client_secret;
          const auth = request.headers["authorization"];
          if (auth !== undefined && auth.startsWith("Basic ")) {
            // Not base64: no Basic credentials, so the body's (if any) apply.
            const decoded = Result.getOrElse(Base64.decodeString(auth.slice(6)), () => "");
            const sep = decoded.indexOf(":");
            if (sep >= 0) {
              clientId = decodeURIComponent(decoded.slice(0, sep));
              clientSecret = decodeURIComponent(decoded.slice(sep + 1));
            }
          }
          const result = yield* oidc.service
            .token({
              grantType: payload.grant_type,
              ...(payload.code !== undefined && { code: payload.code }),
              ...(payload.redirect_uri !== undefined && {
                redirectUri: payload.redirect_uri,
              }),
              ...(payload.code_verifier !== undefined && {
                codeVerifier: payload.code_verifier,
              }),
              ...(payload.refresh_token !== undefined && {
                refreshToken: payload.refresh_token,
              }),
              ...(payload.scope !== undefined && { scope: payload.scope }),
              ...(clientId !== undefined && { clientId }),
              ...(clientSecret !== undefined && { clientSecret }),
            })
            .pipe(
              Effect.catchTags({
                // RFC 6749 error codes: invalid_client -> 401, the rest -> 400.
                OidcTokenError: (e) =>
                  Effect.fail(
                    e.error === "invalid_client"
                      ? new S.Unauthorized({ message: e.error })
                      : new S.BadRequest({ message: e.error }),
                  ),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return {
            access_token: result.accessToken,
            token_type: result.tokenType,
            expires_in: result.expiresIn,
            ...(result.refreshToken !== undefined && { refresh_token: result.refreshToken }),
            ...(result.idToken !== undefined && { id_token: result.idToken }),
            scope: result.scope,
          };
        }),
      )
      .handle("oidcUserInfo", ({ request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          yield* noStore;
          const auth = request.headers["authorization"];
          const token =
            auth !== undefined && auth.startsWith("Bearer ") ? auth.slice(7) : undefined;
          if (token === undefined) {
            return yield* new S.Unauthorized({ message: "Missing bearer token" });
          }
          return yield* oidc.service.userinfo(token).pipe(
            Effect.catchTags({
              OidcProviderError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }),
      )
      // --- RFC 7591 dynamic client registration -------------------------------
      .handle("oidcDynamicRegister", ({ payload, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          const dcr = oidc.service.dynamicRegistration;
          if (!dcr.enabled) {
            return yield* new S.NotFound({
              message: "Dynamic client registration is not enabled",
            });
          }
          yield* applyRegistrationRateLimit(dcr.rateLimit);
          // RFC 7591 §3.2.1: the answer carries the client secret.
          yield* noStore;
          const initialAccessToken = bearerToken(request);
          const result = yield* oidc.service
            .registerDynamicClient(registrationMetadata(payload), {
              ...(initialAccessToken !== undefined && { initialAccessToken }),
            })
            .pipe(asRegistration);
          const registrationEndpoint = registrationEndpointOf(oidc.service);
          return {
            ...encodeOidcRegistration(result.client, registrationEndpoint),
            ...(result.clientSecret !== undefined && {
              client_secret: result.clientSecret,
              // RFC 7591 §3.2.1: 0 means the secret never expires.
              client_secret_expires_at: 0,
            }),
            registration_access_token: result.registrationAccessToken,
          };
        }),
      )
      .handle("oidcReadRegistration", ({ params, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          const token = yield* requireRegistrationAccessToken(oidc.service, request);
          const client = yield* oidc.service
            .readDynamicClient(params.clientId, token)
            .pipe(asRegistration);
          return encodeOidcRegistration(client, registrationEndpointOf(oidc.service));
        }),
      )
      .handle("oidcUpdateRegistration", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          const token = yield* requireRegistrationAccessToken(oidc.service, request);
          const client = yield* oidc.service
            .updateDynamicClient(params.clientId, token, registrationMetadata(payload))
            .pipe(asRegistration);
          return encodeOidcRegistration(client, registrationEndpointOf(oidc.service));
        }),
      )
      .handle("oidcDeleteRegistration", ({ params, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          const token = yield* requireRegistrationAccessToken(oidc.service, request);
          yield* oidc.service.deleteDynamicClient(params.clientId, token).pipe(asRegistration);
        }),
      )
      .handle("oidcDiscovery", () =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          return oidc.service.getMetadata();
        }),
      )
      .handle("oauthAuthorizationServerMetadata", () =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          return oidc.service.getAuthorizationServerMetadata();
        }),
      )
      .handle("oidcJwks", () =>
        // 404 when the OIDC provider is disabled.
        Effect.andThen(resolveOidcProvider, jwksDocument()),
      ),
  );
};

// -----------------------------------------------------------------------------
// SCIM 2.0 provisioning
// -----------------------------------------------------------------------------

/**
 * Build a SCIM error body (RFC 7644 §3.12). `status` is a *string* there, and
 * `scimType` is the machine-readable half an IdP branches on.
 */
const scimBadRequest = (detail: string, scimType?: string): S.ScimBadRequest =>
  new S.ScimBadRequest({
    schemas: [S.SCIM_ERROR_SCHEMA],
    status: "400",
    ...(scimType !== undefined && { scimType }),
    detail,
  });

const scimUnauthorized = (detail: string): S.ScimUnauthorized =>
  new S.ScimUnauthorized({ schemas: [S.SCIM_ERROR_SCHEMA], status: "401", detail });

const scimNotFound = (detail: string): S.ScimNotFound =>
  new S.ScimNotFound({ schemas: [S.SCIM_ERROR_SCHEMA], status: "404", detail });

const scimConflict = (detail: string): S.ScimConflict =>
  new S.ScimConflict({
    schemas: [S.SCIM_ERROR_SCHEMA],
    status: "409",
    scimType: "uniqueness",
    detail,
  });

/**
 * Log the real error and answer with a generic SCIM 500, so internals never
 * reach the IdP. The SCIM mirror of {@link internalServerError}.
 */
const scimInternalError = (
  e: ScimError | Errors.AuthError,
): Effect.Effect<never, S.ScimInternalError> =>
  Effect.logError("[effect-auth] internal error", e).pipe(
    Effect.flatMap(() =>
      Effect.fail(
        new S.ScimInternalError({
          schemas: [S.SCIM_ERROR_SCHEMA],
          status: "500",
          detail: "Internal server error",
        }),
      ),
    ),
  );

/** Translate a core {@link ScimError} into the wire body its status calls for. */
const scimFailure = (
  e: ScimError,
): Effect.Effect<
  never,
  S.ScimBadRequest | S.ScimUnauthorized | S.ScimNotFound | S.ScimConflict | S.ScimInternalError
> =>
  Match.value(e.status).pipe(
    Match.when(400, () => Effect.fail(scimBadRequest(e.message, e.scimType))),
    Match.when(401, () => Effect.fail(scimUnauthorized(e.message))),
    Match.when(404, () => Effect.fail(scimNotFound(e.message))),
    Match.when(409, () => Effect.fail(scimConflict(e.message))),
    Match.orElse(() => scimInternalError(e)),
  );

/** The catch-set every SCIM handler applies to a `ScimService` call. */
const scimCatch = {
  ScimError: scimFailure,
  AuthError: (e: Errors.AuthError) => scimInternalError(e),
} as const;

/**
 * Resolve the SCIM service *and* authenticate the request's bearer token.
 *
 * Two guards in one, because they are inseparable: without the service the
 * feature is not mounted (404, in SCIM's error shape), and with it every route
 * is gated on an organization's provisioning token. A missing, malformed, or
 * unknown token gets the same 401 — the service answers uniformly so a caller
 * cannot probe which tokens exist.
 */
const requireScim = Effect.fn("requireScim")(function* (
  request: HttpServerRequest.HttpServerRequest,
) {
  const service = yield* Effect.serviceOption(ScimService);
  if (Option.isNone(service)) {
    return yield* scimNotFound("SCIM provisioning is not enabled");
  }
  const token = bearerToken(request);
  if (token === undefined) {
    return yield* scimUnauthorized("Missing SCIM provisioning token");
  }
  const connection = yield* service.value.authenticate(token).pipe(Effect.catchTags(scimCatch));
  return { service: service.value, connection };
});

/** The discovery documents are static, so resolving the service is the only gate. */
const requireScimService = Effect.fn("requireScimService")(function* () {
  const service = yield* Effect.serviceOption(ScimService);
  if (Option.isNone(service)) {
    return yield* scimNotFound("SCIM provisioning is not enabled");
  }
  return service.value;
});

const scimMeta = (
  resourceType: string,
  baseUrl: string,
  id: string,
  createdAt: number,
  updatedAt: number,
): S.ScimMetaView => ({
  resourceType,
  created: DateTime.formatIso(DateTime.makeUnsafe(createdAt)),
  lastModified: DateTime.formatIso(DateTime.makeUnsafe(updatedAt)),
  location: `${baseUrl}/${resourceType}s/${id}`,
});

const encodeScimUser = (resource: ScimUserResource, baseUrl: string): S.ScimUserView => ({
  schemas: [S.SCIM_USER_SCHEMA],
  id: resource.id,
  ...(resource.externalId !== undefined && { externalId: resource.externalId }),
  userName: resource.userName,
  ...(resource.displayName !== undefined && { displayName: resource.displayName }),
  emails: resource.emails.map((email) => ({
    value: email.value,
    ...(email.primary !== undefined && { primary: email.primary }),
    ...(email.type !== undefined && { type: email.type }),
  })),
  active: resource.active,
  meta: scimMeta("User", baseUrl, resource.id, resource.createdAt, resource.updatedAt),
});

const encodeScimGroup = (resource: ScimGroupResource, baseUrl: string): S.ScimGroupView => ({
  schemas: [S.SCIM_GROUP_SCHEMA],
  id: resource.id,
  displayName: resource.displayName,
  members: resource.members.map((member) => ({ value: member.value })),
  meta: scimMeta("Group", baseUrl, resource.id, resource.createdAt, resource.updatedAt),
});

/**
 * SCIM list parameters arrive as query strings. `startIndex` and `count` must
 * be integers; anything else is a client bug worth reporting rather than
 * silently coercing to a surprising page.
 */
const scimListQuery = (query: {
  readonly filter?: string | undefined;
  readonly startIndex?: string | undefined;
  readonly count?: string | undefined;
}): Effect.Effect<ScimListQuery, S.ScimBadRequest> => {
  const parseInteger = (raw: string | undefined): number | null | undefined => {
    if (raw === undefined || raw.trim() === "") return undefined;
    const value = Number(raw);
    return Number.isInteger(value) ? value : null;
  };
  const startIndex = parseInteger(query.startIndex);
  if (startIndex === null) {
    return Effect.fail(scimBadRequest("startIndex must be an integer", "invalidValue"));
  }
  const count = parseInteger(query.count);
  if (count === null) {
    return Effect.fail(scimBadRequest("count must be an integer", "invalidValue"));
  }
  return Effect.succeed({
    ...(query.filter !== undefined && query.filter !== "" && { filter: query.filter }),
    ...(startIndex !== undefined && { startIndex }),
    ...(count !== undefined && { count }),
  });
};

/** Fold Okta's `name` sub-attributes into a display name when it sent no `displayName`. */
const scimDisplayName = (payload: S.ScimUserPayload): string | undefined => {
  if (payload.displayName !== undefined && payload.displayName.trim() !== "") {
    return payload.displayName;
  }
  const name = payload.name;
  if (name === undefined) return undefined;
  if (name.formatted !== undefined && name.formatted.trim() !== "") return name.formatted;
  const parts = [name.givenName, name.familyName].filter(
    (part): part is string => part !== undefined && part.trim() !== "",
  );
  return Arr.isReadonlyArrayEmpty(parts) ? undefined : parts.join(" ");
};

const toScimUserInput = (payload: S.ScimUserPayload): ScimUserInput => {
  const displayName = scimDisplayName(payload);
  return {
    userName: payload.userName,
    ...(displayName !== undefined && { displayName }),
    ...(payload.externalId !== undefined && { externalId: payload.externalId }),
    ...(payload.emails !== undefined && {
      emails: payload.emails.map((email) => ({
        value: email.value,
        ...(email.primary !== undefined && { primary: email.primary }),
        ...(email.type !== undefined && { type: email.type }),
      })),
    }),
    ...(payload.active !== undefined && { active: payload.active }),
  };
};

const toScimGroupInput = (payload: S.ScimGroupPayload): ScimGroupInput => ({
  displayName: payload.displayName,
  ...(payload.members !== undefined && {
    members: payload.members.map((member) => ({ value: member.value })),
  }),
});

/**
 * `GET /ServiceProviderConfig` (RFC 7643 §5) — what this server supports.
 *
 * Everything advertised here is implemented, and everything implemented is
 * advertised: `patch` yes, `filter` yes (with `maxResults`), and `bulk`,
 * `changePassword`, `sort` and `etag` all off, because pretending otherwise is
 * how provisioning silently half-works.
 */
const scimServiceProviderConfig = (baseUrl: string, maxResults: number): S.ScimDocumentView => ({
  schemas: [S.SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA],
  documentationUri: "https://datatracker.ietf.org/doc/html/rfc7644",
  patch: { supported: true },
  bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
  filter: { supported: true, maxResults },
  changePassword: { supported: false },
  sort: { supported: false },
  etag: { supported: false },
  authenticationSchemes: [
    {
      type: "oauthbearertoken",
      name: "OAuth Bearer Token",
      description:
        "Authentication with the organization's SCIM provisioning token, sent as " +
        "`Authorization: Bearer <token>`.",
      specUri: "https://datatracker.ietf.org/doc/html/rfc6750",
      primary: true,
    },
  ],
  meta: {
    resourceType: "ServiceProviderConfig",
    location: `${baseUrl}/ServiceProviderConfig`,
  },
});

/** `GET /ResourceTypes` (RFC 7643 §6) — the two resources this server exposes. */
const scimResourceTypes = (baseUrl: string): S.ScimDocumentView => {
  const resource = (name: string, endpoint: string, schema: string) => ({
    schemas: [S.SCIM_RESOURCE_TYPE_SCHEMA],
    id: name,
    name,
    endpoint,
    description: `${name} resource`,
    schema,
    meta: {
      resourceType: "ResourceType",
      location: `${baseUrl}/ResourceTypes/${name}`,
    },
  });
  const resources = [
    resource("User", "/Users", S.SCIM_USER_SCHEMA),
    resource("Group", "/Groups", S.SCIM_GROUP_SCHEMA),
  ];
  return {
    schemas: [S.SCIM_LIST_RESPONSE_SCHEMA],
    totalResults: resources.length,
    startIndex: 1,
    itemsPerPage: resources.length,
    Resources: resources,
  };
};

/**
 * `GET /Schemas` (RFC 7643 §7) — the attributes of the two resources, limited
 * to the ones this server actually reads and writes.
 */
const scimSchemas = (baseUrl: string): S.ScimDocumentView => {
  const attribute = (
    name: string,
    type: string,
    options: {
      readonly multiValued?: boolean;
      readonly required?: boolean;
      readonly uniqueness?: string;
      readonly mutability?: string;
      readonly subAttributes?: ReadonlyArray<unknown>;
    } = {},
  ) => ({
    name,
    type,
    multiValued: options.multiValued ?? false,
    required: options.required ?? false,
    caseExact: false,
    mutability: options.mutability ?? "readWrite",
    returned: "default",
    uniqueness: options.uniqueness ?? "none",
    ...(options.subAttributes !== undefined && { subAttributes: options.subAttributes }),
  });

  const resources = [
    {
      id: S.SCIM_USER_SCHEMA,
      name: "User",
      description: "SCIM core User",
      attributes: [
        attribute("userName", "string", { required: true, uniqueness: "server" }),
        attribute("displayName", "string"),
        attribute("externalId", "string"),
        attribute("active", "boolean"),
        attribute("emails", "complex", {
          multiValued: true,
          subAttributes: [
            attribute("value", "string"),
            attribute("primary", "boolean"),
            attribute("type", "string"),
          ],
        }),
      ],
      meta: { resourceType: "Schema", location: `${baseUrl}/Schemas/${S.SCIM_USER_SCHEMA}` },
    },
    {
      id: S.SCIM_GROUP_SCHEMA,
      name: "Group",
      description: "SCIM core Group",
      attributes: [
        attribute("displayName", "string", { required: true }),
        attribute("members", "complex", {
          multiValued: true,
          subAttributes: [attribute("value", "string", { mutability: "immutable" })],
        }),
      ],
      meta: { resourceType: "Schema", location: `${baseUrl}/Schemas/${S.SCIM_GROUP_SCHEMA}` },
    },
  ];

  return {
    schemas: [S.SCIM_LIST_RESPONSE_SCHEMA],
    totalResults: resources.length,
    startIndex: 1,
    itemsPerPage: resources.length,
    Resources: resources,
  };
};

/**
 * Layer implementing the `scim` group handlers.
 *
 * Every route resolves `ScimService` optionally, so a deployment that never
 * provisions answers `404` here and pays nothing for the feature.
 */
export const scimGroupLayer = () =>
  HttpApiBuilder.group(AuthApi, "scim", (handlers) =>
    handlers
      .handle("scimCreateUser", ({ payload, request }) =>
        Effect.gen(function* () {
          const scim = yield* requireScim(request);
          const resource = yield* scim.service
            .createUser(scim.connection, toScimUserInput(payload))
            .pipe(Effect.catchTags(scimCatch));
          return encodeScimUser(resource, scim.service.baseUrl);
        }),
      )
      .handle("scimListUsers", ({ query, request }) =>
        Effect.gen(function* () {
          const scim = yield* requireScim(request);
          const listQuery = yield* scimListQuery(query);
          const page = yield* scim.service
            .listUsers(scim.connection, listQuery)
            .pipe(Effect.catchTags(scimCatch));
          return {
            schemas: [S.SCIM_LIST_RESPONSE_SCHEMA],
            totalResults: page.totalResults,
            startIndex: page.startIndex,
            itemsPerPage: page.itemsPerPage,
            Resources: page.resources.map((resource) =>
              encodeScimUser(resource, scim.service.baseUrl),
            ),
          };
        }),
      )
      .handle("scimGetUser", ({ params, request }) =>
        Effect.gen(function* () {
          const scim = yield* requireScim(request);
          const resource = yield* scim.service
            .getUser(scim.connection, params.id)
            .pipe(Effect.catchTags(scimCatch));
          return encodeScimUser(resource, scim.service.baseUrl);
        }),
      )
      .handle("scimReplaceUser", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const scim = yield* requireScim(request);
          const resource = yield* scim.service
            .replaceUser(scim.connection, params.id, toScimUserInput(payload))
            .pipe(Effect.catchTags(scimCatch));
          return encodeScimUser(resource, scim.service.baseUrl);
        }),
      )
      .handle("scimPatchUser", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const scim = yield* requireScim(request);
          const resource = yield* scim.service
            .patchUser(scim.connection, params.id, payload.Operations)
            .pipe(Effect.catchTags(scimCatch));
          return encodeScimUser(resource, scim.service.baseUrl);
        }),
      )
      .handle("scimDeleteUser", ({ params, request }) =>
        Effect.gen(function* () {
          const scim = yield* requireScim(request);
          yield* scim.service
            .deactivateUser(scim.connection, params.id)
            .pipe(Effect.catchTags(scimCatch));
        }),
      )
      .handle("scimCreateGroup", ({ payload, request }) =>
        Effect.gen(function* () {
          const scim = yield* requireScim(request);
          const resource = yield* scim.service
            .createGroup(scim.connection, toScimGroupInput(payload))
            .pipe(Effect.catchTags(scimCatch));
          return encodeScimGroup(resource, scim.service.baseUrl);
        }),
      )
      .handle("scimListGroups", ({ query, request }) =>
        Effect.gen(function* () {
          const scim = yield* requireScim(request);
          const listQuery = yield* scimListQuery(query);
          const page = yield* scim.service
            .listGroups(scim.connection, listQuery)
            .pipe(Effect.catchTags(scimCatch));
          return {
            schemas: [S.SCIM_LIST_RESPONSE_SCHEMA],
            totalResults: page.totalResults,
            startIndex: page.startIndex,
            itemsPerPage: page.itemsPerPage,
            Resources: page.resources.map((resource) =>
              encodeScimGroup(resource, scim.service.baseUrl),
            ),
          };
        }),
      )
      .handle("scimGetGroup", ({ params, request }) =>
        Effect.gen(function* () {
          const scim = yield* requireScim(request);
          const resource = yield* scim.service
            .getGroup(scim.connection, params.id)
            .pipe(Effect.catchTags(scimCatch));
          return encodeScimGroup(resource, scim.service.baseUrl);
        }),
      )
      .handle("scimReplaceGroup", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const scim = yield* requireScim(request);
          const resource = yield* scim.service
            .replaceGroup(scim.connection, params.id, toScimGroupInput(payload))
            .pipe(Effect.catchTags(scimCatch));
          return encodeScimGroup(resource, scim.service.baseUrl);
        }),
      )
      .handle("scimPatchGroup", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const scim = yield* requireScim(request);
          const resource = yield* scim.service
            .patchGroup(scim.connection, params.id, payload.Operations)
            .pipe(Effect.catchTags(scimCatch));
          return encodeScimGroup(resource, scim.service.baseUrl);
        }),
      )
      .handle("scimDeleteGroup", ({ params, request }) =>
        Effect.gen(function* () {
          const scim = yield* requireScim(request);
          yield* scim.service
            .deleteGroup(scim.connection, params.id)
            .pipe(Effect.catchTags(scimCatch));
        }),
      )
      .handle("scimServiceProviderConfig", () =>
        Effect.map(requireScimService(), (service) =>
          scimServiceProviderConfig(service.baseUrl, service.maxPageSize),
        ),
      )
      .handle("scimResourceTypes", () =>
        Effect.map(requireScimService(), (service) => scimResourceTypes(service.baseUrl)),
      )
      .handle("scimSchemas", () =>
        Effect.map(requireScimService(), (service) => scimSchemas(service.baseUrl)),
      ),
  );

/**
 * Encode a user for the wire with the derived `email`/`emailVerified`
 * convenience fields resolved from the identifier store. Enrichment is
 * fail-soft: when the identifier lookup errors the fields are simply omitted
 * (with a warning) rather than failing a flow that already succeeded.
 */
const encodeUserView = (user: Types.User): Effect.Effect<S.UserView, never, IdentifierStore> =>
  Effect.map(userIdentifiers(user), (list) => S.encodeUser(user, list));

/**
 * Resolve the authenticated session or fail with 401, preferring the signed
 * cache cookie (no store read) when the cache is enabled and the cookie is
 * valid; otherwise validating against the session store. `cacheHit` lets
 * callers decide whether to (re)issue the cache cookie; `token` is the raw
 * token the request presented, for the calls that need the credential itself
 * (signing it out). The resolved session carries only its stored id.
 */
const resolveSession = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): Effect.Effect<
  {
    readonly resolved: Types.SessionWithUser;
    readonly cacheHit: boolean;
    readonly token: string;
  },
  S.Unauthorized,
  SessionService | Hooks
> =>
  Effect.gen(function* () {
    const token = sessionIdFromRequest(request, cfg);
    if (token === undefined) {
      return yield* new S.Unauthorized({ message: "Not authenticated" });
    }
    const cached = cfg.cache === undefined ? undefined : request.cookies[dataCookieName(cfg)];
    if (cfg.cache !== undefined && cached !== undefined) {
      const resolved = decodeSessionCacheCookie(
        cached,
        cfg.cache,
        yield* Clock.currentTimeMillis,
        hashToken(token),
        yield* sessionCacheGateAttributes,
      );
      if (resolved !== null) return { resolved, cacheHit: true, token };
    }
    const sessionManager = yield* SessionService;
    const resolved = yield* sessionManager.validateSession(token).pipe(
      Effect.catchTag("UserBannedError", (e) =>
        resolveMessage(e.code, e.message).pipe(
          Effect.flatMap((msg) => Effect.fail(new S.Unauthorized({ message: msg, code: e.code }))),
        ),
      ),
      Effect.mapError(() => new S.Unauthorized({ message: "Invalid or expired session" })),
    );
    return { resolved, cacheHit: false, token };
  });

const requireSession = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): Effect.Effect<Types.SessionWithUser, S.Unauthorized, SessionService | Hooks> =>
  resolveSession(request, cfg).pipe(Effect.map((r) => r.resolved));

/**
 * Fail with `Forbidden` unless the request's credential is
 * `"interactive"` — i.e. presented as the session cookie, not the
 * `Authorization: Bearer/Token` header. Gates operations that must not be
 * reachable by a machine credential (a bearer-delivered session token, or —
 * for an app that wires its own API-key middleware on top of this library —
 * an API key), such as minting a new API key from one already in hand.
 */
const requireInteractiveCredential = (
  request: HttpServerRequest.HttpServerRequest,
): Effect.Effect<void, S.Forbidden> =>
  credentialClassFromRequest(request) === "interactive"
    ? Effect.void
    : Effect.fail(new S.Forbidden({ message: "This operation requires an interactive session" }));

/**
 * Attach a new session to a JSON `AuthSuccess` response (whose body names no
 * session at all). When the last-login-method hint is enabled and `method` is
 * given, also (re)writes the non-httpOnly `${name}_last_method` cookie.
 *
 * When `rememberMe` is `false`, a browser-session cookie is emitted (no
 * `Max-Age`/`Expires`) so the cookie is cleared when the browser closes.
 * The server-side session lifetime is unchanged; orphaned sessions expire via
 * the normal idle/absolute-lifetime checks.
 */
const withSessionCookie = (
  body: S.AuthSuccess,
  issued: Types.IssuedSession,
  cfg: ResolvedCookieConfig,
  method?: string,
  rememberMe?: boolean,
) =>
  Effect.gen(function* () {
    const json = yield* HttpServerResponse.json(body);
    return yield* decorateSessionResponse(json, issued, cfg, method, rememberMe);
  }).pipe(Effect.orDie);

/**
 * Carry a new session on `response`: the session cookie (a browser-session one
 * when `rememberMe` is `false`), the device's multi-session list, the
 * last-login-method hint and, in bearer mode, the `set-auth-token` header.
 * These headers are the only places the raw token is written (#581). The
 * response is marked `no-store` (#628).
 */
const decorateSessionResponse = (
  json: HttpServerResponse.HttpServerResponse,
  { session, token }: Types.IssuedSession,
  cfg: ResolvedCookieConfig,
  method?: string,
  rememberMe?: boolean,
) =>
  Effect.gen(function* () {
    const cookieOpts =
      rememberMe === false
        ? sessionOnlyCookieOptions(cfg)
        : sessionCookieOptions(cfg, session.expiresAt);
    let response = yield* HttpServerResponse.setCookie(json, cfg.name, token, cookieOpts);
    // Multi-session: append the new session to the device's session list (the
    // primary cookie remains the active session), capped to `maximumSessions`.
    if (cfg.multiSession !== undefined) {
      const request = yield* HttpServerRequest.HttpServerRequest;
      const existing = readDeviceSessionIds(request, cfg).filter((id) => id !== token);
      const ids = [...existing, token].slice(-cfg.multiSession.maximumSessions);
      response = yield* HttpServerResponse.setCookie(
        response,
        multiCookieName(cfg),
        ids.join("."),
        cookieOpts,
      );
    }
    // Last-login-method hint: a page-readable cookie login UIs use to
    // highlight the user's previous sign-in method.
    if (cfg.lastLoginMethod !== undefined && method !== undefined) {
      response = yield* HttpServerResponse.setCookie(
        response,
        lastMethodCookieName(cfg),
        method,
        lastMethodCookieOptions(cfg, cfg.lastLoginMethod.maxAge),
      );
    }
    // Bearer mode: emit the raw session token in a response header so
    // native/mobile/CLI clients can obtain it without cookie support.
    // "always" → every session-issuing response carries the header.
    // "opt-in" → only when the client sent x-use-bearer: 1.
    if (cfg.bearerMode !== false) {
      let emitBearer = cfg.bearerMode === "always";
      if (!emitBearer) {
        const request = yield* HttpServerRequest.HttpServerRequest;
        emitBearer = request.headers["x-use-bearer"] === "1";
      }
      if (emitBearer) {
        response = HttpServerResponse.setHeader(response, BEARER_TOKEN_HEADER, token);
      }
    }
    return withNoStore(response);
  }).pipe(Effect.orDie);

// -----------------------------------------------------------------------------
// Web handler
// -----------------------------------------------------------------------------

/**
 * Runtime-agnostic platform services required by the HttpApi router. We never
 * serve files, so a no-op `FileSystem` suffices; it is both provided to
 * `HttpPlatform` and exposed in the output (the router requires `FileSystem`
 * directly too).
 */
const PlatformLayer = Layer.mergeAll(Etag.layer, Path.layer, HttpPlatform.layer).pipe(
  Layer.provideMerge(FileSystem.layerNoop({})),
);

// ---------------------------------------------------------------------------
// Per-endpoint IP rate limiting (HTTP layer)
// ---------------------------------------------------------------------------

/**
 * A single per-endpoint IP rate-limit rule.
 *
 * `path` names an endpoint by its path template, as the OpenAPI document
 * writes it (`"/sessions"`, `"/sso/saml/acs/{providerId}"`; the router's
 * `:providerId` form is accepted too), or is a `RegExp` tested against that
 * template. The rule is checked once the router has matched the request to an
 * endpoint, against the endpoint it matched, never against the raw request
 * path: the router is case-insensitive and ignores trailing and duplicate
 * slashes and percent-encoding, so `/Sessions/`, `//sessions` and
 * `/%73essions` all reach `POST /sessions` and all count under its rule
 * (#582). Paths are relative to the mount `prefix`, as the endpoints are.
 *
 * `methods` limits the rule to specific HTTP methods (default: all methods).
 *
 * Each rule counts in one bucket per client address, whatever endpoint matched
 * it: a regex rule shares its bucket across every endpoint it matches, so a
 * caller cannot reset its count by varying the path.
 */
export interface EndpointRateLimitRule {
  readonly path: string | RegExp;
  /** HTTP methods this rule applies to (uppercase). Default: all. */
  readonly methods?: ReadonlyArray<string>;
  readonly maxRequests: number;
  readonly windowMs: number;
  readonly blockDurationMs?: number;
}

/**
 * IP rate-limiting configuration for the HTTP layer.
 *
 * When `rules` is omitted, {@link defaultEndpointRules} is used — sane
 * defaults for all sensitive auth endpoints.
 */
export interface HttpIPRateLimitConfig {
  /**
   * Declarative rule set. First matching rule (in order) wins.
   * Omit to use the built-in defaults for all sensitive endpoints.
   */
  readonly rules?: ReadonlyArray<EndpointRateLimitRule>;
}

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;

/** A `POST` rule for `path`: `maxRequests` per `windowMs`, then a `blockDurationMs` block. */
const postRule = (
  path: string,
  maxRequests: number,
  windowMs: number,
  blockDurationMs: number,
): EndpointRateLimitRule => ({ path, methods: ["POST"], maxRequests, windowMs, blockDurationMs });

/**
 * Sane default IP rate-limit rules applied to sensitive auth endpoints: every
 * unauthenticated endpoint that sends a message, writes a row, makes an
 * outbound call or verifies a secret, and the authenticated ones that hash a
 * password or check a second factor (#583). `Http.make` applies them unless
 * it is given `ipRateLimit: false` or rules of its own.
 *
 * | Endpoint(s)                                                    | Limit   | Window | Block  |
 * |----------------------------------------------------------------|---------|--------|--------|
 * | `POST /sessions` (every sign-in method)                        | 10 req  | 15 min | 30 min |
 * | `POST /users` (sign-up)                                        | 5 req   | 1 hr   | 24 hr  |
 * | `POST /otp-challenges` (email / SMS code, link)                | 5 req   | 10 min | 30 min |
 * | `POST /password-resets`                                        | 5 req   | 1 hr   | 2 hr   |
 * | `POST /email-verifications`                                    | 5 req   | 1 hr   | 2 hr   |
 * | `POST /password-resets/redemptions`                            | 10 req  | 15 min | 30 min |
 * | `POST /email-verifications/redemptions`                        | 10 req  | 15 min | 30 min |
 * | `POST /second-factor-challenges/verifications`                 | 10 req  | 5 min  | 30 min |
 * | `PATCH /users/me/password` (change password)                   | 10 req  | 15 min | 30 min |
 * | `POST`, `PATCH`, `DELETE /multi-factor-enrollments[/current]`  | 10 req  | 15 min | 30 min |
 * | `POST /backup-code-sets` (regenerate backup codes)             | 10 req  | 15 min | 30 min |
 * | `POST /google-one-tap-nonces`                                  | 20 req  | 10 min | 30 min |
 * | `POST /device/code`                                            | 10 req  | 10 min | 30 min |
 * | `POST /device/token` (polling)                                 | 300 req | 15 min | 15 min |
 * | `POST /device-authorizations/decisions` (approve, deny)        | 20 req  | 10 min | 30 min |
 * | `POST /sso-authorizations` (SSO sign-in)                       | 20 req  | 10 min | 30 min |
 * | `POST /sso/callback`, `POST /sso/saml/acs/{providerId}`        | 20 req  | 10 min | 30 min |
 * | `POST /oauth2/token`                                           | 60 req  | 1 min  | 5 min  |
 * | `POST /register` (dynamic client registration)                 | 10 req  | 1 hr   | 1 hr   |
 * | `GET /api-keys/current` (API-key resolution, #730)             | 300 req | 1 min  | 5 min  |
 *
 * Endpoints named on one row share one bucket.
 */
export const defaultEndpointRules: ReadonlyArray<EndpointRateLimitRule> = [
  postRule("/sessions", 10, 15 * MINUTE_MS, 30 * MINUTE_MS),
  postRule("/users", 5, HOUR_MS, 24 * HOUR_MS),
  postRule("/otp-challenges", 5, 10 * MINUTE_MS, 30 * MINUTE_MS),
  postRule("/password-resets", 5, HOUR_MS, 2 * HOUR_MS),
  postRule("/email-verifications", 5, HOUR_MS, 2 * HOUR_MS),
  postRule("/password-resets/redemptions", 10, 15 * MINUTE_MS, 30 * MINUTE_MS),
  postRule("/email-verifications/redemptions", 10, 15 * MINUTE_MS, 30 * MINUTE_MS),
  postRule("/second-factor-challenges/verifications", 10, 5 * MINUTE_MS, 30 * MINUTE_MS),
  // The authenticated endpoints that hash a password or check a second factor.
  {
    path: "/users/me/password",
    methods: ["PATCH"],
    maxRequests: 10,
    windowMs: 15 * MINUTE_MS,
    blockDurationMs: 30 * MINUTE_MS,
  },
  {
    path: /^\/multi-factor-enrollments(\/current)?$/,
    methods: ["POST", "PATCH", "DELETE"],
    maxRequests: 10,
    windowMs: 15 * MINUTE_MS,
    blockDurationMs: 30 * MINUTE_MS,
  },
  postRule("/backup-code-sets", 10, 15 * MINUTE_MS, 30 * MINUTE_MS),
  // Unauthenticated endpoints that write a store row or call out.
  postRule("/google-one-tap-nonces", 20, 10 * MINUTE_MS, 30 * MINUTE_MS),
  postRule("/device/code", 10, 10 * MINUTE_MS, 30 * MINUTE_MS),
  // A device polls every few seconds until the user decides.
  postRule("/device/token", 300, 15 * MINUTE_MS, 15 * MINUTE_MS),
  postRule("/device-authorizations/decisions", 20, 10 * MINUTE_MS, 30 * MINUTE_MS),
  postRule("/sso-authorizations", 20, 10 * MINUTE_MS, 30 * MINUTE_MS),
  {
    path: /^\/sso\/(callback|saml\/acs\/\{providerId\})$/,
    methods: ["POST"],
    maxRequests: 20,
    windowMs: 10 * MINUTE_MS,
    blockDurationMs: 30 * MINUTE_MS,
  },
  postRule("/oauth2/token", 60, MINUTE_MS, 5 * MINUTE_MS),
  // RFC 7591 dynamic client registration is open to anonymous callers.
  postRule("/register", 10, HOUR_MS, HOUR_MS),
  // Verifies a secret on every call; a machine caller resolves its key per
  // request, so the window is short and generous. Like every rule it counts
  // each request before the handler runs, refused and resolved alike, and a
  // request it refuses never reaches the key (no use spent).
  {
    path: "/api-keys/current",
    methods: ["GET"],
    maxRequests: 300,
    windowMs: MINUTE_MS,
    blockDurationMs: 5 * MINUTE_MS,
  },
];

/**
 * A path template as the OpenAPI document writes it: the router's `:name`
 * parameters (with any regex constraint or `?`) become `{name}`.
 */
const openApiTemplate = (path: string): string =>
  path.replaceAll(/:(\w+)(?:\([^)]*\))?\??/g, "{$1}");

const matchesEndpointRule = (
  rule: EndpointRateLimitRule,
  template: string,
  method: string,
): boolean => {
  if (rule.methods !== undefined && !rule.methods.includes(method)) return false;
  return P.isString(rule.path) ? openApiTemplate(rule.path) === template : rule.path.test(template);
};

/**
 * The rate-limit bucket a rule counts in: its path. A pattern rule keeps one
 * bucket for every endpoint it matches, so varying the path (an id in it, say)
 * never earns a caller a fresh bucket.
 */
const ruleKey = (rule: EndpointRateLimitRule): string =>
  P.isString(rule.path) ? openApiTemplate(rule.path) : `pattern:${rule.path.source}`;

const findEndpointRule = (
  rules: ReadonlyArray<EndpointRateLimitRule>,
  template: string,
  method: string,
): EndpointRateLimitRule | undefined =>
  rules.find((rule) => matchesEndpointRule(rule, template, method));

/** The 429 a request to a limited endpoint gets when no `RateLimiter` is in scope. */
const noRateLimiterResponse = (): Effect.Effect<HttpServerResponse.HttpServerResponse> =>
  Effect.logError(
    "[effect-auth] ipRateLimit is configured with no RateLimiter in services; the request is refused",
  ).pipe(Effect.as(HttpServerResponse.jsonUnsafe({ message: NO_RATE_LIMITER }, { status: 429 })));

/**
 * Count one request under `rule` for the caller's address, and answer the
 * refusal, or `undefined` when the request may proceed. The startup check
 * refuses the limit without a `RateLimiter`, so that refusal is a backstop:
 * the limit never runs as a silent no-op (#389). With no address there is no
 * key (#358): the request is refused rather than skipped or counted under a
 * bucket that other callers share.
 */
const consumeEndpointLimit = (
  rule: EndpointRateLimitRule,
): Effect.Effect<HttpServerResponse.HttpServerResponse | undefined> =>
  Effect.gen(function* () {
    const limiter = yield* Effect.serviceOption(RateLimiter);
    if (Option.isNone(limiter)) return yield* noRateLimiterResponse();
    const clientIp = yield* Effect.serviceOption(ClientIP);
    const ip = Option.isSome(clientIp) ? clientIp.value.ip : undefined;
    if (ip === undefined) {
      return HttpServerResponse.jsonUnsafe({ message: NO_CLIENT_ADDRESS }, { status: 429 });
    }
    const denied = yield* limiter.value
      .consumeToken(`ip:${ruleKey(rule)}:${ip}`, {
        maxRequests: rule.maxRequests,
        windowMs: rule.windowMs,
        ...(rule.blockDurationMs !== undefined && { blockDurationMs: rule.blockDurationMs }),
      })
      .pipe(
        Effect.as(null),
        Effect.catchTags({
          RateLimitError: (e) => Effect.succeed(e),
          AuthError: () => Effect.succeed(null),
        }),
      );
    return denied === null ? undefined : tooManyRequests(denied.retryAfter);
  });

/**
 * The per-endpoint IP limit, as router middleware on every auth route. It runs
 * once the router has matched the request, before the endpoint decodes the
 * request or runs any auth logic, and finds its rule by the matched endpoint's
 * path template and method, so no spelling of the path escapes it (#582).
 */
const endpointRateLimit = (rules: ReadonlyArray<EndpointRateLimitRule>) =>
  HttpRouter.middleware((effect) =>
    Effect.gen(function* () {
      const { route } = yield* HttpRouter.RouteContext;
      const request = yield* HttpServerRequest.HttpServerRequest;
      const method = route.method === "*" ? request.method.toUpperCase() : route.method;
      const rule = findEndpointRule(rules, openApiTemplate(route.path), method);
      const refused = rule === undefined ? undefined : yield* consumeEndpointLimit(rule);
      return refused ?? (yield* effect);
    }),
  ).layer;

/** The token endpoints, by path template: RFC 6749 §5.1 / §5.2 and RFC 8628 §3.5. */
const TOKEN_ENDPOINTS: ReadonlyArray<string> = ["/oauth2/token", "/device/token"];

/**
 * A token endpoint's every answer is `no-store`, an error included (RFC 6749
 * §5.2), as router middleware: it marks the response once the router has
 * matched the endpoint and before the endpoint decodes its payload, so the
 * `400` for a malformed request carries it too, which the handlers' own
 * `noStore` never sees.
 */
const tokenEndpointsNoStore = HttpRouter.middleware((effect) =>
  Effect.gen(function* () {
    const { route } = yield* HttpRouter.RouteContext;
    if (Arr.contains(TOKEN_ENDPOINTS, openApiTemplate(route.path))) yield* noStore;
    return yield* effect;
  }),
).layer;

/** The rules `ipRateLimit` puts in force: none for `false`, else its own or the defaults. */
const endpointRules = (
  ipRateLimit: HttpIPRateLimitConfig | false | undefined,
): ReadonlyArray<EndpointRateLimitRule> =>
  ipRateLimit === false ? [] : (ipRateLimit?.rules ?? defaultEndpointRules);

// The class lives in Errors.ts; its TSDoc says when each check raises it.
export { ClientAddressConfigError } from "../Errors.ts";

// The class lives in Errors.ts with the other startup errors; `make` throws it
// under `strict` (#416).
export { ServicesBuildPendingError } from "../Errors.ts";

/**
 * Options for the mountable auth Web handler.
 */
export interface AuthWebHandlerOptions {
  /** Your service layer (SessionService, AuthLifecycle, stores, ...). */
  readonly services: Layer.Layer<AuthServices>;
  /** Cookie configuration. */
  readonly cookie?: CookieConfig;
  /**
   * Enable multi-session: one browser can hold several signed-in accounts and
   * switch between them. Each sign-in appends to a device session list; the
   * active session is the primary cookie. See the `/device-sessions` endpoints.
   */
  readonly multiSession?: MultiSessionConfig;
  /**
   * The keys of `attributes` a sign-up (`POST /users`) may set on the new
   * user. Default `[]`: a sign-up stores no attribute its caller sent (#580).
   * A key not named here is dropped without an error, so existing clients
   * that send one keep signing up, and the answer does not tell a caller
   * which keys the server guards. The new user's attributes in the answer
   * show what was kept.
   *
   * List only keys that carry no authority. Whatever this names,
   * `EmailPasswordService.signUp` and `AuthLifecycleService.signUp` never
   * store the configured `UserServiceConfig.serverOnlyAttributes` (default
   * `["role"]`) or `SIGN_UP_PROTECTED_ATTRIBUTES` (the ban, SCIM and anonymous-user
   * keys) from a sign-up. The kept attributes may take at most
   * {@link SIGN_UP_ATTRIBUTES_MAX_BYTES} as JSON; a larger bag is refused
   * with `400`.
   */
  readonly signUpAttributes?: ReadonlyArray<string> | undefined;
  /**
   * Mount path prefix to strip before routing, e.g. `"/api/auth"`. When set, a
   * request to `/api/auth/sessions` is routed to the `/sessions` endpoint.
   */
  readonly prefix?: string;
  /**
   * Origins (e.g. `"https://app.example.com"`) allowed to make state-changing
   * requests, in addition to the request's own origin.
   *
   * **CSRF protection**: browsers attach an `Origin` header to cross-origin
   * (and most same-origin) mutating requests. When the header is present and
   * matches neither the request URL's origin nor this list, the request is
   * rejected with `403`. When `Origin` is absent but `Referer` is present
   * (e.g. a plain HTML form submission), the `Referer` origin is used as a
   * fallback. Requests with neither header (curl, server-to-server) are
   * allowed through.
   *
   * **Host trust**: the request URL's origin is derived from the `Host` header
   * as seen by the application. When deployed behind a reverse proxy you MUST
   * configure {@link trustedProxy} (from issue #81 / `ClientIP`) so the proxy
   * forwards the correct `Host` and the origin comparison is accurate.
   */
  readonly trustedOrigins?: ReadonlyArray<string>;
  /**
   * Maximum allowed request-body size in bytes. Requests whose
   * `Content-Length` header exceeds this limit are rejected with `413 Payload
   * Too Large` before the body is read or decoded. Default `65536` (64 KiB).
   *
   * Note: `Content-Length` is advisory — a client that omits it or sends a
   * chunked body bypasses this check. Pair with a reverse-proxy body-size
   * limit for a complete defence.
   */
  readonly maxBodySize?: number;
  /**
   * Serve the generated OpenAPI document and an API reference UI. When `true`,
   * `GET {prefix}/openapi.json` returns the OpenAPI 3.1 document and
   * `GET {prefix}/reference` returns a Scalar reference page. Default `false`
   * (keep off in production unless you intend to expose the docs publicly).
   */
  readonly docs?: boolean;
  /**
   * Trusted-proxy configuration for resolving the real client IP.
   *
   * **Secure default**: without this option, all `X-Forwarded-For` and similar
   * headers are IGNORED and the socket remote address is used as-is.
   *
   * Provide this only when the app is deployed behind a known reverse proxy.
   * The resolved IP is available to all hooks and handlers via
   * `Effect.serviceOption(ClientIP)`.
   *
   * Behind Cloudflare, pass {@link ClientIP.cloudflare} (trusts `CF-Connecting-IP`
   * alone). That is correct only when the app is reachable solely through
   * Cloudflare; the `trustedHeader` form of `TrustedProxyConfig` documents the
   * trust assumption in full.
   *
   * `Http.make` serves Web `Request`s, which never carry a socket address, so
   * with this option set the address comes only from the forwarded data. Under
   * `{ hopCount: n }` the client is the `n`-th `X-Forwarded-For` entry from the
   * right (the entry the outermost trusted proxy wrote), never one the client
   * sent ahead of it, and only an IP literal is ever taken. When
   * that data is absent or unusable, the request has no client address:
   * `ClientIP` carries `undefined`, and a request that reaches a rate-limited
   * endpoint (see {@link ipRateLimit}) or an `IPRateLimitPlugin` hook is refused
   * with `429`.
   */
  readonly trustedProxy?: TrustedProxyConfig | undefined;
  /**
   * IP-keyed rate limiting at the HTTP boundary, before handlers run. **On by
   * default** (#583): omitted or `{}`, the built-in
   * {@link defaultEndpointRules} apply; `{ rules: [...] }` replaces them with a
   * custom rule set; `false` turns the limit off, and is the only way to.
   *
   * Requires `RateLimiter` in the `services` layer (compose it with its
   * store via `RateLimiter.layer().pipe(Layer.provide(rateLimitStoreLayer))`).
   * Without one, `make` throws `RateLimiterConfigError`, so the app fails to
   * start rather than run with the limit off (#389). When `services` finishes
   * building only after `make` returns (asynchronous work while building; see
   * `make`), the handler's build fails with that error instead, and every
   * request rejects with it; {@link makeAsync} rejects with it at startup.
   * Requests that exceed a limit receive HTTP 429 before any auth logic runs.
   *
   * **Client address required**: the limiter keys each request by its client
   * address, so `make` throws {@link ClientAddressConfigError} unless this is
   * `false` or {@link trustedProxy} is set. A Web `Request` has no socket
   * address to fall back on, and {@link allowMissingClientIp} is no address
   * source (#682).
   *
   * **Overriding a default.** The first rule that matches an endpoint wins, so
   * a deployment changes one endpoint's limit by putting its own rule ahead of
   * the defaults: `{ rules: [{ path: "/oauth2/token", methods: ["POST"],
   * maxRequests: 600, windowMs: 60_000 }, ...defaultEndpointRules] }` lets a
   * confidential client's backend call the token endpoint from one address
   * more often, and leaves every other default in force. Leaving
   * `defaultEndpointRules` out of `rules` drops the defaults altogether.
   *
   * Each rule is matched against the endpoint the router matched, by its path
   * template and method, so no spelling of a path (case, trailing or duplicate
   * slashes, percent-encoding) escapes its limit (#582).
   *
   * A request to a rate-limited endpoint that resolves no address is refused
   * with `429` and is not counted. It is never let through unlimited and never
   * counted under a bucket shared with other callers. Requests to endpoints
   * with no rule are unaffected.
   */
  readonly ipRateLimit?: HttpIPRateLimitConfig | false | undefined;
  /**
   * Not an address source, and not an opt-out of the client-address check
   * (#682). Under `Http.make` a Web `Request` has no socket address, so with no
   * {@link trustedProxy} no request has an address, and a limit keyed on it
   * would refuse every request it covers with `429`. So `make` throws
   * {@link ClientAddressConfigError} (and {@link makeAsync} rejects with it)
   * whenever {@link ipRateLimit} (on unless it is `false`), an
   * `IPRateLimitPlugin` in the `services` `Hooks`, or dynamic client
   * registration in the `services`' `OidcProviderService` has no
   * `trustedProxy`, whether or not this is set; with it set, the error's
   * message says so. With a `trustedProxy` it changes nothing.
   *
   * Give the handler a `trustedProxy`, or serve without the IP limit with
   * `ipRateLimit: false`, the only way to turn it off. Under a `trustedProxy`,
   * a request whose forwarded address is missing or unusable is refused with
   * `429` on a limited endpoint, and is never counted under a shared bucket.
   */
  readonly allowMissingClientIp?: boolean | undefined;
  /**
   * Make {@link make} throw {@link ServicesBuildPendingError} when the
   * `services` build has not finished by the time `make` has run it as far as
   * it runs synchronously. Default `false`.
   *
   * Without it, `make` returns for such a build (asynchronous work, merged
   * layers that yield, a forked fiber the build waits on, a failed build whose
   * finalizer does asynchronous work: see `make`), and the startup checks run
   * when the build finishes: a failure then fails the handler's build, so
   * every request rejects with it. With it, the app fails to start instead,
   * and the error's message names {@link makeAsync}, which waits for such a
   * build.
   *
   * Before it throws, `make` interrupts the build and releases what the build
   * acquired, as far as that runs synchronously. Two parts finish after `make`
   * has thrown: a finalizer that does asynchronous work, and, when the build
   * is in an uninterruptible step that waits on asynchronous work (an
   * `Effect.acquireRelease` acquire that awaits), the whole release, since the
   * interrupt waits for that step to end.
   *
   * A build that is failing when `make` throws, such as a step that failed
   * while a finalizer it runs awaits, ends with that failure rather than the
   * interrupt. `make` throws `ServicesBuildPendingError` all the same, and
   * logs the build's failure with `Effect.logError` when the build ends.
   *
   * A build that finishes synchronously is unaffected: `make` throws the
   * startup errors or the build's own failure, or returns the handler, as it
   * does without this option.
   *
   * {@link makeAsync} ignores it: it waits for the build however it is
   * composed, so its startup errors always reject at startup.
   */
  readonly strict?: boolean | undefined;
}

/** Minimal Scalar API reference shell pointing at the sibling `openapi.json`. */
const scalarReferenceHtml = `<!doctype html>
<html>
  <head>
    <title>effect-auth API reference</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script id="api-reference" data-url="openapi.json"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>
`;

const openApiJsonResponse = (): Response =>
  Response.json(getOpenApiSpec(), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

const referenceResponse = (): Response =>
  new Response(scalarReferenceHtml, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
  });

/**
 * CSRF guard for the web handler.
 *
 * Returns `true` when the request may proceed. Every state-changing request is
 * checked; a read (`GET`, `HEAD`, `OPTIONS`) mints nothing (a JWT is
 * `POST /tokens`), so it passes.
 */
const isTrustedRequest = (request: Request, trustedOrigins: ReadonlyArray<string>): boolean => {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return true;

  const origin = request.headers.get("origin");

  if (origin !== null) {
    // An opaque "null" origin (sandboxed iframe, some redirects) is NOT trusted
    // unless explicitly listed.
    const requestOrigin = new URL(request.url).origin;
    return origin === requestOrigin || trustedOrigins.includes(origin);
  }

  // No Origin header.  Use Referer as a fallback (plain HTML form submissions,
  // older browsers).  If there is no Referer either the request is likely
  // server-to-server (curl, API clients) — allow through.
  const referer = request.headers.get("referer");
  if (referer === null) return true;
  return Result.getOrElse(
    Result.try(() => {
      const refererOrigin = new URL(referer).origin;
      const requestOrigin = new URL(request.url).origin;
      return refererOrigin === requestOrigin || trustedOrigins.includes(refererOrigin);
    }),
    // Malformed Referer — reject to be safe.
    () => false,
  );
};

/**
 * A mounted auth handler, as {@link make} and {@link makeAsync} return it.
 */
export interface AuthWebHandler {
  /**
   * Serve one Web `Request`. Mount it in any framework (SvelteKit, Next, Hono,
   * …).
   */
  readonly handler: (request: Request, context?: Context.Context<never>) => Promise<Response>;
  /** Release the handler's scope, including the `services` it built. */
  readonly dispose: () => Promise<void>;
}

/**
 * The startup check of `ipRateLimit` (#358), which needs no build: a rate limit
 * keyed by client address needs an address source. A Web Request has no socket
 * address, so `trustedProxy` must be configured; `allowMissingClientIp: true`
 * without it would refuse every request to a limited endpoint, so it is
 * refused too (#682).
 */
const ipRateLimitAddressError = (
  options: AuthWebHandlerOptions,
): ClientAddressConfigError | undefined =>
  options.ipRateLimit !== false && options.trustedProxy === undefined
    ? new ClientAddressConfigError({
        message:
          "ipRateLimit (on by default) needs a client address, and a Web Request has none under Http.make or Http.makeAsync. " +
          "Set trustedProxy (for example ClientIP.cloudflare) to key the limit by the visitor's address, " +
          "or set ipRateLimit: false to serve without the limit." +
          allowMissingClientIpNote(options),
      })
    : undefined;

/**
 * Why a finished `services` build cannot be served, or `undefined` when it can:
 * a failed build gives the failure's error, or for a defect the defect itself,
 * as `Effect.runSync` throws (`Cause.squash`); a built context gives the error
 * of {@link servicesConfigError}. The error sits in a record because a defect
 * may be any value, `undefined` included.
 */
const refusedBuild = (
  built: Exit.Exit<Context.Context<AuthServices>, unknown>,
  options: AuthWebHandlerOptions,
): { readonly error: unknown } | undefined => {
  if (Exit.isFailure(built)) return { error: Cause.squash(built.cause) };
  const error = servicesConfigError(built.value, options);
  return error === undefined ? undefined : { error };
};

/**
 * Release the `services` that `make` or `makeAsync` refused. A finalizer that
 * fails is logged as an error rather than lost: the caller reports the reason
 * it refused the services, not the failed release.
 */
const releaseRefusedServices = (scope: Scope.Closeable): Effect.Effect<void> =>
  Scope.close(scope, Exit.void).pipe(
    Effect.catchCause((cause) =>
      Effect.logError(
        "[effect-auth] releasing the services Http.make or Http.makeAsync refused failed; the services build was refused for another reason",
        cause,
      ),
    ),
  );

/**
 * What `make` throws under `strict` when the `services` build has no exit
 * after it ran synchronously (#416).
 */
const pendingBuildError = (): ServicesBuildPendingError =>
  new ServicesBuildPendingError({
    message:
      "strict is set, and the services build did not finish while Http.make ran it synchronously: " +
      "it waits on asynchronous work (a database connection, Effect.promise), on a merged layer that yields, " +
      "on a forked fiber, or, when the build fails, on a finalizer that does asynchronous work. " +
      "Use Http.makeAsync, which waits for the build, or make the build synchronous. " +
      "If the build fails, its failure is logged with Effect.logError when the build ends.",
  });

/**
 * Wait for the `services` build `make` refused under `strict`, and log its
 * failure unless it ended only by the interrupt `make` sent (#416). The thrown
 * `ServicesBuildPendingError` cannot carry a failure the build ends with only
 * after `make` throws, such as a step that failed while a finalizer it runs
 * awaits.
 */
const logPendingBuildFailure = (fiber: Fiber.Fiber<unknown, unknown>): Effect.Effect<void> =>
  Fiber.await(fiber).pipe(
    Effect.flatMap((exit) =>
      Exit.isFailure(exit) && !Cause.hasInterruptsOnly(exit.cause)
        ? Effect.logError(
            "[effect-auth] the services build Http.make refused with ServicesBuildPendingError (strict) failed",
            exit.cause,
          )
        : Effect.void,
    ),
  );

/**
 * The handler over `services`, built once: `make` and `makeAsync` pass the
 * build they ran. `release` runs on `dispose`, after the handler's own scope
 * closes, and releases that build.
 */
const serve = (
  options: AuthWebHandlerOptions,
  services: Layer.Layer<AuthServices, ClientAddressConfigError | RateLimiterConfigError>,
  release: Effect.Effect<void>,
): AuthWebHandler => {
  // The IP limit is router middleware on every auth route, so it sees the
  // endpoint the router matched rather than the raw path (#582). The later
  // `Layer.provide` is the outer middleware: `tokenEndpointsNoStore` must stay
  // after `endpointRateLimit`, so a token endpoint's 429 is `no-store` too
  // (RFC 6749 §5.2; HttpServer.test.ts, "marks a rate-limited … 429 no-store").
  const apiLayer = HttpApiBuilder.layer(AuthApi).pipe(
    Layer.provide(endpointRateLimit(endpointRules(options.ipRateLimit))),
    Layer.provide(tokenEndpointsNoStore),
    Layer.provide(groupLayers(options.cookie, options.multiSession, options.signUpAttributes)),
    Layer.provide(PlatformLayer),
  );
  // The handlers' service requirements are tracked as phantom
  // `Request<"Requires", RIn>` types; providing `services` to the layer's OUTPUT
  // (provideMerge) both satisfies them at runtime and zeroes the web handler's
  // leftover context (HR), yielding a plain `(request) => Promise<Response>`.
  const appLayer = apiLayer.pipe(Layer.provideMerge(services));

  const web = HttpRouter.toWebHandler(appLayer, {
    // Cast to `Effect<..., never, never>` so TypeScript infers HR = never, keeping the
    // `context` parameter of `web.handler` optional.
    middleware: (effect) =>
      // SAFETY: HttpServerRequest and Scope are always provided by the server
      // infrastructure before middleware runs, so the narrowed requirements hold.
      Effect.gen(function* () {
        const req = yield* HttpServerRequest.HttpServerRequest;
        const ip = resolveClientIP(req, options.trustedProxy);
        // Provide the resolved ClientIP to all downstream effects (the IP
        // limit, hooks, handlers).
        return yield* effect.pipe(Effect.provideService(ClientIP, { ip }));
      }) as Effect.Effect<HttpServerResponse.HttpServerResponse>,
  });

  const trustedOrigins = options.trustedOrigins ?? [];
  const prefix = options.prefix ?? "";
  const docs = options.docs ?? false;
  const maxBodySize = options.maxBodySize ?? 65536; // 64 KiB default

  /** Path relative to the mount `prefix`, or `null` when outside the prefix. */
  const innerPath = (pathname: string): string | null => {
    if (prefix === "") return pathname;
    if (pathname === prefix) return "/";
    if (pathname.startsWith(`${prefix}/`)) return pathname.slice(prefix.length);
    return null;
  };

  const handler = (request: Request, context?: Context.Context<never>): Promise<Response> => {
    const url = new URL(request.url);
    const inner = innerPath(url.pathname);

    // When a non-empty prefix is configured, reject requests that fall outside
    // it with 404 instead of forwarding them to the router where unprefixed
    // paths might accidentally match.
    if (prefix !== "" && inner === null) {
      return Promise.resolve(Response.json({ message: "Not Found" }, { status: 404 }));
    }

    if (!isTrustedRequest(request, trustedOrigins)) {
      return Promise.resolve(Response.json({ message: "Origin not allowed" }, { status: 403 }));
    }

    // Reject bodies that exceed the configured limit before parsing.
    // Content-Length is advisory; complement with a proxy-level limit for full
    // coverage of chunked / omitted-length bodies.
    const contentLength = request.headers.get("content-length");
    if (contentLength !== null) {
      const bytes = parseInt(contentLength, 10);
      if (!isNaN(bytes) && bytes > maxBodySize) {
        return Promise.resolve(Response.json({ message: "Payload too large" }, { status: 413 }));
      }
    }

    if (docs && inner !== null && request.method === "GET") {
      if (inner === "/openapi.json") return Promise.resolve(openApiJsonResponse());
      if (inner === "/reference") return Promise.resolve(referenceResponse());
    }

    // Whatever wrote it, a response carrying Set-Cookie leaves `no-store`
    // (#628); the cookie writers above mark theirs, and this holds the rule
    // for the whole handler.
    if (inner !== null && prefix !== "") {
      url.pathname = inner || "/";
      return web.handler(new Request(url, request), context).then(noStoreWithSetCookie);
    }
    return web.handler(request, context).then(noStoreWithSetCookie);
  };
  const dispose = (): Promise<void> => web.dispose().then(() => Effect.runPromise(release));
  return { handler, dispose };
};

/**
 * Check the `services` build `make` runs synchronously, and throw why it is
 * refused, after releasing what it acquired. Returns when the build passed the
 * check, or is still running without `strict`.
 */
const refuseUnservableBuild = (
  build: SynchronousRun<Context.Context<AuthServices>, never>,
  servicesScope: Scope.Closeable,
  options: AuthWebHandlerOptions,
): void => {
  const servicesFiber = build.fiber;
  let pending = false;
  const refused = Result.getOrElse(
    Result.try((): { readonly error: unknown } | undefined => {
      build.run();
      const built = servicesFiber.pollUnsafe();
      if (built !== undefined) return refusedBuild(built, options);
      if (options.strict !== true) return undefined;
      pending = true;
      return { error: pendingBuildError() };
    }),
    // A task of the build, or the check itself, threw: refuse the services
    // all the same, and release what the build acquired.
    (thrown) => ({ error: thrown }),
  );
  if (refused === undefined) return;
  // Stop the build if it is still running (a no-op once it has an exit),
  // then release what it acquired, as far as that runs synchronously. The
  // interrupted build unwinds on its own fiber, whose tasks (a yield while
  // it unwinds) wait in the build's dispatcher, so run both until the
  // close has an exit or neither has a task left. What waits on
  // asynchronous work (an uninterruptible acquire the interrupt waits for,
  // an asynchronous finalizer) finishes after make throws.
  const close = runSynchronously(
    Fiber.interrupt(servicesFiber).pipe(Effect.andThen(releaseRefusedServices(servicesScope))),
  );
  // One round runs the close's tasks, then the build's; `unfold` repeats it
  // while a round ran anything, without growing the stack.
  const round = (): boolean => {
    const closeRan = close.run();
    return build.run() || closeRan;
  };
  const drained = Result.try(() =>
    Arr.unfold(true, (progressed) =>
      progressed && close.fiber.pollUnsafe() === undefined
        ? Option.some([undefined, round()] as const)
        : Option.none(),
    ),
  );
  close.release();
  if (Result.isFailure(drained)) throw drained.failure;
  // A build still running here may yet fail on its own account (a failed
  // step whose finalizer is asynchronous): log that failure, which the
  // thrown ServicesBuildPendingError cannot carry.
  if (pending) Effect.runFork(logPendingBuildFailure(servicesFiber));
  throw refused.error;
};

/**
 * The 429 the IP rate limit answers with. `Retry-After` (and the body's
 * `retryAfter`) are whole seconds, rounded up so a client that waits that
 * long is not refused again.
 */
const tooManyRequests = (
  retryAfter: Duration.Duration | undefined,
): HttpServerResponse.HttpServerResponse => {
  if (retryAfter === undefined) {
    return HttpServerResponse.jsonUnsafe({ message: "Too many requests" }, { status: 429 });
  }
  const seconds = Math.ceil(Duration.toSeconds(retryAfter));
  return HttpServerResponse.jsonUnsafe(
    { message: "Too many requests", retryAfter: seconds },
    { status: 429, headers: { "retry-after": String(seconds) } },
  );
};

/**
 * Build a standard Web `Request => Response` handler for the auth API.
 *
 * Mount the returned `handler` in any framework (SvelteKit/Next/Hono/...).
 * `dispose` releases the handler's scope, including the `services` it built.
 *
 * `make` builds `services` once, before it returns, and the handler serves that
 * build. It throws, so the app fails to start, when the configuration cannot be
 * served as written:
 *
 * - {@link ClientAddressConfigError}: `ipRateLimit` (on unless it is
 *   `false`, #583), an `IPRateLimitPlugin` in the `services` `Hooks`, or
 *   dynamic client registration enabled in the `services`'
 *   `OidcProviderService`, with no `trustedProxy`.
 *   `allowMissingClientIp: true` does not stand in for one (#682).
 * - `RateLimiterConfigError`: `ipRateLimit` (unless it is `false`), dynamic
 *   client registration or a `DeviceAuthorizationService` (without
 *   `allowMissingRateLimiter: true`) with no `RateLimiter` in `services`.
 * - Any failure of the `services` build itself: the failure's error, or for a
 *   defect the defect itself, as `Effect.runSync` throws.
 * - {@link ServicesBuildPendingError}, only with `strict: true`: the build had
 *   not finished when `make` had run it synchronously (below).
 *
 * **When `make` throws, and when it cannot.** `make` is synchronous, so it can
 * throw only when the `services` build finishes before it returns. It runs the
 * build on the calling stack, the way `Effect.runSync` does: every step on the
 * build's own fiber, however many, and the start of every fiber the build
 * forks and awaits. `Layer.provideMerge` and `Layer.provide` chains build on
 * that fiber.
 * The build is still running when `make` returns if it waits on:
 *
 * - asynchronous work: a database connection, `Effect.promise`, a timer, any
 *   callback that resumes later;
 * - a forked fiber that yields before it finishes. `Layer.merge` and
 *   `Layer.mergeAll` build each layer on a fiber of its own, so a merged layer
 *   whose build yields (`Effect.yieldNow`), or runs past Effect's per-slice
 *   operation budget (2,048 operations by default), counts. So does a fiber
 *   forked with `Effect.forkScoped` that yields before it completes a
 *   `Deferred` the build awaits;
 * - a finalizer that does asynchronous work, when the build fails: Effect
 *   releases what the failed build acquired before the build ends.
 *
 * Then the same checks run when the build finishes, and fail the handler's
 * build instead of `make`: every request rejects with the error. Use
 * {@link makeAsync} when `services` may build like this. It waits for the build
 * however it is composed, and rejects with the same errors.
 *
 * **Strict.** With `strict: true`, `make` throws
 * {@link ServicesBuildPendingError} for such a build instead of returning, so
 * the app fails to start; the error's message names {@link makeAsync}. When
 * the build was failing (a step that failed while a finalizer it runs awaits),
 * `make` logs that failure with `Effect.logError` when the build ends. A build
 * that finishes synchronously is unaffected: it throws its own errors or
 * returns the handler, as without the option.
 *
 * **Release before a throw.** `make` interrupts the build if it is still
 * running, closes what the build acquired, then throws. It runs the release as
 * far as it runs synchronously, the build's own unwinding included, so two
 * parts finish after `make` has thrown: a finalizer that does asynchronous
 * work, and, when the build is in an uninterruptible step that waits on
 * asynchronous work (an `Effect.acquireRelease` acquire that awaits), the
 * whole release, since the interrupt waits for that step to end. A finalizer
 * that fails is logged with `Effect.logError` whenever it finishes, and `make`
 * throws the reason it refused the services.
 *
 * **Forked fibers.** `make` runs the build until it finishes, and no further. A
 * fiber the build forks with `Effect.forkChild` is interrupted when the layer
 * that forks it finishes building. Under `Layer.merge` or `Layer.mergeAll` that
 * is the merged layer's own build, which can end before the whole `services`
 * build does, so a fiber that has not started by then never runs. A fiber
 * forked into the layer's scope (`Effect.forkScoped`, or `Effect.forkIn` with
 * that scope) keeps running on the default scheduler after `make` returns, and
 * stops on `dispose`. A fiber forked with `Effect.forkDetach` keeps running
 * after `make` returns, and `dispose` does not stop it.
 */
export const make = (options: AuthWebHandlerOptions): AuthWebHandler => {
  const addressError = ipRateLimitAddressError(options);
  if (addressError !== undefined) throw addressError;

  // Build `services` here, synchronously until the build has an exit, so the
  // startup check below sees what the handler will serve (#389). The handler
  // reuses this build rather than building `services` again. Fibers the build
  // forks run on the default scheduler, and make does not wait for them (#402).
  const servicesScope = Scope.makeUnsafe();
  const build = runSynchronously(Layer.buildWithScope(options.services, servicesScope));
  const servicesFiber = build.fiber;
  // Release the build's dispatcher however the check ends, then rethrow.
  const checked = Result.try(() => refuseUnservableBuild(build, servicesScope, options));
  build.release();
  if (Result.isFailure(checked)) throw checked.failure;
  // Still building, without strict (see "When make throws" above): the same
  // check runs as a layer when the build finishes, and fails the handler's
  // build instead.
  return serve(
    options,
    Layer.provideMerge(
      requireServicesConfig(options),
      Layer.effectContext(Fiber.join(servicesFiber)),
    ),
    Fiber.interrupt(servicesFiber).pipe(Effect.andThen(Scope.close(servicesScope, Exit.void))),
  );
};

/**
 * Build a standard Web `Request => Response` handler for the auth API, like
 * {@link make}, and wait for the `services` build however it is composed.
 *
 * Use it when `services` may finish building only after a synchronous call
 * returns: asynchronous work while building (a database connection,
 * `Effect.promise`), merged layers that yield, or a finalizer that does
 * asynchronous work (see {@link make}). The startup checks then still fail at
 * startup, rather than as every request rejecting.
 *
 * The promise resolves once `services` is built and checked, with the same
 * `handler` and `dispose` that `make` returns. The handler serves that build,
 * so `services` is built once, and `dispose` releases it. The promise rejects,
 * so the app fails to start, with the error `make` would throw:
 *
 * - {@link ClientAddressConfigError}: `ipRateLimit` (on unless it is
 *   `false`, #583), an `IPRateLimitPlugin` in the `services` `Hooks`, or
 *   dynamic client registration enabled in the `services`'
 *   `OidcProviderService`, with no `trustedProxy`.
 *   `allowMissingClientIp: true` does not stand in for one (#682).
 * - `RateLimiterConfigError`: `ipRateLimit` (unless it is `false`), dynamic
 *   client registration or a `DeviceAuthorizationService` (without
 *   `allowMissingRateLimiter: true`) with no `RateLimiter` in `services`.
 * - Any failure of the `services` build itself: the failure's error, or for a
 *   defect the defect itself, as `Effect.runPromise` rejects.
 *
 * Before it rejects, `makeAsync` releases what the build acquired and waits
 * for every finalizer, asynchronous ones included. A finalizer that fails is
 * logged with `Effect.logError`, and the promise rejects with the reason the
 * services were refused.
 *
 * `makeAsync` ignores `strict`: it waits for the build whatever the option
 * says, so it never needs a synchronous one.
 *
 * A fiber the build forks with `Effect.forkChild` is interrupted when the layer
 * that forks it finishes building, and under `Layer.merge` or `Layer.mergeAll`
 * that can be before the whole `services` build finishes, so a fiber that has
 * not started by then never runs. One forked into the layer's scope
 * (`Effect.forkScoped`, or `Effect.forkIn` with that scope) keeps running after
 * the promise resolves, and stops on `dispose`. One forked with
 * `Effect.forkDetach` keeps running, and `dispose` does not stop it.
 */
export const makeAsync = (options: AuthWebHandlerOptions): Promise<AuthWebHandler> =>
  Effect.runPromise(
    Effect.gen(function* () {
      const addressError = ipRateLimitAddressError(options);
      if (addressError !== undefined) return yield* addressError;
      const servicesScope = yield* Scope.make();
      const services = yield* Layer.buildWithScope(options.services, servicesScope).pipe(
        Effect.tap((built) => {
          const error = servicesConfigError(built, options);
          return error === undefined ? Effect.void : Effect.fail(error);
        }),
        Effect.onError(() => releaseRefusedServices(servicesScope)),
      );
      return serve(options, Layer.succeedContext(services), Scope.close(servicesScope, Exit.void));
    }),
  );
