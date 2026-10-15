import { Context, Effect, FileSystem, Layer, Option, Path } from "effect";
import { resolveMessage } from "../Messages.ts";
import { HttpApiBuilder } from "effect/http-api";
import { Etag, HttpPlatform, HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/http";
import { AuthApi, getOpenApiSpec } from "./HttpApi.ts";
import * as SessionCookies from "../SessionCookies.ts";
import { ClientIP, resolveClientIP, type TrustedProxyConfig } from "../ClientIP.ts";
import { RateLimiter, type RateLimitConfig } from "../RateLimit.ts";
import * as S from "./HttpApiSchema.ts";
import { AuthLifecycleService } from "../AuthLifecycle.ts";
import { Hooks } from "../Hooks.ts";
import { SessionService } from "../SessionService.ts";
import { EmailPasswordService } from "../email/EmailPassword.ts";
import * as EmailPassword from "../email/EmailPassword.ts";
import { IdentifierStore, type Identifier } from "../Identifier.ts";
import { MagicLinkService } from "../MagicLink.ts";
import { AccountManagementService } from "../AccountManagement.ts";
import { AnonymousService } from "../Anonymous.ts";
import { PhoneOtpService } from "../PhoneOtp.ts";
import { UsernameService } from "../Username.ts";
import { DeviceAuthorizationService, normalizeUserCode } from "../DeviceAuthorization.ts";
import { EmailOtpService } from "../email/EmailOtp.ts";
import { MultiFactorService } from "../multifactor/MultiFactor.ts";
import { PasswordHasher } from "../password/Password.ts";
import { EmailVerificationService } from "../email/EmailVerification.ts";
import { PasswordResetService } from "../password/PasswordReset.ts";
import { UserService } from "../User.ts";
import {
  OrganizationService,
  type Organization,
  type Member,
  type Invitation,
  type Team,
  type TeamMember,
  type OrgRole,
  type OrganizationDomain,
  type FullOrganization,
} from "../Organization.ts";
import { AdminService, isAdmin } from "../Admin.ts";
import { ApiKeyService, type ApiKey } from "../ApiKey.ts";
import { type CredentialClass } from "../Authorizer.ts";
import { JwtService } from "../Jwt.ts";
import {
  OidcProviderService,
  type OidcClient,
  type OidcClientMetadata,
  type OidcRegistrationError,
} from "../OidcProvider.ts";
import { SsoService, type SsoProvider } from "../Sso.ts";
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
import { ClientAddressConfigError } from "../Errors.ts";
import { hashToken } from "../TokenHash.ts";
import { GoogleOneTapService } from "../GoogleOneTap.ts";
import {
  decodeSessionCacheCookie,
  encodeSessionCacheCookie,
  resolveSessionCache,
  type ResolvedSessionCache,
  type SessionCacheConfig,
} from "../SessionCookieCache.ts";
import type * as Types from "../Types.ts";

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
  return raw.split(".").filter((id) => id.length > 0);
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

const signUpInput = (payload: S.SignUpPayload) => ({
  email: payload.email,
  password: payload.password,
  ...(payload.name !== undefined && { name: payload.name }),
  ...(payload.attributes !== undefined && { attributes: payload.attributes }),
  ...(payload.captchaToken !== undefined && { captchaToken: payload.captchaToken }),
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
const encodeOrganization = (o: Organization): S.OrganizationView => ({
  id: o.id,
  name: o.name,
  slug: o.slug,
  ...(o.logo !== undefined && { logo: o.logo }),
  metadata: o.metadata,
  defaultRole: o.defaultRole ?? "member",
  jitProvisioning: o.jitProvisioning ?? false,
  createdAt: o.createdAt,
});

const encodeMember = (m: Member): S.MemberView => ({
  id: m.id,
  organizationId: m.organizationId,
  userId: m.userId,
  role: m.role,
  status: m.status ?? "active",
  ...(m.previousRole !== undefined && { previousRole: m.previousRole }),
  createdAt: m.createdAt,
});

const encodeOrganizationDomain = (d: OrganizationDomain): S.OrganizationDomainView => ({
  id: d.id,
  organizationId: d.organizationId,
  domain: d.domain,
  verificationState: d.verificationState,
  verificationStrategy: d.verificationStrategy,
  ...(d.verificationToken !== undefined && { verificationToken: d.verificationToken }),
  createdAt: d.createdAt,
  ...(d.verifiedAt !== undefined && { verifiedAt: d.verifiedAt }),
});

const encodeInvitation = (i: Invitation): S.InvitationView => ({
  id: i.id,
  organizationId: i.organizationId,
  email: i.email,
  role: i.role,
  status: i.status,
  inviterId: i.inviterId,
  expiresAt: i.expiresAt,
  createdAt: i.createdAt,
});

const encodeTeam = (t: Team): S.TeamView => ({
  id: t.id,
  organizationId: t.organizationId,
  name: t.name,
  createdAt: t.createdAt,
  updatedAt: t.updatedAt,
});

const encodeTeamMember = (m: TeamMember): S.TeamMemberView => ({
  teamId: m.teamId,
  userId: m.userId,
  createdAt: m.createdAt,
});

const encodeOrgRole = (r: OrgRole): S.OrgRoleView => ({
  organizationId: r.organizationId,
  role: r.role,
  permissions: r.permissions,
  createdAt: r.createdAt,
  updatedAt: r.updatedAt,
});

const encodeFullOrganization = (f: FullOrganization): S.FullOrganizationView => ({
  organization: encodeOrganization(f.organization),
  members: f.members.map(encodeMember),
});

/**
 * Encode an SSO connection for the wire, one arm of the `protocol` union at a
 * time. Neither arm carries a secret: the OIDC arm drops `clientSecret`, and
 * both drop the registrar's `userId`.
 */
const encodeSsoProvider = (p: SsoProvider): S.SsoProviderView =>
  p.protocol === "saml"
    ? {
        id: p.id,
        domain: p.domain,
        protocol: p.protocol,
        entityId: p.entityId,
        ssoUrl: p.ssoUrl,
        idpCertificates: p.idpCertificates,
        spEntityId: p.spEntityId,
        acsUrl: p.acsUrl,
        ...(p.signatureAlgorithms !== undefined && { signatureAlgorithms: p.signatureAlgorithms }),
        ...(p.wantAssertionsSigned !== undefined && {
          wantAssertionsSigned: p.wantAssertionsSigned,
        }),
        ...(p.wantAuthnResponseSigned !== undefined && {
          wantAuthnResponseSigned: p.wantAuthnResponseSigned,
        }),
        ...(p.forceAuthn !== undefined && { forceAuthn: p.forceAuthn }),
        ...(p.organizationId !== undefined && { organizationId: p.organizationId }),
        createdAt: p.createdAt,
      }
    : {
        id: p.id,
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
        ...(p.organizationId !== undefined && { organizationId: p.organizationId }),
        createdAt: p.createdAt,
      };

const encodeOidcClient = (c: OidcClient): S.OidcClientView => ({
  clientId: c.clientId,
  name: c.name,
  redirectUris: c.redirectUris,
  type: c.type,
  skipConsent: c.skipConsent,
  disabled: c.disabled,
  metadata: c.metadata,
  createdAt: c.createdAt,
  updatedAt: c.updatedAt,
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

const encodeApiKey = (k: ApiKey): S.ApiKeyView => ({
  id: k.id,
  ...(k.name !== undefined && { name: k.name }),
  ...(k.prefix !== undefined && { prefix: k.prefix }),
  start: k.start,
  userId: k.userId,
  enabled: k.enabled,
  ...(k.expiresAt !== undefined && { expiresAt: k.expiresAt }),
  ...(k.lastUsedAt !== undefined && { lastUsedAt: k.lastUsedAt }),
  ...(k.permissions !== undefined && { permissions: k.permissions }),
  metadata: k.metadata,
  ...(k.remaining !== undefined && { remaining: k.remaining }),
  ...(k.rateLimit !== undefined && { rateLimit: k.rateLimit }),
  createdAt: k.createdAt,
  updatedAt: k.updatedAt,
});

/**
 * Log the real error server-side and return a generic 500 body so internal
 * implementation details are never exposed to clients.
 */
const internalServerError = (e: unknown): Effect.Effect<never, S.InternalServerError, never> =>
  Effect.logError("[effect-auth] internal error", e).pipe(
    Effect.flatMap(() =>
      Effect.fail(new S.InternalServerError({ message: "Internal server error" })),
    ),
  );

/**
 * Per-user-code rate limit for device-authorization approve/deny endpoints
 * (RFC 8628 §5.2). Optionally applied when `RateLimiter` is in scope (it
 * resolves its own `RateLimitStore` at Layer-construction time); silent
 * no-op when the service is absent.
 */
const USER_CODE_RATE_LIMIT: RateLimitConfig = {
  maxRequests: 5,
  windowMs: 15 * 60 * 1000,
  blockDurationMs: 30 * 60 * 1000,
};

const applyUserCodeRateLimit = (
  userCode: string,
): Effect.Effect<void, S.TooManyRequests | S.InternalServerError, never> =>
  Effect.gen(function* () {
    const rateLimiterOpt = yield* Effect.serviceOption(RateLimiter);
    if (Option.isNone(rateLimiterOpt)) return;
    const key = `device-user-code:${normalizeUserCode(userCode)}`;
    yield* rateLimiterOpt.value.consumeToken(key, USER_CODE_RATE_LIMIT).pipe(
      Effect.catchTag("RateLimitError", (e) =>
        Effect.fail(new S.TooManyRequests({ message: e.message })),
      ),
      Effect.catchTag("AuthError", (e) => internalServerError(e)),
    );
  });

/**
 * The refusal message when a request reaches a rate-limited endpoint with no
 * client address. The limiter cannot key such a request, so it is refused
 * rather than skipped or counted under a bucket that other callers share.
 */
const NO_CLIENT_ADDRESS = "Client address unavailable; this request cannot be rate limited";

/**
 * Per-IP rate limit for anonymous dynamic client registration. Applied when a
 * `RateLimiter` is in scope (silent no-op otherwise), mirroring the device
 * user-code limiter; the window comes from the provider's own configuration.
 *
 * A caller with no resolvable client address is refused, never keyed under a
 * shared bucket and never let through uncounted (#358).
 */
const applyRegistrationRateLimit = (
  limit: RateLimitConfig,
): Effect.Effect<void, S.TooManyRequests | S.InternalServerError, never> =>
  Effect.gen(function* () {
    const rateLimiterOpt = yield* Effect.serviceOption(RateLimiter);
    if (Option.isNone(rateLimiterOpt)) return;
    const clientIp = yield* Effect.serviceOption(ClientIP);
    const ip = Option.isSome(clientIp) ? clientIp.value.ip : undefined;
    if (ip === undefined) return yield* new S.TooManyRequests({ message: NO_CLIENT_ADDRESS });
    yield* rateLimiterOpt.value.consumeToken(`oidc-register:${ip}`, limit).pipe(
      Effect.catchTag("RateLimitError", (e) =>
        Effect.fail(new S.TooManyRequests({ message: e.message })),
      ),
      Effect.catchTag("AuthError", (e) => internalServerError(e)),
    );
  });

/** Layer implementing the `auth` group handlers. */
export const authGroupLayer = (config?: CookieConfig, multiSession?: MultiSessionConfig) => {
  const cfg = resolveCookieConfig(config, multiSession);

  return HttpApiBuilder.group(AuthApi, "auth", (handlers) =>
    handlers
      .handle("signUp", ({ payload }) =>
        Effect.gen(function* () {
          const lifecycle = yield* AuthLifecycleService;
          const result = yield* lifecycle.signUp(signUpInput(payload)).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
              EmailInUseError: (e) =>
                Effect.fail(new S.Conflict({ message: e.message, code: e.code })),
              EmailNotVerifiedError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              HashingError: (e) => internalServerError(e),
              EmailVerificationError: (e) => internalServerError(e),
              RateLimitError: (e) =>
                Effect.fail(new S.TooManyRequests({ message: e.message, code: e.code })),
              PasswordPolicyError: (e) =>
                resolveMessage(e.code, e.message, e.params).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
              SignUpDisabledError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.Forbidden({ message: msg, code: e.code })),
                  ),
                ),
              InvalidInputError: (e) =>
                resolveMessage(e.code, e.message).pipe(
                  Effect.flatMap((msg) =>
                    Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                  ),
                ),
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
            needsEmailVerification: result.needsEmailVerification,
          };
          return yield* withSessionCookie(body, result.session, cfg, "email-password");
        }),
      )
      .handle("signIn", ({ payload }) =>
        Effect.gen(function* () {
          const lifecycle = yield* AuthLifecycleService;
          const result = yield* lifecycle
            .signIn({
              email: payload.email,
              password: payload.password,
              ...(payload.captchaToken !== undefined && { captchaToken: payload.captchaToken }),
              ...(payload.rememberMe !== undefined && { rememberMe: payload.rememberMe }),
            })
            .pipe(
              Effect.catchTags({
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.Unauthorized({ message: e.message, code: e.code })),
                AuthError: (e) => internalServerError(e),
                HashingError: (e) => internalServerError(e),
                EmailVerificationError: (e) => internalServerError(e),
                RateLimitError: (e) =>
                  Effect.fail(new S.TooManyRequests({ message: e.message, code: e.code })),
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
            needsEmailVerification: result.needsEmailVerification,
            ...(result.secondFactor !== undefined && { secondFactor: result.secondFactor }),
          };
          return yield* withSessionCookie(
            body,
            result.session,
            cfg,
            "email-password",
            result.rememberMe,
          );
        }),
      )
      .handle("signOut", ({ request }) =>
        Effect.gen(function* () {
          const sessionId = sessionIdFromRequest(request, cfg);
          if (sessionId !== undefined) {
            const sessionManager = yield* SessionService;
            yield* Effect.ignore(sessionManager.invalidateSession(sessionId));
          }
          let response = yield* HttpServerResponse.setCookie(
            HttpServerResponse.empty({ status: 204 }),
            cfg.name,
            "",
            clearCookieOptions(cfg),
          );
          // Also clear the session-data cache cookie (if in use).
          if (cfg.cache !== undefined) {
            response = yield* HttpServerResponse.setCookie(
              response,
              dataCookieName(cfg),
              "",
              clearCookieOptions(cfg),
            );
          }
          // Multi-session: sign out only the active account; drop it from the
          // device list and keep the others (switch via /multi-session/set-active).
          if (cfg.multiSession !== undefined) {
            const remaining = readDeviceSessionIds(request, cfg).filter((id) => id !== sessionId);
            response = yield* HttpServerResponse.setCookie(
              response,
              multiCookieName(cfg),
              remaining.join("."),
              sessionCookieOptions(cfg, new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)),
            );
          }
          return response;
        }).pipe(Effect.orDie),
      )
      .handle("getSession", ({ request }) =>
        Effect.gen(function* () {
          const { resolved, cacheHit } = yield* resolveSession(request, cfg);
          // A cache-served response deliberately skips the store round-trip,
          // so the derived email fields are omitted there.
          const body = cacheHit
            ? S.encodeSessionWithUser(resolved)
            : yield* encodeSessionWithUserView(resolved);
          // On a store validation (cache miss) refresh the signed cache cookie
          // so subsequent reads within `maxAge` skip the store.
          if (cfg.cache !== undefined && !cacheHit) {
            const cache = cfg.cache;
            const value = encodeSessionCacheCookie(
              resolved,
              cache,
              Date.now(),
              resolved.session.id,
            );
            return yield* HttpServerResponse.json(body).pipe(
              Effect.flatMap((response) =>
                HttpServerResponse.setCookie(
                  response,
                  dataCookieName(cfg),
                  value,
                  dataCookieOptions(cfg, cache),
                ),
              ),
              Effect.orDie,
            );
          }
          return body;
        }),
      )
      .handle("sendVerificationEmail", ({ payload }) =>
        Effect.gen(function* () {
          const identifiers = yield* IdentifierStore;
          const verification = yield* EmailVerificationService;
          const email = payload.email.trim().toLowerCase();

          const identifier = yield* identifiers
            .getByValue("email", email)
            .pipe(Effect.catch(internalServerError));

          // Anti-enumeration: succeed uniformly whether or not the identifier
          // exists (or is already verified).
          if (identifier !== null && !identifier.verified) {
            yield* verification.resendVerification(identifier.userId, email).pipe(
              Effect.catchTags({
                AuthError: (e) => internalServerError(e),
                EmailVerificationError: (e) => internalServerError(e),
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
          }

          return { status: true };
        }),
      )
      .handle("verifyEmail", ({ payload }) =>
        Effect.gen(function* () {
          const lifecycle = yield* AuthLifecycleService;
          const result = yield* lifecycle.verifyEmail({ token: payload.token }).pipe(
            Effect.catchTags({
              EmailVerificationError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
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
            needsEmailVerification: result.needsEmailVerification,
          };
          return yield* withSessionCookie(body, result.session, cfg, "email-password");
        }),
      )
      .handle("passwordResetRequest", ({ payload }) =>
        Effect.gen(function* () {
          const passwordReset = yield* PasswordResetService;
          yield* passwordReset.requestPasswordReset(payload.email).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
              PasswordResetError: (e) => internalServerError(e),
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
          return { status: true };
        }),
      )
      .handle("passwordResetConfirm", ({ payload }) =>
        Effect.gen(function* () {
          const passwordReset = yield* PasswordResetService;
          yield* passwordReset.resetPassword(payload.token, payload.newPassword).pipe(
            Effect.catchTags({
              PasswordResetError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
              HashingError: (e) => internalServerError(e),
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
          return { status: true };
        }),
      )
      .handle("changePassword", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const emailPassword = yield* EmailPassword.make();
          yield* emailPassword
            .changePassword({
              userId: resolved.user.id,
              currentPassword: payload.currentPassword,
              newPassword: payload.newPassword,
              ...(payload.revokeOtherSessions !== undefined && {
                revokeOtherSessions: payload.revokeOtherSessions,
              }),
              currentSessionId: resolved.session.id,
            })
            .pipe(
              Effect.catchTags({
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.BadRequest({ message: e.message, code: e.code })),
                AuthError: (e) => internalServerError(e),
                HashingError: (e) => internalServerError(e),
                PasswordPolicyError: (e) =>
                  resolveMessage(e.code, e.message, e.params).pipe(
                    Effect.flatMap((msg) =>
                      Effect.fail(new S.BadRequest({ message: msg, code: e.code })),
                    ),
                  ),
              }),
            );
        }),
      )
      .handle("updateUser", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const userService = yield* UserService;
          const updated = yield* userService
            .updateUser(resolved.user.id, {
              ...(payload.name !== undefined && { name: payload.name }),
              ...(payload.image !== undefined && { image: payload.image }),
            })
            .pipe(
              Effect.catchTags({
                UserNotFoundError: () =>
                  Effect.fail(new S.Unauthorized({ message: "Not authenticated" })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return yield* encodeUserView(updated);
        }),
      )
      .handle("changeEmailRequest", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const account = yield* resolveAccountManagement;
          yield* account.service.requestEmailChange(resolved.user.id, payload.newEmail).pipe(
            Effect.catchTags({
              // Anti-enumeration: never reveal whether the target email exists.
              EmailInUseError: () => Effect.void,
              UserNotFoundError: () =>
                Effect.fail(new S.Unauthorized({ message: "Not authenticated" })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { status: true };
        }),
      )
      .handle("changeEmailConfirm", ({ payload, request: _r }) =>
        Effect.gen(function* () {
          const account = yield* resolveAccountManagement;
          yield* account.service.confirmEmailChange(payload.token).pipe(
            Effect.catchTags({
              AccountTokenError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return yield* HttpServerResponse.json({ status: true }).pipe(
            Effect.flatMap((response) =>
              cfg.cache !== undefined
                ? HttpServerResponse.setCookie(
                    response,
                    dataCookieName(cfg),
                    "",
                    clearCookieOptions(cfg),
                  )
                : Effect.succeed(response),
            ),
            Effect.orDie,
          );
        }),
      )
      .handle("deleteUserRequest", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const account = yield* resolveAccountManagement;
          yield* account.service.requestAccountDeletion(resolved.user.id).pipe(
            Effect.catchTags({
              UserNotFoundError: () =>
                Effect.fail(new S.Unauthorized({ message: "Not authenticated" })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { status: true };
        }),
      )
      .handle("deleteUserConfirm", ({ payload, request: _r }) =>
        Effect.gen(function* () {
          const account = yield* resolveAccountManagement;
          yield* account.service.confirmAccountDeletion(payload.token).pipe(
            Effect.catchTags({
              AccountTokenError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return yield* HttpServerResponse.json({ status: true }).pipe(
            Effect.flatMap((response) =>
              cfg.cache !== undefined
                ? HttpServerResponse.setCookie(
                    response,
                    dataCookieName(cfg),
                    "",
                    clearCookieOptions(cfg),
                  )
                : Effect.succeed(response),
            ),
            Effect.orDie,
          );
        }),
      )
      .handle("listSessions", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionService;
          const sessions = yield* sessionManager
            .listSessions(resolved.user.id)
            .pipe(Effect.catch(internalServerError));
          return sessions.map(S.encodeSession);
        }),
      )
      .handle("revokeSession", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionService;

          const sessions = yield* sessionManager
            .listSessions(resolved.user.id)
            .pipe(Effect.catch(internalServerError));

          // Only the owner may revoke a session, and only their own sessions.
          // params.sessionId is the raw token from the URL; sessions in the list
          // have hash ids (stored by hash), so compare against the hash.
          const targetHash = hashToken(params.sessionId);
          const target = sessions.find((session) => session.id === targetHash);
          if (target === undefined) {
            return yield* new S.BadRequest({ message: "Session not found" });
          }

          yield* sessionManager
            .invalidateSession(params.sessionId)
            .pipe(Effect.catch(internalServerError));
        }),
      )
      .handle("revokeOtherSessions", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionService;
          yield* sessionManager
            .revokeOtherSessions(resolved.user.id, resolved.session.id)
            .pipe(Effect.catch(internalServerError));
        }),
      )
      .handle("listIdentifiers", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const identifiers = yield* IdentifierStore;
          const list = yield* identifiers
            .listByUser(resolved.user.id)
            .pipe(Effect.catch(internalServerError));
          return list.map(S.encodeIdentifier);
        }),
      )
      .handle("deleteIdentifier", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const identifiers = yield* IdentifierStore;
          const list = yield* identifiers
            .listByUser(resolved.user.id)
            .pipe(Effect.catch(internalServerError));

          // Only the owner may delete an identifier, and only their own — a
          // foreign or unknown id gets the same answer (anti-enumeration).
          const target = list.find((identifier) => identifier.id === params.identifierId);
          if (target === undefined) {
            return yield* new S.BadRequest({ message: "Identifier not found" });
          }
          // Refuse to orphan the account: the last identifier is the user's
          // only login handle.
          if (list.length === 1) {
            return yield* new S.BadRequest({
              message: "Cannot delete the only identifier on an account",
            });
          }

          yield* identifiers.delete(target.id).pipe(Effect.catch(internalServerError));
        }),
      )
      .handle("magicLinkSend", ({ payload }) =>
        Effect.gen(function* () {
          const magicLink = yield* resolveMagicLink;
          // Anti-enumeration: the service succeeds silently for unknown
          // accounts; only store/delivery failures surface (as 500).
          yield* magicLink.service.send(payload.email).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
              MagicLinkError: (e) => internalServerError(e),
              ResendTooSoonError: (e) =>
                Effect.fail(new S.TooManyRequests({ message: e.message, code: e.code })),
            }),
          );
          return { status: true };
        }),
      )
      .handle("magicLinkVerify", ({ payload }) =>
        Effect.gen(function* () {
          const magicLink = yield* resolveMagicLink;
          const result = yield* magicLink.service.verify(payload.token).pipe(
            Effect.catchTags({
              MagicLinkError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
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
          return yield* withSessionCookie(body, result.session, cfg, "magic-link");
        }),
      )
      .handle("emailOtpSend", ({ payload }) =>
        Effect.gen(function* () {
          const emailOtp = yield* resolveEmailOtp;
          // Anti-enumeration: the service succeeds silently for unknown
          // accounts; only store/delivery failures surface (as 500).
          yield* emailOtp.service.send(payload.email, payload.purpose).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
              EmailOtpError: (e) => internalServerError(e),
              ResendTooSoonError: (e) =>
                Effect.fail(new S.TooManyRequests({ message: e.message, code: e.code })),
            }),
          );
          return { status: true };
        }),
      )
      .handle("signInEmailOtp", ({ payload }) =>
        Effect.gen(function* () {
          const emailOtp = yield* resolveEmailOtp;
          const result = yield* emailOtp.service.signIn(payload.email, payload.otp).pipe(
            Effect.catchTags({
              EmailOtpError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
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
          return yield* withSessionCookie(body, result.session, cfg, "email-otp");
        }),
      )
      .handle("signInAnonymous", () =>
        Effect.gen(function* () {
          const anonymous = yield* resolveAnonymous;
          const result = yield* anonymous.service.signInAnonymous().pipe(
            Effect.catchTags({
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
          return yield* withSessionCookie(body, result.session, cfg, "anonymous");
        }),
      )
      .handle("signInUsername", ({ payload }) =>
        Effect.gen(function* () {
          const username = yield* resolveUsername;
          const result = yield* username.service
            .signIn({
              username: payload.username,
              password: payload.password,
              ...(payload.rememberMe !== undefined && { rememberMe: payload.rememberMe }),
            })
            .pipe(
              Effect.catchTags({
                UsernameError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.Unauthorized({ message: e.message })),
                EmailNotVerifiedError: (e) =>
                  Effect.fail(new S.Unauthorized({ message: e.message })),
                HashingError: (e) => internalServerError(e),
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
            ...(result.secondFactor !== undefined && { secondFactor: result.secondFactor }),
          };
          return yield* withSessionCookie(body, result.session, cfg, "username", result.rememberMe);
        }),
      )
      .handle("multiSessionList", ({ request }) =>
        Effect.gen(function* () {
          if (cfg.multiSession === undefined) {
            return yield* new S.NotFound({ message: "Multi-session is not enabled" });
          }
          const sessionManager = yield* SessionService;
          const active = sessionIdFromRequest(request, cfg);
          const ids = new Set(readDeviceSessionIds(request, cfg));
          if (active !== undefined) ids.add(active);

          const views: S.SessionWithUserView[] = [];
          for (const id of ids) {
            const resolved = yield* sessionManager
              .validateSession(id)
              .pipe(Effect.catch(() => Effect.succeed(null)));
            if (resolved !== null) views.push(yield* encodeSessionWithUserView(resolved));
          }
          return views;
        }),
      )
      .handle("multiSessionSetActive", ({ payload, request }) =>
        Effect.gen(function* () {
          if (cfg.multiSession === undefined) {
            return yield* new S.NotFound({ message: "Multi-session is not enabled" });
          }
          if (!readDeviceSessionIds(request, cfg).includes(payload.sessionId)) {
            return yield* new S.BadRequest({ message: "Session is not on this device" });
          }
          const sessionManager = yield* SessionService;
          const resolved = yield* sessionManager
            .validateSession(payload.sessionId)
            .pipe(
              Effect.mapError(() => new S.BadRequest({ message: "Invalid or expired session" })),
            );
          return yield* HttpServerResponse.json({ status: true }).pipe(
            Effect.flatMap((response) =>
              HttpServerResponse.setCookie(
                response,
                cfg.name,
                resolved.session.id,
                sessionCookieOptions(cfg, resolved.session.expiresAt),
              ),
            ),
            Effect.flatMap((response) =>
              cfg.cache !== undefined
                ? HttpServerResponse.setCookie(
                    response,
                    dataCookieName(cfg),
                    "",
                    clearCookieOptions(cfg),
                  )
                : Effect.succeed(response),
            ),
            Effect.orDie,
          );
        }),
      )
      .handle("multiSessionRevoke", ({ payload, request }) =>
        Effect.gen(function* () {
          if (cfg.multiSession === undefined) {
            return yield* new S.NotFound({ message: "Multi-session is not enabled" });
          }
          const sessionManager = yield* SessionService;
          yield* sessionManager
            .invalidateSession(payload.sessionId)
            .pipe(Effect.catch(internalServerError));

          const remaining = readDeviceSessionIds(request, cfg).filter(
            (id) => id !== payload.sessionId,
          );
          const farFuture = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
          const wasActive = sessionIdFromRequest(request, cfg) === payload.sessionId;
          return yield* Effect.gen(function* () {
            let response = yield* HttpServerResponse.json({ status: true });
            response = yield* HttpServerResponse.setCookie(
              response,
              multiCookieName(cfg),
              remaining.join("."),
              sessionCookieOptions(cfg, farFuture),
            );
            if (wasActive) {
              response = yield* HttpServerResponse.setCookie(
                response,
                cfg.name,
                "",
                clearCookieOptions(cfg),
              );
              if (cfg.cache !== undefined) {
                response = yield* HttpServerResponse.setCookie(
                  response,
                  dataCookieName(cfg),
                  "",
                  clearCookieOptions(cfg),
                );
              }
            }
            return response;
          }).pipe(Effect.orDie);
        }),
      )
      .handle("deviceCode", ({ payload }) =>
        Effect.gen(function* () {
          const device = yield* resolveDevice;
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
          return yield* withSessionCookie(body, result.session, cfg, "device");
        }),
      )
      .handle("deviceApprove", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const device = yield* resolveDevice;
          // Rate-limit user_code attempts per RFC 8628 §5.2 to prevent
          // enumeration of pending codes (approve is session-gated, but
          // still benefits from per-code throttling).
          yield* applyUserCodeRateLimit(payload.userCode);
          yield* device.service.approve(payload.userCode, resolved.user.id).pipe(
            Effect.catchTags({
              DeviceCodeError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { status: true };
        }),
      )
      .handle("deviceDeny", ({ payload }) =>
        Effect.gen(function* () {
          const device = yield* resolveDevice;
          // Rate-limit unauthenticated deny attempts per RFC 8628 §5.2.
          // User codes are ~39 bits; without throttling an attacker can grief
          // pending codes at scale.
          yield* applyUserCodeRateLimit(payload.userCode);
          yield* device.service.deny(payload.userCode).pipe(
            Effect.catchTags({
              DeviceCodeError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { status: true };
        }),
      )
      .handle("phoneOtpSend", ({ payload }) =>
        Effect.gen(function* () {
          const phoneOtp = yield* resolvePhoneOtp;
          yield* phoneOtp.service.send(payload.phoneNumber, payload.purpose).pipe(
            Effect.catchTags({
              // Anti-enumeration: send never signals whether the number exists.
              PhoneOtpError: (e) => internalServerError(e),
              AuthError: (e) => internalServerError(e),
              ResendTooSoonError: (e) =>
                Effect.fail(new S.TooManyRequests({ message: e.message, code: e.code })),
            }),
          );
          return { status: true };
        }),
      )
      .handle("signInPhoneOtp", ({ payload }) =>
        Effect.gen(function* () {
          const phoneOtp = yield* resolvePhoneOtp;
          const result = yield* phoneOtp.service.signIn(payload.phoneNumber, payload.otp).pipe(
            Effect.catchTags({
              PhoneOtpError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
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
          return yield* withSessionCookie(body, result.session, cfg, "phone-otp");
        }),
      )
      .handle("multiFactorEnable", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const multiFactor = yield* resolveMultiFactor;
          return yield* multiFactor.service.enable(resolved.user.id, payload.password).pipe(
            Effect.catchTags({
              InvalidCredentialsError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              MultiFactorError: (e) => internalServerError(e),
              UserNotFoundError: (e) => internalServerError(e),
              HashingError: (e) => internalServerError(e),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }),
      )
      .handle("multiFactorConfirm", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const multiFactor = yield* resolveMultiFactor;
          yield* multiFactor.service.confirmEnable(resolved.user.id, payload.code).pipe(
            Effect.catchTags({
              MultiFactorError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              HashingError: (e) => internalServerError(e),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { status: true };
        }),
      )
      .handle("multiFactorDisable", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const multiFactor = yield* resolveMultiFactor;
          yield* multiFactor.service.disable(resolved.user.id, payload.password).pipe(
            Effect.catchTags({
              InvalidCredentialsError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              HashingError: (e) => internalServerError(e),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { status: true };
        }),
      )
      .handle("multiFactorRegenerateBackupCodes", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const multiFactor = yield* resolveMultiFactor;
          const backupCodes = yield* multiFactor.service
            .regenerateBackupCodes(resolved.user.id, payload.password)
            .pipe(
              Effect.catchTags({
                MultiFactorError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.BadRequest({ message: e.message })),
                HashingError: (e) => internalServerError(e),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { backupCodes };
        }),
      )
      .handle("multiFactorVerifyTotp", ({ payload }) =>
        Effect.gen(function* () {
          const multiFactor = yield* resolveMultiFactor;
          const result = yield* multiFactor.service.verifyTotp(payload.token, payload.code).pipe(
            Effect.catchTags({
              MultiFactorError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
              HashingError: (e) => internalServerError(e),
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
          return yield* secondFactorSuccess(result, cfg, "multi-factor");
        }),
      )
      .handle("multiFactorVerifyBackupCode", ({ payload }) =>
        Effect.gen(function* () {
          const multiFactor = yield* resolveMultiFactor;
          const result = yield* multiFactor.service
            .verifyBackupCode(payload.token, payload.code)
            .pipe(
              Effect.catchTags({
                MultiFactorError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
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
          return yield* secondFactorSuccess(result, cfg, "multi-factor");
        }),
      )
      // --- Organization -----------------------------------------------------
      .handle("orgCreate", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const created = yield* org.service
            .createOrganization(resolved.user.id, {
              name: payload.name,
              slug: payload.slug,
              ...(payload.logo !== undefined && { logo: payload.logo }),
              ...(payload.metadata !== undefined && { metadata: payload.metadata }),
            })
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeOrganization(created);
        }),
      )
      .handle("orgList", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const orgs = yield* org.service.listOrganizations(resolved.user.id).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
            }),
          );
          return orgs.map(encodeOrganization);
        }),
      )
      .handle("orgGet", ({ params, request }) =>
        Effect.gen(function* () {
          yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const full = yield* org.service.getFullOrganization(params.organizationId).pipe(
            Effect.catchTags({
              OrganizationError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return encodeFullOrganization(full);
        }),
      )
      .handle("orgUpdate", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const updated = yield* org.service
            .updateOrganization(resolved.user.id, params.organizationId, {
              ...(payload.name !== undefined && { name: payload.name }),
              ...(payload.slug !== undefined && { slug: payload.slug }),
              ...(payload.logo !== undefined && { logo: payload.logo }),
              ...(payload.metadata !== undefined && { metadata: payload.metadata }),
            })
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeOrganization(updated);
        }),
      )
      .handle("orgDelete", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          yield* org.service.deleteOrganization(resolved.user.id, params.organizationId).pipe(
            Effect.catchTags({
              OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }),
      )
      .handle("orgSetActive", ({ payload, request }) =>
        Effect.gen(function* () {
          yield* resolveOrganization; // 404 when organizations are not enabled
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionService;
          yield* sessionManager
            .setSessionAttributes(resolved.session.id, {
              activeOrganizationId: payload.organizationId,
            })
            .pipe(
              Effect.catchTags({
                SessionNotFoundError: (e) => internalServerError(e),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { status: true };
        }),
      )
      .handle("orgInvite", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const invitation = yield* org.service
            .inviteMember(resolved.user.id, params.organizationId, {
              email: payload.email,
              role: payload.role,
            })
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeInvitation(invitation);
        }),
      )
      .handle("orgListInvitations", ({ params, request }) =>
        Effect.gen(function* () {
          yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const invitations = yield* org.service.listInvitations(params.organizationId).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
            }),
          );
          return invitations.map(encodeInvitation);
        }),
      )
      .handle("orgAcceptInvitation", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const member = yield* org.service
            .acceptInvitation(resolved.user.id, params.invitationId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeMember(member);
        }),
      )
      .handle("orgRejectInvitation", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const invitation = yield* org.service
            .rejectInvitation(resolved.user.id, params.invitationId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeInvitation(invitation);
        }),
      )
      .handle("orgCancelInvitation", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const invitation = yield* org.service
            .cancelInvitation(resolved.user.id, params.invitationId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeInvitation(invitation);
        }),
      )
      .handle("orgResendInvitation", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const invitation = yield* org.service
            .resendInvitation(resolved.user.id, params.invitationId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeInvitation(invitation);
        }),
      )
      .handle("orgAddMember", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const member = yield* org.service
            .addMember(resolved.user.id, params.organizationId, payload.userId, payload.role)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeMember(member);
        }),
      )
      .handle("orgUpdateMemberRole", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const member = yield* org.service
            .updateMemberRole(resolved.user.id, params.organizationId, payload.userId, payload.role)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeMember(member);
        }),
      )
      .handle("orgRemoveMember", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          yield* org.service
            .removeMember(resolved.user.id, params.organizationId, params.userId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
        }),
      )
      .handle("orgDeactivateMember", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const member = yield* org.service
            .deactivateMember(resolved.user.id, params.organizationId, params.userId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeMember(member);
        }),
      )
      .handle("orgReactivateMember", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const member = yield* org.service
            .reactivateMember(resolved.user.id, params.organizationId, params.userId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeMember(member);
        }),
      )
      .handle("orgSetDefaultRole", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const organization = yield* org.service
            .setDefaultRole(resolved.user.id, params.organizationId, payload.role)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeOrganization(organization);
        }),
      )
      // --- Organization domains ----------------------------------------------
      .handle("orgListDomains", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const domains = yield* org.service
            .listDomains(resolved.user.id, params.organizationId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return domains.map(encodeOrganizationDomain);
        }),
      )
      .handle("orgAddDomain", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const domain = yield* org.service
            .addDomain(resolved.user.id, params.organizationId, {
              domain: payload.domain,
              ...(payload.verificationStrategy !== undefined && {
                verificationStrategy: payload.verificationStrategy,
              }),
            })
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeOrganizationDomain(domain);
        }),
      )
      .handle("orgRemoveDomain", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          yield* org.service
            .removeDomain(resolved.user.id, params.organizationId, params.domainId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
        }),
      )
      .handle("orgVerifyDomain", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const domain = yield* org.service
            .verifyDomain(resolved.user.id, params.organizationId, params.domainId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeOrganizationDomain(domain);
        }),
      )
      // --- Organization roles (dynamic access control) -----------------------
      .handle("orgUpsertRole", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const orgRole = yield* org.service
            .upsertOrgRole(resolved.user.id, params.organizationId, {
              role: params.role,
              permissions: payload.permissions,
            })
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeOrgRole(orgRole);
        }),
      )
      .handle("orgListRoles", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const orgRoles = yield* org.service
            .listOrgRoles(resolved.user.id, params.organizationId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return orgRoles.map(encodeOrgRole);
        }),
      )
      .handle("orgDeleteRole", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          yield* org.service
            .deleteOrgRole(resolved.user.id, params.organizationId, params.role)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
        }),
      )
      // --- Organization teams -----------------------------------------------
      .handle("orgCreateTeam", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const team = yield* org.service
            .createTeam(resolved.user.id, params.organizationId, { name: payload.name })
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeTeam(team);
        }),
      )
      .handle("orgListTeams", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const teams = yield* org.service.listTeams(resolved.user.id, params.organizationId).pipe(
            Effect.catchTags({
              OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return teams.map(encodeTeam);
        }),
      )
      .handle("orgListTeamsForMember", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const teams = yield* org.service
            .listTeamsForMember(resolved.user.id, params.organizationId, params.userId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return teams.map(encodeTeam);
        }),
      )
      .handle("orgUpdateTeam", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const team = yield* org.service
            .updateTeam(resolved.user.id, params.teamId, {
              ...(payload.name !== undefined && { name: payload.name }),
            })
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeTeam(team);
        }),
      )
      .handle("orgDeleteTeam", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          yield* org.service.deleteTeam(resolved.user.id, params.teamId).pipe(
            Effect.catchTags({
              OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }),
      )
      .handle("orgAddTeamMember", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const member = yield* org.service
            .addTeamMember(resolved.user.id, params.teamId, payload.userId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeTeamMember(member);
        }),
      )
      .handle("orgListTeamMembers", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          const teamMembers = yield* org.service
            .listTeamMembers(resolved.user.id, params.teamId)
            .pipe(
              Effect.catchTags({
                OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return teamMembers.map(encodeTeamMember);
        }),
      )
      .handle("orgRemoveTeamMember", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const org = yield* resolveOrganization;
          yield* org.service.removeTeamMember(resolved.user.id, params.teamId, params.userId).pipe(
            Effect.catchTags({
              OrganizationError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }),
      )
      // --- Admin ------------------------------------------------------------
      .handle("adminListUsers", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          const result = yield* admin.service
            .listUsers(resolved.user, {
              ...(payload.limit !== undefined && { limit: payload.limit }),
              ...(payload.offset !== undefined && { offset: payload.offset }),
              ...(payload.searchEmail !== undefined && { searchEmail: payload.searchEmail }),
            })
            .pipe(
              Effect.catchTags({
                AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          const users = yield* Effect.forEach(result.users, encodeUserView);
          return { users, total: result.total };
        }),
      )
      .handle("adminSetRole", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          const user = yield* admin.service
            .setRole(resolved.user, payload.userId, payload.role)
            .pipe(
              Effect.catchTags({
                AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return yield* encodeUserView(user);
        }),
      )
      .handle("adminBanUser", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          const user = yield* admin.service
            .banUser(resolved.user, payload.userId, {
              ...(payload.reason !== undefined && { reason: payload.reason }),
              ...(payload.expiresIn !== undefined && { expiresIn: payload.expiresIn }),
            })
            .pipe(
              Effect.catchTags({
                AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
                UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return yield* encodeUserView(user);
        }),
      )
      .handle("adminUnbanUser", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          const user = yield* admin.service.unbanUser(resolved.user, payload.userId).pipe(
            Effect.catchTags({
              AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return yield* encodeUserView(user);
        }),
      )
      .handle("adminRemoveUser", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          yield* admin.service.removeUser(resolved.user, payload.userId).pipe(
            Effect.catchTags({
              AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }),
      )
      .handle("adminRevokeSessions", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          yield* admin.service.revokeUserSessions(resolved.user, payload.userId).pipe(
            Effect.catchTags({
              AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { status: true };
        }),
      )
      .handle("adminImpersonate", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const admin = yield* resolveAdmin;
          const userService = yield* UserService;
          const session = yield* admin.service.impersonateUser(resolved.user, payload.userId).pipe(
            Effect.catchTags({
              AdminError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
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
          const user = yield* userService
            .getUser(session.userId)
            .pipe(Effect.catch(internalServerError));
          const body: S.AuthSuccess = {
            user: yield* encodeUserView(user),
            needsEmailVerification: false,
          };
          return yield* withSessionCookie(body, session, cfg);
        }),
      )
      .handle("adminStopImpersonating", ({ request }) =>
        Effect.gen(function* () {
          yield* resolveAdmin; // 404 when admin is not enabled
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionService;
          yield* sessionManager
            .invalidateSession(resolved.session.id)
            .pipe(Effect.catch(internalServerError));
          return yield* HttpServerResponse.json({ status: true }).pipe(
            Effect.flatMap((response) =>
              HttpServerResponse.setCookie(response, cfg.name, "", clearCookieOptions(cfg)),
            ),
            Effect.flatMap((response) =>
              cfg.cache !== undefined
                ? HttpServerResponse.setCookie(
                    response,
                    dataCookieName(cfg),
                    "",
                    clearCookieOptions(cfg),
                  )
                : Effect.succeed(response),
            ),
            Effect.orDie,
          );
        }),
      )
      // --- API keys ---------------------------------------------------------
      .handle("apiKeyCreate", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          yield* requireInteractiveCredential(request);
          const apiKey = yield* resolveApiKey;
          const result = yield* apiKey.service
            .create(resolved.user.id, {
              ...(payload.name !== undefined && { name: payload.name }),
              ...(payload.prefix !== undefined && { prefix: payload.prefix }),
              ...(payload.expiresIn !== undefined && { expiresIn: payload.expiresIn }),
              ...(payload.permissions !== undefined && { permissions: payload.permissions }),
              ...(payload.metadata !== undefined && { metadata: payload.metadata }),
              ...(payload.remaining !== undefined && { remaining: payload.remaining }),
              ...(payload.rateLimit !== undefined && { rateLimit: payload.rateLimit }),
            })
            .pipe(
              Effect.catchTags({
                ApiKeyError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { key: result.key, apiKey: encodeApiKey(result.apiKey) };
        }),
      )
      .handle("apiKeyList", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const apiKey = yield* resolveApiKey;
          const keys = yield* apiKey.service.list(resolved.user.id).pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
            }),
          );
          return keys.map(encodeApiKey);
        }),
      )
      .handle("apiKeyUpdate", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const apiKey = yield* resolveApiKey;
          const updated = yield* apiKey.service
            .update(resolved.user.id, params.keyId, {
              ...(payload.name !== undefined && { name: payload.name }),
              ...(payload.enabled !== undefined && { enabled: payload.enabled }),
              ...(payload.expiresAt !== undefined && { expiresAt: payload.expiresAt }),
              ...(payload.permissions !== undefined && { permissions: payload.permissions }),
              ...(payload.metadata !== undefined && { metadata: payload.metadata }),
              ...(payload.remaining !== undefined && { remaining: payload.remaining }),
              ...(payload.rateLimit !== undefined && { rateLimit: payload.rateLimit }),
            })
            .pipe(
              Effect.catchTags({
                ApiKeyError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeApiKey(updated);
        }),
      )
      .handle("apiKeyDelete", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const apiKey = yield* resolveApiKey;
          yield* apiKey.service.delete(resolved.user.id, params.keyId).pipe(
            Effect.catchTags({
              ApiKeyError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }),
      )
      // --- Enterprise SSO ---------------------------------------------------
      .handle("ssoRegister", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          if (!isAdmin(resolved.user)) {
            return yield* new S.Forbidden({ message: "Admin privileges required" });
          }
          const sso = yield* resolveSso;
          // The payload is a union discriminated on `protocol`; a body without
          // one is an OIDC registration (what every pre-SAML client sends).
          if (payload.protocol === "saml") {
            const samlProvider = yield* sso.service
              .registerSamlProvider(resolved.user.id, {
                protocol: "saml",
                domain: payload.domain,
                entityId: payload.entityId,
                ssoUrl: payload.ssoUrl,
                idpCertificates: payload.idpCertificates,
                spEntityId: payload.spEntityId,
                acsUrl: payload.acsUrl,
                ...(payload.signatureAlgorithms !== undefined && {
                  signatureAlgorithms: payload.signatureAlgorithms,
                }),
                ...(payload.wantAssertionsSigned !== undefined && {
                  wantAssertionsSigned: payload.wantAssertionsSigned,
                }),
                ...(payload.wantAuthnResponseSigned !== undefined && {
                  wantAuthnResponseSigned: payload.wantAuthnResponseSigned,
                }),
                ...(payload.forceAuthn !== undefined && { forceAuthn: payload.forceAuthn }),
                ...(payload.organizationId !== undefined && {
                  organizationId: payload.organizationId,
                }),
              })
              .pipe(
                Effect.catchTags({
                  SsoError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                  AuthError: (e) => internalServerError(e),
                }),
              );
            return encodeSsoProvider(samlProvider);
          }
          const provider = yield* sso.service
            .registerProvider(resolved.user.id, {
              issuer: payload.issuer,
              domain: payload.domain,
              clientId: payload.clientId,
              clientSecret: payload.clientSecret,
              redirectUri: payload.redirectUri,
              ...(payload.discover !== undefined && { discover: payload.discover }),
              ...(payload.authorizationEndpoint !== undefined && {
                authorizationEndpoint: payload.authorizationEndpoint,
              }),
              ...(payload.tokenEndpoint !== undefined && {
                tokenEndpoint: payload.tokenEndpoint,
              }),
              ...(payload.userInfoEndpoint !== undefined && {
                userInfoEndpoint: payload.userInfoEndpoint,
              }),
              ...(payload.jwksEndpoint !== undefined && { jwksEndpoint: payload.jwksEndpoint }),
              ...(payload.scopes !== undefined && { scopes: payload.scopes }),
              ...(payload.usePKCE !== undefined && { usePKCE: payload.usePKCE }),
              ...(payload.organizationId !== undefined && {
                organizationId: payload.organizationId,
              }),
            })
            .pipe(
              Effect.catchTags({
                SsoError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeSsoProvider(provider);
        }),
      )
      .handle("signInSso", ({ payload }) =>
        Effect.gen(function* () {
          const sso = yield* resolveSso;
          const result = yield* sso.service
            .signIn({
              ...(payload.email !== undefined && { email: payload.email }),
              ...(payload.domain !== undefined && { domain: payload.domain }),
              ...(payload.providerId !== undefined && { providerId: payload.providerId }),
            })
            .pipe(
              Effect.catchTags({
                SsoError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { url: result.url, state: result.state };
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
          return yield* withSessionCookie(body, result.session, cfg, "sso");
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
          return yield* withSessionCookie(body, result.session, cfg, "sso");
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
      // --- JWT --------------------------------------------------------------
      .handle("jwtToken", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const jwt = yield* resolveJwt;
          const result = yield* jwt.service.sign(resolved.user).pipe(
            Effect.catchTags({
              JwtError: (e) => internalServerError(e),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { token: result.token, expiresAt: result.expiresAt };
        }),
      )
      .handle("jwtJwks", () =>
        Effect.gen(function* () {
          const jwt = yield* resolveJwt;
          const jwks = yield* jwt.service.getJwks().pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { keys: jwks.keys.map((k) => ({ ...k })) };
        }),
      )
      // --- OIDC provider ------------------------------------------------------
      .handle("oidcRegisterClient", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          if (!isAdmin(resolved.user)) {
            return yield* new S.Forbidden({ message: "Admin privileges required" });
          }
          const oidc = yield* resolveOidcProvider;
          const result = yield* oidc.service
            .registerClient(
              {
                name: payload.name,
                redirectUris: payload.redirectUris,
                ...(payload.type !== undefined && { type: payload.type }),
                ...(payload.skipConsent !== undefined && { skipConsent: payload.skipConsent }),
                ...(payload.metadata !== undefined && { metadata: payload.metadata }),
              },
              resolved.user.id,
            )
            .pipe(
              Effect.catchTags({
                OidcProviderError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return {
            client: encodeOidcClient(result.client),
            ...(result.clientSecret !== undefined && { clientSecret: result.clientSecret }),
          };
        }),
      )
      .handle("oidcListClients", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          if (!isAdmin(resolved.user)) {
            return yield* new S.Forbidden({ message: "Admin privileges required" });
          }
          const oidc = yield* resolveOidcProvider;
          const clients = yield* oidc.service.listClients().pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
            }),
          );
          return clients.map(encodeOidcClient);
        }),
      )
      .handle("oidcUpdateClient", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          if (!isAdmin(resolved.user)) {
            return yield* new S.Forbidden({ message: "Admin privileges required" });
          }
          const oidc = yield* resolveOidcProvider;
          const updated = yield* oidc.service
            .updateClient(params.clientId, {
              ...(payload.name !== undefined && { name: payload.name }),
              ...(payload.redirectUris !== undefined && {
                redirectUris: payload.redirectUris,
              }),
              ...(payload.skipConsent !== undefined && { skipConsent: payload.skipConsent }),
              ...(payload.disabled !== undefined && { disabled: payload.disabled }),
              ...(payload.metadata !== undefined && { metadata: payload.metadata }),
            })
            .pipe(
              Effect.catchTags({
                OidcProviderError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeOidcClient(updated);
        }),
      )
      .handle("oidcDeleteClient", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          if (!isAdmin(resolved.user)) {
            return yield* new S.Forbidden({ message: "Admin privileges required" });
          }
          const oidc = yield* resolveOidcProvider;
          yield* oidc.service.deleteClient(params.clientId).pipe(
            Effect.catchTags({
              OidcProviderError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => internalServerError(e),
            }),
          );
        }),
      )
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
            .pipe(
              Effect.catchTags({
                OidcProviderError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return HttpServerResponse.redirect(result.redirectTo, { status: 302 });
        }),
      )
      .handle("oidcConsent", ({ payload, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          const resolved = yield* requireSession(request, cfg);
          const result = yield* oidc.service
            .consent(resolved.user.id, payload.consentCode, payload.accept)
            .pipe(
              Effect.catchTags({
                OidcProviderError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => internalServerError(e),
              }),
            );
          return { redirectTo: result.redirectTo };
        }),
      )
      .handle("oidcToken", ({ payload, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          // Client authentication: a Basic Authorization header takes
          // precedence over body credentials (RFC 6749 §2.3.1).
          let clientId = payload.client_id;
          let clientSecret = payload.client_secret;
          const auth = request.headers["authorization"];
          if (auth !== undefined && auth.startsWith("Basic ")) {
            const decoded = Buffer.from(auth.slice(6), "base64").toString("utf8");
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
          const initialAccessToken = bearerToken(request);
          const result = yield* oidc.service
            .registerDynamicClient(registrationMetadata(payload), {
              ...(initialAccessToken !== undefined && { initialAccessToken }),
            })
            .pipe(
              Effect.catchTags({
                OidcRegistrationError: registrationError,
                AuthError: (e) => internalServerError(e),
              }),
            );
          const registrationEndpoint = String(
            oidc.service.getAuthorizationServerMetadata()["registration_endpoint"],
          );
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
          const client = yield* oidc.service.readDynamicClient(params.clientId, token).pipe(
            Effect.catchTags({
              OidcRegistrationError: registrationError,
              AuthError: (e) => internalServerError(e),
            }),
          );
          return encodeOidcRegistration(
            client,
            String(oidc.service.getAuthorizationServerMetadata()["registration_endpoint"]),
          );
        }),
      )
      .handle("oidcUpdateRegistration", ({ params, payload, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          const token = yield* requireRegistrationAccessToken(oidc.service, request);
          const client = yield* oidc.service
            .updateDynamicClient(params.clientId, token, registrationMetadata(payload))
            .pipe(
              Effect.catchTags({
                OidcRegistrationError: registrationError,
                AuthError: (e) => internalServerError(e),
              }),
            );
          return encodeOidcRegistration(
            client,
            String(oidc.service.getAuthorizationServerMetadata()["registration_endpoint"]),
          );
        }),
      )
      .handle("oidcDeleteRegistration", ({ params, request }) =>
        Effect.gen(function* () {
          const oidc = yield* resolveOidcProvider;
          const token = yield* requireRegistrationAccessToken(oidc.service, request);
          yield* oidc.service.deleteDynamicClient(params.clientId, token).pipe(
            Effect.catchTags({
              OidcRegistrationError: registrationError,
              AuthError: (e) => internalServerError(e),
            }),
          );
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
        Effect.gen(function* () {
          yield* resolveOidcProvider; // 404 when the OIDC provider is disabled
          const jwt = yield* resolveJwt;
          const jwks = yield* jwt.service.getJwks().pipe(
            Effect.catchTags({
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { keys: jwks.keys.map((k) => ({ ...k })) };
        }),
      )
      // --- Google One Tap -------------------------------------------------------
      .handle("getGoogleOneTapNonce", () =>
        Effect.gen(function* () {
          const oneTap = yield* resolveGoogleOneTap;
          const nonce = yield* oneTap.service.createNonce().pipe(
            Effect.catchTags({
              GoogleOneTapError: (e) => internalServerError(e),
              AuthError: (e) => internalServerError(e),
            }),
          );
          return { nonce };
        }),
      )
      .handle("signInGoogleOneTap", ({ payload }) =>
        Effect.gen(function* () {
          const oneTap = yield* resolveGoogleOneTap;
          const result = yield* oneTap.service.signIn(payload.credential, payload.nonce).pipe(
            Effect.catchTags({
              GoogleOneTapError: (e) => Effect.fail(new S.Unauthorized({ message: e.message })),
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
          return yield* withSessionCookie(body, result.session, cfg, "google");
        }),
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
const scimInternalError = (e: unknown): Effect.Effect<never, S.ScimInternalError, never> =>
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
> => {
  switch (e.status) {
    case 400:
      return Effect.fail(scimBadRequest(e.message, e.scimType));
    case 401:
      return Effect.fail(scimUnauthorized(e.message));
    case 404:
      return Effect.fail(scimNotFound(e.message));
    case 409:
      return Effect.fail(scimConflict(e.message));
    default:
      return scimInternalError(e);
  }
};

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
const requireScim = (request: HttpServerRequest.HttpServerRequest) =>
  Effect.gen(function* () {
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
const requireScimService = Effect.gen(function* () {
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
  created: new Date(createdAt).toISOString(),
  lastModified: new Date(updatedAt).toISOString(),
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
  return parts.length === 0 ? undefined : parts.join(" ");
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
        Effect.map(requireScimService, (service) =>
          scimServiceProviderConfig(service.baseUrl, service.maxPageSize),
        ),
      )
      .handle("scimResourceTypes", () =>
        Effect.map(requireScimService, (service) => scimResourceTypes(service.baseUrl)),
      )
      .handle("scimSchemas", () =>
        Effect.map(requireScimService, (service) => scimSchemas(service.baseUrl)),
      ),
  );

/**
 * Encode a user for the wire with the derived `email`/`emailVerified`
 * convenience fields resolved from the identifier store. Enrichment is
 * fail-soft: when the identifier lookup errors the fields are simply omitted
 * (with a warning) rather than failing a flow that already succeeded.
 */
const encodeUserView = (user: Types.User): Effect.Effect<S.UserView, never, IdentifierStore> =>
  Effect.gen(function* () {
    const identifiers = yield* IdentifierStore;
    const list = yield* identifiers
      .listByUser(user.id)
      .pipe(
        Effect.catchTag("AuthError", (error) =>
          Effect.logWarning("Failed to resolve identifiers for user view", { error }).pipe(
            Effect.as<ReadonlyArray<Identifier>>([]),
          ),
        ),
      );
    return S.encodeUser(user, list);
  });

/** {@link encodeUserView} over a session+user pair. */
const encodeSessionWithUserView = (
  resolved: Types.SessionWithUser,
): Effect.Effect<S.SessionWithUserView, never, IdentifierStore> =>
  Effect.map(encodeUserView(resolved.user), (user) => ({
    session: S.encodeSession(resolved.session),
    user,
  }));

/**
 * Build the `AuthSuccess` response (with session cookie) for a redeemed
 * second-factor challenge. The multi-factor service returns only `userId` +
 * `session`, so the full user is fetched through the core `UserService`.
 */
const secondFactorSuccess = (
  result: { readonly userId: string; readonly session: Types.Session },
  cfg: ResolvedCookieConfig,
  method?: string,
) =>
  Effect.gen(function* () {
    const userService = yield* UserService;
    const user = yield* userService.getUser(result.userId).pipe(Effect.catch(internalServerError));
    const body: S.AuthSuccess = {
      user: yield* encodeUserView(user),
      needsEmailVerification: false,
    };
    return yield* withSessionCookie(body, result.session, cfg, method);
  });

/** Resolve and validate the request's session or fail with 401. */
/**
 * Resolve the authenticated session, preferring the signed cache cookie (no
 * store read) when the cache is enabled and the cookie is valid; otherwise
 * validating against the session store. `cacheHit` lets callers decide whether
 * to (re)issue the cache cookie.
 */
const resolveSession = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): Effect.Effect<
  { readonly resolved: Types.SessionWithUser; readonly cacheHit: boolean },
  S.Unauthorized,
  SessionService | Hooks
> =>
  Effect.gen(function* () {
    if (cfg.cache !== undefined) {
      const primaryId = sessionIdFromRequest(request, cfg);
      if (primaryId !== undefined) {
        const cached = request.cookies[dataCookieName(cfg)];
        if (cached !== undefined) {
          const resolved = decodeSessionCacheCookie(cached, cfg.cache, Date.now(), primaryId);
          if (resolved !== null) return { resolved, cacheHit: true };
        }
      }
    }
    const sessionId = sessionIdFromRequest(request, cfg);
    if (sessionId === undefined) {
      return yield* new S.Unauthorized({ message: "Not authenticated" });
    }
    const sessionManager = yield* SessionService;
    const resolved = yield* sessionManager.validateSession(sessionId).pipe(
      Effect.catchTag("UserBannedError", (e) =>
        resolveMessage(e.code, e.message).pipe(
          Effect.flatMap((msg) => Effect.fail(new S.Unauthorized({ message: msg, code: e.code }))),
        ),
      ),
      Effect.mapError(() => new S.Unauthorized({ message: "Invalid or expired session" })),
    );
    return { resolved, cacheHit: false };
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
 * Attach the session cookie to a JSON `AuthSuccess` response when a session is
 * present. When the last-login-method hint is enabled and `method` is given,
 * also (re)writes the non-httpOnly `${name}_last_method` cookie.
 *
 * When `rememberMe` is `false`, a browser-session cookie is emitted (no
 * `Max-Age`/`Expires`) so the cookie is cleared when the browser closes.
 * The server-side session lifetime is unchanged; orphaned sessions expire via
 * the normal idle/absolute-lifetime checks.
 */
const withSessionCookie = (
  body: S.AuthSuccess,
  session: Types.Session | undefined,
  cfg: ResolvedCookieConfig,
  method?: string,
  rememberMe?: boolean,
) =>
  Effect.gen(function* () {
    const json = yield* HttpServerResponse.json(body);
    if (session === undefined) return json;
    const cookieOpts =
      rememberMe === false
        ? sessionOnlyCookieOptions(cfg)
        : sessionCookieOptions(cfg, session.expiresAt);
    let response = yield* HttpServerResponse.setCookie(json, cfg.name, session.id, cookieOpts);
    // Multi-session: append the new session to the device's session list (the
    // primary cookie remains the active session), capped to `maximumSessions`.
    if (cfg.multiSession !== undefined) {
      const request = yield* HttpServerRequest.HttpServerRequest;
      const existing = readDeviceSessionIds(request, cfg).filter((id) => id !== session.id);
      const ids = [...existing, session.id].slice(-cfg.multiSession.maximumSessions);
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
        response = HttpServerResponse.setHeader(response, "set-auth-token", session.id);
      }
    }
    return response;
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
 * `path` is matched against the request pathname (exact string or regex).
 * `methods` limits the rule to specific HTTP methods (default: all methods).
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

/**
 * Sane default IP rate-limit rules applied to sensitive auth endpoints.
 *
 * | Endpoint(s)                            | Limit            | Window   | Block    |
 * |----------------------------------------|------------------|----------|----------|
 * | `/sign-in`, `/sign-in/*`               | 10 req           | 15 min   | 30 min   |
 * | `/sign-up`                             | 5 req            | 1 hr     | 24 hr    |
 * | `/magic-link/send`, `/email-otp/send`  | 5 req            | 10 min   | 30 min   |
 * | `/phone-otp/send`                      | 5 req            | 10 min   | 30 min   |
 * | `/password-reset/request`              | 5 req            | 1 hr     | 2 hr     |
 * | `/multi-factor/verify-*`                 | 10 req           | 5 min    | 30 min   |
 * | `/register` (dynamic client registration) | 10 req          | 1 hr     | 1 hr     |
 */
export const defaultEndpointRules: ReadonlyArray<EndpointRateLimitRule> = [
  {
    path: /^\/sign-in(\/.*)?$/,
    methods: ["POST"],
    maxRequests: 10,
    windowMs: 15 * 60 * 1000,
    blockDurationMs: 30 * 60 * 1000,
  },
  {
    path: "/sign-up",
    methods: ["POST"],
    maxRequests: 5,
    windowMs: 60 * 60 * 1000,
    blockDurationMs: 24 * 60 * 60 * 1000,
  },
  {
    path: /^\/(magic-link|email-otp|phone-otp)\/send$/,
    methods: ["POST"],
    maxRequests: 5,
    windowMs: 10 * 60 * 1000,
    blockDurationMs: 30 * 60 * 1000,
  },
  {
    path: "/password-reset/request",
    methods: ["POST"],
    maxRequests: 5,
    windowMs: 60 * 60 * 1000,
    blockDurationMs: 2 * 60 * 60 * 1000,
  },
  {
    path: /^\/multi-factor\/verify-/,
    methods: ["POST"],
    maxRequests: 10,
    windowMs: 5 * 60 * 1000,
    blockDurationMs: 30 * 60 * 1000,
  },
  // RFC 7591 dynamic client registration is open to anonymous callers.
  {
    path: "/register",
    methods: ["POST"],
    maxRequests: 10,
    windowMs: 60 * 60 * 1000,
    blockDurationMs: 60 * 60 * 1000,
  },
];

const matchesEndpointRule = (
  rule: EndpointRateLimitRule,
  pathname: string,
  method: string,
): boolean => {
  if (rule.methods !== undefined && !rule.methods.includes(method.toUpperCase())) return false;
  return typeof rule.path === "string" ? rule.path === pathname : rule.path.test(pathname);
};

const findEndpointRule = (
  rules: ReadonlyArray<EndpointRateLimitRule>,
  pathname: string,
  method: string,
): EndpointRateLimitRule | undefined => rules.find((r) => matchesEndpointRule(r, pathname, method));

// The class lives in Errors.ts, shared with the OIDC layer (#388); its TSDoc
// says when each of them raises it.
export { ClientAddressConfigError } from "../Errors.ts";

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
   * active session is the primary cookie. See the `/multi-session/*` endpoints.
   */
  readonly multiSession?: MultiSessionConfig;
  /**
   * Mount path prefix to strip before routing, e.g. `"/api/auth"`. When set, a
   * request to `/api/auth/sign-in` is routed to the `/sign-in` endpoint.
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
   *
   * Note: `GET /token` (JWT issuance) is treated as state-changing and
   * therefore also subject to this check.
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
   * with this option set the address comes only from the forwarded data. When
   * that data is absent or unusable, the request has no client address: when a
   * `RateLimiter` is in `services`, a request that reaches a rate-limited
   * endpoint is then refused with `429` (see {@link ipRateLimit}), and
   * `ClientIP` carries `undefined`.
   */
  readonly trustedProxy?: TrustedProxyConfig | undefined;
  /**
   * Enable IP-keyed rate limiting at the HTTP boundary, before handlers run.
   *
   * Requires `RateLimiter` in the `services` layer (compose it with its
   * store via `RateLimiter.layer().pipe(Layer.provide(rateLimitStoreLayer))`).
   * Requests that exceed a limit receive HTTP 429 before any auth logic runs.
   *
   * **Client address required**: the limiter keys each request by its client
   * address, so `make` throws {@link ClientAddressConfigError} when this is set
   * with neither {@link trustedProxy} nor {@link allowMissingClientIp}. A Web
   * `Request` has no socket address to fall back on.
   *
   * When a `RateLimiter` is in `services`, a request to a rate-limited endpoint
   * that resolves no address is refused with `429` and is not counted. It is
   * never let through unlimited and never counted under a bucket shared with
   * other callers. Requests to endpoints with no rule are unaffected.
   *
   * Set to `{}` to use the built-in {@link defaultEndpointRules}, or supply
   * `{ rules: [...] }` for a custom rule set.
   */
  readonly ipRateLimit?: HttpIPRateLimitConfig | undefined;
  /**
   * Accept that a request may have no resolvable client address, so
   * {@link ipRateLimit} can be configured without {@link trustedProxy}. Default
   * `false`.
   *
   * This opts out of the build-time check only. The limiter still runs: when a
   * `RateLimiter` is in `services`, a request with no address that reaches a
   * rate-limited endpoint is refused with `429`, not skipped. Use it when that
   * refusal is the intended behaviour for address-less requests, and prefer
   * {@link trustedProxy}, which gives every request an address when the edge
   * provides one.
   *
   * The dynamic client registration limit (`POST /register`) is configured on
   * the OIDC provider, not here, so `make` cannot check it at build. When a
   * `RateLimiter` is in `services`, a request with no address that reaches it is
   * refused with `429` whatever this option says, and is never counted under a
   * shared bucket.
   */
  readonly allowMissingClientIp?: boolean | undefined;
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
  new Response(JSON.stringify(getOpenApiSpec()), {
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
 * Returns `true` when the request may proceed.
 *
 * @param inner - The path relative to the mount prefix (e.g. `/sign-in`), or
 *   `null` when the request is outside the prefix.  Used to detect `GET /token`
 *   which issues a JWT and must be treated as state-changing.
 */
const isTrustedRequest = (
  request: Request,
  trustedOrigins: ReadonlyArray<string>,
  inner: string | null,
): boolean => {
  const method = request.method.toUpperCase();

  // GET /token issues a signed JWT — treat as state-changing so it is subject
  // to the same origin check as POST requests.
  const isStateSafe =
    (method === "GET" || method === "HEAD" || method === "OPTIONS") && inner !== "/token";
  if (isStateSafe) return true;

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
  try {
    const refererOrigin = new URL(referer).origin;
    const requestOrigin = new URL(request.url).origin;
    return refererOrigin === requestOrigin || trustedOrigins.includes(refererOrigin);
  } catch {
    // Malformed Referer — reject to be safe.
    return false;
  }
};

/**
 * Build a standard Web `Request => Response` handler for the auth API.
 *
 * Mount the returned `handler` in any framework (SvelteKit/Next/Hono/...).
 * `dispose` releases the handler's scope.
 */
export const make = (
  options: AuthWebHandlerOptions,
): {
  readonly handler: (request: Request, context?: Context.Context<never>) => Promise<Response>;
  readonly dispose: () => Promise<void>;
} => {
  // Startup check (#358): a rate limit keyed by client address needs an address
  // source. A Web Request has no socket address, so `trustedProxy` (or an explicit
  // opt-out) must be configured. Without one, fail here, not per request.
  if (
    options.ipRateLimit !== undefined &&
    options.trustedProxy === undefined &&
    options.allowMissingClientIp !== true
  ) {
    throw new ClientAddressConfigError({
      message:
        "ipRateLimit needs a client address, and a Web Request has none under Http.make. " +
        "Set trustedProxy (for example ClientIP.cloudflare) to key the limit by the visitor's address, " +
        "or set allowMissingClientIp: true to accept that address-less requests on rate-limited endpoints are refused.",
    });
  }
  const apiLayer = HttpApiBuilder.layer(AuthApi).pipe(
    Layer.provide(authGroupLayer(options.cookie, options.multiSession)),
    // The SCIM group is always mounted; its handlers resolve `ScimService`
    // optionally and answer 404 when provisioning is not configured.
    Layer.provide(scimGroupLayer()),
    Layer.provide(PlatformLayer),
  );
  // The handlers' service requirements are tracked as phantom
  // `Request<"Requires", RIn>` types; providing `services` to the layer's OUTPUT
  // (provideMerge) both satisfies them at runtime and zeroes the web handler's
  // leftover context (HR), yielding a plain `(request) => Promise<Response>`.
  const appLayer = apiLayer.pipe(Layer.provideMerge(options.services));

  const ipRateRules = options.ipRateLimit?.rules ?? defaultEndpointRules;

  const web = HttpRouter.toWebHandler(appLayer, {
    // Cast to `Effect<..., never, never>` so TypeScript infers HR = never, keeping the
    // `context` parameter of `web.handler` optional. The cast is safe: HttpServerRequest
    // and Scope are always provided by the server infrastructure before middleware runs.
    middleware: (effect) =>
      Effect.gen(function* () {
        const req = yield* HttpServerRequest.HttpServerRequest;
        const ip = resolveClientIP(req, options.trustedProxy);

        // Per-endpoint IP rate limiting (requires RateLimiter in services;
        // it resolves its own RateLimitStore at Layer-construction time)
        if (options.ipRateLimit !== undefined) {
          const url = new URL(req.url, "http://localhost");
          const rule = findEndpointRule(ipRateRules, url.pathname, req.method);
          if (rule !== undefined) {
            const rateLimiterOpt = yield* Effect.serviceOption(RateLimiter);
            if (Option.isSome(rateLimiterOpt)) {
              // No address, no key (#358): refuse rather than skip the limit or
              // count the request under a bucket that other callers share.
              if (ip === undefined) {
                return HttpServerResponse.jsonUnsafe(
                  { message: NO_CLIENT_ADDRESS },
                  { status: 429 },
                );
              }
              const limitConfig: RateLimitConfig = {
                maxRequests: rule.maxRequests,
                windowMs: rule.windowMs,
                ...(rule.blockDurationMs !== undefined && {
                  blockDurationMs: rule.blockDurationMs,
                }),
              };
              const denied = yield* rateLimiterOpt.value
                .consumeToken(`ip:${url.pathname}:${ip}`, limitConfig)
                .pipe(
                  Effect.as(null as null),
                  Effect.catchTag("RateLimitError", (e) => Effect.succeed(e)),
                  Effect.catchTag("AuthError", () => Effect.succeed(null)),
                );
              if (denied !== null) {
                return HttpServerResponse.jsonUnsafe(
                  {
                    message: "Too many requests",
                    ...(denied.retryAfter !== undefined && { retryAfter: denied.retryAfter }),
                  },
                  { status: 429 },
                );
              }
            }
          }
        }

        // Provide the resolved ClientIP to all downstream effects (hooks, handlers)
        return yield* effect.pipe(Effect.provideService(ClientIP, { ip }));
      }) as unknown as Effect.Effect<HttpServerResponse.HttpServerResponse, never, never>,
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

    if (!isTrustedRequest(request, trustedOrigins, inner)) {
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

    if (inner !== null && prefix !== "") {
      url.pathname = inner || "/";
      return web.handler(new Request(url, request), context);
    }
    return web.handler(request, context);
  };
  return { handler, dispose: web.dispose };
};
