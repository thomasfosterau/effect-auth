/**
 * Vanilla auth client for the effect-auth HTTP protocol.
 *
 * A small, dependency-free client (plain `fetch`, no Effect runtime in the
 * bundle) with methods mirroring the contract's endpoint names and an
 * observable session store that the framework binding packages subscribe to
 * (`@thomasfosterau/effect-auth-react`, `-svelte`, `-vue`).
 *
 * Only the wire *types* are imported from `effect-auth` — they erase at
 * compile time, so the browser bundle contains just this file.
 *
 * @module client
 */
import type * as Http from "@thomasfosterau/effect-auth/http";

/** A non-2xx response from the auth server. */
export class AuthClientError extends Error {
  override readonly name = "AuthClientError";
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/**
 * A pending second-factor challenge could not be continued: either the
 * authentication result carried none (`reason: "missing"`), or the challenge
 * has expired client-side before the code was submitted (`reason: "expired"`).
 *
 * The expiry check is a local courtesy — the server enforces expiry too — so a
 * UI can tell the user to sign in again without spending a round trip.
 */
export class SecondFactorChallengeError extends Error {
  override readonly name = "SecondFactorChallengeError";
  readonly reason: "missing" | "expired";

  constructor(reason: "missing" | "expired", message: string) {
    super(message);
    this.reason = reason;
  }
}

/**
 * What a sign-in, sign-up or email verification resolves with.
 *
 * `user` is present when the call issued a session. Without one, either
 * `secondFactor` is the challenge to redeem (see
 * {@link AuthClient.multiFactor}'s `continueChallenge`), or
 * `needsEmailVerification` is `true` and the address must be verified first. A
 * sign-up under the server's `antiEnumeration` mode always resolves without a
 * `user`, for a fresh address and a held one alike.
 */
export interface AuthResult {
  readonly user?: Http.UserView;
  readonly needsEmailVerification: boolean;
  readonly secondFactor?: Http.SecondFactorChallengeView;
}

/**
 * A pending second-factor challenge with the verify calls pre-bound to its
 * token. Obtained from {@link AuthClient.multiFactor}'s `continueChallenge`.
 */
export interface SecondFactorContinuation {
  /** The challenge token carried by `AuthResult.secondFactor`. */
  readonly token: string;
  /** Challenge expiry, epoch millis. */
  readonly expiresAt: number;
  /** `true` once {@link expiresAt} has passed on this device's clock. */
  readonly isExpired: () => boolean;
  /**
   * Redeem the challenge with a TOTP code. Rejects with a
   * {@link SecondFactorChallengeError} (`reason: "expired"`) without issuing a
   * request when the challenge has already expired.
   */
  readonly verifyTotp: (code: string) => Promise<AuthResult>;
  /** Redeem the challenge with a single-use backup code. */
  readonly verifyBackupCode: (code: string) => Promise<AuthResult>;
}

/** The session store's state. */
export interface SessionState {
  /** The authenticated session + user, or `null` when signed out. */
  readonly data: Http.SessionWithUserView | null;
  /** `true` while the initial fetch (or a refetch) is in flight. */
  readonly isPending: boolean;
  /** The last unexpected error (401s resolve to `data: null`, not an error). */
  readonly error: AuthClientError | null;
}

/**
 * A minimal observable holding the current session. Framework adapters
 * subscribe to it; the vanilla client refreshes it after every
 * session-changing call (sign-in/up/out, second-factor redemption, ...).
 */
export interface SessionStore {
  /** Current state (stable reference between changes). */
  readonly get: () => SessionState;
  /**
   * Subscribe to state changes. The first subscription triggers the initial
   * session fetch. Returns an unsubscribe function.
   */
  readonly subscribe: (listener: () => void) => () => void;
  /** Re-fetch the session from the server and notify subscribers. */
  readonly refetch: () => Promise<void>;
}

/** Options for opt-in background session refresh. */
export interface RefreshOptions {
  /**
   * Poll the `/session` endpoint every `intervalMs` milliseconds. The interval
   * starts when the first subscriber joins and is cancelled when the last one
   * leaves. Off by default.
   */
  readonly intervalMs?: number | undefined;
  /**
   * Refetch when the browser tab becomes visible or the window gains focus.
   * Falls back to a no-op in non-browser environments. Default: `false`.
   */
  readonly onFocus?: boolean | undefined;
  /**
   * Mirror session changes across browser tabs via `BroadcastChannel`.
   * Pass `true` for the default channel name (`"effect-auth-session"`), or a
   * string for a custom name (useful when multiple auth clients share a page).
   * Falls back to a no-op when `BroadcastChannel` is unavailable (e.g. older
   * Safari or Node.js). Default: `false`.
   */
  readonly crossTab?: boolean | string | undefined;
}

/** Options for {@link createAuthClient}: the base URL, a `fetch` override, extra headers and background refresh. */
export interface AuthClientOptions {
  /**
   * Base URL the auth handler is mounted at, e.g.
   * `"https://app.example.com/api/auth"` or `"/api/auth"` (same origin).
   */
  readonly baseUrl: string;
  /** Custom `fetch` (tests, SSR, mounting the handler in-process). */
  readonly fetch?: typeof globalThis.fetch | undefined;
  /** Extra headers attached to every request. */
  readonly headers?: Record<string, string> | undefined;
  /** Opt-in background session refresh. All features are off by default. */
  readonly refresh?: RefreshOptions | undefined;
}

/** Internals exposed to plugins during {@link AuthClientPlugin.install}. */
export interface AuthClientPluginContext {
  /** Issue a raw HTTP request to the auth server. */
  readonly request: <T>(method: string, path: string, body?: unknown) => Promise<T>;
  /** Issue a session-changing request, then refetch the session if observed. */
  readonly mutating: <T>(run: () => Promise<T>) => Promise<T>;
  /** The observable session store. */
  readonly session: SessionStore;
}

/**
 * A plugin that adds typed methods to an auth client.
 *
 * ```ts
 * const myPlugin = definePlugin((ctx) => ({
 *   myMethod: () => ctx.request<MyView>("GET", "/my-endpoint"),
 * }));
 * const client = createAuthClient({ baseUrl: "/api/auth" }).extend(myPlugin);
 * await client.myMethod();
 * ```
 */
export interface AuthClientPlugin<TExtension extends object> {
  readonly install: (context: AuthClientPluginContext) => TExtension;
}

/**
 * Create a strongly-typed plugin from an install function.
 *
 * @example
 * ```ts
 * const orgPlugin = definePlugin((ctx) => ({
 *   createOrg: (name: string) =>
 *     ctx.request("POST", "/organization/create", { name }),
 * }));
 * ```
 */
export const definePlugin = <TExtension extends object>(
  install: (context: AuthClientPluginContext) => TExtension,
): AuthClientPlugin<TExtension> => ({ install });

/**
 * `true` when the response carries a JSON body.
 *
 * Compares the *essence* of `content-type` — the media type with its
 * parameters (`; charset=utf-8`) stripped — against `application/json` and
 * against the structured `+json` suffix (`application/problem+json`,
 * `application/vnd.example+json`, ...). A substring test would wrongly accept
 * `text/plain; note=application/json` and reject `application/problem+json`.
 */
const isJson = (response: Response): boolean => {
  const [mediaType = ""] = (response.headers.get("content-type") ?? "").split(";");
  const essence = mediaType.trim().toLowerCase();
  return essence === "application/json" || essence.endsWith("+json");
};

// --- JSON:API wire shapes ------------------------------------------------------
//
// The resource groups (`sessions`, `identifiers`, `users`) answer JSON:API
// documents (#205). The client keeps its view types and maps the documents onto
// them here, so callers see the same shapes as before.

const JSON_API = "application/vnd.api+json";

interface ResourceLinkage {
  readonly type: string;
  readonly id: string;
}

interface WireResource<A> {
  readonly type: string;
  readonly id: string;
  readonly attributes: A;
  readonly relationships?: { readonly user?: { readonly data: ResourceLinkage } };
}

interface WireUser {
  readonly name?: string;
  readonly image?: string;
  readonly email?: string;
  readonly emailVerified?: boolean;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly attributes: Http.Attributes;
}

interface WireSession {
  readonly expiresAt: number;
  readonly createdAt: number;
  readonly lastActivityAt: number;
  readonly attributes: Http.Attributes;
}

interface WireIdentifier {
  readonly kind: Http.IdentifierView["type"];
  readonly value: string;
  readonly verified: boolean;
  readonly verifiedAt?: number;
  readonly createdAt: number;
}

interface DataDocument<A> {
  readonly data: WireResource<A>;
  readonly included?: ReadonlyArray<WireResource<WireUser>>;
}

interface CollectionDocument<A> {
  readonly data: ReadonlyArray<WireResource<A>>;
}

/**
 * What `POST /sessions`, `POST /users` and the verifications answer: `201`
 * with the session (its user included), or `202` with a second-factor
 * challenge or no primary data. Sessions and challenges both carry
 * `expiresAt`.
 */
interface SignInDocument {
  readonly data?: WireResource<{ readonly expiresAt: number }>;
  readonly included?: ReadonlyArray<WireResource<WireUser>>;
  readonly meta?: { readonly needsEmailVerification?: boolean };
}

const userView = (resource: WireResource<WireUser>): Http.UserView => ({
  id: resource.id,
  ...resource.attributes,
});

const sessionView = (resource: WireResource<WireSession>): Http.SessionView => ({
  id: resource.id,
  userId: resource.relationships?.user?.data.id ?? "",
  ...resource.attributes,
});

const identifierView = ({ id, attributes }: WireResource<WireIdentifier>): Http.IdentifierView => {
  const { kind, ...rest } = attributes;
  return { id, type: kind, ...rest };
};

/** The {@link AuthResult} of a sign-in answer (`undefined` for a bodiless `204` / `202`). */
const authResult = (document: SignInDocument | undefined): AuthResult => {
  const needsEmailVerification = document?.meta?.needsEmailVerification ?? false;
  const data = document?.data;
  if (data === undefined) return { needsEmailVerification };
  if (data.type === "second-factor-challenges") {
    return {
      needsEmailVerification,
      secondFactor: { token: data.id, expiresAt: data.attributes.expiresAt },
    };
  }
  const user = document?.included?.find((resource) => resource.type === "users");
  return { ...(user !== undefined && { user: userView(user) }), needsEmailVerification };
};

/** The message of an error body: a JSON:API error document's first `detail`, or `{ message }`. */
const errorMessage = (body: unknown): string | undefined => {
  if (typeof body !== "object" || body === null) return undefined;
  if ("errors" in body && Array.isArray(body.errors)) {
    const first: unknown = body.errors[0];
    return typeof first === "object" &&
      first !== null &&
      "detail" in first &&
      typeof first.detail === "string"
      ? first.detail
      : undefined;
  }
  return "message" in body && typeof body.message === "string" ? body.message : undefined;
};

/** The auth client: typed methods over the contract + the session store. */
export interface AuthClient {
  readonly session: SessionStore;

  readonly signUp: (payload: Http.SignUpPayload) => Promise<AuthResult>;
  readonly signIn: (payload: Http.SignInPayload) => Promise<AuthResult>;
  readonly signOut: () => Promise<void>;
  /** Guest sign-in — creates an anonymous user + session. 404 when unconfigured. */
  readonly signInAnonymous: () => Promise<AuthResult>;
  /** Username + password sign-in. 404 when unconfigured. */
  readonly signInUsername: (payload: Http.UsernameSignInPayload) => Promise<AuthResult>;
  /** Resolves `null` when not authenticated (401). */
  readonly getSession: () => Promise<Http.SessionWithUserView | null>;
  readonly sendVerificationEmail: (payload: { email: string }) => Promise<Http.StatusResponse>;
  readonly verifyEmail: (payload: { token: string }) => Promise<AuthResult>;
  readonly passwordResetRequest: (payload: { email: string }) => Promise<Http.StatusResponse>;
  readonly passwordResetConfirm: (payload: {
    token: string;
    newPassword: string;
  }) => Promise<Http.StatusResponse>;
  readonly changePassword: (payload: Http.ChangePasswordPayload) => Promise<void>;
  readonly updateUser: (payload: Http.UpdateUserPayload) => Promise<Http.UserView>;
  readonly listSessions: () => Promise<readonly Http.SessionView[]>;
  readonly revokeSession: (sessionId: string) => Promise<void>;
  readonly revokeOtherSessions: () => Promise<void>;
  /** Fetch a signed JWT for the current session. 404 when unconfigured. */
  readonly jwtToken: () => Promise<Http.JwtTokenView>;
  /** The JWKS that verifies {@link jwtToken}'s tokens. 404 when unconfigured. */
  readonly jwks: () => Promise<Http.JwksView>;

  /**
   * The signed-in user's login handles (email / username / phone). The server
   * refuses to delete the last one (400) so an account is never orphaned.
   */
  readonly identifiers: {
    readonly list: () => Promise<Http.IdentifierListView>;
    readonly delete: (identifierId: string) => Promise<void>;
  };

  /** Verification-gated email change. 404 when unconfigured. */
  readonly changeEmail: {
    readonly request: (payload: Http.ChangeEmailRequestPayload) => Promise<Http.StatusResponse>;
    readonly confirm: (payload: Http.ChangeEmailConfirmPayload) => Promise<Http.StatusResponse>;
  };

  /** Self-service account deletion. 404 when unconfigured. */
  readonly deleteUser: {
    readonly request: () => Promise<Http.StatusResponse>;
    readonly confirm: (payload: Http.DeleteUserConfirmPayload) => Promise<Http.StatusResponse>;
  };

  /** Multi-account management (several accounts per device). 404 when unconfigured. */
  readonly multiSession: {
    readonly list: () => Promise<Http.MultiSessionListView>;
    readonly setActive: (payload: Http.MultiSessionActionPayload) => Promise<Http.StatusResponse>;
    readonly revoke: (payload: Http.MultiSessionActionPayload) => Promise<Http.StatusResponse>;
  };

  readonly magicLink: {
    readonly send: (payload: { email: string }) => Promise<Http.StatusResponse>;
    readonly verify: (payload: { token: string }) => Promise<AuthResult>;
  };

  readonly emailOtp: {
    readonly send: (payload: {
      email: string;
      purpose: Http.EmailOtpPurpose;
    }) => Promise<Http.StatusResponse>;
    readonly signIn: (payload: { email: string; otp: string }) => Promise<AuthResult>;
  };

  /** SMS one-time passcodes. 404 when unconfigured. */
  readonly phoneOtp: {
    readonly send: (payload: {
      phoneNumber: string;
      purpose: Http.PhoneOtpPurpose;
    }) => Promise<Http.StatusResponse>;
    readonly signIn: (payload: { phoneNumber: string; otp: string }) => Promise<AuthResult>;
  };

  /** Google One Tap. 404 when unconfigured. */
  readonly googleOneTap: {
    /** Server-generated nonce to hand to Google's One Tap prompt. */
    readonly nonce: () => Promise<Http.GoogleOneTapNonceView>;
    readonly signIn: (payload: Http.GoogleOneTapPayload) => Promise<AuthResult>;
  };

  /**
   * Device authorization grant (RFC 8628). `code`/`token` are called by the
   * input-constrained device; `approve`/`deny` by the signed-in user on the
   * verification page. 404 when unconfigured.
   */
  readonly device: {
    readonly code: (payload?: Http.DeviceCodePayload) => Promise<Http.DeviceCodeView>;
    /** Poll for the session. 400 while the user has not decided yet. */
    readonly token: (payload: Http.DeviceTokenPayload) => Promise<Http.AuthSuccess>;
    readonly approve: (payload: Http.DeviceUserCodePayload) => Promise<Http.StatusResponse>;
    readonly deny: (payload: Http.DeviceUserCodePayload) => Promise<Http.StatusResponse>;
  };

  readonly multiFactor: {
    readonly enable: (payload: { password: string }) => Promise<Http.MultiFactorEnableView>;
    readonly confirm: (payload: { code: string }) => Promise<Http.StatusResponse>;
    readonly disable: (payload: { password: string }) => Promise<Http.StatusResponse>;
    readonly regenerateBackupCodes: (payload: {
      password: string;
    }) => Promise<Http.BackupCodesView>;
    readonly verifyTotp: (payload: { token: string; code: string }) => Promise<AuthResult>;
    readonly verifyBackupCode: (payload: { token: string; code: string }) => Promise<AuthResult>;
    /**
     * Bind a pending challenge so the caller only needs to pass the code.
     *
     * ```ts
     * const result = await client.signIn({ email, password });
     * if (result.secondFactor) {
     *   await client.multiFactor.challenge(result.secondFactor).verifyTotp(code);
     * }
     * ```
     */
    readonly challenge: (challenge: Http.SecondFactorChallengeView) => SecondFactorContinuation;
    /**
     * Carry a gated sign-in straight into the second-factor step: takes the
     * `AuthResult` a sign-in returned and hands back the verify calls bound
     * to its challenge.
     *
     * ```ts
     * const result = await client.signIn({ email, password });
     * if (result.secondFactor) {
     *   const challenge = client.multiFactor.continueChallenge(result);
     *   await challenge.verifyTotp(codeFromUser); // session issued
     * }
     * ```
     *
     * Throws a {@link SecondFactorChallengeError} with `reason: "missing"`
     * when the result carries no challenge (the user is already signed in),
     * and the verify calls reject with `reason: "expired"` once the challenge
     * window has passed.
     */
    readonly continueChallenge: (result: AuthResult) => SecondFactorContinuation;
  };

  /**
   * Organizations: orgs, members (including deactivation), invitations,
   * claimed email domains, teams and per-organization roles. Every call is
   * session-authenticated; 404 when the module is absent and 403 when the
   * actor's role lacks the required permission.
   */
  readonly organization: {
    readonly create: (payload: Http.CreateOrganizationPayload) => Promise<Http.OrganizationView>;
    /** Organizations the signed-in user is a member of. */
    readonly list: () => Promise<Http.OrganizationListView>;
    /** One organization together with its members. */
    readonly get: (organizationId: string) => Promise<Http.FullOrganizationView>;
    readonly update: (
      organizationId: string,
      payload: Http.UpdateOrganizationPayload,
    ) => Promise<Http.OrganizationView>;
    readonly delete: (organizationId: string) => Promise<void>;
    /** Record the active organization on the session (`null` clears it). */
    readonly setActive: (
      payload: Http.SetActiveOrganizationPayload,
    ) => Promise<Http.StatusResponse>;

    /** Omit `role` to use the organization's default role. */
    readonly addMember: (
      organizationId: string,
      payload: Http.AddMemberPayload,
    ) => Promise<Http.MemberView>;
    readonly updateMemberRole: (
      organizationId: string,
      payload: Http.UpdateMemberRolePayload,
    ) => Promise<Http.MemberView>;
    readonly removeMember: (organizationId: string, userId: string) => Promise<void>;
    /**
     * Suspend a membership without deleting it: the row (and the member's
     * role, restored on reactivation) survives, but every permission check in
     * the organization now denies them. Application sessions are left alone -
     * the server exposes an `onMemberDeactivated` hook for apps that want to
     * end them.
     */
    readonly deactivateMember: (organizationId: string, userId: string) => Promise<Http.MemberView>;
    readonly reactivateMember: (organizationId: string, userId: string) => Promise<Http.MemberView>;
    /** Set the role members added without one receive (owner-only). */
    readonly setDefaultRole: (
      organizationId: string,
      payload: Http.SetDefaultRolePayload,
    ) => Promise<Http.OrganizationView>;

    readonly invite: (
      organizationId: string,
      payload: Http.InviteMemberPayload,
    ) => Promise<Http.InvitationView>;
    readonly listInvitations: (organizationId: string) => Promise<Http.InvitationListView>;
    /** Accept an invitation addressed to the signed-in user's email. */
    readonly acceptInvitation: (invitationId: string) => Promise<Http.MemberView>;
    readonly rejectInvitation: (invitationId: string) => Promise<Http.InvitationView>;
    readonly cancelInvitation: (invitationId: string) => Promise<Http.InvitationView>;
    /** Re-send a pending invitation: same id, fresh expiry, delivered again. */
    readonly resendInvitation: (invitationId: string) => Promise<Http.InvitationView>;

    /** Email domains the organization has claimed, and their verification state. */
    readonly listDomains: (organizationId: string) => Promise<Http.OrganizationDomainListView>;
    /**
     * Claim a domain. The `dns` strategy (the default) answers with the
     * `verificationToken` to publish as a TXT record; `manual` is attested by
     * an admin calling {@link verifyDomain}.
     */
    readonly addDomain: (
      organizationId: string,
      payload: Http.AddOrganizationDomainPayload,
    ) => Promise<Http.OrganizationDomainView>;
    readonly removeDomain: (organizationId: string, domainId: string) => Promise<void>;
    /**
     * Run the verification check. A DNS claim whose record is not published
     * yet comes back in state `"failed"` - retry once it is.
     */
    readonly verifyDomain: (
      organizationId: string,
      domainId: string,
    ) => Promise<Http.OrganizationDomainView>;

    /** Define (or redefine) a role's permissions for one organization. */
    readonly upsertRole: (
      organizationId: string,
      role: string,
      payload: Http.UpsertOrgRolePayload,
    ) => Promise<Http.OrgRoleView>;
    readonly listRoles: (organizationId: string) => Promise<Http.OrgRoleListView>;
    readonly deleteRole: (organizationId: string, role: string) => Promise<void>;

    readonly createTeam: (
      organizationId: string,
      payload: Http.CreateTeamPayload,
    ) => Promise<Http.TeamView>;
    readonly listTeams: (organizationId: string) => Promise<Http.TeamListView>;
    readonly listTeamsForMember: (
      organizationId: string,
      userId: string,
    ) => Promise<Http.TeamListView>;
    readonly updateTeam: (
      teamId: string,
      payload: Http.UpdateTeamPayload,
    ) => Promise<Http.TeamView>;
    readonly deleteTeam: (teamId: string) => Promise<void>;
    readonly addTeamMember: (
      teamId: string,
      payload: Http.AddTeamMemberPayload,
    ) => Promise<Http.TeamMemberView>;
    readonly listTeamMembers: (teamId: string) => Promise<Http.TeamMemberListView>;
    readonly removeTeamMember: (teamId: string, userId: string) => Promise<void>;
  };

  /** API keys owned by the signed-in user. 404 when unconfigured. */
  readonly apiKeys: {
    /** The plaintext key is returned exactly once — show it, then discard. */
    readonly create: (payload: Http.ApiKeyCreatePayload) => Promise<Http.ApiKeyCreatedView>;
    readonly list: () => Promise<Http.ApiKeyListView>;
    readonly update: (keyId: string, payload: Http.ApiKeyUpdatePayload) => Promise<Http.ApiKeyView>;
    readonly delete: (keyId: string) => Promise<void>;
  };

  /** Administration. The actor must satisfy the server's `isAdmin`; 403 otherwise. */
  readonly admin: {
    readonly listUsers: (payload: Http.AdminListUsersPayload) => Promise<Http.AdminUserListView>;
    readonly setRole: (payload: Http.AdminSetRolePayload) => Promise<Http.UserView>;
    readonly banUser: (payload: Http.AdminBanUserPayload) => Promise<Http.UserView>;
    readonly unbanUser: (payload: Http.AdminUserActionPayload) => Promise<Http.UserView>;
    readonly removeUser: (payload: Http.AdminUserActionPayload) => Promise<void>;
    readonly revokeSessions: (payload: Http.AdminUserActionPayload) => Promise<Http.StatusResponse>;
    /** Assume another user's identity — swaps the session cookie. */
    readonly impersonate: (payload: Http.AdminUserActionPayload) => Promise<Http.AuthSuccess>;
    readonly stopImpersonating: () => Promise<Http.StatusResponse>;
  };

  /** Enterprise SSO (this server as an OIDC/SAML relying party). */
  readonly sso: {
    /** Register a connection (admin-gated). */
    readonly register: (payload: Http.SsoRegisterPayload) => Promise<Http.SsoProviderView>;
    /** Resolve the IdP authorization URL to redirect the browser to. */
    readonly signIn: (payload: Http.SsoSignInPayload) => Promise<Http.SsoUrlView>;
    /** Complete the callback and issue a session. */
    readonly callback: (payload: Http.SsoCallbackPayload) => Promise<Http.AuthSuccess>;
  };

  /**
   * OIDC provider surfaces a first-party app drives: client management
   * (admin-gated) and the consent page's decision. The protocol endpoints
   * themselves (`/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`,
   * discovery) are for OAuth clients, not this SDK.
   */
  readonly oidc: {
    readonly registerClient: (
      payload: Http.OidcRegisterClientPayload,
    ) => Promise<Http.OidcClientCreatedView>;
    readonly listClients: () => Promise<Http.OidcClientListView>;
    readonly updateClient: (
      clientId: string,
      payload: Http.OidcClientUpdatePayload,
    ) => Promise<Http.OidcClientView>;
    readonly deleteClient: (clientId: string) => Promise<void>;
    /** Post the consent decision; the response carries the redirect URL. */
    readonly consent: (payload: Http.OidcConsentPayload) => Promise<Http.OidcRedirectView>;
  };

  /** Extend this client with a plugin's typed methods. */
  readonly extend: <TExtension extends object>(
    plugin: AuthClientPlugin<TExtension>,
  ) => AuthClient & TExtension;
}

/**
 * Create an auth client for an effect-auth server.
 *
 * ```ts
 * const client = createAuthClient({ baseUrl: "/api/auth" });
 * const { user } = await client.signIn({ email, password });
 * client.session.subscribe(() => render(client.session.get()));
 * ```
 */
export const createAuthClient = (options: AuthClientOptions): AuthClient => {
  const baseUrl = options.baseUrl.replace(/\/$/, "");
  // Bind lazily so tests can swap `globalThis.fetch` after client creation.
  const doFetch: typeof globalThis.fetch =
    options.fetch ?? ((...args) => globalThis.fetch(...args));

  const send = async <T>(
    method: string,
    path: string,
    body: unknown,
    mediaType: string | undefined,
  ): Promise<T> => {
    const response = await doFetch(`${baseUrl}${path}`, {
      method,
      credentials: "include",
      headers: {
        ...(mediaType !== undefined && { accept: mediaType }),
        ...(body !== undefined && { "content-type": mediaType ?? "application/json" }),
        ...options.headers,
      },
      ...(body !== undefined && { body: JSON.stringify(body) }),
    });
    if (!response.ok) {
      let message = response.statusText || `HTTP ${response.status}`;
      if (isJson(response)) {
        // A body that fails to parse leaves the status text as the message.
        const parsed: unknown = await response.json().catch(() => null);
        message = errorMessage(parsed) ?? message;
      }
      throw new AuthClientError(response.status, message);
    }
    if (response.status === 204 || !isJson(response)) {
      // SAFETY: endpoints that answer 204 or a non-JSON body are requested
      // with `T = void`, so `undefined` is their success value.
      return undefined as T;
    }
    // SAFETY: each call site names as `T` the success type the HTTP contract
    // declares for that endpoint, which is what the server encodes.
    return (await response.json()) as T;
  };

  const request = <T>(method: string, path: string, body?: unknown): Promise<T> =>
    send<T>(method, path, body, undefined);

  /** A request to a JSON:API resource group: `application/vnd.api+json` both ways. */
  const jsonApi = <T>(method: string, path: string, body?: unknown): Promise<T> =>
    send<T>(method, path, body, JSON_API);

  // --- Session store ----------------------------------------------------------

  let state: SessionState = { data: null, isPending: true, error: null };
  let fetchedOnce = false;
  let refetchSeq = 0;
  const listeners = new Set<() => void>();

  // --- Background refresh state ---------------------------------------------

  let refreshActive = false;
  let intervalId: ReturnType<typeof setInterval> | undefined;
  let broadcastChannel: BroadcastChannel | undefined;

  const onFocus = (): void => {
    void refetch();
  };
  const onVisibilityChange = (): void => {
    if (globalThis.document !== undefined && document.visibilityState === "visible") {
      void refetch();
    }
  };

  const setState = (next: SessionState, broadcast = true): void => {
    state = next;
    listeners.forEach((listener) => listener());
    if (broadcast && broadcastChannel !== undefined) {
      broadcastChannel.postMessage({ data: next.data });
    }
  };

  const getSession = (): Promise<Http.SessionWithUserView | null> =>
    jsonApi<DataDocument<WireSession>>("GET", "/sessions/current?include=user").then(
      (document): Http.SessionWithUserView => {
        const session = sessionView(document.data);
        const user = document.included?.find((resource) => resource.id === session.userId);
        if (user === undefined) {
          throw new AuthClientError(0, "The session document did not include its user");
        }
        return { session, user: userView(user) };
      },
      (error) => {
        if (error instanceof AuthClientError && error.status === 401) return null;
        throw error;
      },
    );

  const refetch = async (): Promise<void> => {
    const seq = ++refetchSeq;
    setState({ ...state, isPending: true });
    await getSession()
      .then((data) => {
        if (seq !== refetchSeq) return;
        setState({ data, isPending: false, error: null });
      })
      .catch((error) => {
        if (seq !== refetchSeq) return;
        setState({
          data: state.data,
          isPending: false,
          error:
            error instanceof AuthClientError
              ? error
              : new AuthClientError(0, error instanceof Error ? error.message : String(error)),
        });
      });
  };

  const startRefresh = (): void => {
    if (refreshActive) return;
    refreshActive = true;

    const cfg = options.refresh;
    if (cfg === undefined) return;

    if (cfg.intervalMs !== undefined && cfg.intervalMs > 0) {
      intervalId = setInterval(() => void refetch(), cfg.intervalMs);
    }

    if (cfg.onFocus) {
      if (globalThis.window !== undefined) {
        window.addEventListener("focus", onFocus);
      }
      if (globalThis.document !== undefined) {
        document.addEventListener("visibilitychange", onVisibilityChange);
      }
    }

    if (cfg.crossTab) {
      if (globalThis.BroadcastChannel !== undefined) {
        const channelName = cfg.crossTab === true ? "effect-auth-session" : cfg.crossTab;
        broadcastChannel = new BroadcastChannel(channelName);
        broadcastChannel.onmessage = (
          event: MessageEvent<{ data: Http.SessionWithUserView | null }>,
        ) => {
          setState({ data: event.data.data, isPending: false, error: null }, false);
        };
      }
    }
  };

  const stopRefresh = (): void => {
    if (!refreshActive) return;
    refreshActive = false;

    if (intervalId !== undefined) {
      clearInterval(intervalId);
      intervalId = undefined;
    }

    if (globalThis.window !== undefined) {
      window.removeEventListener("focus", onFocus);
    }
    if (globalThis.document !== undefined) {
      document.removeEventListener("visibilitychange", onVisibilityChange);
    }

    if (broadcastChannel !== undefined) {
      broadcastChannel.close();
      broadcastChannel = undefined;
    }
  };

  const session: SessionStore = {
    get: () => state,
    subscribe: (listener) => {
      listeners.add(listener);
      if (!fetchedOnce) {
        fetchedOnce = true;
        void refetch();
      }
      if (listeners.size === 1) {
        startRefresh();
      }
      return () => {
        listeners.delete(listener);
        if (listeners.size === 0) {
          stopRefresh();
        }
      };
    },
    refetch,
  };

  /**
   * Run a session-changing call, then refresh the store only when there are
   * active subscribers (skipping the round-trip when nobody is observing).
   */
  const mutating = async <T>(run: () => Promise<T>): Promise<T> => {
    const result = await run();
    if (listeners.size > 0) {
      fetchedOnce = true;
      await refetch();
    }
    return result;
  };

  const pluginContext: AuthClientPluginContext = { request, mutating, session };

  /** Sign in with `credential` (`POST /sessions`), refreshing the session store. */
  const signInWith = (credential: Http.SignInCredential, rememberMe?: boolean) =>
    mutating(() =>
      jsonApi<SignInDocument>("POST", "/sessions", {
        data: {
          type: "sessions",
          attributes: { credential, ...(rememberMe !== undefined && { rememberMe }) },
        },
      }).then(authResult),
    );

  /** Send a one-time code or a magic link (`POST /otp-challenges`). */
  const sendChallenge = (
    attributes: Http.OtpChallengeDocument["data"]["attributes"],
  ): Promise<Http.StatusResponse> =>
    jsonApi<void>("POST", "/otp-challenges", { data: { type: "otp-challenges", attributes } }).then(
      () => ({ status: true }),
    );

  /** Redeem a second-factor challenge with a TOTP or backup code. */
  const verifySecondFactor = (
    token: string,
    method: "totp" | "backup-code",
    code: string,
  ): Promise<AuthResult> =>
    mutating(() =>
      jsonApi<SignInDocument>("POST", "/second-factor-challenges/verifications", {
        data: {
          type: "second-factor-verifications",
          attributes: { method, code },
          // The challenge token travels in the body, never in the URL.
          relationships: { challenge: { data: { type: "second-factor-challenges", id: token } } },
        },
      }).then(authResult),
    );

  /**
   * Bind a pending second-factor challenge to the verify endpoints, refusing
   * client-side once the challenge window has passed (the server enforces the
   * same expiry — this just saves a doomed round trip).
   */
  const continuation = (challenge: Http.SecondFactorChallengeView): SecondFactorContinuation => {
    const isExpired = (): boolean => Date.now() >= challenge.expiresAt;
    const verify = (method: "totp" | "backup-code", code: string): Promise<AuthResult> => {
      if (isExpired()) {
        return Promise.reject(
          new SecondFactorChallengeError(
            "expired",
            "The second-factor challenge has expired — sign in again",
          ),
        );
      }
      return verifySecondFactor(challenge.token, method, code);
    };
    return {
      token: challenge.token,
      expiresAt: challenge.expiresAt,
      isExpired,
      verifyTotp: (code) => verify("totp", code),
      verifyBackupCode: (code) => verify("backup-code", code),
    };
  };

  // Use `let` so the `extend` closure can reference `self` after assignment.
  let self!: AuthClient;
  self = {
    session,

    signUp: (payload) =>
      mutating(() =>
        jsonApi<SignInDocument>("POST", "/users", {
          data: { type: "users", attributes: payload },
        }).then(authResult),
      ),
    signIn: ({ email, password, captchaToken, rememberMe }) =>
      signInWith(
        {
          method: "password",
          email,
          password,
          ...(captchaToken !== undefined && { captchaToken }),
        },
        rememberMe,
      ),
    signOut: () =>
      mutating(async () => {
        await jsonApi<void>("DELETE", "/sessions/current");
      }),
    signInAnonymous: () => signInWith({ method: "anonymous" }),
    signInUsername: ({ username, password, rememberMe }) =>
      signInWith({ method: "username", username, password }, rememberMe),
    getSession,
    sendVerificationEmail: ({ email }) =>
      jsonApi<void>("POST", "/email-verifications", {
        data: { type: "email-verifications", attributes: { email } },
      }).then(() => ({ status: true })),
    verifyEmail: ({ token }) =>
      mutating(() =>
        jsonApi<SignInDocument | undefined>("POST", "/email-verifications/redemptions", {
          data: { type: "email-verification-redemptions", attributes: { token } },
        }).then(authResult),
      ),
    passwordResetRequest: ({ email }) =>
      jsonApi<void>("POST", "/password-resets", {
        data: { type: "password-resets", attributes: { email } },
      }).then(() => ({ status: true })),
    passwordResetConfirm: ({ token, newPassword }) =>
      jsonApi<void>("POST", "/password-resets/redemptions", {
        data: { type: "password-reset-redemptions", attributes: { token, newPassword } },
      }).then(() => ({ status: true })),
    changePassword: (payload) => request<void>("POST", "/change-password", payload),
    updateUser: (payload) =>
      mutating(() =>
        jsonApi<DataDocument<WireUser>>("PATCH", "/users/me", {
          data: { type: "users", id: "me", attributes: payload },
        }).then((document) => userView(document.data)),
      ),
    listSessions: () =>
      jsonApi<CollectionDocument<WireSession>>("GET", "/sessions").then((document) =>
        document.data.map(sessionView),
      ),
    revokeSession: (sessionId) =>
      jsonApi<void>("DELETE", `/sessions/${encodeURIComponent(sessionId)}`),
    revokeOtherSessions: () => jsonApi<void>("DELETE", "/sessions?filter%5Bcurrent%5D=false"),
    jwtToken: () => request<Http.JwtTokenView>("GET", "/token"),
    jwks: () => request<Http.JwksView>("GET", "/jwks"),

    identifiers: {
      list: () =>
        jsonApi<CollectionDocument<WireIdentifier>>("GET", "/identifiers").then((document) =>
          document.data.map(identifierView),
        ),
      delete: (identifierId) =>
        jsonApi<void>("DELETE", `/identifiers/${encodeURIComponent(identifierId)}`),
    },

    changeEmail: {
      request: (payload) => request<Http.StatusResponse>("POST", "/change-email/request", payload),
      confirm: (payload) =>
        mutating(() => request<Http.StatusResponse>("POST", "/change-email/confirm", payload)),
    },

    deleteUser: {
      request: () => request<Http.StatusResponse>("POST", "/delete-user/request"),
      confirm: (payload) =>
        mutating(() => request<Http.StatusResponse>("POST", "/delete-user/confirm", payload)),
    },

    multiSession: {
      list: () => request<Http.MultiSessionListView>("GET", "/multi-session/list"),
      setActive: (payload) =>
        mutating(() => request<Http.StatusResponse>("POST", "/multi-session/set-active", payload)),
      revoke: (payload) => request<Http.StatusResponse>("POST", "/multi-session/revoke", payload),
    },

    magicLink: {
      send: ({ email }) => sendChallenge({ channel: "magic-link", email }),
      verify: ({ token }) => signInWith({ method: "magic-link", token }),
    },

    emailOtp: {
      send: ({ email, purpose }) => sendChallenge({ channel: "email", email, purpose }),
      signIn: ({ email, otp }) => signInWith({ method: "email-otp", email, otp }),
    },

    phoneOtp: {
      send: ({ phoneNumber, purpose }) => sendChallenge({ channel: "phone", phoneNumber, purpose }),
      signIn: ({ phoneNumber, otp }) => signInWith({ method: "phone-otp", phoneNumber, otp }),
    },

    googleOneTap: {
      nonce: () =>
        jsonApi<DataDocument<Record<string, never>>>("POST", "/google-one-tap-nonces").then(
          (document) => ({ nonce: document.data.id }),
        ),
      signIn: ({ credential, nonce }) =>
        signInWith({ method: "google-one-tap", idToken: credential, nonce }),
    },

    device: {
      code: (payload) => request<Http.DeviceCodeView>("POST", "/device/code", payload ?? {}),
      token: (payload) =>
        mutating(() => request<Http.AuthSuccess>("POST", "/device/token", payload)),
      approve: (payload) => request<Http.StatusResponse>("POST", "/device/approve", payload),
      deny: (payload) => request<Http.StatusResponse>("POST", "/device/deny", payload),
    },

    multiFactor: {
      enable: (payload) =>
        request<Http.MultiFactorEnableView>("POST", "/multi-factor/enable", payload),
      confirm: (payload) => request<Http.StatusResponse>("POST", "/multi-factor/confirm", payload),
      disable: (payload) => request<Http.StatusResponse>("POST", "/multi-factor/disable", payload),
      regenerateBackupCodes: (payload) =>
        request<Http.BackupCodesView>("POST", "/multi-factor/regenerate-backup-codes", payload),
      verifyTotp: ({ token, code }) => verifySecondFactor(token, "totp", code),
      verifyBackupCode: ({ token, code }) => verifySecondFactor(token, "backup-code", code),
      challenge: continuation,
      continueChallenge: (result) => {
        if (result.secondFactor === undefined) {
          throw new SecondFactorChallengeError(
            "missing",
            "This result carries no second-factor challenge",
          );
        }
        return continuation(result.secondFactor);
      },
    },

    organization: {
      create: (payload) => request<Http.OrganizationView>("POST", "/organization/create", payload),
      list: () => request<Http.OrganizationListView>("GET", "/organizations"),
      get: (organizationId) =>
        request<Http.FullOrganizationView>(
          "GET",
          `/organization/${encodeURIComponent(organizationId)}`,
        ),
      update: (organizationId, payload) =>
        request<Http.OrganizationView>(
          "PATCH",
          `/organization/${encodeURIComponent(organizationId)}`,
          payload,
        ),
      delete: (organizationId) =>
        request<void>("DELETE", `/organization/${encodeURIComponent(organizationId)}`),
      // The active organization is stored on the session, so refresh the store.
      setActive: (payload) =>
        mutating(() => request<Http.StatusResponse>("POST", "/organization/set-active", payload)),

      addMember: (organizationId, payload) =>
        request<Http.MemberView>(
          "POST",
          `/organization/${encodeURIComponent(organizationId)}/members`,
          payload,
        ),
      updateMemberRole: (organizationId, payload) =>
        request<Http.MemberView>(
          "PATCH",
          `/organization/${encodeURIComponent(organizationId)}/members`,
          payload,
        ),
      removeMember: (organizationId, userId) =>
        request<void>(
          "DELETE",
          `/organization/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(userId)}`,
        ),
      deactivateMember: (organizationId, userId) =>
        request<Http.MemberView>(
          "POST",
          `/organization/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(userId)}/deactivate`,
        ),
      reactivateMember: (organizationId, userId) =>
        request<Http.MemberView>(
          "POST",
          `/organization/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(userId)}/reactivate`,
        ),
      setDefaultRole: (organizationId, payload) =>
        request<Http.OrganizationView>(
          "PUT",
          `/organization/${encodeURIComponent(organizationId)}/default-role`,
          payload,
        ),

      invite: (organizationId, payload) =>
        request<Http.InvitationView>(
          "POST",
          `/organization/${encodeURIComponent(organizationId)}/invitations`,
          payload,
        ),
      listInvitations: (organizationId) =>
        request<Http.InvitationListView>(
          "GET",
          `/organization/${encodeURIComponent(organizationId)}/invitations`,
        ),
      acceptInvitation: (invitationId) =>
        request<Http.MemberView>("POST", `/invitations/${encodeURIComponent(invitationId)}/accept`),
      rejectInvitation: (invitationId) =>
        request<Http.InvitationView>(
          "POST",
          `/invitations/${encodeURIComponent(invitationId)}/reject`,
        ),
      cancelInvitation: (invitationId) =>
        request<Http.InvitationView>(
          "POST",
          `/invitations/${encodeURIComponent(invitationId)}/cancel`,
        ),
      resendInvitation: (invitationId) =>
        request<Http.InvitationView>(
          "POST",
          `/invitations/${encodeURIComponent(invitationId)}/resend`,
        ),

      listDomains: (organizationId) =>
        request<Http.OrganizationDomainListView>(
          "GET",
          `/organization/${encodeURIComponent(organizationId)}/domains`,
        ),
      addDomain: (organizationId, payload) =>
        request<Http.OrganizationDomainView>(
          "POST",
          `/organization/${encodeURIComponent(organizationId)}/domains`,
          payload,
        ),
      removeDomain: (organizationId, domainId) =>
        request<void>(
          "DELETE",
          `/organization/${encodeURIComponent(organizationId)}/domains/${encodeURIComponent(domainId)}`,
        ),
      verifyDomain: (organizationId, domainId) =>
        request<Http.OrganizationDomainView>(
          "POST",
          `/organization/${encodeURIComponent(organizationId)}/domains/${encodeURIComponent(domainId)}/verify`,
        ),

      upsertRole: (organizationId, role, payload) =>
        request<Http.OrgRoleView>(
          "PUT",
          `/organization/${encodeURIComponent(organizationId)}/roles/${encodeURIComponent(role)}`,
          payload,
        ),
      listRoles: (organizationId) =>
        request<Http.OrgRoleListView>(
          "GET",
          `/organization/${encodeURIComponent(organizationId)}/roles`,
        ),
      deleteRole: (organizationId, role) =>
        request<void>(
          "DELETE",
          `/organization/${encodeURIComponent(organizationId)}/roles/${encodeURIComponent(role)}`,
        ),

      createTeam: (organizationId, payload) =>
        request<Http.TeamView>(
          "POST",
          `/organization/${encodeURIComponent(organizationId)}/teams`,
          payload,
        ),
      listTeams: (organizationId) =>
        request<Http.TeamListView>(
          "GET",
          `/organization/${encodeURIComponent(organizationId)}/teams`,
        ),
      listTeamsForMember: (organizationId, userId) =>
        request<Http.TeamListView>(
          "GET",
          `/organization/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(userId)}/teams`,
        ),
      updateTeam: (teamId, payload) =>
        request<Http.TeamView>("PATCH", `/teams/${encodeURIComponent(teamId)}`, payload),
      deleteTeam: (teamId) => request<void>("DELETE", `/teams/${encodeURIComponent(teamId)}`),
      addTeamMember: (teamId, payload) =>
        request<Http.TeamMemberView>(
          "POST",
          `/teams/${encodeURIComponent(teamId)}/members`,
          payload,
        ),
      listTeamMembers: (teamId) =>
        request<Http.TeamMemberListView>("GET", `/teams/${encodeURIComponent(teamId)}/members`),
      removeTeamMember: (teamId, userId) =>
        request<void>(
          "DELETE",
          `/teams/${encodeURIComponent(teamId)}/members/${encodeURIComponent(userId)}`,
        ),
    },

    apiKeys: {
      create: (payload) => request<Http.ApiKeyCreatedView>("POST", "/api-keys", payload),
      list: () => request<Http.ApiKeyListView>("GET", "/api-keys"),
      update: (keyId, payload) =>
        request<Http.ApiKeyView>("PATCH", `/api-keys/${encodeURIComponent(keyId)}`, payload),
      delete: (keyId) => request<void>("DELETE", `/api-keys/${encodeURIComponent(keyId)}`),
    },

    admin: {
      listUsers: (payload) => request<Http.AdminUserListView>("POST", "/admin/users/list", payload),
      setRole: (payload) => request<Http.UserView>("POST", "/admin/users/set-role", payload),
      banUser: (payload) => request<Http.UserView>("POST", "/admin/users/ban", payload),
      unbanUser: (payload) => request<Http.UserView>("POST", "/admin/users/unban", payload),
      removeUser: (payload) => request<void>("POST", "/admin/users/remove", payload),
      revokeSessions: (payload) =>
        request<Http.StatusResponse>("POST", "/admin/users/revoke-sessions", payload),
      // Impersonation swaps the session cookie in both directions.
      impersonate: (payload) =>
        mutating(() => request<Http.AuthSuccess>("POST", "/admin/impersonate", payload)),
      stopImpersonating: () =>
        mutating(() => request<Http.StatusResponse>("POST", "/admin/stop-impersonating")),
    },

    sso: {
      register: (payload) => request<Http.SsoProviderView>("POST", "/sso/register", payload),
      signIn: (payload) => request<Http.SsoUrlView>("POST", "/sign-in/sso", payload),
      callback: (payload) =>
        mutating(() => request<Http.AuthSuccess>("POST", "/sso/callback", payload)),
    },

    oidc: {
      registerClient: (payload) =>
        request<Http.OidcClientCreatedView>("POST", "/oauth2/register", payload),
      listClients: () => request<Http.OidcClientListView>("GET", "/oauth2/clients"),
      updateClient: (clientId, payload) =>
        request<Http.OidcClientView>(
          "PATCH",
          `/oauth2/clients/${encodeURIComponent(clientId)}`,
          payload,
        ),
      deleteClient: (clientId) =>
        request<void>("DELETE", `/oauth2/clients/${encodeURIComponent(clientId)}`),
      consent: (payload) => request<Http.OidcRedirectView>("POST", "/oauth2/consent", payload),
    },

    extend: <TExtension extends object>(
      plugin: AuthClientPlugin<TExtension>,
    ): AuthClient & TExtension =>
      // SAFETY: the fresh object receives every own property of `self` (an
      // `AuthClient`) and then of the plugin's `TExtension`, so it is both.
      Object.assign(Object.create(null), self, plugin.install(pluginContext)) as AuthClient &
        TExtension,
  };

  return self;
};
