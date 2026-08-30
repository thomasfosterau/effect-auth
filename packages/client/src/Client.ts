/**
 * Vanilla auth client for the effect-auth HTTP protocol.
 *
 * A small, dependency-free client (plain `fetch`, no Effect runtime in the
 * bundle) with methods mirroring the contract's endpoint names and an
 * observable session store that framework adapters subscribe to
 * (`@thomasfosterau/effect-auth-client/react`, `/svelte`, `/vue`).
 *
 * Only the wire *types* are imported from `effect-auth` — they erase at
 * compile time, so the browser bundle contains just this file.
 *
 * @module client
 */
import type {
  AddMemberPayload,
  AddTeamMemberPayload,
  AdminBanUserPayload,
  AdminListUsersPayload,
  AdminSetRolePayload,
  AdminUserActionPayload,
  AdminUserListView,
  APIKeyCreatePayload,
  APIKeyCreatedView,
  APIKeyListView,
  APIKeyUpdatePayload,
  APIKeyView,
  AuthSuccess,
  BackupCodesView,
  ChangeEmailConfirmPayload,
  ChangeEmailRequestPayload,
  ChangePasswordPayload,
  CreateOrganizationPayload,
  CreateTeamPayload,
  DeleteUserConfirmPayload,
  DeviceCodePayload,
  DeviceCodeView,
  DeviceTokenPayload,
  DeviceUserCodePayload,
  EmailOTPPurpose,
  FullOrganizationView,
  GoogleOneTapNonceView,
  GoogleOneTapPayload,
  IdentifierListView,
  InvitationListView,
  InvitationView,
  InviteMemberPayload,
  JWTTokenView,
  JwksView,
  MemberView,
  MultiSessionActionPayload,
  MultiSessionListView,
  OIDCClientCreatedView,
  OIDCClientListView,
  OIDCClientUpdatePayload,
  OIDCClientView,
  OIDCConsentPayload,
  OIDCRedirectView,
  OIDCRegisterClientPayload,
  OrgRoleListView,
  OrgRoleView,
  OrganizationListView,
  OrganizationView,
  PhoneOTPPurpose,
  SecondFactorChallengeView,
  SessionView,
  SessionWithUserView,
  SetActiveOrganizationPayload,
  SignInPayload,
  SignUpPayload,
  SSOCallbackPayload,
  SSOProviderView,
  SSORegisterPayload,
  SSOSignInPayload,
  SSOURLView,
  StatusResponse,
  MultiFactorEnableView,
  TeamListView,
  TeamMemberListView,
  TeamMemberView,
  TeamView,
  UpdateMemberRolePayload,
  UpdateOrganizationPayload,
  UpdateTeamPayload,
  UpdateUserPayload,
  UpsertOrgRolePayload,
  UserView,
  UsernameSignInPayload,
} from "./types.ts";

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
 * A pending second-factor challenge with the verify calls pre-bound to its
 * token. Obtained from {@link AuthClient.multiFactor}'s `continueChallenge`.
 */
export interface SecondFactorContinuation {
  /** The challenge token carried by `AuthSuccess.secondFactor`. */
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
  readonly verifyTotp: (code: string) => Promise<AuthSuccess>;
  /** Redeem the challenge with a single-use backup code. */
  readonly verifyBackupCode: (code: string) => Promise<AuthSuccess>;
}

/** The session store's state. */
export interface SessionState {
  /** The authenticated session + user, or `null` when signed out. */
  readonly data: SessionWithUserView | null;
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
  readonly intervalMs?: number;
  /**
   * Refetch when the browser tab becomes visible or the window gains focus.
   * Falls back to a no-op in non-browser environments. Default: `false`.
   */
  readonly onFocus?: boolean;
  /**
   * Mirror session changes across browser tabs via `BroadcastChannel`.
   * Pass `true` for the default channel name (`"effect-auth-session"`), or a
   * string for a custom name (useful when multiple auth clients share a page).
   * Falls back to a no-op when `BroadcastChannel` is unavailable (e.g. older
   * Safari or Node.js). Default: `false`.
   */
  readonly crossTab?: boolean | string;
}

export interface AuthClientOptions {
  /**
   * Base URL the auth handler is mounted at, e.g.
   * `"https://app.example.com/api/auth"` or `"/api/auth"` (same origin).
   */
  readonly baseUrl: string;
  /** Custom `fetch` (tests, SSR, mounting the handler in-process). */
  readonly fetch?: typeof globalThis.fetch;
  /** Extra headers attached to every request. */
  readonly headers?: Record<string, string>;
  /** Opt-in background session refresh. All features are off by default. */
  readonly refresh?: RefreshOptions;
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

/** Percent-encode one path segment (ids may contain `/`, `:` or spaces). */
const seg = (value: string): string => encodeURIComponent(value);

const isJson = (response: Response): boolean =>
  (response.headers.get("content-type") ?? "").includes("application/json");

/** The auth client: typed methods over the contract + the session store. */
export interface AuthClient {
  readonly session: SessionStore;

  readonly signUp: (payload: SignUpPayload) => Promise<AuthSuccess>;
  readonly signIn: (payload: SignInPayload) => Promise<AuthSuccess>;
  readonly signOut: () => Promise<void>;
  /** Guest sign-in — creates an anonymous user + session. 404 when unconfigured. */
  readonly signInAnonymous: () => Promise<AuthSuccess>;
  /** Username + password sign-in. 404 when unconfigured. */
  readonly signInUsername: (payload: UsernameSignInPayload) => Promise<AuthSuccess>;
  /** Resolves `null` when not authenticated (401). */
  readonly getSession: () => Promise<SessionWithUserView | null>;
  readonly sendVerificationEmail: (payload: { email: string }) => Promise<StatusResponse>;
  readonly verifyEmail: (payload: { token: string }) => Promise<AuthSuccess>;
  readonly passwordResetRequest: (payload: { email: string }) => Promise<StatusResponse>;
  readonly passwordResetConfirm: (payload: {
    token: string;
    newPassword: string;
  }) => Promise<StatusResponse>;
  readonly changePassword: (payload: ChangePasswordPayload) => Promise<void>;
  readonly updateUser: (payload: UpdateUserPayload) => Promise<UserView>;
  readonly listSessions: () => Promise<readonly SessionView[]>;
  readonly revokeSession: (sessionId: string) => Promise<void>;
  readonly revokeOtherSessions: () => Promise<void>;
  /** Fetch a signed JWT for the current session. 404 when unconfigured. */
  readonly jwtToken: () => Promise<JWTTokenView>;
  /** The JWKS that verifies {@link jwtToken}'s tokens. 404 when unconfigured. */
  readonly jwks: () => Promise<JwksView>;

  /**
   * The signed-in user's login handles (email / username / phone). The server
   * refuses to delete the last one (400) so an account is never orphaned.
   */
  readonly identifiers: {
    readonly list: () => Promise<IdentifierListView>;
    readonly delete: (identifierId: string) => Promise<void>;
  };

  /** Verification-gated email change. 404 when unconfigured. */
  readonly changeEmail: {
    readonly request: (payload: ChangeEmailRequestPayload) => Promise<StatusResponse>;
    readonly confirm: (payload: ChangeEmailConfirmPayload) => Promise<StatusResponse>;
  };

  /** Self-service account deletion. 404 when unconfigured. */
  readonly deleteUser: {
    readonly request: () => Promise<StatusResponse>;
    readonly confirm: (payload: DeleteUserConfirmPayload) => Promise<StatusResponse>;
  };

  /** Multi-account management (several accounts per device). 404 when unconfigured. */
  readonly multiSession: {
    readonly list: () => Promise<MultiSessionListView>;
    readonly setActive: (payload: MultiSessionActionPayload) => Promise<StatusResponse>;
    readonly revoke: (payload: MultiSessionActionPayload) => Promise<StatusResponse>;
  };

  readonly magicLink: {
    readonly send: (payload: { email: string }) => Promise<StatusResponse>;
    readonly verify: (payload: { token: string }) => Promise<AuthSuccess>;
  };

  readonly emailOTP: {
    readonly send: (payload: {
      email: string;
      purpose: EmailOTPPurpose;
    }) => Promise<StatusResponse>;
    readonly signIn: (payload: { email: string; otp: string }) => Promise<AuthSuccess>;
  };

  /** SMS one-time passcodes. 404 when unconfigured. */
  readonly phoneOTP: {
    readonly send: (payload: {
      phoneNumber: string;
      purpose: PhoneOTPPurpose;
    }) => Promise<StatusResponse>;
    readonly signIn: (payload: { phoneNumber: string; otp: string }) => Promise<AuthSuccess>;
  };

  /** Google One Tap. 404 when unconfigured. */
  readonly googleOneTap: {
    /** Server-generated nonce to hand to Google's One Tap prompt. */
    readonly nonce: () => Promise<GoogleOneTapNonceView>;
    readonly signIn: (payload: GoogleOneTapPayload) => Promise<AuthSuccess>;
  };

  /**
   * Device authorization grant (RFC 8628). `code`/`token` are called by the
   * input-constrained device; `approve`/`deny` by the signed-in user on the
   * verification page. 404 when unconfigured.
   */
  readonly device: {
    readonly code: (payload?: DeviceCodePayload) => Promise<DeviceCodeView>;
    /** Poll for the session. 400 while the user has not decided yet. */
    readonly token: (payload: DeviceTokenPayload) => Promise<AuthSuccess>;
    readonly approve: (payload: DeviceUserCodePayload) => Promise<StatusResponse>;
    readonly deny: (payload: DeviceUserCodePayload) => Promise<StatusResponse>;
  };

  readonly multiFactor: {
    readonly enable: (payload: { password: string }) => Promise<MultiFactorEnableView>;
    readonly confirm: (payload: { code: string }) => Promise<StatusResponse>;
    readonly disable: (payload: { password: string }) => Promise<StatusResponse>;
    readonly regenerateBackupCodes: (payload: { password: string }) => Promise<BackupCodesView>;
    readonly verifyTotp: (payload: { token: string; code: string }) => Promise<AuthSuccess>;
    readonly verifyBackupCode: (payload: { token: string; code: string }) => Promise<AuthSuccess>;
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
    readonly challenge: (challenge: SecondFactorChallengeView) => SecondFactorContinuation;
    /**
     * Carry a gated sign-in straight into the second-factor step: takes the
     * `AuthSuccess` a sign-in returned and hands back the verify calls bound
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
    readonly continueChallenge: (result: AuthSuccess) => SecondFactorContinuation;
  };

  /**
   * Organizations: orgs, members, invitations, teams and per-organization
   * roles. Every call is session-authenticated; 404 when the module is absent
   * and 403 when the actor's role lacks the required permission.
   */
  readonly organization: {
    readonly create: (payload: CreateOrganizationPayload) => Promise<OrganizationView>;
    /** Organizations the signed-in user is a member of. */
    readonly list: () => Promise<OrganizationListView>;
    /** One organization together with its members. */
    readonly get: (organizationId: string) => Promise<FullOrganizationView>;
    readonly update: (
      organizationId: string,
      payload: UpdateOrganizationPayload,
    ) => Promise<OrganizationView>;
    readonly delete: (organizationId: string) => Promise<void>;
    /** Record the active organization on the session (`null` clears it). */
    readonly setActive: (payload: SetActiveOrganizationPayload) => Promise<StatusResponse>;

    readonly addMember: (organizationId: string, payload: AddMemberPayload) => Promise<MemberView>;
    readonly updateMemberRole: (
      organizationId: string,
      payload: UpdateMemberRolePayload,
    ) => Promise<MemberView>;
    readonly removeMember: (organizationId: string, userId: string) => Promise<void>;

    readonly invite: (
      organizationId: string,
      payload: InviteMemberPayload,
    ) => Promise<InvitationView>;
    readonly listInvitations: (organizationId: string) => Promise<InvitationListView>;
    /** Accept an invitation addressed to the signed-in user's email. */
    readonly acceptInvitation: (invitationId: string) => Promise<MemberView>;
    readonly rejectInvitation: (invitationId: string) => Promise<InvitationView>;
    readonly cancelInvitation: (invitationId: string) => Promise<InvitationView>;

    /** Define (or redefine) a role's permissions for one organization. */
    readonly upsertRole: (
      organizationId: string,
      role: string,
      payload: UpsertOrgRolePayload,
    ) => Promise<OrgRoleView>;
    readonly listRoles: (organizationId: string) => Promise<OrgRoleListView>;
    readonly deleteRole: (organizationId: string, role: string) => Promise<void>;

    readonly createTeam: (organizationId: string, payload: CreateTeamPayload) => Promise<TeamView>;
    readonly listTeams: (organizationId: string) => Promise<TeamListView>;
    readonly listTeamsForMember: (organizationId: string, userId: string) => Promise<TeamListView>;
    readonly updateTeam: (teamId: string, payload: UpdateTeamPayload) => Promise<TeamView>;
    readonly deleteTeam: (teamId: string) => Promise<void>;
    readonly addTeamMember: (
      teamId: string,
      payload: AddTeamMemberPayload,
    ) => Promise<TeamMemberView>;
    readonly listTeamMembers: (teamId: string) => Promise<TeamMemberListView>;
    readonly removeTeamMember: (teamId: string, userId: string) => Promise<void>;
  };

  /** API keys owned by the signed-in user. 404 when unconfigured. */
  readonly apiKeys: {
    /** The plaintext key is returned exactly once — show it, then discard. */
    readonly create: (payload: APIKeyCreatePayload) => Promise<APIKeyCreatedView>;
    readonly list: () => Promise<APIKeyListView>;
    readonly update: (keyId: string, payload: APIKeyUpdatePayload) => Promise<APIKeyView>;
    readonly delete: (keyId: string) => Promise<void>;
  };

  /** Administration. The actor must satisfy the server's `isAdmin`; 403 otherwise. */
  readonly admin: {
    readonly listUsers: (payload: AdminListUsersPayload) => Promise<AdminUserListView>;
    readonly setRole: (payload: AdminSetRolePayload) => Promise<UserView>;
    readonly banUser: (payload: AdminBanUserPayload) => Promise<UserView>;
    readonly unbanUser: (payload: AdminUserActionPayload) => Promise<UserView>;
    readonly removeUser: (payload: AdminUserActionPayload) => Promise<void>;
    readonly revokeSessions: (payload: AdminUserActionPayload) => Promise<StatusResponse>;
    /** Assume another user's identity — swaps the session cookie. */
    readonly impersonate: (payload: AdminUserActionPayload) => Promise<AuthSuccess>;
    readonly stopImpersonating: () => Promise<StatusResponse>;
  };

  /** Enterprise SSO (this server as an OIDC/SAML relying party). */
  readonly sso: {
    /** Register a connection (admin-gated). */
    readonly register: (payload: SSORegisterPayload) => Promise<SSOProviderView>;
    /** Resolve the IdP authorization URL to redirect the browser to. */
    readonly signIn: (payload: SSOSignInPayload) => Promise<SSOURLView>;
    /** Complete the callback and issue a session. */
    readonly callback: (payload: SSOCallbackPayload) => Promise<AuthSuccess>;
  };

  /**
   * OIDC provider surfaces a first-party app drives: client management
   * (admin-gated) and the consent page's decision. The protocol endpoints
   * themselves (`/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`,
   * discovery) are for OAuth clients, not this SDK.
   */
  readonly oidc: {
    readonly registerClient: (payload: OIDCRegisterClientPayload) => Promise<OIDCClientCreatedView>;
    readonly listClients: () => Promise<OIDCClientListView>;
    readonly updateClient: (
      clientId: string,
      payload: OIDCClientUpdatePayload,
    ) => Promise<OIDCClientView>;
    readonly deleteClient: (clientId: string) => Promise<void>;
    /** Post the consent decision; the response carries the redirect URL. */
    readonly consent: (payload: OIDCConsentPayload) => Promise<OIDCRedirectView>;
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

  const request = async <T>(method: string, path: string, body?: unknown): Promise<T> => {
    const response = await doFetch(`${baseUrl}${path}`, {
      method,
      credentials: "include",
      headers: {
        ...(body !== undefined && { "content-type": "application/json" }),
        ...options.headers,
      },
      ...(body !== undefined && { body: JSON.stringify(body) }),
    });
    if (!response.ok) {
      let message = response.statusText || `HTTP ${response.status}`;
      if (isJson(response)) {
        const parsed = (await response.json().catch(() => null)) as { message?: string } | null;
        if (parsed?.message !== undefined) message = parsed.message;
      }
      throw new AuthClientError(response.status, message);
    }
    if (response.status === 204 || !isJson(response)) {
      return undefined as T;
    }
    return (await response.json()) as T;
  };

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
    if (typeof document !== "undefined" && document.visibilityState === "visible") {
      void refetch();
    }
  };

  const setState = (next: SessionState, broadcast = true): void => {
    state = next;
    for (const listener of listeners) listener();
    if (broadcast && broadcastChannel !== undefined) {
      broadcastChannel.postMessage({ data: next.data });
    }
  };

  const getSession = async (): Promise<SessionWithUserView | null> => {
    try {
      return await request<SessionWithUserView>("GET", "/session");
    } catch (error) {
      if (error instanceof AuthClientError && error.status === 401) return null;
      throw error;
    }
  };

  const refetch = async (): Promise<void> => {
    const seq = ++refetchSeq;
    setState({ ...state, isPending: true });
    try {
      const data = await getSession();
      if (seq !== refetchSeq) return;
      setState({ data, isPending: false, error: null });
    } catch (error) {
      if (seq !== refetchSeq) return;
      setState({
        data: state.data,
        isPending: false,
        error:
          error instanceof AuthClientError
            ? error
            : new AuthClientError(0, error instanceof Error ? error.message : String(error)),
      });
    }
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
      if (typeof window !== "undefined") {
        window.addEventListener("focus", onFocus);
      }
      if (typeof document !== "undefined") {
        document.addEventListener("visibilitychange", onVisibilityChange);
      }
    }

    if (cfg.crossTab) {
      if (typeof BroadcastChannel !== "undefined") {
        const channelName = typeof cfg.crossTab === "string" ? cfg.crossTab : "effect-auth-session";
        broadcastChannel = new BroadcastChannel(channelName);
        broadcastChannel.onmessage = (
          event: MessageEvent<{ data: SessionWithUserView | null }>,
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

    if (typeof window !== "undefined") {
      window.removeEventListener("focus", onFocus);
    }
    if (typeof document !== "undefined") {
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

  /**
   * Bind a pending second-factor challenge to the verify endpoints, refusing
   * client-side once the challenge window has passed (the server enforces the
   * same expiry — this just saves a doomed round trip).
   */
  const continuation = (challenge: SecondFactorChallengeView): SecondFactorContinuation => {
    const isExpired = (): boolean => Date.now() >= challenge.expiresAt;
    const verify = (path: string, code: string): Promise<AuthSuccess> => {
      if (isExpired()) {
        return Promise.reject(
          new SecondFactorChallengeError(
            "expired",
            "The second-factor challenge has expired — sign in again",
          ),
        );
      }
      return mutating(() => request<AuthSuccess>("POST", path, { token: challenge.token, code }));
    };
    return {
      token: challenge.token,
      expiresAt: challenge.expiresAt,
      isExpired,
      verifyTotp: (code) => verify("/multi-factor/verify-totp", code),
      verifyBackupCode: (code) => verify("/multi-factor/verify-backup-code", code),
    };
  };

  // Use `let` so the `extend` closure can reference `self` after assignment.
  let self!: AuthClient;
  self = {
    session,

    signUp: (payload) => mutating(() => request<AuthSuccess>("POST", "/sign-up", payload)),
    signIn: (payload) => mutating(() => request<AuthSuccess>("POST", "/sign-in", payload)),
    signOut: () =>
      mutating(async () => {
        await request<void>("POST", "/sign-out");
      }),
    signInAnonymous: () => mutating(() => request<AuthSuccess>("POST", "/sign-in/anonymous")),
    signInUsername: (payload) =>
      mutating(() => request<AuthSuccess>("POST", "/sign-in/username", payload)),
    getSession,
    sendVerificationEmail: (payload) =>
      request<StatusResponse>("POST", "/email-verification/send", payload),
    verifyEmail: (payload) =>
      mutating(() => request<AuthSuccess>("POST", "/email-verification/verify", payload)),
    passwordResetRequest: (payload) =>
      request<StatusResponse>("POST", "/password-reset/request", payload),
    passwordResetConfirm: (payload) =>
      request<StatusResponse>("POST", "/password-reset/reset", payload),
    changePassword: (payload) => request<void>("POST", "/change-password", payload),
    updateUser: (payload) => mutating(() => request<UserView>("PATCH", "/user", payload)),
    listSessions: () => request<readonly SessionView[]>("GET", "/sessions"),
    revokeSession: (sessionId) => request<void>("DELETE", `/sessions/${seg(sessionId)}`),
    revokeOtherSessions: () => request<void>("POST", "/sessions/revoke-others"),
    jwtToken: () => request<JWTTokenView>("GET", "/token"),
    jwks: () => request<JwksView>("GET", "/jwks"),

    identifiers: {
      list: () => request<IdentifierListView>("GET", "/identifiers"),
      delete: (identifierId) => request<void>("DELETE", `/identifiers/${seg(identifierId)}`),
    },

    changeEmail: {
      request: (payload) => request<StatusResponse>("POST", "/change-email/request", payload),
      confirm: (payload) =>
        mutating(() => request<StatusResponse>("POST", "/change-email/confirm", payload)),
    },

    deleteUser: {
      request: () => request<StatusResponse>("POST", "/delete-user/request"),
      confirm: (payload) =>
        mutating(() => request<StatusResponse>("POST", "/delete-user/confirm", payload)),
    },

    multiSession: {
      list: () => request<MultiSessionListView>("GET", "/multi-session/list"),
      setActive: (payload) =>
        mutating(() => request<StatusResponse>("POST", "/multi-session/set-active", payload)),
      revoke: (payload) => request<StatusResponse>("POST", "/multi-session/revoke", payload),
    },

    magicLink: {
      send: (payload) => request<StatusResponse>("POST", "/magic-link/send", payload),
      verify: (payload) =>
        mutating(() => request<AuthSuccess>("POST", "/magic-link/verify", payload)),
    },

    emailOTP: {
      send: (payload) => request<StatusResponse>("POST", "/email-otp/send", payload),
      signIn: (payload) =>
        mutating(() => request<AuthSuccess>("POST", "/sign-in/email-otp", payload)),
    },

    phoneOTP: {
      send: (payload) => request<StatusResponse>("POST", "/phone-otp/send", payload),
      signIn: (payload) =>
        mutating(() => request<AuthSuccess>("POST", "/sign-in/phone-otp", payload)),
    },

    googleOneTap: {
      nonce: () => request<GoogleOneTapNonceView>("GET", "/sign-in/google-one-tap/nonce"),
      signIn: (payload) =>
        mutating(() => request<AuthSuccess>("POST", "/sign-in/google-one-tap", payload)),
    },

    device: {
      code: (payload) => request<DeviceCodeView>("POST", "/device/code", payload ?? {}),
      token: (payload) => mutating(() => request<AuthSuccess>("POST", "/device/token", payload)),
      approve: (payload) => request<StatusResponse>("POST", "/device/approve", payload),
      deny: (payload) => request<StatusResponse>("POST", "/device/deny", payload),
    },

    multiFactor: {
      enable: (payload) => request<MultiFactorEnableView>("POST", "/multi-factor/enable", payload),
      confirm: (payload) => request<StatusResponse>("POST", "/multi-factor/confirm", payload),
      disable: (payload) => request<StatusResponse>("POST", "/multi-factor/disable", payload),
      regenerateBackupCodes: (payload) =>
        request<BackupCodesView>("POST", "/multi-factor/regenerate-backup-codes", payload),
      verifyTotp: (payload) =>
        mutating(() => request<AuthSuccess>("POST", "/multi-factor/verify-totp", payload)),
      verifyBackupCode: (payload) =>
        mutating(() => request<AuthSuccess>("POST", "/multi-factor/verify-backup-code", payload)),
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
      create: (payload) => request<OrganizationView>("POST", "/organization/create", payload),
      list: () => request<OrganizationListView>("GET", "/organizations"),
      get: (organizationId) =>
        request<FullOrganizationView>("GET", `/organization/${seg(organizationId)}`),
      update: (organizationId, payload) =>
        request<OrganizationView>("PATCH", `/organization/${seg(organizationId)}`, payload),
      delete: (organizationId) => request<void>("DELETE", `/organization/${seg(organizationId)}`),
      // The active organization is stored on the session, so refresh the store.
      setActive: (payload) =>
        mutating(() => request<StatusResponse>("POST", "/organization/set-active", payload)),

      addMember: (organizationId, payload) =>
        request<MemberView>("POST", `/organization/${seg(organizationId)}/members`, payload),
      updateMemberRole: (organizationId, payload) =>
        request<MemberView>("PATCH", `/organization/${seg(organizationId)}/members`, payload),
      removeMember: (organizationId, userId) =>
        request<void>("DELETE", `/organization/${seg(organizationId)}/members/${seg(userId)}`),

      invite: (organizationId, payload) =>
        request<InvitationView>(
          "POST",
          `/organization/${seg(organizationId)}/invitations`,
          payload,
        ),
      listInvitations: (organizationId) =>
        request<InvitationListView>("GET", `/organization/${seg(organizationId)}/invitations`),
      acceptInvitation: (invitationId) =>
        request<MemberView>("POST", `/invitations/${seg(invitationId)}/accept`),
      rejectInvitation: (invitationId) =>
        request<InvitationView>("POST", `/invitations/${seg(invitationId)}/reject`),
      cancelInvitation: (invitationId) =>
        request<InvitationView>("POST", `/invitations/${seg(invitationId)}/cancel`),

      upsertRole: (organizationId, role, payload) =>
        request<OrgRoleView>(
          "PUT",
          `/organization/${seg(organizationId)}/roles/${seg(role)}`,
          payload,
        ),
      listRoles: (organizationId) =>
        request<OrgRoleListView>("GET", `/organization/${seg(organizationId)}/roles`),
      deleteRole: (organizationId, role) =>
        request<void>("DELETE", `/organization/${seg(organizationId)}/roles/${seg(role)}`),

      createTeam: (organizationId, payload) =>
        request<TeamView>("POST", `/organization/${seg(organizationId)}/teams`, payload),
      listTeams: (organizationId) =>
        request<TeamListView>("GET", `/organization/${seg(organizationId)}/teams`),
      listTeamsForMember: (organizationId, userId) =>
        request<TeamListView>(
          "GET",
          `/organization/${seg(organizationId)}/members/${seg(userId)}/teams`,
        ),
      updateTeam: (teamId, payload) => request<TeamView>("PATCH", `/teams/${seg(teamId)}`, payload),
      deleteTeam: (teamId) => request<void>("DELETE", `/teams/${seg(teamId)}`),
      addTeamMember: (teamId, payload) =>
        request<TeamMemberView>("POST", `/teams/${seg(teamId)}/members`, payload),
      listTeamMembers: (teamId) =>
        request<TeamMemberListView>("GET", `/teams/${seg(teamId)}/members`),
      removeTeamMember: (teamId, userId) =>
        request<void>("DELETE", `/teams/${seg(teamId)}/members/${seg(userId)}`),
    },

    apiKeys: {
      create: (payload) => request<APIKeyCreatedView>("POST", "/api-keys", payload),
      list: () => request<APIKeyListView>("GET", "/api-keys"),
      update: (keyId, payload) => request<APIKeyView>("PATCH", `/api-keys/${seg(keyId)}`, payload),
      delete: (keyId) => request<void>("DELETE", `/api-keys/${seg(keyId)}`),
    },

    admin: {
      listUsers: (payload) => request<AdminUserListView>("POST", "/admin/users/list", payload),
      setRole: (payload) => request<UserView>("POST", "/admin/users/set-role", payload),
      banUser: (payload) => request<UserView>("POST", "/admin/users/ban", payload),
      unbanUser: (payload) => request<UserView>("POST", "/admin/users/unban", payload),
      removeUser: (payload) => request<void>("POST", "/admin/users/remove", payload),
      revokeSessions: (payload) =>
        request<StatusResponse>("POST", "/admin/users/revoke-sessions", payload),
      // Impersonation swaps the session cookie in both directions.
      impersonate: (payload) =>
        mutating(() => request<AuthSuccess>("POST", "/admin/impersonate", payload)),
      stopImpersonating: () =>
        mutating(() => request<StatusResponse>("POST", "/admin/stop-impersonating")),
    },

    sso: {
      register: (payload) => request<SSOProviderView>("POST", "/sso/register", payload),
      signIn: (payload) => request<SSOURLView>("POST", "/sign-in/sso", payload),
      callback: (payload) => mutating(() => request<AuthSuccess>("POST", "/sso/callback", payload)),
    },

    oidc: {
      registerClient: (payload) =>
        request<OIDCClientCreatedView>("POST", "/oauth2/register", payload),
      listClients: () => request<OIDCClientListView>("GET", "/oauth2/clients"),
      updateClient: (clientId, payload) =>
        request<OIDCClientView>("PATCH", `/oauth2/clients/${seg(clientId)}`, payload),
      deleteClient: (clientId) => request<void>("DELETE", `/oauth2/clients/${seg(clientId)}`),
      consent: (payload) => request<OIDCRedirectView>("POST", "/oauth2/consent", payload),
    },

    extend: <TExtension extends object>(
      plugin: AuthClientPlugin<TExtension>,
    ): AuthClient & TExtension =>
      Object.assign(Object.create(null), self, plugin.install(pluginContext)) as AuthClient &
        TExtension,
  };

  return self;
};
