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
import type * as Auth from "@thomasfosterau/effect-auth";

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
  readonly verifyTotp: (code: string) => Promise<Auth.Http.AuthSuccess>;
  /** Redeem the challenge with a single-use backup code. */
  readonly verifyBackupCode: (code: string) => Promise<Auth.Http.AuthSuccess>;
}

/** The session store's state. */
export interface SessionState {
  /** The authenticated session + user, or `null` when signed out. */
  readonly data: Auth.Http.SessionWithUserView | null;
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

/** The auth client: typed methods over the contract + the session store. */
export interface AuthClient {
  readonly session: SessionStore;

  readonly signUp: (payload: Auth.Http.SignUpPayload) => Promise<Auth.Http.AuthSuccess>;
  readonly signIn: (payload: Auth.Http.SignInPayload) => Promise<Auth.Http.AuthSuccess>;
  readonly signOut: () => Promise<void>;
  /** Guest sign-in — creates an anonymous user + session. 404 when unconfigured. */
  readonly signInAnonymous: () => Promise<Auth.Http.AuthSuccess>;
  /** Username + password sign-in. 404 when unconfigured. */
  readonly signInUsername: (
    payload: Auth.Http.UsernameSignInPayload,
  ) => Promise<Auth.Http.AuthSuccess>;
  /** Resolves `null` when not authenticated (401). */
  readonly getSession: () => Promise<Auth.Http.SessionWithUserView | null>;
  readonly sendVerificationEmail: (payload: { email: string }) => Promise<Auth.Http.StatusResponse>;
  readonly verifyEmail: (payload: { token: string }) => Promise<Auth.Http.AuthSuccess>;
  readonly passwordResetRequest: (payload: { email: string }) => Promise<Auth.Http.StatusResponse>;
  readonly passwordResetConfirm: (payload: {
    token: string;
    newPassword: string;
  }) => Promise<Auth.Http.StatusResponse>;
  readonly changePassword: (payload: Auth.Http.ChangePasswordPayload) => Promise<void>;
  readonly updateUser: (payload: Auth.Http.UpdateUserPayload) => Promise<Auth.Http.UserView>;
  readonly listSessions: () => Promise<readonly Auth.Http.SessionView[]>;
  readonly revokeSession: (sessionId: string) => Promise<void>;
  readonly revokeOtherSessions: () => Promise<void>;
  /** Fetch a signed JWT for the current session. 404 when unconfigured. */
  readonly jwtToken: () => Promise<Auth.Http.JwtTokenView>;
  /** The JWKS that verifies {@link jwtToken}'s tokens. 404 when unconfigured. */
  readonly jwks: () => Promise<Auth.Http.JwksView>;

  /**
   * The signed-in user's login handles (email / username / phone). The server
   * refuses to delete the last one (400) so an account is never orphaned.
   */
  readonly identifiers: {
    readonly list: () => Promise<Auth.Http.IdentifierListView>;
    readonly delete: (identifierId: string) => Promise<void>;
  };

  /** Verification-gated email change. 404 when unconfigured. */
  readonly changeEmail: {
    readonly request: (
      payload: Auth.Http.ChangeEmailRequestPayload,
    ) => Promise<Auth.Http.StatusResponse>;
    readonly confirm: (
      payload: Auth.Http.ChangeEmailConfirmPayload,
    ) => Promise<Auth.Http.StatusResponse>;
  };

  /** Self-service account deletion. 404 when unconfigured. */
  readonly deleteUser: {
    readonly request: () => Promise<Auth.Http.StatusResponse>;
    readonly confirm: (
      payload: Auth.Http.DeleteUserConfirmPayload,
    ) => Promise<Auth.Http.StatusResponse>;
  };

  /** Multi-account management (several accounts per device). 404 when unconfigured. */
  readonly multiSession: {
    readonly list: () => Promise<Auth.Http.MultiSessionListView>;
    readonly setActive: (
      payload: Auth.Http.MultiSessionActionPayload,
    ) => Promise<Auth.Http.StatusResponse>;
    readonly revoke: (
      payload: Auth.Http.MultiSessionActionPayload,
    ) => Promise<Auth.Http.StatusResponse>;
  };

  readonly magicLink: {
    readonly send: (payload: { email: string }) => Promise<Auth.Http.StatusResponse>;
    readonly verify: (payload: { token: string }) => Promise<Auth.Http.AuthSuccess>;
  };

  readonly emailOtp: {
    readonly send: (payload: {
      email: string;
      purpose: Auth.Http.EmailOtpPurpose;
    }) => Promise<Auth.Http.StatusResponse>;
    readonly signIn: (payload: { email: string; otp: string }) => Promise<Auth.Http.AuthSuccess>;
  };

  /** SMS one-time passcodes. 404 when unconfigured. */
  readonly phoneOtp: {
    readonly send: (payload: {
      phoneNumber: string;
      purpose: Auth.Http.PhoneOtpPurpose;
    }) => Promise<Auth.Http.StatusResponse>;
    readonly signIn: (payload: {
      phoneNumber: string;
      otp: string;
    }) => Promise<Auth.Http.AuthSuccess>;
  };

  /** Google One Tap. 404 when unconfigured. */
  readonly googleOneTap: {
    /** Server-generated nonce to hand to Google's One Tap prompt. */
    readonly nonce: () => Promise<Auth.Http.GoogleOneTapNonceView>;
    readonly signIn: (payload: Auth.Http.GoogleOneTapPayload) => Promise<Auth.Http.AuthSuccess>;
  };

  /**
   * Device authorization grant (RFC 8628). `code`/`token` are called by the
   * input-constrained device; `approve`/`deny` by the signed-in user on the
   * verification page. 404 when unconfigured.
   */
  readonly device: {
    readonly code: (payload?: Auth.Http.DeviceCodePayload) => Promise<Auth.Http.DeviceCodeView>;
    /** Poll for the session. 400 while the user has not decided yet. */
    readonly token: (payload: Auth.Http.DeviceTokenPayload) => Promise<Auth.Http.AuthSuccess>;
    readonly approve: (
      payload: Auth.Http.DeviceUserCodePayload,
    ) => Promise<Auth.Http.StatusResponse>;
    readonly deny: (payload: Auth.Http.DeviceUserCodePayload) => Promise<Auth.Http.StatusResponse>;
  };

  readonly multiFactor: {
    readonly enable: (payload: { password: string }) => Promise<Auth.Http.MultiFactorEnableView>;
    readonly confirm: (payload: { code: string }) => Promise<Auth.Http.StatusResponse>;
    readonly disable: (payload: { password: string }) => Promise<Auth.Http.StatusResponse>;
    readonly regenerateBackupCodes: (payload: {
      password: string;
    }) => Promise<Auth.Http.BackupCodesView>;
    readonly verifyTotp: (payload: {
      token: string;
      code: string;
    }) => Promise<Auth.Http.AuthSuccess>;
    readonly verifyBackupCode: (payload: {
      token: string;
      code: string;
    }) => Promise<Auth.Http.AuthSuccess>;
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
    readonly challenge: (
      challenge: Auth.Http.SecondFactorChallengeView,
    ) => SecondFactorContinuation;
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
    readonly continueChallenge: (result: Auth.Http.AuthSuccess) => SecondFactorContinuation;
  };

  /**
   * Organizations: orgs, members, invitations, teams and per-organization
   * roles. Every call is session-authenticated; 404 when the module is absent
   * and 403 when the actor's role lacks the required permission.
   */
  readonly organization: {
    readonly create: (
      payload: Auth.Http.CreateOrganizationPayload,
    ) => Promise<Auth.Http.OrganizationView>;
    /** Organizations the signed-in user is a member of. */
    readonly list: () => Promise<Auth.Http.OrganizationListView>;
    /** One organization together with its members. */
    readonly get: (organizationId: string) => Promise<Auth.Http.FullOrganizationView>;
    readonly update: (
      organizationId: string,
      payload: Auth.Http.UpdateOrganizationPayload,
    ) => Promise<Auth.Http.OrganizationView>;
    readonly delete: (organizationId: string) => Promise<void>;
    /** Record the active organization on the session (`null` clears it). */
    readonly setActive: (
      payload: Auth.Http.SetActiveOrganizationPayload,
    ) => Promise<Auth.Http.StatusResponse>;

    readonly addMember: (
      organizationId: string,
      payload: Auth.Http.AddMemberPayload,
    ) => Promise<Auth.Http.MemberView>;
    readonly updateMemberRole: (
      organizationId: string,
      payload: Auth.Http.UpdateMemberRolePayload,
    ) => Promise<Auth.Http.MemberView>;
    readonly removeMember: (organizationId: string, userId: string) => Promise<void>;

    readonly invite: (
      organizationId: string,
      payload: Auth.Http.InviteMemberPayload,
    ) => Promise<Auth.Http.InvitationView>;
    readonly listInvitations: (organizationId: string) => Promise<Auth.Http.InvitationListView>;
    /** Accept an invitation addressed to the signed-in user's email. */
    readonly acceptInvitation: (invitationId: string) => Promise<Auth.Http.MemberView>;
    readonly rejectInvitation: (invitationId: string) => Promise<Auth.Http.InvitationView>;
    readonly cancelInvitation: (invitationId: string) => Promise<Auth.Http.InvitationView>;

    /** Define (or redefine) a role's permissions for one organization. */
    readonly upsertRole: (
      organizationId: string,
      role: string,
      payload: Auth.Http.UpsertOrgRolePayload,
    ) => Promise<Auth.Http.OrgRoleView>;
    readonly listRoles: (organizationId: string) => Promise<Auth.Http.OrgRoleListView>;
    readonly deleteRole: (organizationId: string, role: string) => Promise<void>;

    readonly createTeam: (
      organizationId: string,
      payload: Auth.Http.CreateTeamPayload,
    ) => Promise<Auth.Http.TeamView>;
    readonly listTeams: (organizationId: string) => Promise<Auth.Http.TeamListView>;
    readonly listTeamsForMember: (
      organizationId: string,
      userId: string,
    ) => Promise<Auth.Http.TeamListView>;
    readonly updateTeam: (
      teamId: string,
      payload: Auth.Http.UpdateTeamPayload,
    ) => Promise<Auth.Http.TeamView>;
    readonly deleteTeam: (teamId: string) => Promise<void>;
    readonly addTeamMember: (
      teamId: string,
      payload: Auth.Http.AddTeamMemberPayload,
    ) => Promise<Auth.Http.TeamMemberView>;
    readonly listTeamMembers: (teamId: string) => Promise<Auth.Http.TeamMemberListView>;
    readonly removeTeamMember: (teamId: string, userId: string) => Promise<void>;
  };

  /** API keys owned by the signed-in user. 404 when unconfigured. */
  readonly apiKeys: {
    /** The plaintext key is returned exactly once — show it, then discard. */
    readonly create: (
      payload: Auth.Http.ApiKeyCreatePayload,
    ) => Promise<Auth.Http.ApiKeyCreatedView>;
    readonly list: () => Promise<Auth.Http.ApiKeyListView>;
    readonly update: (
      keyId: string,
      payload: Auth.Http.ApiKeyUpdatePayload,
    ) => Promise<Auth.Http.ApiKeyView>;
    readonly delete: (keyId: string) => Promise<void>;
  };

  /** Administration. The actor must satisfy the server's `isAdmin`; 403 otherwise. */
  readonly admin: {
    readonly listUsers: (
      payload: Auth.Http.AdminListUsersPayload,
    ) => Promise<Auth.Http.AdminUserListView>;
    readonly setRole: (payload: Auth.Http.AdminSetRolePayload) => Promise<Auth.Http.UserView>;
    readonly banUser: (payload: Auth.Http.AdminBanUserPayload) => Promise<Auth.Http.UserView>;
    readonly unbanUser: (payload: Auth.Http.AdminUserActionPayload) => Promise<Auth.Http.UserView>;
    readonly removeUser: (payload: Auth.Http.AdminUserActionPayload) => Promise<void>;
    readonly revokeSessions: (
      payload: Auth.Http.AdminUserActionPayload,
    ) => Promise<Auth.Http.StatusResponse>;
    /** Assume another user's identity — swaps the session cookie. */
    readonly impersonate: (
      payload: Auth.Http.AdminUserActionPayload,
    ) => Promise<Auth.Http.AuthSuccess>;
    readonly stopImpersonating: () => Promise<Auth.Http.StatusResponse>;
  };

  /** Enterprise SSO (this server as an OIDC/SAML relying party). */
  readonly sso: {
    /** Register a connection (admin-gated). */
    readonly register: (
      payload: Auth.Http.SsoRegisterPayload,
    ) => Promise<Auth.Http.SsoProviderView>;
    /** Resolve the IdP authorization URL to redirect the browser to. */
    readonly signIn: (payload: Auth.Http.SsoSignInPayload) => Promise<Auth.Http.SsoUrlView>;
    /** Complete the callback and issue a session. */
    readonly callback: (payload: Auth.Http.SsoCallbackPayload) => Promise<Auth.Http.AuthSuccess>;
  };

  /**
   * OIDC provider surfaces a first-party app drives: client management
   * (admin-gated) and the consent page's decision. The protocol endpoints
   * themselves (`/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`,
   * discovery) are for OAuth clients, not this SDK.
   */
  readonly oidc: {
    readonly registerClient: (
      payload: Auth.Http.OidcRegisterClientPayload,
    ) => Promise<Auth.Http.OidcClientCreatedView>;
    readonly listClients: () => Promise<Auth.Http.OidcClientListView>;
    readonly updateClient: (
      clientId: string,
      payload: Auth.Http.OidcClientUpdatePayload,
    ) => Promise<Auth.Http.OidcClientView>;
    readonly deleteClient: (clientId: string) => Promise<void>;
    /** Post the consent decision; the response carries the redirect URL. */
    readonly consent: (
      payload: Auth.Http.OidcConsentPayload,
    ) => Promise<Auth.Http.OidcRedirectView>;
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

  const getSession = async (): Promise<Auth.Http.SessionWithUserView | null> => {
    try {
      return await request<Auth.Http.SessionWithUserView>("GET", "/session");
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
          event: MessageEvent<{ data: Auth.Http.SessionWithUserView | null }>,
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
  const continuation = (
    challenge: Auth.Http.SecondFactorChallengeView,
  ): SecondFactorContinuation => {
    const isExpired = (): boolean => Date.now() >= challenge.expiresAt;
    const verify = (path: string, code: string): Promise<Auth.Http.AuthSuccess> => {
      if (isExpired()) {
        return Promise.reject(
          new SecondFactorChallengeError(
            "expired",
            "The second-factor challenge has expired — sign in again",
          ),
        );
      }
      return mutating(() =>
        request<Auth.Http.AuthSuccess>("POST", path, { token: challenge.token, code }),
      );
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

    signUp: (payload) =>
      mutating(() => request<Auth.Http.AuthSuccess>("POST", "/sign-up", payload)),
    signIn: (payload) =>
      mutating(() => request<Auth.Http.AuthSuccess>("POST", "/sign-in", payload)),
    signOut: () =>
      mutating(async () => {
        await request<void>("POST", "/sign-out");
      }),
    signInAnonymous: () =>
      mutating(() => request<Auth.Http.AuthSuccess>("POST", "/sign-in/anonymous")),
    signInUsername: (payload) =>
      mutating(() => request<Auth.Http.AuthSuccess>("POST", "/sign-in/username", payload)),
    getSession,
    sendVerificationEmail: (payload) =>
      request<Auth.Http.StatusResponse>("POST", "/email-verification/send", payload),
    verifyEmail: (payload) =>
      mutating(() => request<Auth.Http.AuthSuccess>("POST", "/email-verification/verify", payload)),
    passwordResetRequest: (payload) =>
      request<Auth.Http.StatusResponse>("POST", "/password-reset/request", payload),
    passwordResetConfirm: (payload) =>
      request<Auth.Http.StatusResponse>("POST", "/password-reset/reset", payload),
    changePassword: (payload) => request<void>("POST", "/change-password", payload),
    updateUser: (payload) => mutating(() => request<Auth.Http.UserView>("PATCH", "/user", payload)),
    listSessions: () => request<readonly Auth.Http.SessionView[]>("GET", "/sessions"),
    revokeSession: (sessionId) =>
      request<void>("DELETE", `/sessions/${encodeURIComponent(sessionId)}`),
    revokeOtherSessions: () => request<void>("POST", "/sessions/revoke-others"),
    jwtToken: () => request<Auth.Http.JwtTokenView>("GET", "/token"),
    jwks: () => request<Auth.Http.JwksView>("GET", "/jwks"),

    identifiers: {
      list: () => request<Auth.Http.IdentifierListView>("GET", "/identifiers"),
      delete: (identifierId) =>
        request<void>("DELETE", `/identifiers/${encodeURIComponent(identifierId)}`),
    },

    changeEmail: {
      request: (payload) =>
        request<Auth.Http.StatusResponse>("POST", "/change-email/request", payload),
      confirm: (payload) =>
        mutating(() => request<Auth.Http.StatusResponse>("POST", "/change-email/confirm", payload)),
    },

    deleteUser: {
      request: () => request<Auth.Http.StatusResponse>("POST", "/delete-user/request"),
      confirm: (payload) =>
        mutating(() => request<Auth.Http.StatusResponse>("POST", "/delete-user/confirm", payload)),
    },

    multiSession: {
      list: () => request<Auth.Http.MultiSessionListView>("GET", "/multi-session/list"),
      setActive: (payload) =>
        mutating(() =>
          request<Auth.Http.StatusResponse>("POST", "/multi-session/set-active", payload),
        ),
      revoke: (payload) =>
        request<Auth.Http.StatusResponse>("POST", "/multi-session/revoke", payload),
    },

    magicLink: {
      send: (payload) => request<Auth.Http.StatusResponse>("POST", "/magic-link/send", payload),
      verify: (payload) =>
        mutating(() => request<Auth.Http.AuthSuccess>("POST", "/magic-link/verify", payload)),
    },

    emailOtp: {
      send: (payload) => request<Auth.Http.StatusResponse>("POST", "/email-otp/send", payload),
      signIn: (payload) =>
        mutating(() => request<Auth.Http.AuthSuccess>("POST", "/sign-in/email-otp", payload)),
    },

    phoneOtp: {
      send: (payload) => request<Auth.Http.StatusResponse>("POST", "/phone-otp/send", payload),
      signIn: (payload) =>
        mutating(() => request<Auth.Http.AuthSuccess>("POST", "/sign-in/phone-otp", payload)),
    },

    googleOneTap: {
      nonce: () => request<Auth.Http.GoogleOneTapNonceView>("GET", "/sign-in/google-one-tap/nonce"),
      signIn: (payload) =>
        mutating(() => request<Auth.Http.AuthSuccess>("POST", "/sign-in/google-one-tap", payload)),
    },

    device: {
      code: (payload) => request<Auth.Http.DeviceCodeView>("POST", "/device/code", payload ?? {}),
      token: (payload) =>
        mutating(() => request<Auth.Http.AuthSuccess>("POST", "/device/token", payload)),
      approve: (payload) => request<Auth.Http.StatusResponse>("POST", "/device/approve", payload),
      deny: (payload) => request<Auth.Http.StatusResponse>("POST", "/device/deny", payload),
    },

    multiFactor: {
      enable: (payload) =>
        request<Auth.Http.MultiFactorEnableView>("POST", "/multi-factor/enable", payload),
      confirm: (payload) =>
        request<Auth.Http.StatusResponse>("POST", "/multi-factor/confirm", payload),
      disable: (payload) =>
        request<Auth.Http.StatusResponse>("POST", "/multi-factor/disable", payload),
      regenerateBackupCodes: (payload) =>
        request<Auth.Http.BackupCodesView>(
          "POST",
          "/multi-factor/regenerate-backup-codes",
          payload,
        ),
      verifyTotp: (payload) =>
        mutating(() =>
          request<Auth.Http.AuthSuccess>("POST", "/multi-factor/verify-totp", payload),
        ),
      verifyBackupCode: (payload) =>
        mutating(() =>
          request<Auth.Http.AuthSuccess>("POST", "/multi-factor/verify-backup-code", payload),
        ),
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
      create: (payload) =>
        request<Auth.Http.OrganizationView>("POST", "/organization/create", payload),
      list: () => request<Auth.Http.OrganizationListView>("GET", "/organizations"),
      get: (organizationId) =>
        request<Auth.Http.FullOrganizationView>(
          "GET",
          `/organization/${encodeURIComponent(organizationId)}`,
        ),
      update: (organizationId, payload) =>
        request<Auth.Http.OrganizationView>(
          "PATCH",
          `/organization/${encodeURIComponent(organizationId)}`,
          payload,
        ),
      delete: (organizationId) =>
        request<void>("DELETE", `/organization/${encodeURIComponent(organizationId)}`),
      // The active organization is stored on the session, so refresh the store.
      setActive: (payload) =>
        mutating(() =>
          request<Auth.Http.StatusResponse>("POST", "/organization/set-active", payload),
        ),

      addMember: (organizationId, payload) =>
        request<Auth.Http.MemberView>(
          "POST",
          `/organization/${encodeURIComponent(organizationId)}/members`,
          payload,
        ),
      updateMemberRole: (organizationId, payload) =>
        request<Auth.Http.MemberView>(
          "PATCH",
          `/organization/${encodeURIComponent(organizationId)}/members`,
          payload,
        ),
      removeMember: (organizationId, userId) =>
        request<void>(
          "DELETE",
          `/organization/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(userId)}`,
        ),

      invite: (organizationId, payload) =>
        request<Auth.Http.InvitationView>(
          "POST",
          `/organization/${encodeURIComponent(organizationId)}/invitations`,
          payload,
        ),
      listInvitations: (organizationId) =>
        request<Auth.Http.InvitationListView>(
          "GET",
          `/organization/${encodeURIComponent(organizationId)}/invitations`,
        ),
      acceptInvitation: (invitationId) =>
        request<Auth.Http.MemberView>(
          "POST",
          `/invitations/${encodeURIComponent(invitationId)}/accept`,
        ),
      rejectInvitation: (invitationId) =>
        request<Auth.Http.InvitationView>(
          "POST",
          `/invitations/${encodeURIComponent(invitationId)}/reject`,
        ),
      cancelInvitation: (invitationId) =>
        request<Auth.Http.InvitationView>(
          "POST",
          `/invitations/${encodeURIComponent(invitationId)}/cancel`,
        ),

      upsertRole: (organizationId, role, payload) =>
        request<Auth.Http.OrgRoleView>(
          "PUT",
          `/organization/${encodeURIComponent(organizationId)}/roles/${encodeURIComponent(role)}`,
          payload,
        ),
      listRoles: (organizationId) =>
        request<Auth.Http.OrgRoleListView>(
          "GET",
          `/organization/${encodeURIComponent(organizationId)}/roles`,
        ),
      deleteRole: (organizationId, role) =>
        request<void>(
          "DELETE",
          `/organization/${encodeURIComponent(organizationId)}/roles/${encodeURIComponent(role)}`,
        ),

      createTeam: (organizationId, payload) =>
        request<Auth.Http.TeamView>(
          "POST",
          `/organization/${encodeURIComponent(organizationId)}/teams`,
          payload,
        ),
      listTeams: (organizationId) =>
        request<Auth.Http.TeamListView>(
          "GET",
          `/organization/${encodeURIComponent(organizationId)}/teams`,
        ),
      listTeamsForMember: (organizationId, userId) =>
        request<Auth.Http.TeamListView>(
          "GET",
          `/organization/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(userId)}/teams`,
        ),
      updateTeam: (teamId, payload) =>
        request<Auth.Http.TeamView>("PATCH", `/teams/${encodeURIComponent(teamId)}`, payload),
      deleteTeam: (teamId) => request<void>("DELETE", `/teams/${encodeURIComponent(teamId)}`),
      addTeamMember: (teamId, payload) =>
        request<Auth.Http.TeamMemberView>(
          "POST",
          `/teams/${encodeURIComponent(teamId)}/members`,
          payload,
        ),
      listTeamMembers: (teamId) =>
        request<Auth.Http.TeamMemberListView>(
          "GET",
          `/teams/${encodeURIComponent(teamId)}/members`,
        ),
      removeTeamMember: (teamId, userId) =>
        request<void>(
          "DELETE",
          `/teams/${encodeURIComponent(teamId)}/members/${encodeURIComponent(userId)}`,
        ),
    },

    apiKeys: {
      create: (payload) => request<Auth.Http.ApiKeyCreatedView>("POST", "/api-keys", payload),
      list: () => request<Auth.Http.ApiKeyListView>("GET", "/api-keys"),
      update: (keyId, payload) =>
        request<Auth.Http.ApiKeyView>("PATCH", `/api-keys/${encodeURIComponent(keyId)}`, payload),
      delete: (keyId) => request<void>("DELETE", `/api-keys/${encodeURIComponent(keyId)}`),
    },

    admin: {
      listUsers: (payload) =>
        request<Auth.Http.AdminUserListView>("POST", "/admin/users/list", payload),
      setRole: (payload) => request<Auth.Http.UserView>("POST", "/admin/users/set-role", payload),
      banUser: (payload) => request<Auth.Http.UserView>("POST", "/admin/users/ban", payload),
      unbanUser: (payload) => request<Auth.Http.UserView>("POST", "/admin/users/unban", payload),
      removeUser: (payload) => request<void>("POST", "/admin/users/remove", payload),
      revokeSessions: (payload) =>
        request<Auth.Http.StatusResponse>("POST", "/admin/users/revoke-sessions", payload),
      // Impersonation swaps the session cookie in both directions.
      impersonate: (payload) =>
        mutating(() => request<Auth.Http.AuthSuccess>("POST", "/admin/impersonate", payload)),
      stopImpersonating: () =>
        mutating(() => request<Auth.Http.StatusResponse>("POST", "/admin/stop-impersonating")),
    },

    sso: {
      register: (payload) => request<Auth.Http.SsoProviderView>("POST", "/sso/register", payload),
      signIn: (payload) => request<Auth.Http.SsoUrlView>("POST", "/sign-in/sso", payload),
      callback: (payload) =>
        mutating(() => request<Auth.Http.AuthSuccess>("POST", "/sso/callback", payload)),
    },

    oidc: {
      registerClient: (payload) =>
        request<Auth.Http.OidcClientCreatedView>("POST", "/oauth2/register", payload),
      listClients: () => request<Auth.Http.OidcClientListView>("GET", "/oauth2/clients"),
      updateClient: (clientId, payload) =>
        request<Auth.Http.OidcClientView>(
          "PATCH",
          `/oauth2/clients/${encodeURIComponent(clientId)}`,
          payload,
        ),
      deleteClient: (clientId) =>
        request<void>("DELETE", `/oauth2/clients/${encodeURIComponent(clientId)}`),
      consent: (payload) => request<Auth.Http.OidcRedirectView>("POST", "/oauth2/consent", payload),
    },

    extend: <TExtension extends object>(
      plugin: AuthClientPlugin<TExtension>,
    ): AuthClient & TExtension =>
      Object.assign(Object.create(null), self, plugin.install(pluginContext)) as AuthClient &
        TExtension,
  };

  return self;
};
