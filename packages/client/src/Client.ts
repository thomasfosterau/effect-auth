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
  AuthSuccess,
  BackupCodesView,
  ChangeEmailConfirmPayload,
  ChangeEmailRequestPayload,
  ChangePasswordPayload,
  DeleteUserConfirmPayload,
  EmailOTPPurpose,
  JWTTokenView,
  MultiSessionActionPayload,
  MultiSessionListView,
  SecondFactorChallengeView,
  SessionView,
  SessionWithUserView,
  SignInPayload,
  SignUpPayload,
  StatusResponse,
  MultiFactorEnableView,
  UpdateUserPayload,
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
    readonly challenge: (challenge: SecondFactorChallengeView) => {
      readonly verifyTotp: (code: string) => Promise<AuthSuccess>;
      readonly verifyBackupCode: (code: string) => Promise<AuthSuccess>;
    };
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
    revokeSession: (sessionId) =>
      request<void>("DELETE", `/sessions/${encodeURIComponent(sessionId)}`),
    revokeOtherSessions: () => request<void>("POST", "/sessions/revoke-others"),
    jwtToken: () => request<JWTTokenView>("GET", "/token"),

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
      challenge: (ch) => ({
        verifyTotp: (code) =>
          mutating(() =>
            request<AuthSuccess>("POST", "/multi-factor/verify-totp", { token: ch.token, code }),
          ),
        verifyBackupCode: (code) =>
          mutating(() =>
            request<AuthSuccess>("POST", "/multi-factor/verify-backup-code", {
              token: ch.token,
              code,
            }),
          ),
      }),
    },

    extend: <TExtension extends object>(
      plugin: AuthClientPlugin<TExtension>,
    ): AuthClient & TExtension =>
      Object.assign(Object.create(null), self, plugin.install(pluginContext)) as AuthClient &
        TExtension,
  };

  return self;
};
