/**
 * Vanilla auth client for the effect-auth HTTP protocol.
 *
 * A small, dependency-free client (plain `fetch`, no Effect runtime in the
 * bundle) with methods mirroring the contract's endpoint names and an
 * observable session store that framework adapters subscribe to
 * (`@effect-auth/client/react`, `/svelte`, `/vue`).
 *
 * Only the wire *types* are imported from `effect-auth` — they erase at
 * compile time, so the browser bundle contains just this file.
 *
 * @module client
 */
import type {
  AuthSuccess,
  ChangePasswordPayload,
  EmailOtpPurpose,
  SessionView,
  SessionWithUserView,
  SignInPayload,
  SignUpPayload,
  StatusResponse,
  TwoFactorEnableView,
  BackupCodesView,
  UpdateUserPayload,
  UserView,
} from "./types.js";

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
}

const isJson = (response: Response): boolean =>
  (response.headers.get("content-type") ?? "").includes("application/json");

/** The auth client: typed methods over the contract + the session store. */
export interface AuthClient {
  readonly session: SessionStore;

  readonly signUp: (payload: SignUpPayload) => Promise<AuthSuccess>;
  readonly signIn: (payload: SignInPayload) => Promise<AuthSuccess>;
  readonly signOut: () => Promise<void>;
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

  readonly magicLink: {
    readonly send: (payload: { email: string }) => Promise<StatusResponse>;
    readonly verify: (payload: { token: string }) => Promise<AuthSuccess>;
  };

  readonly emailOtp: {
    readonly send: (payload: {
      email: string;
      purpose: EmailOtpPurpose;
    }) => Promise<StatusResponse>;
    readonly signIn: (payload: { email: string; otp: string }) => Promise<AuthSuccess>;
  };

  readonly twoFactor: {
    readonly enable: (payload: { password: string }) => Promise<TwoFactorEnableView>;
    readonly confirm: (payload: { code: string }) => Promise<StatusResponse>;
    readonly disable: (payload: { password: string }) => Promise<StatusResponse>;
    readonly regenerateBackupCodes: (payload: { password: string }) => Promise<BackupCodesView>;
    readonly verifyTotp: (payload: { token: string; code: string }) => Promise<AuthSuccess>;
    readonly verifyBackupCode: (payload: { token: string; code: string }) => Promise<AuthSuccess>;
  };
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

  const setState = (next: SessionState): void => {
    state = next;
    for (const listener of listeners) listener();
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

  const session: SessionStore = {
    get: () => state,
    subscribe: (listener) => {
      listeners.add(listener);
      if (!fetchedOnce) {
        fetchedOnce = true;
        void refetch();
      }
      return () => listeners.delete(listener);
    },
    refetch,
  };

  /** Run a session-changing call, then refresh the store (when observed). */
  const mutating = async <T>(run: () => Promise<T>): Promise<T> => {
    const result = await run();
    fetchedOnce = true;
    await refetch();
    return result;
  };

  return {
    session,

    signUp: (payload) => mutating(() => request<AuthSuccess>("POST", "/sign-up", payload)),
    signIn: (payload) => mutating(() => request<AuthSuccess>("POST", "/sign-in", payload)),
    signOut: () =>
      mutating(async () => {
        await request<void>("POST", "/sign-out");
      }),
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

    magicLink: {
      send: (payload) => request<StatusResponse>("POST", "/magic-link/send", payload),
      verify: (payload) =>
        mutating(() => request<AuthSuccess>("POST", "/magic-link/verify", payload)),
    },

    emailOtp: {
      send: (payload) => request<StatusResponse>("POST", "/email-otp/send", payload),
      signIn: (payload) =>
        mutating(() => request<AuthSuccess>("POST", "/sign-in/email-otp", payload)),
    },

    twoFactor: {
      enable: (payload) => request<TwoFactorEnableView>("POST", "/two-factor/enable", payload),
      confirm: (payload) => request<StatusResponse>("POST", "/two-factor/confirm", payload),
      disable: (payload) => request<StatusResponse>("POST", "/two-factor/disable", payload),
      regenerateBackupCodes: (payload) =>
        request<BackupCodesView>("POST", "/two-factor/regenerate-backup-codes", payload),
      verifyTotp: (payload) =>
        mutating(() => request<AuthSuccess>("POST", "/two-factor/verify-totp", payload)),
      verifyBackupCode: (payload) =>
        mutating(() => request<AuthSuccess>("POST", "/two-factor/verify-backup-code", payload)),
    },
  };
};
