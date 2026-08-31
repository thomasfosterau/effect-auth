/**
 * Solid bindings for `@thomasfosterau/effect-auth-client`: reactive primitives
 * over the client's observable session store, plus a set of unstyled,
 * accessible form components covering the usual authentication screens.
 *
 * ```tsx
 * const client = createAuthClient({ baseUrl: "/api/auth" });
 *
 * function Navbar() {
 *   const session = createSession(client);
 *   return (
 *     <Show fallback={<a href="/login">Sign in</a>} when={session().data}>
 *       {(data) => <b>{data().user.email}</b>}
 *     </Show>
 *   );
 * }
 *
 * function Login() {
 *   return (
 *     <AuthClientProvider client={client}>
 *       <SignInForm onSuccess={() => navigate("/app")} />
 *     </AuthClientProvider>
 *   );
 * }
 * ```
 *
 * The components ship no CSS. Every element carries a stable `ea-*` class
 * (`ea-form`, `ea-field`, `ea-label`, `ea-input`, `ea-submit`, `ea-error`,
 * `ea-status`) for a stylesheet to target, and every one is overridable
 * per-instance through the `classes` prop.
 *
 * @module effect-auth-solid
 */
import { createSignal, getOwner, onCleanup } from "solid-js";
import type { Accessor } from "solid-js";
import type { AuthClient, AuthClientError, SessionState } from "@thomasfosterau/effect-auth-client";
import { useAuthClient } from "./AuthClientContext.jsx";

export { AuthClientContext, AuthClientProvider, useAuthClient } from "./AuthClientContext.jsx";
export type { AuthClientProviderProps } from "./AuthClientContext.jsx";

export type {
  AuthFormBaseProps,
  AuthFormClasses,
  AuthSuccess,
  StatusResponse,
} from "./forms/internal.jsx";

export { SignInForm } from "./forms/SignInForm.jsx";
export type { SignInFormProps, SignInLabels } from "./forms/SignInForm.jsx";

export { SignUpForm } from "./forms/SignUpForm.jsx";
export type { SignUpFormProps, SignUpLabels } from "./forms/SignUpForm.jsx";

export { PasswordResetRequestForm } from "./forms/PasswordResetRequestForm.jsx";
export type {
  PasswordResetRequestFormProps,
  PasswordResetRequestLabels,
} from "./forms/PasswordResetRequestForm.jsx";

export { PasswordResetConfirmForm } from "./forms/PasswordResetConfirmForm.jsx";
export type {
  PasswordResetConfirmFormProps,
  PasswordResetConfirmLabels,
} from "./forms/PasswordResetConfirmForm.jsx";

export { MagicLinkForm } from "./forms/MagicLinkForm.jsx";
export type { MagicLinkFormProps, MagicLinkLabels } from "./forms/MagicLinkForm.jsx";

export { EmailOtpForm } from "./forms/EmailOtpForm.jsx";
export type { EmailOtpFormProps, EmailOtpLabels } from "./forms/EmailOtpForm.jsx";

/** The sessions `client.listSessions()` resolves to. */
type SessionList = Awaited<ReturnType<AuthClient["listSessions"]>>;

const OUTSIDE_OWNER =
  "[effect-auth] was called outside a reactive owner (a component body or " +
  "createRoot). Call .dispose() on the returned value to avoid a subscription leak.";

/**
 * An accessor over the session store that also carries a `dispose()` for
 * manual cleanup when created outside a reactive owner.
 */
export type SessionAccessor = Accessor<SessionState> & {
  /** Unsubscribe from the store. Called for you when the owner is disposed. */
  readonly dispose: () => void;
};

/**
 * A signal tracking the client's session store.
 *
 * Subscribing triggers the client's initial `/session` fetch, and every auth
 * mutation on the client refreshes it. The subscription is released with the
 * owning component; created outside an owner (a plain script, a test), call
 * `.dispose()` yourself.
 *
 * ```tsx
 * const session = createSession(client);
 * <Show when={!session().isPending}>{session().data?.user.email ?? "signed out"}</Show>
 * ```
 */
export const createSession = (client: AuthClient): SessionAccessor => {
  const [state, setState] = createSignal<SessionState>(client.session.get());
  const unsubscribe = client.session.subscribe(() => setState(client.session.get()));
  if (getOwner() === null) console.warn(`createSession()${OUTSIDE_OWNER}`);
  else onCleanup(unsubscribe);
  return Object.assign(state, { dispose: unsubscribe });
};

/**
 * {@link createSession} against the client from the nearest
 * `<AuthClientProvider>`. Throws when there is no provider above it.
 */
export const useSession = (): SessionAccessor => createSession(useAuthClient());

/** The accessors returned by {@link createListSessions}. */
export interface ListSessionsResult {
  readonly data: Accessor<SessionList | null>;
  readonly isPending: Accessor<boolean>;
  readonly error: Accessor<AuthClientError | null>;
  /** Re-run the query (e.g. after revoking a session). */
  readonly refetch: () => void;
  /** Stop applying in-flight results. Called for you when the owner is disposed. */
  readonly dispose: () => void;
}

/**
 * Fetch the authenticated user's active sessions. The query runs immediately
 * and can be re-run with `refetch()`; results stop being applied once the
 * owner is disposed (or `.dispose()` is called outside one).
 */
export const createListSessions = (client: AuthClient): ListSessionsResult => {
  const [data, setData] = createSignal<SessionList | null>(null);
  const [isPending, setIsPending] = createSignal(true);
  const [error, setError] = createSignal<AuthClientError | null>(null);
  let disposed = false;

  const refetch = (): void => {
    setIsPending(true);
    client.listSessions().then(
      (sessions) => {
        if (disposed) return;
        setData(() => sessions);
        setError(null);
        setIsPending(false);
      },
      (cause: AuthClientError) => {
        if (disposed) return;
        setData(null);
        setError(cause);
        setIsPending(false);
      },
    );
  };

  const dispose = (): void => {
    disposed = true;
  };

  refetch();
  if (getOwner() === null) console.warn(`createListSessions()${OUTSIDE_OWNER}`);
  else onCleanup(dispose);

  return { data, isPending, error, refetch, dispose };
};

/**
 * {@link createListSessions} against the client from the nearest
 * `<AuthClientProvider>`. Throws when there is no provider above it.
 */
export const useListSessions = (): ListSessionsResult => createListSessions(useAuthClient());
