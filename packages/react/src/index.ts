/**
 * React bindings for `@thomasfosterau/effect-auth-client`: hooks over the
 * client's observable session store, plus a set of unstyled, accessible form
 * components covering the usual authentication screens.
 *
 * ```tsx
 * const client = createAuthClient({ baseUrl: "/api/auth" });
 *
 * function Navbar() {
 *   const { data, isPending } = useSession(client);
 *   if (isPending) return <Spinner />;
 *   return data ? <b>{data.user.email}</b> : <a href="/login">Sign in</a>;
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
 * @module effect-auth-react
 */
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import type { AuthClient, AuthClientError, SessionState } from "@thomasfosterau/effect-auth-client";

export { AuthClientProvider, useAuthClient } from "./AuthClientContext.tsx";
export type { AuthClientProviderProps } from "./AuthClientContext.tsx";

export type {
  AuthFormBaseProps,
  AuthFormClasses,
  AuthSuccess,
  StatusResponse,
} from "./forms/internal.tsx";

export { SignInForm } from "./forms/SignInForm.tsx";
export type { SignInFormProps, SignInLabels } from "./forms/SignInForm.tsx";

export { SignUpForm } from "./forms/SignUpForm.tsx";
export type { SignUpFormProps, SignUpLabels } from "./forms/SignUpForm.tsx";

export { PasswordResetRequestForm } from "./forms/PasswordResetRequestForm.tsx";
export type {
  PasswordResetRequestFormProps,
  PasswordResetRequestLabels,
} from "./forms/PasswordResetRequestForm.tsx";

export { PasswordResetConfirmForm } from "./forms/PasswordResetConfirmForm.tsx";
export type {
  PasswordResetConfirmFormProps,
  PasswordResetConfirmLabels,
} from "./forms/PasswordResetConfirmForm.tsx";

export { MagicLinkForm } from "./forms/MagicLinkForm.tsx";
export type { MagicLinkFormProps, MagicLinkLabels } from "./forms/MagicLinkForm.tsx";

export { EmailOtpForm } from "./forms/EmailOtpForm.tsx";
export type { EmailOtpFormProps, EmailOtpLabels } from "./forms/EmailOtpForm.tsx";

/** The sessions `client.listSessions()` resolves to. */
type SessionList = Awaited<ReturnType<AuthClient["listSessions"]>>;

/**
 * Subscribe to the client's session store. The first mounted hook triggers
 * the initial session fetch; every auth mutation on the client refreshes it.
 */
export const useSession = (client: AuthClient): SessionState =>
  useSyncExternalStore(client.session.subscribe, client.session.get, client.session.get);

/** The state of a {@link useListSessions} query. */
export interface ListSessionsState {
  readonly data: SessionList | null;
  readonly isPending: boolean;
  readonly error: AuthClientError | null;
  /** Re-run the query (e.g. after revoking a session). */
  readonly refetch: () => void;
}

/** Fetch the authenticated user's active sessions. */
export const useListSessions = (client: AuthClient): ListSessionsState => {
  const [data, setData] = useState<SessionList | null>(null);
  const [isPending, setIsPending] = useState(true);
  const [error, setError] = useState<AuthClientError | null>(null);
  const [generation, setGeneration] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setIsPending(true);
    client
      .listSessions()
      .then((sessions) => {
        if (cancelled) return;
        setData(sessions);
        setError(null);
        setIsPending(false);
      })
      .catch((cause: AuthClientError) => {
        if (cancelled) return;
        setData(null);
        setError(cause);
        setIsPending(false);
      });
    return () => {
      cancelled = true;
    };
  }, [client, generation]);

  const refetch = useCallback(() => setGeneration((n) => n + 1), []);

  return { data, isPending, error, refetch };
};
