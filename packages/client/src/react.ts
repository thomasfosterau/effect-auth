/**
 * React bindings for `@effect-auth/client`.
 *
 * ```tsx
 * const client = createAuthClient({ baseUrl: "/api/auth" });
 *
 * function Navbar() {
 *   const { data, isPending } = useSession(client);
 *   if (isPending) return <Spinner />;
 *   return data ? <b>{data.user.email}</b> : <a href="/login">Sign in</a>;
 * }
 * ```
 *
 * @module react
 */
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import type { AuthClient, AuthClientError, SessionState } from "./Client.js";
import type { SessionView } from "./types.js";

/**
 * Subscribe to the client's session store. The first mounted hook triggers
 * the initial session fetch; every auth mutation on the client refreshes it.
 */
export const useSession = (client: AuthClient): SessionState =>
  useSyncExternalStore(client.session.subscribe, client.session.get, client.session.get);

/** The state of a {@link useListSessions} query. */
export interface ListSessionsState {
  readonly data: readonly SessionView[] | null;
  readonly isPending: boolean;
  readonly error: AuthClientError | null;
  /** Re-run the query (e.g. after revoking a session). */
  readonly refetch: () => void;
}

/** Fetch the authenticated user's active sessions. */
export const useListSessions = (client: AuthClient): ListSessionsState => {
  const [data, setData] = useState<readonly SessionView[] | null>(null);
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
