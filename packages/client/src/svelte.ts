/**
 * Svelte bindings for `@effect-auth/client`.
 *
 * `sessionStore` implements Svelte's readable-store contract directly (no
 * `svelte` import needed), so it works with the `$store` syntax:
 *
 * ```svelte
 * <script>
 *   const session = sessionStore(client);
 * </script>
 * {#if $session.data}Signed in as {$session.data.user.email}{/if}
 * ```
 *
 * @module svelte
 */
import type { AuthClient, AuthClientError, SessionState } from "./Client.ts";
import type { SessionView } from "./types.ts";

/** Svelte's readable-store contract. */
export interface Readable<T> {
  readonly subscribe: (run: (value: T) => void) => () => void;
}

/**
 * A readable store over the client's session. Subscribing triggers the
 * initial session fetch; auth mutations on the client refresh it.
 */
export const sessionStore = (client: AuthClient): Readable<SessionState> => ({
  subscribe: (run) => {
    run(client.session.get());
    return client.session.subscribe(() => run(client.session.get()));
  },
});

/** The state emitted by {@link listSessionsStore}. */
export interface ListSessionsState {
  readonly data: readonly SessionView[] | null;
  readonly isPending: boolean;
  readonly error: AuthClientError | null;
}

/** A readable store over the user's active sessions, with a refetch handle. */
export interface ListSessionsStore extends Readable<ListSessionsState> {
  /** Re-run the query (e.g. after revoking a session). */
  readonly refetch: () => void;
}

/**
 * Fetch the authenticated user's active sessions as a readable store. The
 * first subscription triggers the fetch; call `refetch()` to refresh.
 * Mirrors the React `useListSessions` hook.
 */
export const listSessionsStore = (client: AuthClient): ListSessionsStore => {
  let state: ListSessionsState = { data: null, isPending: true, error: null };
  const subscribers = new Set<(value: ListSessionsState) => void>();
  let fetched = false;
  let refetchSeq = 0;

  const set = (next: ListSessionsState) => {
    state = next;
    for (const run of subscribers) {
      run(state);
    }
  };

  const refetch = () => {
    const seq = ++refetchSeq;
    set({ ...state, isPending: true });
    client.listSessions().then(
      (sessions) => {
        if (seq !== refetchSeq) return;
        set({ data: sessions, isPending: false, error: null });
      },
      (cause: AuthClientError) => {
        if (seq !== refetchSeq) return;
        set({ data: null, isPending: false, error: cause });
      },
    );
  };

  return {
    refetch,
    subscribe: (run) => {
      subscribers.add(run);
      run(state);
      if (!fetched) {
        fetched = true;
        refetch();
      }
      return () => {
        subscribers.delete(run);
      };
    },
  };
};
