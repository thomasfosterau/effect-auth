/**
 * Vue bindings for `@effect-auth/client`.
 *
 * ```vue
 * <script setup>
 * const session = useSession(client);
 * </script>
 * <template>
 *   <span v-if="session.data">{{ session.data.user.email }}</span>
 * </template>
 * ```
 *
 * @module vue
 */
import { getCurrentScope, onScopeDispose, shallowRef, type ShallowRef } from "vue";
import type { AuthClient, AuthClientError, SessionState } from "./Client.js";
import type { SessionView } from "./types.js";

/**
 * A `ref` over the client's session store. Subscribing triggers the initial
 * session fetch; the subscription is released with the current effect scope
 * (when called inside `setup`).
 */
export const useSession = (client: AuthClient): Readonly<ShallowRef<SessionState>> => {
  const state = shallowRef(client.session.get());
  const unsubscribe = client.session.subscribe(() => {
    state.value = client.session.get();
  });
  if (getCurrentScope()) {
    onScopeDispose(unsubscribe);
  }
  return state;
};

/** The refs returned by {@link useListSessions}. */
export interface ListSessionsRefs {
  readonly data: Readonly<ShallowRef<readonly SessionView[] | null>>;
  readonly isPending: Readonly<ShallowRef<boolean>>;
  readonly error: Readonly<ShallowRef<AuthClientError | null>>;
  /** Re-run the query (e.g. after revoking a session). */
  readonly refetch: () => void;
}

/**
 * Fetch the authenticated user's active sessions. The query runs immediately
 * and can be re-run with `refetch()`; updates stop once the current effect
 * scope is disposed. Mirrors the React `useListSessions` hook.
 */
export const useListSessions = (client: AuthClient): ListSessionsRefs => {
  const data = shallowRef<readonly SessionView[] | null>(null);
  const isPending = shallowRef(true);
  const error = shallowRef<AuthClientError | null>(null);
  let disposed = false;

  const refetch = () => {
    isPending.value = true;
    client.listSessions().then(
      (sessions) => {
        if (disposed) return;
        data.value = sessions;
        error.value = null;
        isPending.value = false;
      },
      (cause: AuthClientError) => {
        if (disposed) return;
        data.value = null;
        error.value = cause;
        isPending.value = false;
      },
    );
  };

  refetch();
  if (getCurrentScope()) {
    onScopeDispose(() => {
      disposed = true;
    });
  }
  return { data, isPending, error, refetch };
};
