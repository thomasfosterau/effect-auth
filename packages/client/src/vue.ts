/**
 * Vue bindings for `@thomasfosterau/effect-auth-client`.
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
import type { AuthClient, AuthClientError, SessionState } from "./Client.ts";
import type { SessionView } from "./types.ts";

/**
 * A `ref` over the client's session store that also carries a `dispose()`
 * method for manual cleanup when used outside a Vue effect scope.
 *
 * Inside `setup()` the subscription is released automatically when the
 * component unmounts. Outside a scope (plain scripts, tests) the returned
 * `.dispose()` must be called to avoid a subscription leak.
 */
export type UseSessionResult = Readonly<ShallowRef<SessionState>> & {
  readonly dispose: () => void;
};

/**
 * A `ref` over the client's session store. Subscribing triggers the initial
 * session fetch; the subscription is released with the current effect scope
 * (when called inside `setup`). Outside a scope, call `.dispose()` on the
 * returned ref to stop updates.
 */
export const useSession = (client: AuthClient): UseSessionResult => {
  const stateRef = shallowRef(client.session.get());
  const unsubscribe = client.session.subscribe(() => {
    stateRef.value = client.session.get();
  });
  if (getCurrentScope()) {
    onScopeDispose(unsubscribe);
  } else {
    console.warn(
      "[effect-auth] useSession() was called outside a Vue effect scope. " +
        "Call .dispose() on the returned ref to avoid a subscription leak.",
    );
  }
  return Object.assign(stateRef, { dispose: unsubscribe }) as UseSessionResult;
};

/** The refs returned by {@link useListSessions}. */
export interface ListSessionsRefs {
  readonly data: Readonly<ShallowRef<readonly SessionView[] | null>>;
  readonly isPending: Readonly<ShallowRef<boolean>>;
  readonly error: Readonly<ShallowRef<AuthClientError | null>>;
  /** Re-run the query (e.g. after revoking a session). */
  readonly refetch: () => void;
  /** Release resources. Only needed when called outside a Vue effect scope. */
  readonly dispose: () => void;
}

/**
 * Fetch the authenticated user's active sessions. The query runs immediately
 * and can be re-run with `refetch()`; updates stop once the current effect
 * scope is disposed (or `.dispose()` is called when outside a scope). Mirrors
 * the React `useListSessions` hook.
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

  const dispose = (): void => {
    disposed = true;
  };

  refetch();
  if (getCurrentScope()) {
    onScopeDispose(dispose);
  } else {
    console.warn(
      "[effect-auth] useListSessions() was called outside a Vue effect scope. " +
        "Call .dispose() on the returned object to stop stale updates.",
    );
  }
  return { data, isPending, error, refetch, dispose };
};
