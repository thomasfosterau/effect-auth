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
import type { AuthClient, SessionState } from "./Client.js";

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
