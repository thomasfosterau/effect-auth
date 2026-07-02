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
import type { AuthClient, SessionState } from "./Client.js";

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
