/**
 * Svelte context plumbing for the auth client, so the bundled form components
 * (and app code) reach it without threading it through every prop.
 *
 * Set it once, high up:
 *
 * ```svelte
 * <script lang="ts">
 *   import { createAuthClient } from "@thomasfosterau/effect-auth-client";
 *   import { setAuthClient } from "@thomasfosterau/effect-auth-svelte";
 *
 *   setAuthClient(createAuthClient({ baseUrl: "/api/auth" }));
 * </script>
 *
 * {@render children()}
 * ```
 *
 * @module context
 */
import { getContext, setContext, untrack } from "svelte";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";

/**
 * The context key the client is stored under. A `Symbol.for` key rather than a
 * module-local symbol so two copies of this package in one dependency tree
 * still see each other's client.
 */
export const authClientKey: symbol = Symbol.for("effect-auth.client");

const MISSING_CLIENT =
  "[effect-auth] No auth client in context. Call `setAuthClient(client)` during " +
  "the initialisation of a parent component, or pass a `client` prop to this component.";

/**
 * Put `client` in context for this component's descendants. Must be called
 * while a component is initialising, like every Svelte context function.
 */
export const setAuthClient = (client: AuthClient): AuthClient => setContext(authClientKey, client);

/**
 * The client from the nearest {@link setAuthClient} above this component.
 *
 * Throws when there is none: an auth client is never a sensible thing to guess
 * at, so failing loudly beats a `undefined` that only surfaces as a
 * `TypeError` deeper in the tree. Must be called during component
 * initialisation.
 */
export const getAuthClient = (): AuthClient => {
  const client = getContext<AuthClient | undefined>(authClientKey);
  if (client === undefined) throw new Error(MISSING_CLIENT);
  return client;
};

/**
 * The client a component should use: an explicit `client` prop wins, otherwise
 * the one in context. Unlike {@link getAuthClient} this is safe to call with
 * the prop present and nothing in context, because the context read happens
 * either way.
 *
 * `override` is read through `untrack` on purpose. A form resolves its client
 * once, while it initialises — swapping the client under a mounted form is not
 * a thing, and resolving eagerly is what makes a missing client fail at mount
 * rather than at the user's first submit.
 *
 * @internal
 */
export const resolveAuthClient = (override: () => AuthClient | undefined): AuthClient => {
  const client = untrack(override) ?? getContext<AuthClient | undefined>(authClientKey);
  if (client === undefined) throw new Error(MISSING_CLIENT);
  return client;
};
