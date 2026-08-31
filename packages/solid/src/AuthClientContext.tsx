/**
 * Solid context carrying the auth client, so the bundled form components (and
 * app code) can reach it without threading it through every prop.
 *
 * ```tsx
 * const client = createAuthClient({ baseUrl: "/api/auth" });
 *
 * render(
 *   () => (
 *     <AuthClientProvider client={client}>
 *       <App />
 *     </AuthClientProvider>
 *   ),
 *   document.getElementById("root")!,
 * );
 * ```
 *
 * @module AuthClientContext
 */
import { createContext, useContext } from "solid-js";
import type { JSX } from "solid-js";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";

/**
 * The context the client is carried in. Exported so an app can read it with
 * `useContext(AuthClientContext)` directly (or seed it in a test).
 */
export const AuthClientContext = createContext<AuthClient>();

/** Props for {@link AuthClientProvider}. */
export interface AuthClientProviderProps {
  /** The client every descendant should use. */
  readonly client: AuthClient;
  readonly children?: JSX.Element | undefined;
}

/**
 * Make `client` available to {@link useAuthClient} and the form components.
 *
 * Props are read lazily (never destructured), so swapping the `client` prop
 * re-provides the new one to everything below it.
 */
export const AuthClientProvider = (props: AuthClientProviderProps): JSX.Element => (
  <AuthClientContext.Provider value={props.client}>{props.children}</AuthClientContext.Provider>
);

/** @internal */
export const MISSING_PROVIDER =
  "[effect-auth] No auth client in context. Wrap the tree in " +
  "<AuthClientProvider client={...}>, or pass a `client` prop to this component.";

/**
 * The client from the nearest {@link AuthClientProvider}.
 *
 * Throws when there is no provider above it — an auth client is never a
 * sensible thing to guess at, so failing loudly beats an `undefined` that only
 * surfaces as a `TypeError` deeper in the tree.
 *
 * Call it during component setup, like every other Solid context read.
 */
export const useAuthClient = (): AuthClient => {
  const client = useContext(AuthClientContext);
  if (client === undefined) throw new Error(MISSING_PROVIDER);
  return client;
};

/**
 * The client a component should use: an explicit `client` prop wins, otherwise
 * the provider's.
 *
 * `getOverride` is a thunk rather than a value so the prop stays reactive; the
 * context itself is read once, during setup, as Solid requires. A component
 * with neither source available fails at setup rather than at submit.
 *
 * @internal
 */
export const createResolvedAuthClient = (
  getOverride: () => AuthClient | undefined,
): (() => AuthClient) => {
  const fromContext = useContext(AuthClientContext);
  if (getOverride() === undefined && fromContext === undefined) throw new Error(MISSING_PROVIDER);
  return () => {
    const client = getOverride() ?? fromContext;
    if (client === undefined) throw new Error(MISSING_PROVIDER);
    return client;
  };
};
