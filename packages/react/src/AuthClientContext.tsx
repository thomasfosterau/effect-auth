/**
 * React context carrying the auth client, so the bundled form components (and
 * app code) can reach it without threading it through every prop.
 *
 * ```tsx
 * const client = createAuthClient({ baseUrl: "/api/auth" });
 *
 * createRoot(el).render(
 *   <AuthClientProvider client={client}>
 *     <App />
 *   </AuthClientProvider>,
 * );
 * ```
 *
 * @module AuthClientContext
 */
import { createContext, useContext } from "react";
import type { ReactNode } from "react";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";

const AuthClientContext = createContext<AuthClient | null>(null);

/** Props for {@link AuthClientProvider}. */
export interface AuthClientProviderProps {
  /** The client every descendant should use. */
  readonly client: AuthClient;
  readonly children?: ReactNode | undefined;
}

/** Make `client` available to {@link useAuthClient} and the form components. */
export const AuthClientProvider = ({ client, children }: AuthClientProviderProps): ReactNode => (
  // `.Provider` rather than React 19's bare `<Context>` form: this package
  // still supports React 18.
  <AuthClientContext.Provider value={client}>{children}</AuthClientContext.Provider>
);

const MISSING_PROVIDER =
  "No auth client in context. Wrap the tree in <AuthClientProvider client={...}>, " +
  "or pass a `client` prop to this component.";

/**
 * The client from the nearest {@link AuthClientProvider}.
 *
 * Throws when there is no provider above it — an auth client is never a
 * sensible thing to guess at, so failing loudly beats a `null` that only
 * surfaces as a `TypeError` deeper in the tree.
 */
export const useAuthClient = (): AuthClient => {
  const client = useContext(AuthClientContext);
  if (client === null) throw new Error(MISSING_PROVIDER);
  return client;
};

/**
 * The client a component should use: an explicit `client` prop wins, otherwise
 * the provider's. Unlike {@link useAuthClient} this is safe to call with the
 * prop present and no provider anywhere, because the context read is
 * unconditional.
 *
 * @internal
 */
export const useResolvedAuthClient = (override: AuthClient | undefined): AuthClient => {
  const fromContext = useContext(AuthClientContext);
  const client = override ?? fromContext;
  if (client === null || client === undefined) throw new Error(MISSING_PROVIDER);
  return client;
};
