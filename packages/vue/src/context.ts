/**
 * Provide/inject plumbing for the auth client.
 *
 * Install the client once at the app root — either with the plugin or with
 * {@link provideAuthClient} inside a parent component's `setup` — and every
 * descendant (the form components included) resolves it without prop drilling.
 *
 * ```ts
 * const app = createApp(App);
 * app.use(authClientPlugin, { client: createAuthClient({ baseUrl: "/api/auth" }) });
 * ```
 *
 * @module context
 */
import { inject, provide, type App, type InjectionKey, type Plugin } from "vue";
import type { AuthClient } from "@thomasfosterau/effect-auth-client";

/**
 * The injection key the client is provided under. Exported so an app can
 * `app.provide(authClientKey, client)` directly (or read it in a test).
 */
export const authClientKey: InjectionKey<AuthClient> = Symbol.for("effect-auth.client");

/** The error thrown when a component cannot resolve a client. */
const missingClientMessage =
  "[effect-auth] No auth client was provided. Install one with " +
  "`app.use(authClientPlugin, { client })`, call `provideAuthClient(client)` in a " +
  "parent component's setup(), or pass a `client` prop to the component.";

/**
 * Provide the auth client to this component's descendants. Must be called
 * during `setup()`.
 */
export const provideAuthClient = (client: AuthClient): void => {
  provide(authClientKey, client);
};

/** Options for {@link authClientPlugin}. */
export interface AuthClientPluginOptions {
  readonly client: AuthClient;
}

/**
 * A Vue plugin that provides the auth client app-wide:
 * `app.use(authClientPlugin, { client })`.
 */
export const authClientPlugin: Plugin<[AuthClientPluginOptions]> = {
  install: (app: App, options: AuthClientPluginOptions): void => {
    app.provide(authClientKey, options.client);
  },
};

/**
 * Resolve the auth client for the current component. Must be called during
 * `setup()`.
 *
 * `override` wins when present — that is how every form component's optional
 * `client` prop takes precedence over injection. Throws a message naming all
 * three ways to supply a client when none is found.
 */
export const useAuthClient = (override?: AuthClient | undefined): AuthClient => {
  const injected = inject(authClientKey, null);
  const client = override ?? injected;
  if (client === null) throw new Error(missingClientMessage);
  return client;
};
