/**
 * Cookie **naming** policy, separated from the HTTP cluster so an app can read
 * the names its own edge has to look for.
 *
 * The effective session cookie name is a computed value, not a configured one:
 * `resolveCookieConfig` derives it from `name`, `secure` and `hostPrefix`, and
 * can emit a `__Host-` prefix. An app that wants to answer "does this request
 * carry a credential at all?" before dispatching therefore cannot simply
 * restate the configured name — it has to run the same derivation.
 *
 * This module is that derivation, and it has exactly one implementation:
 * `http/HttpServer.ts`'s `resolveCookieConfig` calls {@link resolveNaming}, and
 * `SessionResolution`'s credential predicates call {@link cookieNames}. Changing
 * `name`, `secure` or `hostPrefix` cannot desynchronise an app's fast path from
 * what the middleware reads, because there is nothing to keep in sync.
 *
 * It deliberately lives outside `http/` and pulls in no HTTP machinery: the
 * callers that need it most run at a raw `Request` with no Effect HTTP stack
 * in sight.
 *
 * @module session-cookies
 */

/**
 * The naming-relevant slice of `Http.CookieConfig`.
 *
 * `CookieConfig` is structurally assignable to this, so an app that already
 * holds the config it passed to `Http.make` can hand the same value to
 * {@link cookieNames}.
 *
 * @since 1.0.0
 * @category models
 */
export interface SessionCookieNaming {
  /** Cookie name. Default `conduit_session`. */
  readonly name?: string;
  /** Mark the cookie `Secure`. Default `true` (set `false` for local http). */
  readonly secure?: boolean;
  /** Cookie path. Default `/`. */
  readonly path?: string;
  /**
   * Apply the `__Host-` cookie name prefix. Defaults to `true` when `secure`
   * is `true` and `path` is `/` (or not set).
   */
  readonly hostPrefix?: boolean;
}

/**
 * The resolved naming triple: the effective cookie name (prefix applied), the
 * effective path (forced to `/` when the prefix is active), and `secure`.
 *
 * @since 1.0.0
 * @category models
 */
export interface ResolvedNaming {
  readonly name: string;
  readonly secure: boolean;
  readonly path: string;
}

/** The default session cookie name, before any prefix is applied. */
export const defaultCookieName = "conduit_session";

/**
 * Derive the effective cookie name, path and `secure` flag.
 *
 * The `__Host-` prefix is applied by default when the cookie is `Secure` and
 * the path is `/`; the prefix forces `Path=/` so browsers enforce host-binding
 * (no `Domain`, `Secure`, `Path=/`). Opt out with `hostPrefix: false`.
 *
 * @since 1.0.0
 * @category constructors
 */
export const resolveNaming = (config?: SessionCookieNaming): ResolvedNaming => {
  const secure = config?.secure ?? true;
  const configuredPath = config?.path ?? "/";
  const useHostPrefix = config?.hostPrefix ?? (secure && configuredPath === "/");
  const baseName = config?.name ?? defaultCookieName;
  return {
    name: useHostPrefix && secure ? `__Host-${baseName}` : baseName,
    secure,
    // __Host- cookies must have Path=/; override whatever path was configured.
    path: useHostPrefix && secure ? "/" : configuredPath,
  };
};

/**
 * Every cookie name the session machinery uses, derived from one config.
 *
 * @since 1.0.0
 * @category models
 */
export interface SessionCookieNames {
  /** The session cookie: holds the session id / raw token. */
  readonly session: string;
  /** The signed session-data cache cookie (`${name}_data`). */
  readonly data: string;
  /** The device session-list cookie (`${name}_multi`), when multi-session is on. */
  readonly multi: string;
  /** The non-httpOnly last-login-method hint cookie (`${name}_last_method`). */
  readonly lastMethod: string;
}

/**
 * Every cookie name the session machinery uses, for the given config.
 *
 * @example Deciding at a Worker edge whether a request can possibly resolve
 * ```ts
 * import { SessionCookies } from "@thomasfosterau/effect-auth"
 *
 * const names = SessionCookies.cookieNames({ name: "app_session" })
 * // names.session === "__Host-app_session"
 * ```
 *
 * @since 1.0.0
 * @category constructors
 */
export const cookieNames = (config?: SessionCookieNaming): SessionCookieNames => {
  const { name } = resolveNaming(config);
  return {
    session: name,
    data: `${name}_data`,
    multi: `${name}_multi`,
    lastMethod: `${name}_last_method`,
  };
};

/**
 * The cookie names that can carry a session credential: the session cookie and
 * the signed cache cookie.
 *
 * The cache cookie is included even though effect-auth's own middleware will
 * not resolve from it alone (its cache path still needs a session id from the
 * cookie or `Authorization` header first). The costs are asymmetric: a
 * wrongly-skipped request looks signed out to the user, while a wrongly-kept
 * one costs one round trip. A predicate whose whole job is to authorise a skip
 * should err toward not skipping — and a resolver on the far side of a service
 * binding need not share this middleware's cache precedence.
 *
 * @since 1.0.0
 * @category constructors
 */
export const credentialCookieNames = (
  config?: SessionCookieNaming,
): readonly [session: string, data: string] => {
  const names = cookieNames(config);
  return [names.session, names.data];
};
