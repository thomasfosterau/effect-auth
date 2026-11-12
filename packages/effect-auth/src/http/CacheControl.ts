/**
 * `Cache-Control: no-store` for responses that carry session state (#628).
 *
 * A response that sets a cookie is the viewer's: a shared cache (a CDN, a
 * proxy) that stored it would replay one browser's session cookie to the next
 * visitor. So every response carrying `Set-Cookie` that `Http.make` serves or
 * `RemoteSession` relays carries `no-store`, and so do the bodies that hand a
 * credential over without a cookie (the current session, a signed token, a new
 * API key, a TOTP secret).
 *
 * The merge keeps what is already there: a `Cache-Control` that has
 * `no-store` stays as it is, and one that lacks it keeps its directives
 * (`private`, `no-cache`, …) with `no-store` appended. RFC 9111 §5.2.2.5 has a
 * cache honour `no-store` whatever else the header says, so no directive
 * beside it can make the response storable again.
 *
 * Internal to the HTTP tier: `HttpServer` and `RemoteSession` share it.
 *
 * @module cache-control
 */
import * as Arr from "effect/Array";

/** The directive every session-bearing response carries. */
const NO_STORE = "no-store";

/** Whether a `Cache-Control` value already holds the `no-store` directive. */
const hasNoStore = (value: string): boolean =>
  value.split(",").some((directive) => directive.trim().toLowerCase() === NO_STORE);

/**
 * The `Cache-Control` value to send in place of `existing`: `no-store` when
 * there is none, `existing` when it already has `no-store`, else `existing`
 * with `no-store` appended.
 */
export const mergeNoStore = (existing: string | null | undefined): string => {
  const trimmed = existing?.trim() ?? "";
  if (trimmed === "") return NO_STORE;
  return hasNoStore(trimmed) ? trimmed : `${trimmed}, ${NO_STORE}`;
};

/**
 * `response` with `no-store` merged into its `Cache-Control` when it carries
 * `Set-Cookie`; otherwise `response` itself. Web `Response`s are rebuilt
 * rather than mutated, since a fetched response's headers are immutable.
 */
export const noStoreWithSetCookie = (response: Response): Response => {
  if (Arr.isReadonlyArrayEmpty(response.headers.getSetCookie())) return response;
  const existing = response.headers.get("cache-control");
  const merged = mergeNoStore(existing);
  if (merged === existing) return response;
  const headers = new Headers(response.headers);
  headers.set("cache-control", merged);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
};
