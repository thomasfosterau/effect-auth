/**
 * Post-authentication redirect targets.
 *
 * A sign-in form, an OAuth or SSO callback, and an OIDC authorization flow
 * all carry a "where to go next" value the client controls
 * (`/login?redirect=…`). Following it unchecked turns the sign-in page into
 * a phishing relay: `/login?redirect=https://evil.example` signs the victim
 * in and hands them to the attacker's look-alike. CSRF's trusted-origin check
 * does not cover this, because the request is same-origin; the *destination*
 * is what is untrusted.
 *
 * {@link safeRedirect} accepts only a same-origin path and falls back for
 * anything else.
 *
 * @module redirect
 */
import { Array as Arr, Predicate } from "effect";

/** C0 controls and DEL: a browser strips some of them while parsing a URL, which can turn `/\t/evil` into `//evil`. */
const isControlCharacter = (character: string): boolean => {
  const code = character.codePointAt(0) ?? 0;
  return code < 0x20 || code === 0x7f;
};

/** A base no real path resolves away from: used only to parse a relative target. */
const PROBE_ORIGIN = "https://redirect.invalid";

/**
 * `target` when it is a same-origin path, otherwise `fallback`.
 *
 * A target is accepted when it starts with exactly one `/`, contains no
 * backslash and no control character, and, resolved against an origin, stays
 * on that origin. That rejects absolute URLs (`https://evil.example`),
 * protocol-relative ones (`//evil.example`), the backslash forms browsers
 * normalise into them (`/\evil.example`), schemes (`javascript:…`) and
 * whitespace tricks (`/\t/evil.example`). A missing or empty target falls
 * back too. `fallback` is returned as given: pass a constant.
 *
 * @example
 * ```ts
 * import { strictEqual } from "node:assert";
 * import { safeRedirect } from "@thomasfosterau/effect-auth";
 *
 * strictEqual(safeRedirect("/dashboard?tab=1", "/"), "/dashboard?tab=1");
 * strictEqual(safeRedirect("https://evil.example", "/"), "/");
 * strictEqual(safeRedirect("//evil.example", "/"), "/");
 * strictEqual(safeRedirect(null, "/home"), "/home");
 * ```
 *
 * @since 1.0.0
 * @category redirects
 */
export const safeRedirect = (target: string | null | undefined, fallback: string): string => {
  if (!Predicate.isString(target) || !target.startsWith("/")) return fallback;
  if (target.startsWith("//") || target.includes("\\")) return fallback;
  if (Arr.some(Arr.fromIterable(target), isControlCharacter)) return fallback;
  return URL.canParse(target, PROBE_ORIGIN) && new URL(target, PROBE_ORIGIN).origin === PROBE_ORIGIN
    ? target
    : fallback;
};
