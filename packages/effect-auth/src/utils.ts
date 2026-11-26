/**
 * Shared internal utilities.
 *
 * @module utils
 */
import * as Option from "effect/Option";

const PRINTABLE_ASCII = /^[ -~]*$/;
// A host the WHATWG URL parser would split, percent-decode or read as an
// address literal rather than map label by label.
const NOT_A_DOMAIN = /[\s%/?#\\@:[\]]/;
const IPV4 = /^\d+\.\d+\.\d+\.\d+$/;

const lowerNfc = (value: string): string => value.toLowerCase().normalize("NFC");

const urlHostname: (domain: string) => Option.Option<string> = Option.liftThrowable(
  (domain: string) => new URL(`http://${domain}/`).hostname,
);

/**
 * Trim surrounding whitespace and convert a domain to its ASCII (punycode)
 * form under UTS 46 (IDNA 2008): `Exämple.COM` becomes `xn--exmple-cua.com`,
 * and a full-width `ｅxample.com` becomes `example.com`.
 *
 * The mapping is the WHATWG URL host parser's, which every runtime ships. A
 * value it refuses (an invalid label, an address literal) is lower-cased and
 * NFC-normalised instead, so it still compares exactly and matches no valid
 * domain.
 *
 * @since 0.9.0
 */
export const normalizeDomain = (domain: string): string => {
  const trimmed = domain.trim();
  if (PRINTABLE_ASCII.test(trimmed) || NOT_A_DOMAIN.test(trimmed)) return lowerNfc(trimmed);
  return urlHostname(trimmed).pipe(
    Option.filter((host) => !IPV4.test(host)),
    Option.getOrElse(() => lowerNfc(trimmed)),
  );
};

/**
 * Normalise an email address before it is stored or compared: trim it,
 * lower-case and NFC-normalise the local part, and convert the domain (after
 * the last `@`) to punycode with {@link normalizeDomain}.
 *
 * So `Bob@Exämple.com`, `bob@xn--exmple-cua.com` and the same address with a
 * decomposed `ä` are one identifier.
 *
 * @since 0.1.0
 */
export const normalizeEmail = (email: string): string => {
  const trimmed = email.trim();
  const at = trimmed.lastIndexOf("@");
  return at < 0
    ? lowerNfc(trimmed)
    : `${lowerNfc(trimmed.slice(0, at))}@${normalizeDomain(trimmed.slice(at + 1))}`;
};

/** Trim surrounding whitespace and lower-case a username. */
export const normalizeUsername = (username: string): string => username.trim().toLowerCase();
