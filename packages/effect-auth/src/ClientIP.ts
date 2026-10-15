/**
 * Trusted-proxy aware client IP resolution.
 *
 * The SECURE DEFAULT is to use the socket remote address and IGNORE all
 * forwarded headers. Forwarded-header parsing is only enabled when an explicit
 * {@link TrustedProxyConfig} is provided, preventing X-Forwarded-For spoofing
 * in environments that don't control every proxy in the chain.
 *
 * @module client-ip
 */
import { Context, Effect, Layer, Option } from "effect";
import { HttpServerRequest } from "effect/http";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * Trust forwarded-IP headers from a fixed number of proxy hops.
 *
 * `hopCount: 1` trusts the single reverse proxy in front of the app and
 * selects the last `X-Forwarded-For` entry as the client IP.
 */
export interface TrustedProxyHopCount {
  /** Header to read. Defaults to `"x-forwarded-for"`. */
  readonly header?: string;
  /**
   * Number of proxy hops to trust (counting from the socket end).
   * The client IP is the entry N positions from the right of the extended
   * `[...xffValues, remoteAddress]` chain.
   */
  readonly hopCount: number;
  readonly trustedProxyCidrs?: never;
  readonly trustedHeader?: never;
}

/**
 * Trust forwarded-IP headers from proxies whose IPs fall within known CIDRs.
 *
 * Entries in the XFF chain are walked right-to-left; the first IP that is
 * *not* in a trusted CIDR is returned as the client IP.
 */
export interface TrustedProxyCidrs {
  /** Header to read. Defaults to `"x-forwarded-for"`. */
  readonly header?: string;
  /**
   * CIDR ranges of trusted proxy IPs (e.g. `["10.0.0.0/8", "::1/128"]`).
   * Both IPv4 and IPv6 CIDRs are supported.
   */
  readonly trustedProxyCidrs: ReadonlyArray<string>;
  readonly hopCount?: never;
  readonly trustedHeader?: never;
}

/**
 * Trust exactly one header, set by an edge in front of the app, as the client
 * IP. Build one with {@link ClientIP.trustedHeader}, or use the
 * {@link ClientIP.cloudflare} preset.
 *
 * **Trust assumption**: this is only correct when the app is reachable solely
 * through that edge. Cloudflare is the case in point: every request reaches the
 * app through Cloudflare, so the socket address is a Cloudflare address and
 * `CF-Connecting-IP` carries the visitor's. Anyone who can reach the app
 * directly, bypassing the edge, can send that header with any value and so
 * choose their own rate-limit key (and the address any hook reads). Deploy only behind the edge
 * (for example, a Worker route that is the sole public entry point).
 *
 * Resolution, when this form is configured:
 * - Only the named header is read. `X-Forwarded-For` and every other header are
 *   ignored.
 * - The value is taken only when it is one IPv4 or IPv6 literal, with
 *   surrounding SP and HTAB ignored. A missing, empty, malformed, or
 *   comma-separated value falls back to the socket address. The first entry of
 *   a list is never taken, because a client can prepend anything to a list.
 * - The accepted address is normalised like every other resolved address: an
 *   IPv4-mapped IPv6 address (`::ffff:203.0.113.9`) becomes `203.0.113.9`, and
 *   hex digits are lowercased.
 * - When there is no socket address either, the result is `undefined`.
 */
export interface TrustedHeaderConfig {
  /** Name of the single header to trust, for example `"cf-connecting-ip"`. Case-insensitive. */
  readonly trustedHeader: string;
  readonly header?: never;
  readonly hopCount?: never;
  readonly trustedProxyCidrs?: never;
}

/**
 * Configuration for trusted-proxy-aware client IP extraction.
 * Exactly one of the three forms is provided: `hopCount`, `trustedProxyCidrs`,
 * or `trustedHeader`.
 */
export type TrustedProxyConfig = TrustedProxyHopCount | TrustedProxyCidrs | TrustedHeaderConfig;

// ---------------------------------------------------------------------------
// Context service
// ---------------------------------------------------------------------------

/** RFC 9110 `token`: the characters a header field name may contain. */
const headerNameRe = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * Per-request resolved client IP.
 *
 * Available in all hook and handler Effects after `HttpServer.make` (or a
 * custom `layer`) has been provided. Access via
 * `Effect.serviceOption(ClientIP)` — returns `None` when running outside an
 * HTTP request scope.
 */
export class ClientIP extends Context.Service<ClientIP, { readonly ip: string | undefined }>()(
  "@effect-auth/ClientIP",
) {
  /**
   * Trust exactly one header as the client IP. See {@link TrustedHeaderConfig}
   * for the trust assumption and the fallback rules.
   *
   * The name is lowercased, so `ClientIP.trustedHeader("CF-Connecting-IP")` and
   * `ClientIP.trustedHeader("cf-connecting-ip")` are the same configuration.
   *
   * @example
   * ```ts
   * import assert from "node:assert/strict"
   * import { ClientIP } from "@thomasfosterau/effect-auth"
   *
   * assert.deepEqual(ClientIP.trustedHeader("X-Real-IP"), { trustedHeader: "x-real-ip" })
   * ```
   *
   * @throws {Error} when `name` is empty or contains characters that are not
   * valid in an HTTP header name.
   */
  static trustedHeader(name: string): TrustedHeaderConfig {
    if (!headerNameRe.test(name))
      throw new Error(`ClientIP.trustedHeader: "${name}" is not a valid HTTP header name`);
    return { trustedHeader: name.toLowerCase() };
  }

  /**
   * Preset for a Cloudflare-fronted app: trust `CF-Connecting-IP` and ignore
   * every other forwarded header. Pass it as `trustedProxy` on the HTTP
   * handler, or to {@link clientIPLayer}.
   *
   * Use it only when the app is reachable solely through Cloudflare. A direct
   * request can set `CF-Connecting-IP` to any value.
   *
   * @example
   * ```ts
   * import assert from "node:assert/strict"
   * import { ClientIP } from "@thomasfosterau/effect-auth"
   *
   * assert.deepEqual(ClientIP.cloudflare, { trustedHeader: "cf-connecting-ip" })
   * ```
   */
  static readonly cloudflare: TrustedHeaderConfig = { trustedHeader: "cf-connecting-ip" };
}

// ---------------------------------------------------------------------------
// Internal: IP utilities
// ---------------------------------------------------------------------------

const isIPv4Re = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

const ipv4ToUint32 = (ip: string): number | undefined => {
  const parts = ip.split(".").map((n) => Number(n));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255))
    return undefined;
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
};

/**
 * Expand a (potentially compressed) IPv6 address to the full
 * `xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx` form, or return `undefined` on
 * parse failure.
 */
const expandIPv6 = (ip: string): string | undefined => {
  // Strip zone ID (e.g. "fe80::1%eth0")
  const zoneIdx = ip.indexOf("%");
  if (zoneIdx >= 0) ip = ip.slice(0, zoneIdx);

  // IPv4-mapped: ::ffff:a.b.c.d or ::a.b.c.d
  const v4m = ip.match(/^::(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (v4m) {
    const parts = v4m[1]!.split(".").map(Number);
    if (parts.some((p) => p < 0 || p > 255)) return undefined;
    const hi = ((parts[0]! << 8) | parts[1]!) >>> 0;
    const lo = ((parts[2]! << 8) | parts[3]!) >>> 0;
    return `0000:0000:0000:0000:0000:ffff:${hi.toString(16).padStart(4, "0")}:${lo.toString(16).padStart(4, "0")}`;
  }

  // Expand :: compressed form
  const dc = ip.indexOf("::");
  let groups: string[];
  if (dc >= 0) {
    const L = ip
      .slice(0, dc)
      .split(":")
      .filter((s) => s !== "");
    const R = ip
      .slice(dc + 2)
      .split(":")
      .filter((s) => s !== "");
    const missing = 8 - L.length - R.length;
    if (missing < 0) return undefined;
    groups = [...L, ...Array<string>(missing).fill("0"), ...R];
  } else {
    groups = ip.split(":");
  }

  if (groups.length !== 8) return undefined;

  const padded = groups.map((g) => {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    return g.padStart(4, "0");
  });

  if (padded.some((g) => g === null)) return undefined;
  return (padded as string[]).join(":");
};

/** A dotted-quad IPv4 address with no leading zeros in any octet. */
const strictIPv4Re =
  /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** One IPv6 group: one to four hex digits. */
const hexGroupRe = /^[0-9a-fA-F]{1,4}$/;

/**
 * Whether `s` is one IPv6 address in colon-hex form (no embedded IPv4, zone ID
 * or brackets). Unlike {@link expandIPv6}, this rejects a second `::` and a
 * group count that does not fit.
 */
const isStrictIPv6 = (s: string): boolean => {
  if (!/^[0-9a-fA-F:]+$/.test(s)) return false;
  const halves = s.split("::");
  if (halves.length > 2) return false;
  const groupsOf = (part: string): ReadonlyArray<string> => (part === "" ? [] : part.split(":"));
  const head = groupsOf(halves[0] ?? "");
  const tail = halves.length === 2 ? groupsOf(halves[1] ?? "") : [];
  const groups = [...head, ...tail];
  if (!groups.every((g) => hexGroupRe.test(g))) return false;
  // `::` stands for at least one zero group, so it needs room for one more.
  return halves.length === 2 ? groups.length <= 7 : groups.length === 8;
};

/**
 * Parse `raw` as exactly one IPv4 or IPv6 literal, or return `undefined`.
 * Surrounding HTTP whitespace (SP, HTAB) is ignored. Anything else is rejected, including a
 * comma-separated list, a port, brackets, a zone ID and a CIDR suffix.
 *
 * Returns IPv4 as written and IPv6 in canonical form (see `canonicalIPv6`).
 */
const parseIpLiteral = (raw: string): string | undefined => {
  // HTTP optional whitespace is SP and HTAB only (RFC 9110 §5.6.3).
  const s = raw.replace(/^[ \t]+|[ \t]+$/g, "");
  if (strictIPv4Re.test(s)) return s;
  if (!s.includes(":")) return undefined;

  // An embedded IPv4 tail becomes two hex groups before the colon-hex check.
  let body = s;
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    if (!strictIPv4Re.test(tail)) return undefined;
    const n = ipv4ToUint32(tail)!;
    body = `${s.slice(0, lastColon + 1)}${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  return isStrictIPv6(body) ? canonicalIPv6(body) : undefined;
};

/**
 * The RFC 5952 text form of a validated colon-hex IPv6 address: lowercase,
 * no leading zeros, the longest run of two or more zero groups compressed to
 * `::` (the first on a tie). An IPv4-mapped address (`::ffff:0:0/96`) becomes
 * dotted IPv4, as {@link normalizeIp} makes it on the socket path, so a
 * visitor gets the same rate-limit key however the address is written.
 */
const canonicalIPv6 = (ip: string): string => {
  const groups = expandIPv6(ip)!
    .split(":")
    .map((g) => parseInt(g, 16));
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    const hi = groups[6]!;
    const lo = groups[7]!;
    return `${hi >>> 8}.${hi & 0xff}.${lo >>> 8}.${lo & 0xff}`;
  }
  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLength) {
      bestStart = i;
      bestLength = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLength < 2) return hex.join(":");
  return `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLength).join(":")}`;
};

const ipv6ToBigInt = (ip: string): bigint | undefined => {
  const expanded = expandIPv6(ip);
  if (expanded === undefined) return undefined;
  const groups = expanded.split(":");
  let result = 0n;
  for (const g of groups) {
    result = (result << 16n) | BigInt(parseInt(g, 16));
  }
  return result;
};

// ---------------------------------------------------------------------------
// Public: IPv6 normalization
// ---------------------------------------------------------------------------

/**
 * Normalize an IP address string:
 * - Strips the IPv4-mapped IPv6 prefix (`::ffff:`) so `::ffff:192.0.2.1`
 *   becomes `192.0.2.1`.
 * - Strips zone IDs (`fe80::1%eth0` → `fe80::1`).
 * - Lowercases hex digits.
 *
 * Returns the original string unchanged if it does not look like an IP address.
 */
export const normalizeIp = (ip: string): string => {
  let s = ip.trim();

  // Strip zone ID
  const zoneIdx = s.indexOf("%");
  if (zoneIdx >= 0) s = s.slice(0, zoneIdx);

  // IPv4-mapped prefix
  const v4m = s.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (v4m) return v4m[1]!;

  return s.toLowerCase();
};

// ---------------------------------------------------------------------------
// Public: CIDR membership
// ---------------------------------------------------------------------------

/**
 * Returns `true` when `ip` falls within the `cidr` range.
 * Accepts both IPv4 and IPv6 CIDRs. IPv4-mapped IPv6 addresses
 * (`::ffff:x.x.x.x`) are normalized to plain IPv4 before matching.
 */
export const cidrContains = (cidr: string, ip: string): boolean => {
  const slashIdx = cidr.indexOf("/");
  const base = slashIdx >= 0 ? cidr.slice(0, slashIdx) : cidr;
  const prefixStr = slashIdx >= 0 ? cidr.slice(slashIdx + 1) : "";

  const normalizedIp = normalizeIp(ip);

  // IPv4 vs IPv4
  if (isIPv4Re.test(normalizedIp) && isIPv4Re.test(base)) {
    const prefix = prefixStr !== "" ? parseInt(prefixStr, 10) : 32;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
    const ipInt = ipv4ToUint32(normalizedIp);
    const baseInt = ipv4ToUint32(base);
    if (ipInt === undefined || baseInt === undefined) return false;
    if (prefix === 0) return true;
    const mask = (0xffffffff << (32 - prefix)) >>> 0;
    return (ipInt & mask) === (baseInt & mask);
  }

  // IPv6 (or mixed: IPv4 IP matched against IPv6 CIDR via ::ffff mapping)
  const prefix = prefixStr !== "" ? parseInt(prefixStr, 10) : 128;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false;

  // If the normalized IP is plain IPv4, treat it as ::ffff:x.x.x.x for IPv6 CIDR matching
  const ipForV6 = isIPv4Re.test(normalizedIp) ? `::ffff:${normalizedIp}` : normalizedIp;
  const ipBig = ipv6ToBigInt(ipForV6);
  const baseBig = ipv6ToBigInt(base);
  if (ipBig === undefined || baseBig === undefined) return false;
  if (prefix === 0) return true;

  const shift = BigInt(128 - prefix);
  return ipBig >> shift === baseBig >> shift;
};

// ---------------------------------------------------------------------------
// Public: IP resolution
// ---------------------------------------------------------------------------

/**
 * Minimal interface covering the parts of `HttpServerRequest` we need.
 */
export interface IPResolvableRequest {
  readonly headers: Readonly<Record<string, string>>;
  readonly remoteAddress: Option.Option<string>;
}

/**
 * Resolve the real client IP from an HTTP request.
 *
 * **Secure default**: without a `config`, the socket `remoteAddress` is
 * returned and all forwarded headers are IGNORED.
 *
 * With a `TrustedProxyConfig`:
 * - `hopCount` — select the IP that is `hopCount` positions from the right of
 *   the extended `[...xffValues, remoteAddress]` chain.
 * - `trustedProxyCidrs` — walk right-to-left and skip IPs that fall in a
 *   trusted CIDR; return the first untrusted IP.
 * - `trustedHeader` — read only that header, and take it only when it is a
 *   single IP literal; otherwise return the socket address. See
 *   {@link TrustedHeaderConfig}.
 *
 * The resolved IP is always IPv6-normalized (strips `::ffff:`, zone IDs, and
 * lowercases hex).
 */
export const resolveClientIP = (
  req: IPResolvableRequest,
  config?: TrustedProxyConfig,
): string | undefined => {
  const rawRemote = Option.getOrUndefined(req.remoteAddress);
  const remoteIp = rawRemote !== undefined ? normalizeIp(rawRemote) : undefined;

  // SECURE DEFAULT: ignore all forwarded headers
  if (config === undefined) return remoteIp;

  if (config.trustedHeader !== undefined) {
    // Exactly one header, read on its own. Only a single well-formed address is
    // taken; anything else falls back to the socket address.
    const name = config.trustedHeader.toLowerCase();
    const raw = Object.hasOwn(req.headers, name) ? req.headers[name] : undefined;
    const fromHeader = typeof raw === "string" ? parseIpLiteral(raw) : undefined;
    return fromHeader ?? remoteIp;
  }

  const headerName = (config.header ?? "x-forwarded-for").toLowerCase();
  const rawHeader = Object.hasOwn(req.headers, headerName) ? req.headers[headerName] : undefined;
  if (rawHeader === undefined || rawHeader === "") return remoteIp;

  const xffEntries = rawHeader
    .split(",")
    .map((s) => normalizeIp(s.trim()))
    .filter((s) => s.length > 0);

  if (xffEntries.length === 0) return remoteIp;

  // Extended chain: leftmost = original client, rightmost = socket peer
  const chain = remoteIp !== undefined ? [...xffEntries, remoteIp] : xffEntries;

  if (config.hopCount !== undefined) {
    const clientIdx = chain.length - 1 - config.hopCount;
    if (clientIdx < 0 || clientIdx >= chain.length) return undefined;
    return chain[clientIdx];
  }

  // trustedProxyCidrs: walk right-to-left, skip trusted proxies
  for (let i = chain.length - 1; i >= 0; i--) {
    const candidate = chain[i]!;
    const trusted = config.trustedProxyCidrs.some((cidr) => cidrContains(cidr, candidate));
    if (!trusted) return candidate;
  }

  // Every IP in the chain belongs to a trusted proxy — indeterminate
  return undefined;
};

// ---------------------------------------------------------------------------
// Layer
// ---------------------------------------------------------------------------

/**
 * A per-request Layer that resolves the client IP from the ambient
 * `HttpServerRequest` and provides it as the {@link ClientIP} service.
 *
 * Merge this into your app layer to make `ClientIP` available to all handlers
 * and hook Effects.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer } from "effect"
 * import { HttpServerRequest } from "effect/http"
 * import { clientIPLayer, ClientIP } from "@thomasfosterau/effect-auth"
 *
 * // The services the app already provides.
 * const services = Layer.empty
 *
 * // In HttpServer.make the trustedProxy option wires this up automatically.
 * // For custom usage:
 * const myLayer = Layer.mergeAll(services, clientIPLayer({ hopCount: 1 }))
 *
 * // One trusted proxy in front of the app: it appended the client address to
 * // X-Forwarded-For, and its own address is the socket peer.
 * const request = HttpServerRequest.fromWeb(
 *   new Request("http://localhost/", { headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.1" } }),
 * )
 *
 * const program = Effect.gen(function* () {
 *   const { ip } = yield* ClientIP
 *   assert.equal(ip, "203.0.113.7")
 * }).pipe(Effect.provide(myLayer), Effect.provideService(HttpServerRequest.HttpServerRequest, request))
 *
 * await Effect.runPromise(program)
 * ```
 */
export const clientIPLayer = (
  config?: TrustedProxyConfig,
): Layer.Layer<ClientIP, never, HttpServerRequest.HttpServerRequest> =>
  Layer.effect(
    ClientIP,
    Effect.gen(function* () {
      const req = yield* HttpServerRequest.HttpServerRequest;
      return { ip: resolveClientIP(req, config) };
    }),
  );
