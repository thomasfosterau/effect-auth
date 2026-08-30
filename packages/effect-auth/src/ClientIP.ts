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
import { HttpServerRequest } from "effect/unstable/http";

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
}

/**
 * Configuration for trusted-proxy-aware client IP extraction.
 * Exactly one of `hopCount` or `trustedProxyCidrs` must be provided.
 */
export type TrustedProxyConfig = TrustedProxyHopCount | TrustedProxyCidrs;

// ---------------------------------------------------------------------------
// Context service
// ---------------------------------------------------------------------------

/**
 * Per-request resolved client IP.
 *
 * Available in all hook and handler Effects after `HTTPServer.make` (or a
 * custom `layer`) has been provided. Access via
 * `Effect.serviceOption(ClientIP)` — returns `None` when running outside an
 * HTTP request scope.
 */
export class ClientIP extends Context.Service<ClientIP, { readonly ip: string | undefined }>()(
  "@effect-auth/ClientIP",
) {}

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

  const headerName = (config.header ?? "x-forwarded-for").toLowerCase();
  const rawHeader: string | undefined = req.headers[headerName];
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
 * // In HTTPServer.make the trustedProxy option wires this up automatically.
 * // For custom usage:
 * const myLayer = Layer.mergeAll(services, clientIPLayer({ hopCount: 1 }))
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
