/**
 * The URL policy for identity-provider endpoints a tenant registers: `https`,
 * no credentials, and no private, loopback, link-local or internal host. Hosts
 * are checked as written, never resolved (Workers have no DNS), so egress
 * filtering is the defence against a name that resolves privately.
 */
import * as Arr from "effect/Array";
import { cidrContains } from "./ClientIP.ts";
import type { UrlPolicy } from "./OutboundHttp.ts";

/** IPv4 ranges no IdP URL may name: private, loopback, link-local, CGNAT, multicast and reserved. */
const blockedIpv4: ReadonlyArray<string> = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "224.0.0.0/4",
  "240.0.0.0/4",
];

/**
 * IPv6 ranges likewise. The IPv4-compatible and IPv4-mapped forms are refused
 * whole: `URL` writes them in hex (`[::ffff:7f00:1]`), and no IdP needs them.
 */
const blockedIpv6: ReadonlyArray<string> = [
  "::/96",
  "::ffff:0:0/96",
  "64:ff9b::/96",
  "fc00::/7",
  "fe80::/10",
  "ff00::/8",
];

/** Name suffixes that are never public: loopback, mDNS and private-use zones. */
const internalSuffixes: ReadonlyArray<string> = [".localhost", ".local", ".internal", ".home.arpa"];

const ipv4Re = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/** Why a host is internal, or `undefined` for a public one. */
const internalHost = (hostname: string): string | undefined => {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[") && host.endsWith("]")) {
    const address = host.slice(1, -1);
    return Arr.some(blockedIpv6, (range) => cidrContains(range, address))
      ? "a private or reserved address"
      : undefined;
  }
  if (ipv4Re.test(host)) {
    return Arr.some(blockedIpv4, (range) => cidrContains(range, host))
      ? "a private or reserved address"
      : undefined;
  }
  if (host === "localhost" || Arr.some(internalSuffixes, (suffix) => host.endsWith(suffix))) {
    return "an internal host name";
  }
  if (!host.includes(".")) return "a single-label host name";
  return undefined;
};

/** The parsed URL, or `undefined` when it is not one. */
const parse = (url: string): URL | undefined => (URL.canParse(url) ? new URL(url) : undefined);

/**
 * The strict policy, or with `allowPrivate` (`SsoConfig.allowPrivateIdpUrls`)
 * one that asks only for an `http` or `https` URL without credentials.
 */
export const idpUrlPolicy =
  (allowPrivate: boolean): UrlPolicy =>
  (url) => {
    const parsed = parse(url);
    if (parsed === undefined) return `Invalid IdP URL: ${url}`;
    if (parsed.username !== "" || parsed.password !== "") {
      return `IdP URL must not carry credentials: ${parsed.origin}`;
    }
    if (allowPrivate) {
      return parsed.protocol === "https:" || parsed.protocol === "http:"
        ? undefined
        : `IdP URL must be http or https: ${url}`;
    }
    if (parsed.protocol !== "https:") return `IdP URL must be https: ${url}`;
    const internal = internalHost(parsed.hostname);
    return internal === undefined
      ? undefined
      : `IdP URL names ${internal} (set allowPrivateIdpUrls for an IdP on a private network): ${url}`;
  };
