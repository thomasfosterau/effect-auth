import { describe, it, expect } from "vite-plus/test";
import { Effect } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import { HttpServerRequest } from "effect/http";
import {
  ClientIP,
  clientIPLayer,
  normalizeIp,
  cidrContains,
  resolveClientIP,
  type IPResolvableRequest,
} from "./ClientIP.ts";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const req = (
  xff: string | undefined,
  remote: string | undefined,
  header = "x-forwarded-for",
): IPResolvableRequest => ({
  headers: xff !== undefined ? { [header]: xff } : {},
  remoteAddress: remote !== undefined ? Option.some(remote) : Option.none(),
});

// ---------------------------------------------------------------------------
// normalizeIp
// ---------------------------------------------------------------------------

describe("normalizeIp", () => {
  it("passes plain IPv4 through unchanged", () => {
    expect(normalizeIp("192.168.1.1")).toBe("192.168.1.1");
  });

  it("strips ::ffff: IPv4-mapped prefix", () => {
    expect(normalizeIp("::ffff:192.168.1.1")).toBe("192.168.1.1");
    expect(normalizeIp("::FFFF:10.0.0.1")).toBe("10.0.0.1");
  });

  it("strips zone ID from IPv6", () => {
    expect(normalizeIp("fe80::1%eth0")).toBe("fe80::1");
  });

  it("lowercases IPv6", () => {
    expect(normalizeIp("2001:DB8::1")).toBe("2001:db8::1");
  });

  it("handles loopback addresses", () => {
    expect(normalizeIp("127.0.0.1")).toBe("127.0.0.1");
    expect(normalizeIp("::1")).toBe("::1");
  });
});

// ---------------------------------------------------------------------------
// cidrContains
// ---------------------------------------------------------------------------

describe("cidrContains", () => {
  describe("IPv4 CIDRs", () => {
    it("matches a host within the range", () => {
      expect(cidrContains("10.0.0.0/8", "10.99.200.1")).toBe(true);
      expect(cidrContains("192.168.0.0/16", "192.168.1.100")).toBe(true);
    });

    it("rejects a host outside the range", () => {
      expect(cidrContains("10.0.0.0/8", "11.0.0.1")).toBe(false);
      expect(cidrContains("192.168.0.0/16", "192.169.0.1")).toBe(false);
    });

    it("handles /32 (single host)", () => {
      expect(cidrContains("203.0.113.5/32", "203.0.113.5")).toBe(true);
      expect(cidrContains("203.0.113.5/32", "203.0.113.6")).toBe(false);
    });

    it("handles /0 (match all)", () => {
      expect(cidrContains("0.0.0.0/0", "203.0.113.5")).toBe(true);
    });

    it("CIDR without prefix length means /32", () => {
      expect(cidrContains("10.0.0.1", "10.0.0.1")).toBe(true);
      expect(cidrContains("10.0.0.1", "10.0.0.2")).toBe(false);
    });
  });

  describe("IPv6 CIDRs", () => {
    it("matches a host within the range", () => {
      expect(cidrContains("2001:db8::/32", "2001:db8::1")).toBe(true);
      expect(cidrContains("::1/128", "::1")).toBe(true);
    });

    it("rejects a host outside the range", () => {
      expect(cidrContains("2001:db8::/32", "2001:db9::1")).toBe(false);
    });

    it("handles /0 (match all IPv6)", () => {
      expect(cidrContains("::/0", "2001:db8::1")).toBe(true);
    });
  });

  describe("IPv4-mapped IPv6", () => {
    it("normalizes ::ffff: prefix before IPv4 CIDR matching", () => {
      expect(cidrContains("10.0.0.0/8", "::ffff:10.5.6.7")).toBe(true);
      expect(cidrContains("10.0.0.0/8", "::FFFF:11.0.0.1")).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// resolveClientIP — secure default (no config)
// ---------------------------------------------------------------------------

describe("resolveClientIP — no config (secure default)", () => {
  it("returns the remote address", () => {
    expect(resolveClientIP(req("1.2.3.4", "9.10.11.12"))).toBe("9.10.11.12");
  });

  it("IGNORES X-Forwarded-For entirely", () => {
    const spoofed = req("evil.ip.attacker.example", "9.10.11.12");
    expect(resolveClientIP(spoofed)).toBe("9.10.11.12");
  });

  it("returns undefined when there is no remote address", () => {
    expect(resolveClientIP(req(undefined, undefined))).toBeUndefined();
  });

  it("normalizes IPv4-mapped remote address", () => {
    expect(resolveClientIP(req(undefined, "::ffff:192.168.1.1"))).toBe("192.168.1.1");
  });
});

// ---------------------------------------------------------------------------
// resolveClientIP — hop count based trust
// ---------------------------------------------------------------------------

describe("resolveClientIP — hopCount", () => {
  it("hopCount:1 returns last XFF entry (skip direct connection)", () => {
    // Chain: [1.2.3.4, 5.6.7.8, 9.10.11.12(remote)]
    // With hopCount:1 → skip remote → client = 5.6.7.8
    const result = resolveClientIP(req("1.2.3.4, 5.6.7.8", "9.10.11.12"), {
      hopCount: 1,
    });
    expect(result).toBe("5.6.7.8");
  });

  it("hopCount:2 skips 2 from right", () => {
    // Chain: [1.2.3.4, 5.6.7.8, 9.10.11.12(remote)]
    // With hopCount:2 → client = 1.2.3.4
    const result = resolveClientIP(req("1.2.3.4, 5.6.7.8", "9.10.11.12"), {
      hopCount: 2,
    });
    expect(result).toBe("1.2.3.4");
  });

  it("hopCount:0 returns remote address", () => {
    // Chain: [1.2.3.4, 5.6.7.8, 9.10.11.12(remote)]
    // With hopCount:0 → client = 9.10.11.12 (rightmost = remote)
    const result = resolveClientIP(req("1.2.3.4, 5.6.7.8", "9.10.11.12"), {
      hopCount: 0,
    });
    expect(result).toBe("9.10.11.12");
  });

  it("returns undefined when hopCount exceeds chain length", () => {
    // Chain: [5.6.7.8, 9.10.11.12(remote)] — only 2 entries
    const result = resolveClientIP(req("5.6.7.8", "9.10.11.12"), { hopCount: 5 });
    expect(result).toBeUndefined();
  });

  it("does NOT allow spoofing by prepending extra IPs beyond the hop count", () => {
    // The client sent `6.6.6.6, 7.7.7.7`; the one trusted proxy (the socket
    // peer 9.10.11.12) appended the address it saw, 10.0.0.100.
    // Chain: [6.6.6.6, 7.7.7.7, 10.0.0.100, 9.10.11.12(remote)] → index 2.
    const result = resolveClientIP(req("6.6.6.6, 7.7.7.7, 10.0.0.100", "9.10.11.12"), {
      hopCount: 1,
    });
    expect(result).toBe("10.0.0.100");
  });

  it("ignores client-written garbage to the left of the selected entry", () => {
    expect(resolveClientIP(req("garbage, 203.0.113.9", "9.10.11.12"), { hopCount: 1 })).toBe(
      "203.0.113.9",
    );
  });

  it("resolves no address when the selected entry is not an IP literal", () => {
    expect(resolveClientIP(req("garbage", "9.10.11.12"), { hopCount: 1 })).toBeUndefined();
    expect(resolveClientIP(req("203.0.113.9:443", "9.10.11.12"), { hopCount: 1 })).toBeUndefined();
    expect(resolveClientIP(req("[2001:db8::1]", "9.10.11.12"), { hopCount: 1 })).toBeUndefined();
  });

  it("resolves no address when an entry a trusted proxy wrote is not an IP literal", () => {
    // hopCount:2 trusts the socket peer and the proxy before it; that proxy's
    // entry (`unknown`) is not an address, so the chain is not what was configured.
    expect(
      resolveClientIP(req("203.0.113.9, unknown", "9.10.11.12"), { hopCount: 2 }),
    ).toBeUndefined();
  });

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "resolves no address for hopCount %s",
    (hopCount) => {
      expect(resolveClientIP(req("203.0.113.9", "9.10.11.12"), { hopCount })).toBeUndefined();
      expect(resolveClientIP(req("203.0.113.9", undefined), { hopCount })).toBeUndefined();
    },
  );

  it("uses custom header name", () => {
    const r: IPResolvableRequest = {
      headers: { "x-real-ip": "1.2.3.4" },
      remoteAddress: Option.some("9.10.11.12"),
    };
    const result = resolveClientIP(r, { header: "x-real-ip", hopCount: 1 });
    // Chain: [1.2.3.4, 9.10.11.12(remote)] — hopCount:1 → index 0 → 1.2.3.4
    expect(result).toBe("1.2.3.4");
  });
});

// A Web `Request` (what `Http.make` handles) has no socket address: the header's
// last `hopCount` entries are the ones the trusted proxies wrote (#584).
describe("resolveClientIP — hopCount without a socket address (#584)", () => {
  const oneHop = { hopCount: 1 };

  it("takes the header's last entry for an honest client behind one proxy", () => {
    expect(resolveClientIP(req("203.0.113.9", undefined), oneHop)).toBe("203.0.113.9");
  });

  it("is not moved by a value the client prepends", () => {
    Arr.forEach(Arr.range(1, 13), (i) => {
      expect(resolveClientIP(req(`10.9.9.${i}, 203.0.113.9`, undefined), oneHop)).toBe(
        "203.0.113.9",
      );
    });
  });

  it("never keys on a prepended non-address", () => {
    expect(resolveClientIP(req("garbage, 203.0.113.9", undefined), oneHop)).toBe("203.0.113.9");
  });

  it("counts every trusted hop from the header's end", () => {
    // client → proxy A (writes 203.0.113.9) → proxy B (writes 10.0.0.1) → app
    expect(
      resolveClientIP(req("198.51.100.1, 203.0.113.9, 10.0.0.1", undefined), { hopCount: 2 }),
    ).toBe("203.0.113.9");
  });

  it("resolves no address for hopCount 0, which trusts no header entry", () => {
    expect(resolveClientIP(req("203.0.113.9", undefined), { hopCount: 0 })).toBeUndefined();
  });

  it("resolves no address when hopCount exceeds the header", () => {
    expect(resolveClientIP(req("203.0.113.9", undefined), { hopCount: 2 })).toBeUndefined();
  });

  it("resolves no address when the selected or a trusted entry is not an IP literal", () => {
    expect(resolveClientIP(req("garbage", undefined), oneHop)).toBeUndefined();
    expect(resolveClientIP(req("203.0.113.9, garbage", undefined), oneHop)).toBeUndefined();
    expect(
      resolveClientIP(req("203.0.113.9, garbage", undefined), { hopCount: 2 }),
    ).toBeUndefined();
  });

  it("resolves no address when the header is missing or holds only separators", () => {
    expect(resolveClientIP(req(undefined, undefined), oneHop)).toBeUndefined();
    expect(resolveClientIP(req(" , ", undefined), oneHop)).toBeUndefined();
  });

  it("skips empty list elements", () => {
    expect(resolveClientIP(req("198.51.100.1,, 203.0.113.9 ,", undefined), oneHop)).toBe(
      "203.0.113.9",
    );
  });

  it("canonicalises the selected address, so one visitor has one key", () => {
    expect(resolveClientIP(req("2001:DB8:0:0:0:0:0:1", undefined), oneHop)).toBe("2001:db8::1");
    expect(resolveClientIP(req("::ffff:203.0.113.9", undefined), oneHop)).toBe("203.0.113.9");
  });

  it("resolves the same way through clientIPLayer over a real Web Request", async () => {
    const request = HttpServerRequest.fromWeb(
      new Request("http://localhost/", {
        headers: { "x-forwarded-for": "10.9.9.1, 203.0.113.9" },
      }),
    );
    const resolved = await Effect.runPromise(
      Effect.gen(function* () {
        const { ip } = yield* ClientIP;
        return ip;
      }).pipe(
        Effect.provide(clientIPLayer(oneHop)),
        Effect.provideService(HttpServerRequest.HttpServerRequest, request),
      ),
    );
    expect(resolved).toBe("203.0.113.9");
  });
});

// ---------------------------------------------------------------------------
// resolveClientIP — CIDR based trust
// ---------------------------------------------------------------------------

describe("resolveClientIP — trustedProxyCidrs", () => {
  const trusted10 = { trustedProxyCidrs: ["10.0.0.0/8"] };

  it("returns first untrusted IP walking right-to-left", () => {
    // remote=10.0.0.200 (trusted), xff last=10.0.0.100 (trusted), first=1.2.3.4 (client)
    expect(resolveClientIP(req("1.2.3.4, 10.0.0.100", "10.0.0.200"), trusted10)).toBe("1.2.3.4");
  });

  it("prevents XFF spoofing — stops at first untrusted from the right", () => {
    // Remote is untrusted (attacker directly connected), XFF is attacker-crafted
    const result = resolveClientIP(req("198.51.100.7, 10.0.0.100", "6.6.6.6"), trusted10);
    // Chain right-to-left: 6.6.6.6 (NOT in 10/8) → stop, return it
    expect(result).toBe("6.6.6.6");
  });

  it("resolves no address when the first untrusted entry is not an IP literal", () => {
    // Without validation this keyed the limit on the literal `garbage` (#584).
    expect(resolveClientIP(req("garbage, 10.0.0.100", "10.0.0.200"), trusted10)).toBeUndefined();
  });

  it("does not skip a non-address to reach an entry further left", () => {
    expect(
      resolveClientIP(req("198.51.100.7, garbage, 10.0.0.100", "10.0.0.200"), trusted10),
    ).toBeUndefined();
  });

  it("walks the header alone when there is no socket address", () => {
    expect(resolveClientIP(req("198.51.100.7, 10.0.0.100", undefined), trusted10)).toBe(
      "198.51.100.7",
    );
    expect(resolveClientIP(req("10.0.0.1, 10.0.0.2", undefined), trusted10)).toBeUndefined();
  });

  it("returns undefined when all IPs are trusted proxies", () => {
    // Every IP in the chain is a proxy — can't determine real client
    expect(resolveClientIP(req("10.0.0.1, 10.0.0.2", "10.0.0.3"), trusted10)).toBeUndefined();
  });

  it("handles multiple CIDRs", () => {
    const config = { trustedProxyCidrs: ["10.0.0.0/8", "172.16.0.0/12"] };
    expect(resolveClientIP(req("1.2.3.4, 172.16.5.1", "10.99.0.1"), config)).toBe("1.2.3.4");
  });

  it("normalizes IPv4-mapped IPv6 remote address before CIDR check", () => {
    // Remote is ::ffff:10.0.0.200 → normalized to 10.0.0.200 → trusted
    const result = resolveClientIP(req("1.2.3.4", "::ffff:10.0.0.200"), trusted10);
    expect(result).toBe("1.2.3.4");
  });

  it("uses a custom header", () => {
    const r: IPResolvableRequest = {
      headers: { "cf-connecting-ip": "1.2.3.4" },
      remoteAddress: Option.some("10.0.0.50"),
    };
    const result = resolveClientIP(r, {
      header: "cf-connecting-ip",
      trustedProxyCidrs: ["10.0.0.0/8"],
    });
    expect(result).toBe("1.2.3.4");
  });

  it("falls back to remote address when XFF header is absent", () => {
    const r: IPResolvableRequest = {
      headers: {},
      remoteAddress: Option.some("9.10.11.12"),
    };
    expect(resolveClientIP(r, trusted10)).toBe("9.10.11.12");
  });
});

// ---------------------------------------------------------------------------
// IPv6 normalization in end-to-end resolution
// ---------------------------------------------------------------------------

describe("resolveClientIP — IPv6", () => {
  it("normalizes IPv6 XFF entries to lowercase", () => {
    const result = resolveClientIP(req("2001:DB8::1", "::ffff:10.0.0.1"), {
      trustedProxyCidrs: ["10.0.0.0/8"],
    });
    expect(result).toBe("2001:db8::1");
  });

  it("matches IPv6 loopback in CIDR", () => {
    expect(
      resolveClientIP(req("2001:db8::1", "::1"), {
        trustedProxyCidrs: ["::1/128"],
      }),
    ).toBe("2001:db8::1");
  });
});

// ---------------------------------------------------------------------------
// Single trusted header: ClientIP.cloudflare and ClientIP.trustedHeader
// ---------------------------------------------------------------------------

/** A request from a socket at `remote` carrying `headers`. */
const edge = (
  headers: Record<string, string>,
  remote: string | null = "10.0.0.50",
): IPResolvableRequest => ({
  headers,
  remoteAddress: remote !== null ? Option.some(remote) : Option.none(),
});

describe("ClientIP.cloudflare (opt-in single trusted header)", () => {
  it("uses CF-Connecting-IP when it holds one IP", () => {
    expect(resolveClientIP(edge({ "cf-connecting-ip": "203.0.113.7" }), ClientIP.cloudflare)).toBe(
      "203.0.113.7",
    );
  });

  it("ignores X-Forwarded-For and every other forwarded header", () => {
    const spoofed = edge({
      "x-forwarded-for": "6.6.6.6",
      "x-real-ip": "7.7.7.7",
      forwarded: "for=8.8.8.8",
    });
    expect(resolveClientIP(spoofed, ClientIP.cloudflare)).toBe("10.0.0.50");
  });

  it("is ignored when no trusted proxy is configured (secure default)", () => {
    expect(resolveClientIP(edge({ "cf-connecting-ip": "203.0.113.7" }))).toBe("10.0.0.50");
  });

  it("falls back to the socket address when the header is absent", () => {
    expect(resolveClientIP(edge({}), ClientIP.cloudflare)).toBe("10.0.0.50");
  });

  it("falls back to the socket address when the header is empty or blank", () => {
    expect(resolveClientIP(edge({ "cf-connecting-ip": "" }), ClientIP.cloudflare)).toBe(
      "10.0.0.50",
    );
    expect(resolveClientIP(edge({ "cf-connecting-ip": "   " }), ClientIP.cloudflare)).toBe(
      "10.0.0.50",
    );
  });

  it("refuses a comma-separated list whole, never taking its first entry", () => {
    // A client can prepend anything to a list, so the first entry is attacker-chosen.
    expect(
      resolveClientIP(edge({ "cf-connecting-ip": "6.6.6.6, 203.0.113.7" }), ClientIP.cloudflare),
    ).toBe("10.0.0.50");
    expect(
      resolveClientIP(edge({ "cf-connecting-ip": "6.6.6.6,203.0.113.7" }), ClientIP.cloudflare),
    ).toBe("10.0.0.50");
  });

  it.each([
    ["a word", "unknown"],
    ["an IPv4 with a port", "203.0.113.7:443"],
    ["a bracketed IPv6", "[2001:db8::1]"],
    ["an IPv6 with a zone ID", "fe80::1%eth0"],
    ["a mapped address with a zone ID", "::ffff:203.0.113.7%eth0"],
    ["a CIDR", "203.0.113.0/24"],
    ["an octet over 255", "256.1.1.1"],
    ["an octet with a leading zero", "203.0.113.07"],
    ["three IPv4 octets", "203.0.113"],
    ["a doubled ::", "2001:db8::1::2"],
    ["nine IPv6 groups", "1:2:3:4:5:6:7:8:9"],
    ["a five-digit IPv6 group", "2001:db8:12345::1"],
    ["a mapped prefix with a non-IPv4 tail", "::ffff:example"],
    ["two addresses separated by a space", "203.0.113.7 6.6.6.6"],
  ])("falls back to the socket address for %s", (_label, value) => {
    expect(resolveClientIP(edge({ "cf-connecting-ip": value }), ClientIP.cloudflare)).toBe(
      "10.0.0.50",
    );
  });

  it("accepts IPv4, IPv6 and IPv4-mapped literals, normalised like other resolved addresses", () => {
    const resolve = (value: string) =>
      resolveClientIP(edge({ "cf-connecting-ip": value }), ClientIP.cloudflare);
    expect(resolve("198.51.100.7")).toBe("198.51.100.7");
    expect(resolve("  198.51.100.7  ")).toBe("198.51.100.7");
    expect(resolve("2001:DB8::1")).toBe("2001:db8::1");
    expect(resolve("::1")).toBe("::1");
    // RFC 5952: a single zero group is not compressed.
    expect(resolve("1:2:3:4:5:6:7::")).toBe("1:2:3:4:5:6:7:0");
    expect(resolve("::FFFF:203.0.113.7")).toBe("203.0.113.7");
    expect(resolve("::ffff:203.0.113.7")).toBe("203.0.113.7");
  });

  it("canonicalises IPv6 (RFC 5952) so one visitor gets one key however the address is written", () => {
    const resolve = (value: string) =>
      resolveClientIP(edge({ "cf-connecting-ip": value }), ClientIP.cloudflare);
    expect(resolve("2001:0db8:0000:0000:0000:0000:0000:0001")).toBe("2001:db8::1");
    expect(resolve("2001:0db8::0001")).toBe("2001:db8::1");
    expect(resolve("2001:db8:0:0:1:0:0:1")).toBe("2001:db8::1:0:0:1");
    expect(resolve("0:0:0:0:0:0:0:1")).toBe("::1");
    // The longest zero run is compressed, not the first.
    expect(resolve("2001:0:0:1:0:0:0:1")).toBe("2001:0:0:1::1");
    // Every spelling of an IPv4-mapped address unwraps to dotted IPv4, as the
    // socket path does.
    expect(resolve("0:0:0:0:0:ffff:203.0.113.7")).toBe("203.0.113.7");
    expect(resolve("::ffff:cb00:7107")).toBe("203.0.113.7");
    expect(resolve("::FFFF:CB00:7107")).toBe("203.0.113.7");
  });

  it("refuses duplicate headers, which the Fetch API joins with a comma", () => {
    const headers = new Headers();
    headers.append("cf-connecting-ip", "203.0.113.7");
    headers.append("cf-connecting-ip", "6.6.6.6");
    expect(resolveClientIP(edge(R.fromEntries(headers)), ClientIP.cloudflare)).toBe("10.0.0.50");
  });

  it("reads only an own header property, never an inherited one", () => {
    const inherited: Record<string, string> = Object.create({ "cf-connecting-ip": "203.0.113.7" });
    expect(resolveClientIP(edge(inherited), ClientIP.cloudflare)).toBe("10.0.0.50");
  });

  it("never reads an inherited key as the forwarded-list header either", () => {
    expect(resolveClientIP(edge({}), { header: "constructor", hopCount: 1 })).toBe("10.0.0.50");
  });

  it("ignores inherited object keys as header names", () => {
    expect(resolveClientIP(edge({}), ClientIP.trustedHeader("constructor"))).toBe("10.0.0.50");
  });

  it("trims only HTTP whitespace (SP and HTAB) around the value", () => {
    const resolve = (value: string) =>
      resolveClientIP(edge({ "cf-connecting-ip": value }), ClientIP.cloudflare);
    expect(resolve("\t203.0.113.7 ")).toBe("203.0.113.7");
    expect(resolve("\u00a0203.0.113.7")).toBe("10.0.0.50");
  });

  it("accepts an IPv6 address with an embedded IPv4 tail, in hex-group form", () => {
    expect(resolveClientIP(edge({ "cf-connecting-ip": "::1.2.3.4" }), ClientIP.cloudflare)).toBe(
      "::102:304",
    );
  });

  it("uses the header's address even when there is no socket address", () => {
    expect(
      resolveClientIP(edge({ "cf-connecting-ip": "203.0.113.7" }, null), ClientIP.cloudflare),
    ).toBe("203.0.113.7");
  });

  it("returns undefined when the header is unusable and there is no socket address", () => {
    expect(
      resolveClientIP(edge({ "cf-connecting-ip": "6.6.6.6, 7.7.7.7" }, null), ClientIP.cloudflare),
    ).toBeUndefined();
  });
});

describe("ClientIP.trustedHeader", () => {
  it("lowercases the header name", () => {
    expect(ClientIP.trustedHeader("CF-Connecting-IP")).toEqual({
      trustedHeader: "cf-connecting-ip",
    });
  });

  it("reads only the named header", () => {
    const realIp = ClientIP.trustedHeader("x-real-ip");
    expect(resolveClientIP(edge({ "x-real-ip": "203.0.113.7" }), realIp)).toBe("203.0.113.7");
    expect(resolveClientIP(edge({ "cf-connecting-ip": "203.0.113.7" }), realIp)).toBe("10.0.0.50");
  });

  it("is the same configuration as the cloudflare preset for that header", () => {
    expect(ClientIP.trustedHeader("cf-connecting-ip")).toEqual(ClientIP.cloudflare);
  });

  it.each(["", "x y", "x:y", "x,y", "x/y"])("rejects %j as a header name", (name) => {
    expect(() => ClientIP.trustedHeader(name)).toThrow(/not a valid HTTP header name/);
  });
});

describe("clientIPLayer with a trusted header", () => {
  it("provides the resolved address from the ambient request", async () => {
    const request = HttpServerRequest.fromWeb(
      new Request("http://localhost/", {
        headers: { "cf-connecting-ip": "203.0.113.7", "x-forwarded-for": "6.6.6.6" },
      }),
    );
    const ip = await Effect.runPromise(
      Effect.gen(function* () {
        const { ip } = yield* ClientIP;
        return ip;
      }).pipe(
        Effect.provide(clientIPLayer(ClientIP.cloudflare)),
        Effect.provideService(HttpServerRequest.HttpServerRequest, request),
      ),
    );
    expect(ip).toBe("203.0.113.7");
  });
});
