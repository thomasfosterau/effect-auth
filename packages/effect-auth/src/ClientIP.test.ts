import { describe, it, expect } from "vite-plus/test";
import { Option } from "effect";
import {
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
    // Attacker sends: X-Forwarded-For: evil, victim, proxy1
    // Real chain (remote=proxy1): [evil, victim, proxy1(xff), 9.10.11.12(remote)]
    // With hopCount:1 → skip remote → return proxy1 from xff, NOT victim
    // Client = chain[3 - 1 - 1] = chain[1] = "victim.ip"
    // Wait, let's trace more carefully:
    // XFF: "evil, victim, proxy1" → entries: [evil, victim, proxy1]
    // remote: "9.10.11.12"
    // extended chain: [evil, victim, proxy1, 9.10.11.12]
    // hopCount:1 → index = 4 - 1 - 1 = 2 → "proxy1" (not evil or victim)
    const result = resolveClientIP(req("evil.ip, victim.ip, 10.0.0.100", "9.10.11.12"), {
      hopCount: 1,
    });
    // With hopCount:1 we trust 1 proxy (the last one, socket peer 9.10.11.12).
    // The second-to-last is the entry the trusted proxy got: 10.0.0.100.
    expect(result).toBe("10.0.0.100");
  });

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
    const result = resolveClientIP(req("victim.ip, 10.0.0.100", "evil.attacker.ip"), trusted10);
    // Chain right-to-left: evil.attacker.ip (NOT in 10/8) → stop, return it
    expect(result).toBe("evil.attacker.ip");
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
