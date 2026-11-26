import { describe, expect, it } from "vite-plus/test";
import * as Arr from "effect/Array";
import { normalizeDomain, normalizeEmail } from "./utils.ts";

describe("normalizeEmail", () => {
  it("trims and lower-cases an ASCII address", () => {
    expect(normalizeEmail("  Bob@Example.COM ")).toBe("bob@example.com");
  });

  it("makes every spelling of an internationalised domain one identifier", () => {
    const spellings = [
      "bob@exämple.com", // precomposed
      "bob@exämple.com", // decomposed
      "bob@EXÄMPLE.com",
      "bob@xn--exmple-cua.com",
      "bob@XN--EXMPLE-CUA.COM",
    ];
    expect(Arr.dedupe(Arr.map(spellings, normalizeEmail))).toEqual(["bob@xn--exmple-cua.com"]);
  });

  it("keeps an internationalised domain distinct from its ASCII look-alike", () => {
    expect(normalizeEmail("bob@exämple.com")).not.toBe(normalizeEmail("bob@example.com"));
  });

  it("maps full-width domain letters to ASCII", () => {
    expect(normalizeEmail("bob@ｅｘａｍｐｌｅ.com")).toBe("bob@example.com");
  });

  it("NFC-normalises the local part and keeps it Unicode", () => {
    expect(normalizeEmail("Jäger@example.com")).toBe("jäger@example.com");
  });

  it("splits at the last @", () => {
    expect(normalizeEmail('"a@b"@Exämple.com')).toBe('"a@b"@xn--exmple-cua.com');
  });

  it("normalises a value with no @ as a whole", () => {
    expect(normalizeEmail(" Jäger ")).toBe("jäger");
  });
});

describe("normalizeDomain", () => {
  it("uses UTS 46 non-transitional processing", () => {
    expect(normalizeDomain("faß.de")).toBe("xn--fa-hia.de");
  });

  it("falls back to lower case and NFC when the domain is not a valid IDN", () => {
    // Labels the URL parser would refuse, split, decode or read as an address.
    expect(normalizeDomain("Exämple%2e.com")).toBe("exämple%2e.com");
    expect(normalizeDomain("[Ä::1]")).toBe("[ä::1]");
    expect(normalizeDomain("１.２.３.４")).toBe("１.２.３.４");
    expect(normalizeDomain("xn--ä.com")).toBe("xn--ä.com");
  });
});
