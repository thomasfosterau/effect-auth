import { describe, expect, it } from "vite-plus/test";
import { idpUrlPolicy } from "./IdpUrlPolicy.ts";

const strict = idpUrlPolicy(false);
const lenient = idpUrlPolicy(true);

describe("idpUrlPolicy", () => {
  it("accepts a public https URL", () => {
    expect(strict("https://login.example.com/oauth2/token")).toBeUndefined();
    expect(strict("https://8.8.8.8/jwks")).toBeUndefined();
    expect(strict("https://[2001:4860:4860::8888]/jwks")).toBeUndefined();
  });

  it.each([
    ["plain http", "http://login.example.com/token"],
    ["not a URL", "not a url"],
    ["another scheme", "file:///etc/passwd"],
    ["credentials", "https://user:secret@login.example.com/token"],
    ["loopback", "https://127.0.0.1/token"],
    ["loopback (another form)", "https://127.1.2.3/token"],
    ["unspecified", "https://0.0.0.0/token"],
    ["private 10/8", "https://10.20.30.40/token"],
    ["private 172.16/12", "https://172.31.255.1/token"],
    ["private 192.168/16", "https://192.168.0.10/token"],
    ["link-local metadata", "https://169.254.169.254/latest/meta-data"],
    ["CGNAT", "https://100.64.0.1/token"],
    ["IPv6 loopback", "https://[::1]/token"],
    ["IPv6 unique local", "https://[fd00::1]/token"],
    ["IPv6 link-local", "https://[fe80::1]/token"],
    ["IPv4-mapped loopback", "https://[::ffff:127.0.0.1]/token"],
    ["localhost", "https://localhost/token"],
    ["a localhost subdomain", "https://idp.localhost/token"],
    ["mDNS", "https://printer.local/token"],
    ["an internal zone", "https://idp.corp.internal/token"],
    ["a single label", "https://intranet/token"],
    ["a trailing dot", "https://localhost./token"],
  ])("refuses %s", (_label, url) => {
    expect(strict(url)).toBeTypeOf("string");
  });

  it("with allowPrivate, accepts private and plain-http URLs but still refuses credentials", () => {
    expect(lenient("http://10.0.0.5:8080/token")).toBeUndefined();
    expect(lenient("https://localhost/token")).toBeUndefined();
    expect(lenient("https://user:pw@idp.local/token")).toBeTypeOf("string");
    expect(lenient("ftp://idp.example.com/token")).toBeTypeOf("string");
  });
});
