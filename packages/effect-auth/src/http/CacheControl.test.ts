/**
 * The `no-store` merge (#628), and the backstop `Http.make`'s handler runs
 * over every response it serves: `noStoreWithSetCookie`. No endpoint answers a
 * cacheable `Cache-Control` beside a cookie, so the backstop is driven here
 * with the response a handler would have produced.
 */
import { describe, expect, it } from "vite-plus/test";
import { mergeNoStore, noStoreWithSetCookie } from "./CacheControl.ts";

const served = (headers: Record<string, string>) =>
  new Response("{}", { status: 200, statusText: "OK", headers });

describe("the serve backstop: noStoreWithSetCookie (#628)", () => {
  it("appends no-store to a public, max-age=60 response that sets a cookie", () => {
    const response = noStoreWithSetCookie(
      served({ "cache-control": "public, max-age=60", "set-cookie": "a=b; Path=/" }),
    );
    expect(response.headers.get("cache-control")).toBe("public, max-age=60, no-store");
    expect(response.headers.getSetCookie()).toStrictEqual(["a=b; Path=/"]);
    expect(response.status).toBe(200);
    expect(response.statusText).toBe("OK");
  });

  it("marks a cookie-setting response with no Cache-Control no-store", () => {
    const response = noStoreWithSetCookie(served({ "set-cookie": "a=b" }));
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("returns a response that needs no change as it is", () => {
    const cacheable = served({ "cache-control": "public, max-age=60" });
    expect(noStoreWithSetCookie(cacheable)).toBe(cacheable);
    const marked = served({ "cache-control": "No-Store", "set-cookie": "a=b" });
    expect(noStoreWithSetCookie(marked)).toBe(marked);
  });

  it("merges no-store once into any Cache-Control", () => {
    expect(mergeNoStore(undefined)).toBe("no-store");
    expect(mergeNoStore("  ")).toBe("no-store");
    expect(mergeNoStore("private")).toBe("private, no-store");
    expect(mergeNoStore("private, no-store")).toBe("private, no-store");
  });
});
