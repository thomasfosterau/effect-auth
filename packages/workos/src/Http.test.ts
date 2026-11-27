import { describe, expect, it } from "vite-plus/test";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import { KeyValueStore } from "effect/persistence";
import * as Auth from "@thomasfosterau/effect-auth";
import { createAuthClient } from "@thomasfosterau/effect-auth/client";
import { makeCookieJarFetch } from "@thomasfosterau/effect-auth/client/testing";
import * as Http from "@thomasfosterau/effect-auth/http";
import * as Fake from "./FakeWorkOS.fixtures.ts";
import * as Backend from "./index.ts";
import { RevokedSessions } from "./Session.ts";

const BASE = "http://app.test";
const email = "ada@example.com";
const password = "correct horse battery staple";

/** `Http.make` over the WorkOS backend and a fake WorkOS, with a browser. */
const withServer = async (fakeOptions: Fake.FakeOptions = {}) => {
  const fake = await Effect.runPromise(Fake.make(fakeOptions));
  const services = Backend.layerHttpClient(Fake.testConfig({ clockSkewLeeway: 0 })).pipe(
    Layer.provideMerge(
      Layer.mergeAll(
        fake.layer,
        Auth.Hooks.Hooks.Default,
        Auth.KeyValueStores.OAuthStateStoreKV.pipe(Layer.provide(KeyValueStore.layerMemory)),
        Auth.RootSecret.RootSecret.layer("a-root-secret-of-at-least-32-bytes-long").pipe(
          Layer.orDie,
        ),
        RevokedSessions.layerMemory,
      ),
    ),
  );
  const { handler } = Http.make({ services, cookie: { secure: false }, ipRateLimit: false });
  const responses: Array<Response> = [];
  const fetch = makeCookieJarFetch(async (request) => {
    const response = await handler(request);
    responses.push(response.clone());
    return response;
  });
  return { fake, responses, client: createAuthClient({ baseUrl: BASE, fetch }) };
};

describe("Http.make over WorkOS", () => {
  it("signs up, signs in, refreshes behind the cookie and signs out", async () => {
    const { fake, responses, client } = await withServer({ accessTokenTtl: 2 });
    await client.signUp({ email, password, name: "Ada Lovelace" });
    const signedIn = await client.signIn({ email, password });
    expect(signedIn.user?.email).toBe(email);
    const session = Option.getOrUndefined(await client.getSession());
    expect(session?.user.id).toBe(signedIn.user?.id);

    const refreshes = () => fake.calls.filter((c) => c.body?.grant_type === "refresh_token").length;
    expect(refreshes()).toBe(0);
    await new Promise((resolve) => setTimeout(resolve, 2_100));
    const before = responses.length;
    const refreshed = Option.getOrUndefined(await client.getSession());
    expect(refreshed?.user.id).toBe(signedIn.user?.id);
    expect(refreshes()).toBe(1);
    const answer = responses[before];
    const setCookie = answer.headers.getSetCookie().join("\n");
    expect(setCookie).toMatch(/w1~/);
    expect(answer.headers.get("cache-control")).toContain("no-store");
    expect(await answer.text()).not.toMatch(/w1~/);
    // The browser now holds the reissued cookie: no second refresh.
    await client.getSession();
    expect(refreshes()).toBe(1);

    const current = refreshed?.session.id;
    expect(fake.sessionStatus(current ?? "")).toBe("active");
    await client.signOut();
    expect(fake.sessionStatus(current ?? "")).toBe("inactive");
    expect(Option.isNone(await client.getSession())).toBe(true);
  });
});
