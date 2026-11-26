/**
 * The SvelteKit binding on top of a BetterAuth app: `handle` over
 * `BetterAuthSessions.lookup`, and `credentialAction` posting to BetterAuth's
 * own sign-in route through `auth.handler`.
 */
import { describe, expect, it } from "vite-plus/test";
import { Effect, Layer, ManagedRuntime } from "effect";
import * as Arr from "effect/Array";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import { credentialAction, handle, type LocalsAuth } from "@thomasfosterau/effect-auth-sveltekit";
import { twoFactor } from "better-auth/plugins";
import { makeAuth, rowOf, signUp, type TestAuth } from "./testing/Fixtures.ts";
import { BetterAuthInstance } from "./BetterAuth.ts";
import { BetterAuthSessions } from "./Session.ts";

class Redirect {
  constructor(
    readonly status: number,
    readonly location: string,
  ) {}
}

const kit = {
  redirect: (status: 303, location: string): never => {
    throw new Redirect(status, location);
  },
  fail: <Data>(status: number, data: Data) => ({ status, data }),
};

const formText = (form: FormData, name: string): string => {
  const value = form.get(name);
  return P.isString(value) ? value : "";
};

const sessionsOf = async (auth: TestAuth) => {
  const runtime = ManagedRuntime.make(
    BetterAuthSessions.layer.pipe(Layer.provide(BetterAuthInstance.layer(auth))),
  );
  return runtime.runPromise(Effect.service(BetterAuthSessions));
};

const event = (cookie: string | undefined) => {
  const request = new Request("http://localhost/dashboard", {
    headers: cookie === undefined ? {} : { cookie },
  });
  const jar = R.fromEntries(
    Arr.map((cookie ?? "").split("; "), (pair) => {
      const at = pair.indexOf("=");
      return [pair.slice(0, at), pair.slice(at + 1)] as const;
    }),
  );
  const locals: { auth?: LocalsAuth } = {};
  return {
    request,
    getClientAddress: () => "203.0.113.9",
    cookies: { get: (name: string) => jar[name] },
    locals,
  };
};

describe("handle over BetterAuth", () => {
  it("puts BetterAuth's session on locals, and skips a request without its cookie", async () => {
    const { auth } = makeAuth();
    const { cookie, user } = await signUp(auth);
    const sessions = await sessionsOf(auth);
    const hook = handle({
      cookies: sessions.credentialConfig,
      lookup: (request) => sessions.lookup(request),
      failure: { mode: "closed" },
    });

    const signedIn = event(cookie);
    const response = await hook({ event: signedIn, resolve: () => new Response("ok") });
    expect(signedIn.locals.auth?.session?.user.id).toBe(user.id);
    expect(signedIn.locals.auth?.outcome).toBe("resolved");
    expect(response.headers.get("cache-control")).toContain("no-store");

    const anonymous = event(undefined);
    await hook({ event: anonymous, resolve: () => new Response("ok") });
    expect(anonymous.locals.auth).toEqual({ session: null, outcome: "skipped" });
  });
});

const signInAction = (auth: TestAuth) =>
  credentialAction(kit, {
    fetch: (request) => auth.handler(request),
    endpoint: "http://localhost/api/auth/sign-in/email",
    contentType: "application/json",
    body: (form) => ({ email: formText(form, "email"), password: formText(form, "password") }),
    fields: (form) => ({ email: formText(form, "email") }),
    fallback: "/home",
  });

const submit = (email: string, password: string) => {
  const form = new FormData();
  form.set("email", email);
  form.set("password", password);
  const cookies: Array<string> = [];
  const values: Record<string, string> = {};
  return {
    cookies,
    values,
    event: {
      request: new Request("http://localhost/login", { method: "POST", body: form }),
      url: new URL("http://localhost/login"),
      getClientAddress: () => "203.0.113.9",
      cookies: {
        set: (name: string, value: string) => {
          cookies.push(name);
          values[name] = value;
        },
      },
    },
  };
};

describe("credentialAction against BetterAuth's sign-in route", () => {
  it("relays BetterAuth's session cookie and redirects", async () => {
    const { auth } = makeAuth();
    const { email, password } = await signUp(auth);
    const { event: input, cookies } = submit(email, password);
    await expect(signInAction(auth)(input)).rejects.toMatchObject({
      status: 303,
      location: "/home",
    });
    expect(cookies).toContain("better-auth.session_token");
  });

  it("fails a wrong password as invalid", async () => {
    const { auth } = makeAuth();
    const { email } = await signUp(auth);
    const { event: input } = submit(email, "not the password");
    expect(await signInAction(auth)(input)).toMatchObject({
      status: 400,
      data: { kind: "invalid" },
    });
  });

  // A documented limit: BetterAuth holds a two-factor sign-in with
  // `200 { twoFactorRedirect: true }`, not the `202` the action reads as
  // pending, so the action redirects as if signed in. BetterAuth clears the
  // session cookie, so the viewer arrives signed out; the app routes to its
  // second-factor page itself.
  it("redirects a two-factor sign-in BetterAuth holds, setting no session cookie", async () => {
    const { auth, db } = makeAuth({ plugins: [twoFactor()] });
    db["twoFactor"] = [];
    const { email, password, user } = await signUp(auth);
    const row = rowOf(db, "user", (u) => u["id"] === user.id);
    row["twoFactorEnabled"] = true;
    const { event: input, values } = submit(email, password);
    await expect(signInAction(auth)(input)).rejects.toBeInstanceOf(Redirect);
    // BetterAuth clears the session cookie and sets its two-factor cookie.
    expect(values["better-auth.session_token"] ?? "").toBe("");
    expect(values["better-auth.two_factor"]).toBeTruthy();
  });
});
