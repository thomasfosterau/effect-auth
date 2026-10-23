import { assert, describe, expect, it } from "vite-plus/test";
import { Effect, Option } from "effect";
import type { SessionWithUser } from "@thomasfosterau/effect-auth";
import {
  type ActionEvent,
  type CookieOptions,
  credentialAction,
  handle,
  type LocalsAuth,
  parseSetCookie,
  PRIVATE_CACHE_CONTROL,
} from "./index.ts";

const now = new Date("2026-10-23T00:00:00.000Z");
const signedIn: SessionWithUser = {
  session: {
    id: "session-hash",
    userId: "u-1",
    expiresAt: new Date(now.getTime() + 60_000),
    createdAt: now,
    lastActivityAt: now,
    attributes: {},
  },
  user: { id: "u-1", createdAt: now, updatedAt: now, attributes: {} },
};

const event = (cookies: Record<string, string> = {}) => ({
  request: new Request("https://app.example/page"),
  cookies: { get: (name: string) => cookies[name] },
  locals: {} as { auth?: LocalsAuth },
});

const sessionCookie = { "__Host-conduit_session": "token" };

describe("handle", () => {
  it("skips the lookup without a credential and leaves caching alone", async () => {
    let looked = false;
    const hook = handle({
      lookup: () =>
        Effect.sync(() => {
          looked = true;
          return Option.some(signedIn);
        }),
      failure: { mode: "closed" },
    });
    const input = event();
    const response = await hook({
      event: input,
      resolve: () => new Response("page", { headers: { "cache-control": "public, max-age=60" } }),
    });
    expect(looked).toBe(false);
    expect(input.locals.auth).toEqual({ session: null, outcome: "skipped" });
    expect(response.headers.get("cache-control")).toBe("public, max-age=60");
  });

  it("resolves before rendering and forces private caching for a signed-in viewer", async () => {
    const hook = handle({ lookup: () => Effect.succeed(Option.some(signedIn)), failure: { mode: "closed" } });
    const input = event(sessionCookie);
    let seenByRender: LocalsAuth | undefined;
    const response = await hook({
      event: input,
      resolve: (resolved) => {
        seenByRender = resolved.locals.auth;
        return new Response("page", { headers: { "cache-control": "public, max-age=60" } });
      },
    });
    expect(seenByRender?.session?.user.id).toBe("u-1");
    expect(seenByRender?.outcome).toBe("resolved");
    expect(response.headers.get("cache-control")).toBe(PRIVATE_CACHE_CONTROL);
    expect(await response.text()).toBe("page");
  });

  it("forces private caching even when the rendered response's headers are immutable", async () => {
    const hook = handle({ lookup: () => Effect.succeed(Option.some(signedIn)), failure: { mode: "closed" } });
    const immutable = Response.redirect("https://app.example/elsewhere", 302);
    const response = await hook({ event: event(sessionCookie), resolve: () => immutable });
    expect(response.headers.get("cache-control")).toBe(PRIVATE_CACHE_CONTROL);
    expect(response.status).toBe(302);
  });

  it("fails open as anonymous, and reports the fault", async () => {
    let degraded = 0;
    const hook = handle({
      lookup: () => Effect.fail("binding unreachable"),
      failure: { mode: "open", onDegraded: () => Effect.sync(() => void degraded++) },
    });
    const input = event(sessionCookie);
    await hook({ event: input, resolve: () => new Response("page") });
    expect(input.locals.auth).toEqual({ session: null, outcome: "degraded" });
    expect(degraded).toBe(1);
  });

  it("fails closed by rejecting", async () => {
    const hook = handle({ lookup: () => Effect.fail("binding unreachable"), failure: { mode: "closed" } });
    await expect(hook({ event: event(sessionCookie), resolve: () => new Response("page") })).rejects.toThrow();
  });
});

describe("parseSetCookie", () => {
  it("reads the name, value and attributes", () => {
    const parsed = parseSetCookie(
      "__Host-conduit_session=abc.def; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax",
    );
    assert(Option.isSome(parsed));
    expect(parsed.value).toEqual({
      name: "__Host-conduit_session",
      value: "abc.def",
      options: { path: "/", maxAge: 3600, httpOnly: true, secure: true, sameSite: "lax" },
    });
  });

  it("keeps the handler's choice when HttpOnly or Secure is absent", () => {
    const parsed = parseSetCookie("theme=dark; Path=/settings");
    assert(Option.isSome(parsed));
    expect(parsed.value.options).toEqual({ path: "/settings", httpOnly: false, secure: false });
  });

  it("rejects a header with no name", () => {
    expect(Option.isNone(parseSetCookie("=value; Path=/"))).toBe(true);
  });
});

/** Stands in for SvelteKit's `Redirect`, which `redirect()` throws. */
class Redirect extends Error {
  constructor(
    readonly status: number,
    readonly location: string,
  ) {
    super(`redirect ${status} ${location}`);
  }
}
const kit = {
  redirect: (status: 303, location: string): never => {
    throw new Redirect(status, location);
  },
  fail: (status: number, data: unknown) => ({ status, data }),
};

const submit = (url: string): { event: ActionEvent; cookies: Array<[string, string, CookieOptions]> } => {
  const form = new FormData();
  form.set("email", "ada@example.com");
  form.set("password", "hunter2");
  const cookies: Array<[string, string, CookieOptions]> = [];
  return {
    cookies,
    event: {
      request: new Request("https://app.example/login", {
        method: "POST",
        body: form,
        headers: { origin: "https://app.example" },
      }),
      url: new URL(url),
      cookies: { set: (name, value, options) => void cookies.push([name, value, options]) },
    },
  };
};

const signInWith = (answer: () => Promise<Response>, seen?: Array<Request>) =>
  credentialAction(kit, {
    fetch: async (request) => {
      seen?.push(request);
      return answer();
    },
    endpoint: "https://auth.internal/api/auth/sign-in",
    body: (form) => ({ email: form.get("email"), password: form.get("password") }),
    fields: (form) => ({ email: String(form.get("email") ?? "") }),
    fallback: "/home",
  });

const thrown = async (promise: Promise<unknown>): Promise<unknown> =>
  promise.then(
    () => undefined,
    (error: unknown) => error,
  );

describe("credentialAction", () => {
  it("relays Set-Cookie and redirects to the validated target", async () => {
    const seen: Array<Request> = [];
    const { event: input, cookies } = submit("https://app.example/login?redirect=/dashboard");
    const headers = new Headers();
    headers.append("set-cookie", "__Host-conduit_session=tok; Path=/; HttpOnly; Secure; SameSite=Lax");
    headers.append("set-cookie", "__Host-conduit_session_data=cache; Path=/; HttpOnly; Secure");
    const redirect = await thrown(signInWith(async () => new Response("{}", { headers }), seen)(input));
    expect(redirect).toMatchObject({ status: 303, location: "/dashboard" });
    expect(cookies.map(([name]) => name)).toEqual([
      "__Host-conduit_session",
      "__Host-conduit_session_data",
    ]);
    const [request] = seen;
    assert(request !== undefined);
    expect(request.headers.get("origin")).toBe("https://app.example");
    expect(await request.json()).toEqual({ email: "ada@example.com", password: "hunter2" });
  });

  it("refuses an off-site redirect target", async () => {
    const { event: input } = submit("https://app.example/login?redirect=https://evil.example");
    const redirect = await thrown(signInWith(async () => new Response("{}"))(input));
    expect(redirect).toMatchObject({ status: 303, location: "/home" });
  });

  it("reports wrong credentials (401) as invalid, without echoing the password", async () => {
    const { event: input, cookies } = submit("https://app.example/login");
    const result = await signInWith(async () => new Response(null, { status: 401 }))(input);
    expect(result).toEqual({
      status: 400,
      data: {
        kind: "invalid",
        message: "Invalid email or password.",
        retryAfterSeconds: null,
        fields: { email: "ada@example.com" },
      },
    });
    expect(cookies).toEqual([]);
  });

  it("reports throttling (429) distinctly, with Retry-After", async () => {
    const { event: input } = submit("https://app.example/login");
    const result = await signInWith(
      async () => new Response(null, { status: 429, headers: { "retry-after": "42" } }),
    )(input);
    expect(result).toMatchObject({ status: 429, data: { kind: "rate-limited", retryAfterSeconds: 42 } });
  });

  it("reports a failing service as unavailable", async () => {
    const { event: input } = submit("https://app.example/login");
    expect(await signInWith(async () => new Response(null, { status: 502 }))(input)).toMatchObject({
      status: 503,
      data: { kind: "unavailable" },
    });
    const { event: again } = submit("https://app.example/login");
    expect(await signInWith(() => Promise.reject(new TypeError("fetch failed")))(again)).toMatchObject({
      status: 503,
      data: { kind: "unavailable" },
    });
  });
});
