import { assert, describe, expect, it } from "vite-plus/test";
import { DateTime, Effect } from "effect";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import type { SessionWithUser } from "@thomasfosterau/effect-auth";
import {
  type ActionEvent,
  type CookieOptions,
  credentialAction,
  credentialCommand,
  credentialForm,
  handle,
  type LocalsAuth,
  parseSetCookie,
  PRIVATE_CACHE_CONTROL,
} from "./index.ts";

const now = DateTime.toDateUtc(DateTime.makeUnsafe("2026-10-23T00:00:00.000Z"));
const signedIn: SessionWithUser = {
  session: {
    id: "session-hash",
    userId: "u-1",
    expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(now.getTime() + 60_000)),
    createdAt: now,
    lastActivityAt: now,
    attributes: {},
  },
  user: { id: "u-1", createdAt: now, updatedAt: now, attributes: {} },
};

const event = (cookies: Record<string, string> = {}) => {
  const locals: { auth?: LocalsAuth } = {};
  return {
    request: new Request("https://app.example/page"),
    cookies: { get: (name: string) => cookies[name] },
    locals,
  };
};

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
    const hook = handle({
      lookup: () => Effect.succeed(Option.some(signedIn)),
      failure: { mode: "closed" },
    });
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
    const hook = handle({
      lookup: () => Effect.succeed(Option.some(signedIn)),
      failure: { mode: "closed" },
    });
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
    const hook = handle({
      lookup: () => Effect.fail("binding unreachable"),
      failure: { mode: "closed" },
    });
    await expect(
      hook({ event: event(sessionCookie), resolve: () => new Response("page") }),
    ).rejects.toThrow(/binding unreachable/);
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
/** A text field of a submitted form; a missing field or a file reads as empty. */
const formText = (form: FormData, name: string): string => {
  const value = form.get(name);
  return P.isString(value) ? value : "";
};

/** A JSON body for a stubbed handler response. */
const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

const kit = {
  redirect: (status: 303, location: string): never => {
    throw new Redirect(status, location);
  },
  fail: <Data>(status: number, data: Data) => ({ status, data }),
};

const submit = (
  url: string,
): { event: ActionEvent; cookies: Array<[string, string, CookieOptions]> } => {
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
    endpoint: "https://auth.internal/api/auth/sessions",
    body: (form) => ({
      data: {
        type: "sessions",
        attributes: {
          credential: {
            method: "password",
            email: formText(form, "email"),
            password: formText(form, "password"),
          },
        },
      },
    }),
    fields: (form) => ({ email: formText(form, "email") }),
    fallback: "/home",
  });

describe("credentialAction", () => {
  it("relays Set-Cookie and redirects to the validated target", async () => {
    const seen: Array<Request> = [];
    const { event: input, cookies } = submit("https://app.example/login?redirect=/dashboard");
    const headers = new Headers();
    headers.append(
      "set-cookie",
      "__Host-conduit_session=tok; Path=/; HttpOnly; Secure; SameSite=Lax",
    );
    headers.append("set-cookie", "__Host-conduit_session_data=cache; Path=/; HttpOnly; Secure");
    await expect(
      signInWith(async () => new Response("{}", { headers }), seen)(input),
    ).rejects.toMatchObject({ status: 303, location: "/dashboard" });
    expect(cookies.map(([name]) => name)).toEqual([
      "__Host-conduit_session",
      "__Host-conduit_session_data",
    ]);
    const [request] = seen;
    assert(request !== undefined);
    expect(request.headers.get("origin")).toBe("https://app.example");
    // A JSON:API document, as the auth handler's credential flows accept.
    expect(request.headers.get("content-type")).toBe("application/vnd.api+json");
    expect(await request.json()).toEqual({
      data: {
        type: "sessions",
        attributes: {
          credential: { method: "password", email: "ada@example.com", password: "hunter2" },
        },
      },
    });
  });

  it("relays Set-Cookie and redirects on a 201 that issued a session", async () => {
    const { event: input, cookies } = submit("https://app.example/login?redirect=/dashboard");
    const headers = new Headers({ "content-type": "application/vnd.api+json" });
    headers.append("set-cookie", "__Host-conduit_session=tok; Path=/; HttpOnly; Secure");
    await expect(
      signInWith(async () => new Response("{}", { status: 201, headers }))(input),
    ).rejects.toMatchObject({ status: 303, location: "/dashboard" });
    expect(cookies.map(([name]) => name)).toEqual(["__Host-conduit_session"]);
  });

  it("returns the second-factor challenge on a 202, without redirecting", async () => {
    const { event: input, cookies } = submit("https://app.example/login?redirect=/dashboard");
    const body = {
      data: {
        type: "second-factor-challenges",
        id: "challenge-token",
        attributes: { expiresAt: "2026-10-23T00:05:00.000Z" },
      },
      meta: { needsEmailVerification: false },
    };
    const result = await signInWith(async () => new Response(encodeJson(body), { status: 202 }))(
      input,
    );
    expect(result).toEqual({
      kind: "pending",
      secondFactor: { token: "challenge-token", expiresAt: "2026-10-23T00:05:00.000Z" },
      needsEmailVerification: false,
      fields: { email: "ada@example.com" },
    });
    expect(cookies).toEqual([]);
  });

  it("returns needsEmailVerification on a 202 with no primary data", async () => {
    const { event: input } = submit("https://app.example/login");
    const result = await signInWith(
      async () =>
        new Response(encodeJson({ meta: { needsEmailVerification: true } }), {
          status: 202,
        }),
    )(input);
    expect(result).toEqual({
      kind: "pending",
      secondFactor: null,
      needsEmailVerification: true,
      fields: { email: "ada@example.com" },
    });
  });

  it("reports a 202 whose body is not a pending document as unavailable", async () => {
    const { event: input } = submit("https://app.example/login");
    expect(
      await signInWith(async () => new Response("not json", { status: 202 }))(input),
    ).toMatchObject({ status: 503, data: { kind: "unavailable" } });
  });

  it("refuses an off-site redirect target", async () => {
    const { event: input } = submit("https://app.example/login?redirect=https://evil.example");
    await expect(signInWith(async () => new Response("{}"))(input)).rejects.toMatchObject({
      status: 303,
      location: "/home",
    });
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
    expect(result).toMatchObject({
      status: 429,
      data: { kind: "rate-limited", retryAfterSeconds: 42 },
    });
  });

  it("reports a failing service as unavailable", async () => {
    const { event: input } = submit("https://app.example/login");
    expect(await signInWith(async () => new Response(null, { status: 502 }))(input)).toMatchObject({
      status: 503,
      data: { kind: "unavailable" },
    });
    const { event: again } = submit("https://app.example/login");
    expect(
      await signInWith(() => Promise.reject(new TypeError("fetch failed")))(again),
    ).toMatchObject({
      status: 503,
      data: { kind: "unavailable" },
    });
  });
});

/** A remote call's event: its URL is the remote endpoint's, not the page's. */
const remote = () => {
  const cookies: Array<[string, string, CookieOptions]> = [];
  const remoteEvent: ActionEvent = {
    request: new Request("https://app.example/_app/remote/abc/signIn", {
      method: "POST",
      headers: { origin: "https://app.example" },
    }),
    url: new URL("https://app.example/_app/remote/abc/signIn?redirect=/elsewhere"),
    cookies: { set: (name, value, options) => void cookies.push([name, value, options]) },
  };
  return { cookies, getRequestEvent: () => remoteEvent };
};

const sessionResponse = () => {
  const headers = new Headers();
  headers.append("set-cookie", "__Host-conduit_session=tok; Path=/; HttpOnly; Secure");
  return new Response("{}", { status: 201, headers });
};

describe("remote functions", () => {
  type Credential = { readonly email: string; readonly password: string; readonly next: string };
  const input: Credential = { email: "ada@example.com", password: "hunter2", next: "/dashboard" };

  const options = (answer: () => Promise<Response>, seen?: Array<Request>) => ({
    fetch: async (request: Request) => {
      seen?.push(request);
      return answer();
    },
    endpoint: "https://auth.internal/api/auth/sessions",
    body: (credential: Credential) => ({
      data: {
        type: "sessions",
        attributes: {
          credential: {
            method: "password",
            email: credential.email,
            password: credential.password,
          },
        },
      },
    }),
    fields: (credential: Credential) => ({ email: credential.email }),
    target: (credential: Credential) => credential.next,
    fallback: "/home",
  });

  it("form: sets the session cookie and redirects to the validated target from the input", async () => {
    const { cookies, getRequestEvent } = remote();
    const seen: Array<Request> = [];
    await expect(
      credentialForm(
        { getRequestEvent, redirect: kit.redirect },
        options(async () => sessionResponse(), seen),
      )(input),
    ).rejects.toMatchObject({ status: 303, location: "/dashboard" });
    expect(cookies.map(([name, , cookie]) => [name, cookie.httpOnly, cookie.secure])).toEqual([
      ["__Host-conduit_session", true, true],
    ]);
    expect(seen[0]?.headers.get("origin")).toBe("https://app.example");
  });

  it("form: refuses an off-site target from the input", async () => {
    const { getRequestEvent } = remote();
    await expect(
      credentialForm(
        { getRequestEvent, redirect: kit.redirect },
        options(async () => sessionResponse()),
      )({ ...input, next: "https://evil.example" }),
    ).rejects.toMatchObject({ status: 303, location: "/home" });
  });

  it("form: returns 401 and 429 as distinguishable failures, setting no cookie", async () => {
    const { cookies, getRequestEvent } = remote();
    const signIn = (answer: () => Promise<Response>) =>
      credentialForm({ getRequestEvent, redirect: kit.redirect }, options(answer))(input);
    expect(await signIn(async () => new Response(null, { status: 401 }))).toEqual({
      kind: "invalid",
      message: "Invalid email or password.",
      retryAfterSeconds: null,
      fields: { email: "ada@example.com" },
    });
    expect(
      await signIn(
        async () => new Response(null, { status: 429, headers: { "retry-after": "7" } }),
      ),
    ).toEqual({
      kind: "rate-limited",
      message: "Too many attempts. Please wait and try again.",
      retryAfterSeconds: 7,
      fields: { email: "ada@example.com" },
    });
    expect(cookies).toEqual([]);
  });

  it("form: returns the pending step on a 202, without redirecting", async () => {
    const { getRequestEvent } = remote();
    const result = await credentialForm(
      { getRequestEvent, redirect: kit.redirect },
      options(
        async () =>
          new Response(encodeJson({ meta: { needsEmailVerification: true } }), { status: 202 }),
      ),
    )(input);
    expect(result).toEqual({
      kind: "pending",
      secondFactor: null,
      needsEmailVerification: true,
      fields: { email: "ada@example.com" },
    });
  });

  it("command: sets the cookie and answers the target instead of redirecting", async () => {
    const { cookies, getRequestEvent } = remote();
    expect(
      await credentialCommand(
        { getRequestEvent },
        options(async () => sessionResponse()),
      )(input),
    ).toEqual({ kind: "signed-in", location: "/dashboard" });
    expect(cookies.map(([name]) => name)).toEqual(["__Host-conduit_session"]);
  });

  it("command: answers 401, 429 and faults as distinct failures with their statuses", async () => {
    const { getRequestEvent } = remote();
    const signIn = (answer: () => Promise<Response>) =>
      credentialCommand({ getRequestEvent }, options(answer))(input);
    expect(await signIn(async () => new Response(null, { status: 401 }))).toMatchObject({
      kind: "failed",
      status: 400,
      failure: { kind: "invalid" },
    });
    expect(
      await signIn(
        async () => new Response(null, { status: 429, headers: { "retry-after": "3" } }),
      ),
    ).toMatchObject({
      kind: "failed",
      status: 429,
      failure: { kind: "rate-limited", retryAfterSeconds: 3 },
    });
    expect(await signIn(() => Promise.reject(new TypeError("fetch failed")))).toMatchObject({
      kind: "failed",
      status: 503,
      failure: { kind: "unavailable" },
    });
  });

  it("defaults the target to the event URL's redirect parameter", async () => {
    const { getRequestEvent } = remote();
    const { target: _target, ...withoutTarget } = options(async () => sessionResponse());
    expect(await credentialCommand({ getRequestEvent }, withoutTarget)(input)).toEqual({
      kind: "signed-in",
      location: "/elsewhere",
    });
  });
});
