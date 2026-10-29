import { assert, describe, it, expect, vi } from "vite-plus/test";
import { Predicate, Schema } from "effect";
import { type AuthResult, createAuthClient, AuthClientError, definePlugin } from "./Client.ts";
import { makeCookieJarFetch, makeServerFixture } from "./testing/fixture.ts";

/** Whether a request is the store's session read (`GET /sessions/current`). */
const isSessionRead = (input: RequestInfo | URL, init?: RequestInit): boolean =>
  String(input).includes("/sessions/current") && (init?.method ?? "GET") === "GET";

const EMAIL = "alice@client.test";
const PW = "password-123";

const toJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

/** What `promise` rejected with, asserted to be an instance of `type`. */
const rejectionOf = <E>(
  promise: Promise<unknown>,
  type: abstract new (...args: never) => E,
): Promise<E> =>
  promise.then(
    () => assert.fail("expected the promise to reject"),
    (error) =>
      error instanceof type
        ? error
        : assert.fail(`expected a ${type.name} rejection, got ${String(error)}`),
  );

const makeClient = () => {
  const server = makeServerFixture();
  const client = createAuthClient({
    baseUrl: "http://client.test",
    fetch: makeCookieJarFetch(server.handler),
  });
  return { client, server };
};

/** The user a call that issued a session resolved with. */
const signedInUser = (result: AuthResult) => {
  assert(result.user !== undefined, "the call issued a session");
  return result.user;
};

describe("createAuthClient", () => {
  it("signs up, reads the session, and signs out", async () => {
    const { client } = makeClient();

    const signedUp = await client.signUp({ email: EMAIL, password: PW, name: "Alice" });
    expect(signedInUser(signedUp).email).toBe(EMAIL);

    const session = await client.getSession();
    expect(session?.user.email).toBe(EMAIL);

    await client.signOut();
    expect(await client.getSession()).toBeNull();
  });

  it("signs in with credentials and surfaces failures as AuthClientError", async () => {
    const { client } = makeClient();
    await client.signUp({ email: EMAIL, password: PW });
    await client.signOut();

    const err = await rejectionOf(
      client.signIn({ email: EMAIL, password: "wrong" }),
      AuthClientError,
    );
    assert.instanceOf(err, AuthClientError);
    expect(err.status).toBe(401);

    const ok = await client.signIn({ email: EMAIL, password: PW });
    expect(signedInUser(ok).email).toBe(EMAIL);
  });

  it("keeps the session store in sync across auth mutations", async () => {
    const { client } = makeClient();

    const states: Array<{ email: string | undefined; isPending: boolean }> = [];
    const unsubscribe = client.session.subscribe(() => {
      const s = client.session.get();
      states.push({ email: s.data?.user.email, isPending: s.isPending });
    });

    // Initial fetch (triggered by the subscription) resolves to signed out.
    await client.session.refetch();
    expect(client.session.get().data).toBeNull();
    expect(client.session.get().isPending).toBe(false);

    await client.signUp({ email: EMAIL, password: PW });
    expect(client.session.get().data?.user.email).toBe(EMAIL);

    await client.signOut();
    expect(client.session.get().data).toBeNull();

    unsubscribe();
    const count = states.length;
    await client.signIn({ email: EMAIL, password: PW });
    // No subscribers → the session refetch is skipped to save the round-trip.
    expect(states.length).toBe(count);
    expect(client.session.get().data).toBeNull(); // state unchanged, no refetch
  });

  it("manages the user and their sessions across two devices", async () => {
    const { client, server } = makeClient();
    await client.signUp({ email: EMAIL, password: PW });

    const updated = await client.updateUser({ name: "Alice Cooper" });
    expect(updated.name).toBe("Alice Cooper");

    // A second device (own cookie jar, same server) signs in.
    const other = createAuthClient({
      baseUrl: "http://client.test",
      fetch: makeCookieJarFetch(server.handler),
    });
    await other.signIn({ email: EMAIL, password: PW });

    expect((await client.listSessions()).length).toBe(2);

    // Revoke the other device's session from the first device.
    await client.revokeOtherSessions();
    expect((await client.listSessions()).length).toBe(1);
    expect(await other.getSession()).toBeNull();

    await client.changePassword({ currentPassword: PW, newPassword: "new-password-456" });
    await client.signOut();
    const back = await client.signIn({ email: EMAIL, password: "new-password-456" });
    expect(signedInUser(back).email).toBe(EMAIL);
  });

  it("answers 404 feature errors for unconfigured optional modules", async () => {
    const { client } = makeClient();
    const err = await rejectionOf(client.magicLink.send({ email: EMAIL }), AuthClientError);
    assert.instanceOf(err, AuthClientError);
    expect(err.status).toBe(404);
  });
});

describe("session store correctness", () => {
  it("initializes isPending:true to avoid a signed-out flash on first paint", () => {
    const { client } = makeClient();
    const initial = client.session.get();
    expect(initial.isPending).toBe(true);
    expect(initial.data).toBeNull();
    expect(initial.error).toBeNull();
  });

  it("preserves session data when a refetch fails with a transient (non-401) error", async () => {
    const server = makeServerFixture();
    let injectError = false;
    const base = makeCookieJarFetch(server.handler);

    const client = createAuthClient({
      baseUrl: "http://client.test",
      fetch: (input, init?) => {
        if (injectError && String(input).includes("/sessions/current")) {
          return Promise.resolve(
            new Response(toJson({ message: "Service Unavailable" }), {
              status: 503,
              headers: { "content-type": "application/json" },
            }),
          );
        }
        return base(input, init);
      },
    });

    // Subscribe so mutations trigger session refetches that populate the store.
    const unsubscribe = client.session.subscribe(() => {});
    await client.signUp({ email: EMAIL, password: PW });
    expect(client.session.get().data?.user.email).toBe(EMAIL);

    injectError = true;
    await client.session.refetch();

    const after = client.session.get();
    expect(after.data?.user.email).toBe(EMAIL);
    assert.instanceOf(after.error, AuthClientError);
    expect(after.error.status).toBe(503);
    expect(after.isPending).toBe(false);

    unsubscribe();
  });

  it("discards stale refetch responses — last dispatch wins", async () => {
    let firstResolve!: () => void;
    let callCount = 0;

    const client = createAuthClient({
      baseUrl: "http://client.test",
      fetch: (input) => {
        if (String(input).includes("/sessions/current")) {
          callCount++;
          if (callCount === 1) {
            // First (stale) call: held until manually released with a 500.
            return new Promise<Response>((resolve) => {
              firstResolve = () =>
                resolve(
                  new Response(toJson({ message: "Internal Server Error" }), {
                    status: 500,
                    headers: { "content-type": "application/json" },
                  }),
                );
            });
          }
          // Second (newer) call: resolves immediately as signed-out.
          return Promise.resolve(new Response(null, { status: 401 }));
        }
        return Promise.resolve(new Response(null, { status: 404 }));
      },
    });

    const first = client.session.refetch();
    const second = client.session.refetch();
    await second; // newer refetch settled: signed out, no error

    expect(client.session.get().data).toBeNull();
    expect(client.session.get().error).toBeNull();
    expect(client.session.get().isPending).toBe(false);

    // Release the stale first request (500 error).
    firstResolve();
    await first;

    // Stale response discarded — state must not change.
    expect(client.session.get().data).toBeNull();
    expect(client.session.get().error).toBeNull();
    expect(client.session.get().isPending).toBe(false);
  });

  it("skips the session refetch after a mutation when there are no subscribers", async () => {
    let sessionFetchCount = 0;
    const server = makeServerFixture();
    const base = makeCookieJarFetch(server.handler);

    const client = createAuthClient({
      baseUrl: "http://client.test",
      fetch: (input, init?) => {
        if (isSessionRead(input, init)) sessionFetchCount++;
        return base(input, init);
      },
    });

    // No subscribers: signUp should not trigger a session refetch.
    await client.signUp({ email: EMAIL, password: PW });
    expect(sessionFetchCount).toBe(0);
    // Store state is unchanged (no refetch ran).
    expect(client.session.get().data).toBeNull();
    expect(client.session.get().isPending).toBe(true);

    // Once subscribed, the lazy fetch runs.
    const unsubscribe = client.session.subscribe(() => {});
    await client.session.refetch();
    expect(sessionFetchCount).toBe(2); // lazy + explicit
    expect(client.session.get().data?.user.email).toBe(EMAIL);

    // With a subscriber, signOut triggers the refetch.
    await client.signOut();
    expect(sessionFetchCount).toBe(3);
    expect(client.session.get().data).toBeNull();

    unsubscribe();
  });
});

describe("background refresh", () => {
  it("polls on the configured interval and stops when unsubscribed", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    let sessionFetchCount = 0;

    const client = createAuthClient({
      baseUrl: "http://refresh.test",
      fetch: (input, init?) => {
        if (isSessionRead(input, init)) sessionFetchCount++;
        return Promise.resolve(new Response(null, { status: 401 }));
      },
      refresh: { intervalMs: 500 },
    });

    const unsubscribe = client.session.subscribe(() => {});
    // Settle the lazy initial fetch.
    await client.session.refetch();
    const baseline = sessionFetchCount;

    // 500ms → 1 interval tick.
    await vi.advanceTimersByTimeAsync(500);
    expect(sessionFetchCount).toBe(baseline + 1);

    // Another 500ms → 2 ticks total.
    await vi.advanceTimersByTimeAsync(500);
    expect(sessionFetchCount).toBe(baseline + 2);

    // Unsubscribing must cancel the interval.
    unsubscribe();
    await vi.advanceTimersByTimeAsync(1000);
    expect(sessionFetchCount).toBe(baseline + 2);

    vi.useRealTimers();
  });

  it("restarts polling when a new subscriber joins after all left", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    let sessionFetchCount = 0;

    const client = createAuthClient({
      baseUrl: "http://refresh.test",
      fetch: (input, init?) => {
        if (isSessionRead(input, init)) sessionFetchCount++;
        return Promise.resolve(new Response(null, { status: 401 }));
      },
      refresh: { intervalMs: 500 },
    });

    const unsub1 = client.session.subscribe(() => {});
    await client.session.refetch();
    unsub1(); // last subscriber leaves → interval cancelled

    const before = sessionFetchCount;
    await vi.advanceTimersByTimeAsync(1500);
    expect(sessionFetchCount).toBe(before); // no polling

    // A new subscriber restarts polling.
    const unsub2 = client.session.subscribe(() => {});
    await vi.advanceTimersByTimeAsync(500);
    expect(sessionFetchCount).toBeGreaterThan(before);
    unsub2();

    vi.useRealTimers();
  });
});

describe("JSON response detection", () => {
  // `GET /token` answers plain JSON, so it probes the response handling
  // every non-JSON:API endpoint shares.
  /** A client whose every request answers with `response`. */
  const clientReturning = (response: () => Response) =>
    createAuthClient({ baseUrl: "http://client.test", fetch: () => Promise.resolve(response()) });

  const respond = (body: string | null, contentType: string, init?: ResponseInit) =>
    new Response(body, { ...init, headers: { "content-type": contentType } });

  it("parses a body whose content-type carries parameters", async () => {
    const client = clientReturning(() =>
      respond(toJson([{ id: "s1" }]), "application/json; charset=utf-8"),
    );
    expect(await client.jwtToken()).toEqual([{ id: "s1" }]);
  });

  it("reads the server's message from a `+json` suffix media type", async () => {
    const client = clientReturning(() =>
      respond(toJson({ message: "Session expired" }), "application/problem+json", {
        status: 400,
        statusText: "Bad Request",
      }),
    );

    const error = await rejectionOf(client.jwtToken(), AuthClientError);
    assert.instanceOf(error, AuthClientError);
    expect(error.message).toBe("Session expired");
  });

  it("does not parse a non-JSON body", async () => {
    const client = clientReturning(() => respond("<html>ok</html>", "text/html"));
    expect(await client.jwtToken()).toBeUndefined();
  });

  it("matches the media type, not a substring of the header", async () => {
    // A `text/plain` body must not be read as JSON just because a header
    // parameter happens to spell out `application/json`.
    const client = clientReturning(() =>
      respond(toJson({ message: "leaked" }), "text/plain; note=application/json", {
        status: 400,
        statusText: "Bad Request",
      }),
    );

    const error = await rejectionOf(client.jwtToken(), AuthClientError);
    assert.instanceOf(error, AuthClientError);
    expect(error.message).toBe("Bad Request");
  });

  it("treats a missing content-type as non-JSON", async () => {
    const client = clientReturning(() => {
      const response = new Response(toJson([{ id: "s1" }]), { status: 200 });
      response.headers.delete("content-type");
      return response;
    });
    expect(await client.jwtToken()).toBeUndefined();
  });
});

describe("plugin extension", () => {
  it("extend() adds typed methods from a plugin", async () => {
    const { client } = makeClient();
    await client.signUp({ email: EMAIL, password: PW });

    const sessionPlugin = definePlugin((ctx) => ({
      sessionCount: async () => {
        // `GET /sessions` answers a JSON:API collection document.
        const sessions = await ctx.request<{ readonly data: readonly { id: string }[] }>(
          "GET",
          "/sessions",
        );
        return sessions.data.length;
      },
    }));

    const extended = client.extend(sessionPlugin);
    expect(Predicate.isFunction(extended.sessionCount)).toBe(true);
    expect(await extended.sessionCount()).toBe(1);
    // Core methods are still present.
    expect(Predicate.isFunction(extended.signOut)).toBe(true);
  });

  it("plugin receives mutating context that refreshes the session store", async () => {
    const server = makeServerFixture();
    const client = createAuthClient({
      baseUrl: "http://client.test",
      fetch: makeCookieJarFetch(server.handler),
    });

    const signOutPlugin = definePlugin((ctx) => ({
      logOut: () => ctx.mutating(() => ctx.request<void>("DELETE", "/sessions/current")),
    }));

    const ext = client.extend(signOutPlugin);
    const unsubscribe = ext.session.subscribe(() => {});
    await ext.signUp({ email: EMAIL, password: PW });
    expect(ext.session.get().data?.user.email).toBe(EMAIL);

    await ext.logOut();
    expect(ext.session.get().data).toBeNull();
    unsubscribe();
  });
});
