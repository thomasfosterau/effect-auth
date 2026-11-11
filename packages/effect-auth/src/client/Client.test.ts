import { assert, describe, it, expect, vi } from "vite-plus/test";
import { Predicate, Schema } from "effect";
import { type AuthResult, createAuthClient, AuthClientError, definePlugin } from "./Client.ts";
import { makeCookieJarFetch, makeServerFixture } from "./testing/fixture.ts";

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

  it("notifies session observers after a session-changing call, and awaits them", async () => {
    const { client } = makeClient();
    const order: string[] = [];
    let release!: () => void;
    const remove = client.onSessionChange(
      () =>
        new Promise<void>((resolve) => {
          order.push("observer");
          release = () => {
            order.push("settled");
            resolve();
          };
        }),
    );

    const signedUp = client.signUp({ email: EMAIL, password: PW }).then((result) => {
      order.push("resolved");
      return result;
    });
    // The call waits for its observer to settle before it resolves.
    await vi.waitFor(() => expect(order).toEqual(["observer"]));
    release();
    expect(signedInUser(await signedUp).email).toBe(EMAIL);
    expect(order).toEqual(["observer", "settled", "resolved"]);

    // A removed observer hears nothing more; a read-only call notifies no one.
    remove();
    await client.signOut();
    await client.getSession();
    expect(order).toEqual(["observer", "settled", "resolved"]);
  });

  it("never fails a call because an observer rejected", async () => {
    const { client } = makeClient();
    let calls = 0;
    client.onSessionChange(() => {
      calls++;
      return Promise.reject(new AuthClientError(0, "observer failed"));
    });
    expect(signedInUser(await client.signUp({ email: EMAIL, password: PW })).email).toBe(EMAIL);
    await client.invalidateSession();
    expect(calls).toBe(2);
  });

  it("counts one listener registered twice as two observers", async () => {
    const { client } = makeClient();
    let calls = 0;
    const listener = () => {
      calls++;
    };
    const removeFirst = client.onSessionChange(listener);
    client.onSessionChange(listener);
    await client.invalidateSession();
    expect(calls).toBe(2);
    removeFirst();
    await client.invalidateSession();
    expect(calls).toBe(3);
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

  it("plugin receives mutating context that notifies the session observers", async () => {
    const server = makeServerFixture();
    const client = createAuthClient({
      baseUrl: "http://client.test",
      fetch: makeCookieJarFetch(server.handler),
    });

    const signOutPlugin = definePlugin((ctx) => ({
      logOut: () => ctx.mutating(() => ctx.request<void>("DELETE", "/sessions/current")),
    }));

    const ext = client.extend(signOutPlugin);
    await ext.signUp({ email: EMAIL, password: PW });
    let notified = 0;
    ext.onSessionChange(() => {
      notified++;
    });

    await ext.logOut();
    expect(notified).toBe(1);
    expect(await ext.getSession()).toBeNull();
  });
});
