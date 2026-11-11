import { assert, describe, it, expect, vi } from "vite-plus/test";
import * as Schema from "effect/Schema";
import { Atom, AtomRegistry } from "effect/reactivity";
import { AuthClientError, createAuthClient } from "./Client.ts";
import { makeSessionAtoms } from "./SessionAtoms.ts";
import { makeCookieJarFetch, makeServerFixture } from "./testing/fixture.ts";

/** The URL a `fetch` was called with. */
const urlOf = (input: RequestInfo | URL): URL =>
  new URL(input instanceof Request ? input.url : input);

/** Whether a request is the session read (`GET /sessions/current`). */
const isSessionRead = (input: RequestInfo | URL, init?: RequestInit): boolean =>
  urlOf(input).pathname === "/sessions/current" && (init?.method ?? "GET") === "GET";

/** Whether a request is the session list (`GET /sessions`). */
const isSessionList = (input: RequestInfo | URL, init?: RequestInit): boolean =>
  urlOf(input).pathname === "/sessions" && (init?.method ?? "GET") === "GET";

const EMAIL = "alice@atoms.test";
const PW = "password-123";

const toJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

/** A macrotask: long enough for the registry to drop an unobserved node. */
const nextTask = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const counted = (count: (input: RequestInfo | URL, init?: RequestInit) => void) => {
  const server = makeServerFixture();
  const base = makeCookieJarFetch(server.handler);
  return createAuthClient({
    baseUrl: "http://atoms.test",
    fetch: (input, init?) => {
      count(input, init);
      return base(input, init);
    },
  });
};

describe("session atoms", () => {
  it("start pending, with no session and no error, and read lazily", () => {
    let reads = 0;
    const client = counted((input, init) => {
      if (isSessionRead(input, init)) reads++;
    });
    const atoms = makeSessionAtoms(client);
    expect(reads).toBe(0);

    const registry = AtomRegistry.make();
    expect(registry.get(atoms.state)).toEqual({ data: null, isPending: true, error: null });
    expect(registry.get(atoms.isSignedIn)).toBe(false);
    expect(reads).toBe(1);
    registry.dispose();
  });

  it("follow sign-up and sign-out, each call resolving after the refetch", async () => {
    const client = counted(() => {});
    const atoms = makeSessionAtoms(client);
    const registry = AtomRegistry.make();
    const states: Array<{ email: string | undefined; isPending: boolean }> = [];
    const unsubscribe = registry.subscribe(
      atoms.state,
      (state) => states.push({ email: state.data?.user.email, isPending: state.isPending }),
      { immediate: true },
    );

    await client.invalidateSession();
    expect(registry.get(atoms.state)).toEqual({ data: null, isPending: false, error: null });

    await client.signUp({ email: EMAIL, password: PW });
    expect(registry.get(atoms.data)?.user.email).toBe(EMAIL);
    expect(registry.get(atoms.isSignedIn)).toBe(true);

    await client.signOut();
    expect(registry.get(atoms.data)).toBeNull();
    expect(states.at(-1)).toEqual({ email: undefined, isPending: false });
    expect(states).toContainEqual({ email: EMAIL, isPending: false });
    unsubscribe();
    registry.dispose();
  });

  it("propagates a session change through the graph to dependent atoms", async () => {
    const client = counted(() => {});
    const atoms = makeSessionAtoms(client);
    const registry = AtomRegistry.make();

    // An application atom that knows nothing of the client: it only reads
    // the session graph, and has no invalidation of its own.
    let builds = 0;
    const greeting = Atom.make((get) => {
      builds++;
      const user = get(atoms.data)?.user;
      return user === undefined ? "Hello, guest" : `Hello, ${user.email}`;
    });
    const seen: string[] = [];
    const unsubscribe = registry.subscribe(greeting, (value) => seen.push(value), {
      immediate: true,
    });
    await client.invalidateSession();

    await client.signUp({ email: EMAIL, password: PW });
    expect(registry.get(greeting)).toBe(`Hello, ${EMAIL}`);

    await client.signOut();
    expect(registry.get(greeting)).toBe("Hello, guest");
    expect(seen).toEqual(["Hello, guest", `Hello, ${EMAIL}`, "Hello, guest"]);

    // `isSignedIn` is a boolean, so a refetch that changes nothing stops there.
    const before = builds;
    let signedInChanges = 0;
    const stop = registry.subscribe(atoms.isSignedIn, () => signedInChanges++);
    await client.invalidateSession();
    expect(signedInChanges).toBe(0);
    expect(builds).toBe(before);

    stop();
    unsubscribe();
    registry.dispose();
  });

  it("keeps the session through a transient failure and reports the error", async () => {
    const server = makeServerFixture();
    let injectError = false;
    const base = makeCookieJarFetch(server.handler);
    const client = createAuthClient({
      baseUrl: "http://atoms.test",
      fetch: (input, init?) => {
        if (injectError && isSessionRead(input, init)) {
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
    const atoms = makeSessionAtoms(client);
    const registry = AtomRegistry.make();
    const unmount = registry.mount(atoms.result);

    await client.signUp({ email: EMAIL, password: PW });
    expect(registry.get(atoms.data)?.user.email).toBe(EMAIL);

    injectError = true;
    await client.invalidateSession();
    const after = registry.get(atoms.state);
    expect(after.data?.user.email).toBe(EMAIL);
    assert.instanceOf(after.error, AuthClientError);
    expect(after.error.status).toBe(503);
    expect(after.isPending).toBe(false);
    expect(registry.get(atoms.isSignedIn)).toBe(true);

    // The next good read clears the error.
    injectError = false;
    await client.invalidateSession();
    expect(registry.get(atoms.error)).toBeNull();
    unmount();
    registry.dispose();
  });

  it("maps a fetch that never reached the server to status 0", async () => {
    const client = createAuthClient({
      baseUrl: "http://atoms.test",
      fetch: () => Promise.reject(new TypeError("network down")),
    });
    const atoms = makeSessionAtoms(client);
    const registry = AtomRegistry.make();
    const unmount = registry.mount(atoms.result);
    await client.invalidateSession();
    const error = registry.get(atoms.error);
    assert.instanceOf(error, AuthClientError);
    expect(error.status).toBe(0);
    expect(error.message).toBe("network down");
    unmount();
    registry.dispose();
  });

  it("drops a superseded refetch — last dispatch wins", async () => {
    let releaseFirst!: () => void;
    let reads = 0;
    const client = createAuthClient({
      baseUrl: "http://atoms.test",
      fetch: (input) => {
        if (urlOf(input).pathname === "/sessions/current") {
          reads++;
          if (reads === 3) {
            // The first of the two refetches: held, then released with a 500.
            return new Promise<Response>((resolve) => {
              releaseFirst = () =>
                resolve(
                  new Response(toJson({ message: "Internal Server Error" }), {
                    status: 500,
                    headers: { "content-type": "application/json" },
                  }),
                );
            });
          }
          return Promise.resolve(new Response(null, { status: 401 }));
        }
        return Promise.resolve(new Response(null, { status: 404 }));
      },
    });
    const atoms = makeSessionAtoms(client);
    const registry = AtomRegistry.make();
    const unmount = registry.mount(atoms.result);
    await client.invalidateSession();

    const first = client.invalidateSession();
    const second = client.invalidateSession();
    await Promise.all([first, second]);
    expect(registry.get(atoms.state)).toEqual({ data: null, isPending: false, error: null });

    // The stale answer arrives after the newer one: it must not land.
    releaseFirst();
    await nextTask();
    expect(registry.get(atoms.state)).toEqual({ data: null, isPending: false, error: null });
    unmount();
    registry.dispose();
  });

  it("skips the refetch while nothing observes the session, and keeps the last read", async () => {
    let reads = 0;
    const client = counted((input, init) => {
      if (isSessionRead(input, init)) reads++;
    });
    const atoms = makeSessionAtoms(client);
    const registry = AtomRegistry.make();

    // Nothing observes: a session-changing call costs no session read.
    await client.signUp({ email: EMAIL, password: PW });
    expect(reads).toBe(0);

    // The first observer starts the lazy read.
    const unmount = registry.mount(atoms.result);
    await client.invalidateSession();
    expect(registry.get(atoms.data)?.user.email).toBe(EMAIL);
    const afterObserve = reads;

    // Observed, a sign-out refetches.
    await client.signOut();
    expect(reads).toBe(afterObserve + 1);
    expect(registry.get(atoms.data)).toBeNull();

    // Unobserved again: the next call is not refetched…
    unmount();
    await nextTask();
    await client.signIn({ email: EMAIL, password: PW });
    expect(reads).toBe(afterObserve + 1);

    // …and a new observer starts from the last read, without a request.
    const remount = registry.mount(atoms.result);
    expect(registry.get(atoms.state)).toEqual({ data: null, isPending: false, error: null });
    expect(reads).toBe(afterObserve + 1);
    await client.invalidateSession();
    expect(registry.get(atoms.data)?.user.email).toBe(EMAIL);
    remount();
    registry.dispose();
  });

  it("refetches the session when any session atom is refreshed", async () => {
    let reads = 0;
    const client = counted((input, init) => {
      if (isSessionRead(input, init)) reads++;
    });
    const atoms = makeSessionAtoms(client);
    const registry = AtomRegistry.make();
    const unmount = registry.mount(atoms.isSignedIn);
    await client.invalidateSession();
    const before = reads;

    registry.refresh(atoms.isSignedIn);
    expect(registry.get(atoms.isPending)).toBe(true);
    await vi.waitFor(() => expect(registry.get(atoms.isPending)).toBe(false));
    expect(reads).toBe(before + 1);
    unmount();
    registry.dispose();
  });
});

describe("the session list atom", () => {
  it("is empty while signed out, and refetches when the session changes", async () => {
    let lists = 0;
    const client = counted((input, init) => {
      if (isSessionList(input, init)) lists++;
    });
    const atoms = makeSessionAtoms(client);
    const registry = AtomRegistry.make();
    const unsubscribe = registry.subscribe(atoms.sessionsState, () => {}, { immediate: true });
    expect(registry.get(atoms.sessionsState)).toEqual({ data: null, isPending: true, error: null });

    await client.invalidateSession();
    await vi.waitFor(() =>
      expect(registry.get(atoms.sessionsState)).toEqual({
        data: [],
        isPending: false,
        error: null,
      }),
    );
    expect(lists).toBe(0);

    // A sign-up changes the session id, which reaches the list through the graph.
    await client.signUp({ email: EMAIL, password: PW });
    await vi.waitFor(() => expect(registry.get(atoms.sessionsState).data?.length).toBe(1));
    expect(lists).toBe(1);

    // A refetch of the same session does not refetch the list.
    await client.invalidateSession();
    await nextTask();
    expect(lists).toBe(1);

    // An explicit refresh does.
    registry.refresh(atoms.sessions);
    await vi.waitFor(() => expect(registry.get(atoms.sessionsState).isPending).toBe(false));
    expect(lists).toBe(2);

    await client.signOut();
    await vi.waitFor(() => expect(registry.get(atoms.sessionsState).data).toEqual([]));
    expect(lists).toBe(2);
    unsubscribe();
    registry.dispose();
  });

  it("reports a failed list", async () => {
    const server = makeServerFixture();
    const base = makeCookieJarFetch(server.handler);
    const client = createAuthClient({
      baseUrl: "http://atoms.test",
      fetch: (input, init?) =>
        isSessionList(input, init)
          ? Promise.resolve(new Response(null, { status: 500, statusText: "Boom" }))
          : base(input, init),
    });
    const atoms = makeSessionAtoms(client);
    const registry = AtomRegistry.make();
    const unmount = registry.mount(atoms.sessionsState);
    await client.signUp({ email: EMAIL, password: PW });
    await vi.waitFor(() => expect(registry.get(atoms.sessionsState).isPending).toBe(false));
    const { error } = registry.get(atoms.sessionsState);
    assert.instanceOf(error, AuthClientError);
    expect(error.status).toBe(500);
    unmount();
    registry.dispose();
  });
});

describe("background refresh", () => {
  it("polls on the configured interval while observed", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    let reads = 0;
    const client = createAuthClient({
      baseUrl: "http://refresh.test",
      fetch: (input, init?) => {
        if (isSessionRead(input, init)) reads++;
        return Promise.resolve(new Response(null, { status: 401 }));
      },
    });
    const atoms = makeSessionAtoms(client, { refresh: { intervalMs: 500 } });
    const registry = AtomRegistry.make();

    const unmount = registry.mount(atoms.result);
    await client.invalidateSession();
    const baseline = reads;

    await vi.advanceTimersByTimeAsync(500);
    expect(reads).toBe(baseline + 1);
    await vi.advanceTimersByTimeAsync(500);
    expect(reads).toBe(baseline + 2);

    // The last subscriber leaving cancels the interval.
    unmount();
    await nextTask();
    await vi.advanceTimersByTimeAsync(1000);
    expect(reads).toBe(baseline + 2);

    // A new subscriber restarts it.
    const remount = registry.mount(atoms.result);
    await vi.advanceTimersByTimeAsync(500);
    expect(reads).toBe(baseline + 3);
    remount();
    registry.dispose();
    vi.useRealTimers();
  });
});
