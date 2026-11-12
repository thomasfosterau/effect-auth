// @vitest-environment jsdom
import { assert, describe, it, expect, vi, beforeEach, afterEach } from "vite-plus/test";
import * as Schema from "effect/Schema";
import type * as Http from "../http/index.ts";
import { hashToken } from "../TokenHash.ts";
import { AtomRegistry } from "effect/reactivity";
import { createAuthClient } from "./Client.ts";
import { makeSessionAtoms } from "./SessionAtoms.ts";
import { makeCookieJarFetch, makeServerFixture } from "./testing/fixture.ts";
import { MutableHashMap, MutableHashSet } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";

/** Whether a request is the session read (`GET /sessions/current`). */
const isSessionRead = (input: RequestInfo | URL, init?: RequestInit): boolean =>
  new URL(input instanceof Request ? input.url : input).pathname === "/sessions/current" &&
  (init?.method ?? "GET") === "GET";

const toJson = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown));

const EMAIL = "alice@refresh.test";
const PW = "password-123";

// ---------------------------------------------------------------------------
// Minimal in-process BroadcastChannel mock: messages are delivered
// synchronously within the same test process (no actual OS IPC needed).
// ---------------------------------------------------------------------------

class FakeBroadcastChannel extends EventTarget {
  static readonly _channels = MutableHashMap.empty<
    string,
    MutableHashSet.MutableHashSet<FakeBroadcastChannel>
  >();

  // Effect's hash sets compare plain objects structurally; a per-instance
  // symbol keeps two channels on the same name distinct peers.
  readonly identity = Symbol("FakeBroadcastChannel");

  constructor(private readonly name: string) {
    super();
    const ch = Option.getOrElse(MutableHashMap.get(FakeBroadcastChannel._channels, name), () =>
      MutableHashSet.empty<FakeBroadcastChannel>(),
    );
    MutableHashMap.set(FakeBroadcastChannel._channels, name, ch);
    MutableHashSet.add(ch, this);
  }

  postMessage(data: { readonly data: Http.SessionWithUserView | null }): void {
    this.deliver(data);
  }

  /** Deliver `data` to every other channel on this name, as a peer tab's post would. */
  deliver(data: { readonly data: Http.SessionWithUserView | null }): void {
    const peers = MutableHashMap.get(FakeBroadcastChannel._channels, this.name);
    Arr.forEach(Option.match(peers, { onNone: () => [], onSome: Arr.fromIterable }), (peer) => {
      if (peer !== this) peer.dispatchEvent(new MessageEvent("message", { data }));
    });
  }

  close(): void {
    Option.map(MutableHashMap.get(FakeBroadcastChannel._channels, this.name), (peers) =>
      MutableHashSet.remove(peers, this),
    );
  }

  static reset(): void {
    MutableHashMap.clear(FakeBroadcastChannel._channels);
  }
}

// ---------------------------------------------------------------------------

/** How many channels named `name` are open. */
const channelCount = (name: string) =>
  Option.map(MutableHashMap.get(FakeBroadcastChannel._channels, name), MutableHashSet.size);

/** A client whose session read always answers signed out, counting the reads. */
const countingClient = (baseUrl: string) => {
  const counter = { reads: 0 };
  const client = createAuthClient({
    baseUrl,
    fetch: (input, init?) => {
      if (isSessionRead(input, init)) counter.reads++;
      return Promise.resolve(new Response(null, { status: 401 }));
    },
  });
  return { client, counter };
};

/** A macrotask: long enough for the registry to drop an unobserved node. */
const nextTask = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

describe("onFocus refresh", () => {
  it("refetches when the window gains focus", async () => {
    const { client, counter } = countingClient("http://focus.test");
    const atoms = makeSessionAtoms(client, { refresh: { onFocus: true } });
    const registry = AtomRegistry.make();
    const unmount = registry.mount(atoms.result);
    await client.invalidateSession();
    const baseline = counter.reads;

    window.dispatchEvent(new Event("focus"));
    await nextTask();
    expect(counter.reads).toBe(baseline + 1);

    unmount();
    registry.dispose();
  });

  it("refetches when the tab becomes visible", async () => {
    const { client, counter } = countingClient("http://visibility.test");
    const atoms = makeSessionAtoms(client, { refresh: { onFocus: true } });
    const registry = AtomRegistry.make();
    const unmount = registry.mount(atoms.result);
    await client.invalidateSession();
    const baseline = counter.reads;

    // jsdom defaults to visible, so trigger a synthetic visibilitychange.
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "visible",
    });
    document.dispatchEvent(new Event("visibilitychange"));
    await nextTask();
    expect(counter.reads).toBe(baseline + 1);

    unmount();
    registry.dispose();
  });

  it("does not listen for events after the last subscriber leaves", async () => {
    const { client, counter } = countingClient("http://focus-stop.test");
    const atoms = makeSessionAtoms(client, { refresh: { onFocus: true } });
    const registry = AtomRegistry.make();
    const unmount = registry.mount(atoms.result);
    await client.invalidateSession();
    unmount(); // remove the only subscriber → event listeners removed
    await nextTask();

    const before = counter.reads;
    window.dispatchEvent(new Event("focus"));
    document.dispatchEvent(new Event("visibilitychange"));
    await nextTask();
    expect(counter.reads).toBe(before);
    registry.dispose();
  });
});

describe("cross-tab sync (BroadcastChannel)", () => {
  beforeEach(() => {
    vi.stubGlobal("BroadcastChannel", FakeBroadcastChannel);
    FakeBroadcastChannel.reset();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    FakeBroadcastChannel.reset();
  });

  it("mirrors sign-in session state to a second tab without a network round-trip", async () => {
    const server = makeServerFixture();
    // Two tabs, each with its own cookie jar, so tab B cannot read A's session.
    const clientA = createAuthClient({
      baseUrl: "http://cross.test",
      fetch: makeCookieJarFetch(server.handler),
    });
    const clientB = createAuthClient({
      baseUrl: "http://cross.test",
      fetch: makeCookieJarFetch(server.handler),
    });
    const tabA = makeSessionAtoms(clientA, { refresh: { crossTab: "auth-test" } });
    const tabB = makeSessionAtoms(clientB, { refresh: { crossTab: "auth-test" } });
    const registryA = AtomRegistry.make();
    const registryB = AtomRegistry.make();

    const eventsB: Array<string | null> = [];
    const unmountA = registryA.mount(tabA.result);
    const unsubB = registryB.subscribe(tabB.data, (data) => {
      eventsB.push(data?.user.email ?? null);
    });
    await clientA.invalidateSession();
    await clientB.invalidateSession();

    // Tab A signs up → broadcasts the new session to tab B.
    await clientA.signUp({ email: EMAIL, password: PW });
    expect(registryA.get(tabA.data)?.user.email).toBe(EMAIL);
    expect(registryB.get(tabB.data)?.user.email).toBe(EMAIL);
    expect(registryB.get(tabB.state).isPending).toBe(false);
    expect(eventsB).toContain(EMAIL);

    // A refetch in tab B keeps the mirrored session on show while it waits.
    let pendingData: string | null | undefined;
    const watch = registryB.subscribe(tabB.state, (state) => {
      if (state.isPending) pendingData = state.data?.user.email ?? null;
    });
    await clientB.invalidateSession();
    expect(pendingData).toBe(EMAIL);
    watch();

    unmountA();
    unsubB();
    registryA.dispose();
    registryB.dispose();
  });

  it("broadcasts a session named by its digest, never the cookie's token (#581)", async () => {
    const server = makeServerFixture();
    const tokens: string[] = [];
    const base = makeCookieJarFetch(server.handler);
    const client = createAuthClient({
      baseUrl: "http://cross.test",
      fetch: async (input, init?) => {
        const response = await base(input, init);
        Arr.forEach(response.headers.getSetCookie(), (line) => {
          const token = /^conduit_session=([^;]+)/.exec(line)?.[1];
          if (token !== undefined) tokens.push(token);
        });
        return response;
      },
    });
    const atoms = makeSessionAtoms(client, { refresh: { crossTab: "no-token" } });
    const posted: Array<Http.SessionWithUserView | null> = [];
    const post = vi
      .spyOn(FakeBroadcastChannel.prototype, "postMessage")
      .mockImplementation((message) => void posted.push(message.data));
    const registry = AtomRegistry.make();
    const unmount = registry.mount(atoms.result);

    await client.signUp({ email: EMAIL, password: PW });
    const [token] = tokens;
    expect(token).toBeDefined();
    const session = Arr.findFirst(posted, (message) => message !== null);
    assert(Option.isSome(session), "the sign-in was broadcast");
    expect(session.value.session.id).toBe(hashToken(token ?? ""));
    expect(toJson(posted)).not.toContain(token);

    post.mockRestore();
    unmount();
    registry.dispose();
  });

  it("takes a peer's session without a request, and does not echo it", async () => {
    const server = makeServerFixture();
    let reads = 0;
    const base = makeCookieJarFetch(server.handler);
    const client = createAuthClient({
      baseUrl: "http://cross.test",
      fetch: (input, init?) => {
        if (isSessionRead(input, init)) reads++;
        return base(input, init);
      },
    });
    const atoms = makeSessionAtoms(client, { refresh: { crossTab: "no-echo" } });
    const registry = AtomRegistry.make();
    const unmount = registry.mount(atoms.result);
    await client.invalidateSession();
    const before = reads;

    // A peer tab on the same channel posts a session.
    const peer = new FakeBroadcastChannel("no-echo");
    const echoes: unknown[] = [];
    peer.addEventListener("message", (event) => echoes.push(event));
    const user = { id: "u1", email: EMAIL, createdAt: 0, updatedAt: 0, attributes: {} };
    const session = {
      id: "s1",
      userId: "u1",
      expiresAt: 60_000,
      createdAt: 0,
      lastActivityAt: 0,
      attributes: {},
    };
    peer.deliver({ data: { session, user } });

    expect(reads).toBe(before);
    expect(registry.get(atoms.data)?.user.email).toBe(EMAIL);
    expect(echoes).toEqual([]);

    peer.deliver({ data: null });
    expect(registry.get(atoms.isSignedIn)).toBe(false);
    expect(reads).toBe(before);

    peer.close();
    unmount();
    registry.dispose();
  });

  it("closes the channel when the last subscriber leaves", async () => {
    const { client: clientA } = countingClient("http://cross.test");
    const { client: clientB } = countingClient("http://cross.test");
    const tabA = makeSessionAtoms(clientA, { refresh: { crossTab: "stop-test" } });
    const tabB = makeSessionAtoms(clientB, { refresh: { crossTab: "stop-test" } });
    const registry = AtomRegistry.make();

    const unmountA = registry.mount(tabA.result);
    const unmountB = registry.mount(tabB.result);
    expect(channelCount("stop-test")).toEqual(Option.some(2));

    unmountA();
    await nextTask();
    expect(channelCount("stop-test")).toEqual(Option.some(1)); // only B

    unmountB();
    await nextTask();
    expect(channelCount("stop-test")).toEqual(Option.some(0));
    registry.dispose();
  });

  it("uses the default channel name for `crossTab: true`", async () => {
    const { client } = countingClient("http://cross.test");
    const atoms = makeSessionAtoms(client, { refresh: { crossTab: true } });
    const registry = AtomRegistry.make();
    const unmount = registry.mount(atoms.result);
    expect(channelCount("effect-auth-session")).toEqual(Option.some(1));
    unmount();
    registry.dispose();
  });

  it("is a no-op where BroadcastChannel is unavailable", async () => {
    vi.stubGlobal("BroadcastChannel", undefined);
    const { client } = countingClient("http://cross.test");
    const atoms = makeSessionAtoms(client, { refresh: { crossTab: true } });
    const registry = AtomRegistry.make();
    const unmount = registry.mount(atoms.result);
    await client.invalidateSession();
    expect(registry.get(atoms.state)).toEqual({ data: null, isPending: false, error: null });
    unmount();
    registry.dispose();
  });
});
