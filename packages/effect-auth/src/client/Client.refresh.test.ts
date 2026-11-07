// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from "vite-plus/test";
import type * as Http from "../http/index.ts";
import { createAuthClient } from "./Client.ts";
import { makeCookieJarFetch, makeServerFixture } from "./testing/fixture.ts";
import { Array as Arr, MutableHashMap, MutableHashSet, Option } from "effect";

/** Whether a request is the store's session read (`GET /sessions/current`). */
const isSessionRead = (input: RequestInfo | URL, init?: RequestInit): boolean =>
  String(input).includes("/sessions/current") && (init?.method ?? "GET") === "GET";

const EMAIL = "alice@refresh.test";
const PW = "password-123";

// ---------------------------------------------------------------------------
// Minimal in-process BroadcastChannel mock: messages are delivered
// synchronously within the same test process (no actual OS IPC needed).
// ---------------------------------------------------------------------------

class FakeBroadcastChannel {
  static readonly _channels = MutableHashMap.empty<
    string,
    MutableHashSet.MutableHashSet<FakeBroadcastChannel>
  >();

  onmessage: ((event: MessageEvent) => void) | null = null;

  constructor(private readonly name: string) {
    const ch = Option.getOrElse(MutableHashMap.get(FakeBroadcastChannel._channels, name), () =>
      MutableHashSet.empty<FakeBroadcastChannel>(),
    );
    MutableHashMap.set(FakeBroadcastChannel._channels, name, ch);
    MutableHashSet.add(ch, this);
  }

  postMessage(data: { readonly data: Http.SessionWithUserView | null }): void {
    const peers = MutableHashMap.get(FakeBroadcastChannel._channels, this.name);
    Arr.forEach(Option.match(peers, { onNone: () => [], onSome: Arr.fromIterable }), (peer) => {
      if (peer !== this) peer.onmessage?.(new MessageEvent("message", { data }));
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

describe("onFocus refresh", () => {
  it("refetches when the window gains focus", async () => {
    let sessionFetchCount = 0;

    const client = createAuthClient({
      baseUrl: "http://focus.test",
      fetch: (input, init?) => {
        if (isSessionRead(input, init)) sessionFetchCount++;
        return Promise.resolve(new Response(null, { status: 401 }));
      },
      refresh: { onFocus: true },
    });

    const unsubscribe = client.session.subscribe(() => {});
    await client.session.refetch();
    const baseline = sessionFetchCount;

    // Simulate the window receiving focus.
    window.dispatchEvent(new Event("focus"));
    // The refetch is async; flush promises.
    await new Promise<void>((r) => setTimeout(r, 0));
    expect(sessionFetchCount).toBe(baseline + 1);

    unsubscribe();
  });

  it("refetches when the tab becomes visible", async () => {
    let sessionFetchCount = 0;

    const client = createAuthClient({
      baseUrl: "http://visibility.test",
      fetch: (input, init?) => {
        if (isSessionRead(input, init)) sessionFetchCount++;
        return Promise.resolve(new Response(null, { status: 401 }));
      },
      refresh: { onFocus: true },
    });

    const unsubscribe = client.session.subscribe(() => {});
    await client.session.refetch();
    const baseline = sessionFetchCount;

    // jsdom defaults to visible, so trigger a synthetic visibilitychange.
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "visible",
    });
    document.dispatchEvent(new Event("visibilitychange"));
    await new Promise<void>((r) => setTimeout(r, 0));
    expect(sessionFetchCount).toBe(baseline + 1);

    unsubscribe();
  });

  it("does not listen for events after the last subscriber leaves", async () => {
    let sessionFetchCount = 0;

    const client = createAuthClient({
      baseUrl: "http://focus-stop.test",
      fetch: (input, init?) => {
        if (isSessionRead(input, init)) sessionFetchCount++;
        return Promise.resolve(new Response(null, { status: 401 }));
      },
      refresh: { onFocus: true },
    });

    const unsubscribe = client.session.subscribe(() => {});
    await client.session.refetch();
    unsubscribe(); // remove the only subscriber → event listener removed

    const before = sessionFetchCount;
    window.dispatchEvent(new Event("focus"));
    await new Promise<void>((r) => setTimeout(r, 0));
    expect(sessionFetchCount).toBe(before); // no new fetch
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

    // Tab A: has a real cookie jar and signs in.
    const clientA = createAuthClient({
      baseUrl: "http://cross.test",
      fetch: makeCookieJarFetch(server.handler),
      refresh: { crossTab: "auth-test" },
    });

    // Tab B: different cookie jar — cannot reach the server session.
    const clientB = createAuthClient({
      baseUrl: "http://cross.test",
      fetch: makeCookieJarFetch(server.handler),
      refresh: { crossTab: "auth-test" },
    });

    const eventsB: Array<string | null | undefined> = [];
    const unsubA = clientA.session.subscribe(() => {});
    const unsubB = clientB.session.subscribe(() => {
      eventsB.push(clientB.session.get().data?.user.email ?? null);
    });

    // Initial fetch on both tabs: both are signed out.
    await clientA.session.refetch();
    await clientB.session.refetch();

    // Tab A signs in → broadcasts the new session data to Tab B.
    await clientA.signUp({ email: EMAIL, password: PW });

    expect(clientA.session.get().data?.user.email).toBe(EMAIL);
    // B received the broadcast synchronously during setState.
    expect(clientB.session.get().data?.user.email).toBe(EMAIL);
    expect(eventsB).toContain(EMAIL);

    unsubA();
    unsubB();
  });

  it("does not echo broadcasts back to the originating tab", async () => {
    const server = makeServerFixture();
    let fetchCount = 0;
    const base = makeCookieJarFetch(server.handler);

    const client = createAuthClient({
      baseUrl: "http://cross.test",
      fetch: (input, init?) => {
        if (isSessionRead(input, init)) fetchCount++;
        return base(input, init);
      },
      refresh: { crossTab: "no-echo" },
    });

    const unsubscribe = client.session.subscribe(() => {});
    await client.session.refetch();
    const before = fetchCount;

    // Simulate a message arriving from a peer tab.
    const ch = [
      ...(Option.getOrUndefined(MutableHashMap.get(FakeBroadcastChannel._channels, "no-echo")) ??
        []),
    ][0];
    ch?.onmessage?.(new MessageEvent("message", { data: { data: null } }));

    // setState(false) was called — no extra fetch triggered.
    expect(fetchCount).toBe(before);
    expect(client.session.get().data).toBeNull();

    unsubscribe();
  });

  it("stops broadcasting when the last subscriber leaves", async () => {
    const server = makeServerFixture();
    const clientA = createAuthClient({
      baseUrl: "http://cross.test",
      fetch: makeCookieJarFetch(server.handler),
      refresh: { crossTab: "stop-test" },
    });
    const clientB = createAuthClient({
      baseUrl: "http://cross.test",
      fetch: makeCookieJarFetch(server.handler),
      refresh: { crossTab: "stop-test" },
    });

    const unsubA = clientA.session.subscribe(() => {});
    const unsubB = clientB.session.subscribe(() => {});
    await clientA.session.refetch();

    // Unsubscribe A — its BroadcastChannel should be closed.
    unsubA();
    expect(
      Option.map(
        MutableHashMap.get(FakeBroadcastChannel._channels, "stop-test"),
        MutableHashSet.size,
      ),
    ).toEqual(Option.some(1)); // only B

    unsubB();
    expect(
      Option.map(
        MutableHashMap.get(FakeBroadcastChannel._channels, "stop-test"),
        MutableHashSet.size,
      ),
    ).toEqual(Option.some(0));
  });
});
