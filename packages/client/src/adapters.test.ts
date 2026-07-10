import { describe, it, expect, vi } from "vite-plus/test";
import { createAuthClient, type AuthClient } from "./Client.ts";
import { listSessionsStore, sessionStore, type ListSessionsState } from "./svelte.ts";
import { useListSessions as useVueListSessions, useSession as useVueSession } from "./vue.ts";
import { makeCookieJarFetch, makeServerFixture } from "./testing/fixture.ts";
import type { SessionView } from "./types.ts";

const EMAIL = "alice@adapters.test";
const PW = "password-123";

const makeClient = () => {
  const server = makeServerFixture();
  return createAuthClient({
    baseUrl: "http://adapters.test",
    fetch: makeCookieJarFetch(server.handler),
  });
};

describe("svelte sessionStore", () => {
  it("pushes session state to subscribers (readable-store contract)", async () => {
    const client = makeClient();
    const store = sessionStore(client);

    const seen: Array<string | null | undefined> = [];
    const unsubscribe = store.subscribe((state) => {
      seen.push(state.data === null ? null : state.data.user.email);
    });

    // Immediate synchronous emission with the current value.
    expect(seen.length).toBeGreaterThan(0);

    await client.signUp({ email: EMAIL, password: PW });
    expect(seen[seen.length - 1]).toBe(EMAIL);

    await client.signOut();
    expect(seen[seen.length - 1]).toBeNull();

    unsubscribe();
  });
});

describe("vue useSession", () => {
  it("keeps a ref in sync with the session store", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = makeClient();
    const session = useVueSession(client);

    await client.session.refetch();
    expect(session.value.data).toBeNull();

    await client.signUp({ email: EMAIL, password: PW });
    expect(session.value.data?.user.email).toBe(EMAIL);

    await client.signOut();
    expect(session.value.data).toBeNull();

    session.dispose();
    warnSpy.mockRestore();
  });

  it("warns when called outside an effect scope", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = makeClient();

    useVueSession(client).dispose();

    expect(warnSpy).toHaveBeenCalledOnce();
    expect(warnSpy.mock.calls[0]![0]).toMatch(/effect-auth/);
    expect(warnSpy.mock.calls[0]![0]).toMatch(/dispose\(\)/);
    warnSpy.mockRestore();
  });

  it("dispose() stops receiving session updates", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = makeClient();
    const session = useVueSession(client);

    await client.session.refetch();
    await client.signUp({ email: EMAIL, password: PW });
    expect(session.value.data?.user.email).toBe(EMAIL);

    // Dispose — subsequent mutations must not change the ref.
    session.dispose();

    // Use a fresh subscriber so signOut's mutating() still calls refetch().
    const unsub = client.session.subscribe(() => {});
    await client.signOut();
    unsub();

    expect(session.value.data?.user.email).toBe(EMAIL); // frozen after dispose
    warnSpy.mockRestore();
  });
});

const nextTick = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("svelte listSessionsStore", () => {
  it("fetches sessions on first subscribe and supports refetch", async () => {
    const client = makeClient();
    await client.signUp({ email: EMAIL, password: PW });

    const store = listSessionsStore(client);
    const seen: ListSessionsState[] = [];
    const unsubscribe = store.subscribe((state) => {
      seen.push(state);
    });

    expect(seen[0]?.isPending).toBe(true);
    await nextTick();

    const settled = seen[seen.length - 1];
    expect(settled?.isPending).toBe(false);
    expect(settled?.error).toBeNull();
    expect(settled?.data?.length).toBe(1);

    store.refetch();
    await nextTick();
    expect(seen[seen.length - 1]?.data?.length).toBe(1);

    unsubscribe();
  });

  it("discards stale listSessions responses — last refetch wins", async () => {
    let resolveFirst!: (sessions: readonly SessionView[]) => void;
    let callCount = 0;

    const fakeClient = {
      listSessions: (): Promise<readonly SessionView[]> => {
        callCount++;
        if (callCount === 2) {
          // First explicit refetch: slow.
          return new Promise((resolve) => {
            resolveFirst = resolve;
          });
        }
        // Initial fetch and second explicit refetch: resolve immediately with [] sessions.
        return Promise.resolve([]);
      },
    } as unknown as AuthClient;

    const store = listSessionsStore(fakeClient);
    const seen: ListSessionsState[] = [];
    const unsubscribe = store.subscribe((s) => seen.push(s));
    await nextTick(); // let the initial fetch settle

    const initialLen = seen[seen.length - 1]?.data?.length ?? -1;
    expect(initialLen).toBe(0);

    // First refetch (slow/stale), then second refetch immediately.
    store.refetch();
    store.refetch();
    await nextTick(); // second refetch settles

    // Second refetch resolved with [].
    expect(seen[seen.length - 1]?.data?.length).toBe(0);
    expect(seen[seen.length - 1]?.isPending).toBe(false);

    // Release the stale first refetch with different data.
    const staleSession = { id: "stale" } as unknown as SessionView;
    resolveFirst([staleSession]);
    await nextTick();

    // Stale response discarded — data still reflects the second refetch.
    expect(seen[seen.length - 1]?.data?.length).toBe(0);
    unsubscribe();
  });
});

describe("vue useListSessions", () => {
  it("fetches sessions into refs and supports refetch", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = makeClient();
    await client.signUp({ email: EMAIL, password: PW });

    const { data, isPending, error, refetch, dispose } = useVueListSessions(client);
    expect(isPending.value).toBe(true);
    await nextTick();

    expect(isPending.value).toBe(false);
    expect(error.value).toBeNull();
    expect(data.value?.length).toBe(1);

    refetch();
    await nextTick();
    expect(data.value?.length).toBe(1);

    dispose();
    warnSpy.mockRestore();
  });

  it("warns when called outside an effect scope", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = makeClient();

    const { dispose } = useVueListSessions(client);
    dispose();

    expect(warnSpy).toHaveBeenCalledOnce();
    expect(warnSpy.mock.calls[0]![0]).toMatch(/effect-auth/);
    expect(warnSpy.mock.calls[0]![0]).toMatch(/dispose\(\)/);
    warnSpy.mockRestore();
  });

  it("dispose() prevents stale promise updates", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    let resolveDelayed!: (sessions: readonly SessionView[]) => void;
    let callCount = 0;

    const fakeClient = {
      listSessions: (): Promise<readonly SessionView[]> => {
        callCount++;
        if (callCount === 2) {
          return new Promise((resolve) => {
            resolveDelayed = resolve;
          });
        }
        return Promise.resolve([]);
      },
    } as unknown as AuthClient;

    const { data, isPending, dispose } = useVueListSessions(fakeClient);
    await nextTick(); // initial fetch settles: []

    // Kick off a slow refetch, then dispose before it resolves.
    const { refetch } = useVueListSessions(fakeClient);
    refetch();
    dispose();

    const stale = { id: "stale" } as unknown as SessionView;
    resolveDelayed([stale]);
    await nextTick();

    // Stale update was blocked by the disposed flag.
    expect(data.value?.length).toBe(0);
    expect(isPending.value).toBe(false);
    warnSpy.mockRestore();
  });
});
