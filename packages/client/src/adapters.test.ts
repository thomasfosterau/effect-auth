import { describe, it, expect } from "vite-plus/test";
import { createAuthClient } from "./Client.js";
import { listSessionsStore, sessionStore, type ListSessionsState } from "./svelte.js";
import { useListSessions as useVueListSessions, useSession as useVueSession } from "./vue.js";
import { makeCookieJarFetch, makeServerFixture } from "./testing/fixture.js";

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
    const client = makeClient();
    const session = useVueSession(client);

    await client.session.refetch();
    expect(session.value.data).toBeNull();

    await client.signUp({ email: EMAIL, password: PW });
    expect(session.value.data?.user.email).toBe(EMAIL);

    await client.signOut();
    expect(session.value.data).toBeNull();
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
});

describe("vue useListSessions", () => {
  it("fetches sessions into refs and supports refetch", async () => {
    const client = makeClient();
    await client.signUp({ email: EMAIL, password: PW });

    const { data, isPending, error, refetch } = useVueListSessions(client);
    expect(isPending.value).toBe(true);
    await nextTick();

    expect(isPending.value).toBe(false);
    expect(error.value).toBeNull();
    expect(data.value?.length).toBe(1);

    refetch();
    await nextTick();
    expect(data.value?.length).toBe(1);
  });
});
