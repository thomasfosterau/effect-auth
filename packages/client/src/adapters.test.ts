import { describe, it, expect } from "vite-plus/test";
import { createAuthClient } from "./Client.js";
import { sessionStore } from "./svelte.js";
import { useSession as useVueSession } from "./vue.js";
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
