import { describe, it, expect } from "vite-plus/test";
import { createAuthClient, type AuthClient } from "@thomasfosterau/effect-auth-client";
import { listSessionsStore, sessionStore, type ListSessionsState } from "./index.ts";

const EMAIL = "alice@svelte.test";
const PW = "password-123";

type SessionList = Awaited<ReturnType<AuthClient["listSessions"]>>;

const json = (body: object): Response =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

/** A member as a stub may supply it: a method as is, a namespace as any subset of its members. */
type StubOf<T> = T extends (...args: infer A) => infer R
  ? (...args: A) => R
  : { readonly [K in keyof T]?: StubOf<T[K]> };

/** Any subset of the client's members; the code under test touches only the ones a test supplies. */
type ClientStub = StubOf<AuthClient>;
const stub = (methods: ClientStub): AuthClient =>
  // SAFETY: the code under test touches only the members a test supplies; reaching
  // for a missing one throws, so a stub cannot let a test pass by omission.
  methods as AuthClient;

/**
 * A client backed by a stand-in server covering only the endpoints these
 * stores touch (`/users`, `/sessions/current`, `/sessions`). The
 * bindings care about nothing but the session store moving, so the in-process
 * auth server the client package tests against would only add a dependency
 * here.
 */
const makeClient = () => {
  const now = Date.now();
  const user = { id: "user-1", email: EMAIL, createdAt: now, updatedAt: now, attributes: {} };
  const session = {
    id: "session-1",
    userId: user.id,
    expiresAt: now + 60_000,
    createdAt: now,
    lastActivityAt: now,
    attributes: {},
  };
  let signedIn = false;
  // The JSON:API resources the server answers with (#205).
  const { id: userId, ...userAttributes } = user;
  const { id: sessionId, userId: _owner, ...sessionAttributes } = session;
  const userResource = () => ({ type: "users", id: userId, attributes: userAttributes });
  const sessionResource = () => ({
    type: "sessions",
    id: sessionId,
    attributes: sessionAttributes,
    relationships: { user: { data: { type: "users", id: userId } } },
  });

  return createAuthClient({
    baseUrl: "http://svelte.test",
    fetch: (input, init) => {
      const { pathname } = new URL(String(input));
      switch (`${init?.method ?? "GET"} ${pathname}`) {
        case "POST /users":
          signedIn = true;
          return Promise.resolve(
            json({
              data: sessionResource(),
              included: [userResource()],
              meta: { needsEmailVerification: false },
            }),
          );
        case "DELETE /sessions/current":
          signedIn = false;
          return Promise.resolve(new Response(null, { status: 204 }));
        case "GET /sessions/current":
          return Promise.resolve(
            signedIn
              ? json({ data: sessionResource(), included: [userResource()] })
              : new Response(null, { status: 401 }),
          );
        case "GET /sessions":
          return Promise.resolve(json({ data: signedIn ? [sessionResource()] : [] }));
        default:
          return Promise.resolve(new Response(null, { status: 404 }));
      }
    },
  });
};

const nextTick = () => new Promise((resolve) => setTimeout(resolve, 0));

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
    let resolveFirst!: (sessions: SessionList) => void;
    let callCount = 0;

    const fakeClient = stub({
      listSessions: (): Promise<SessionList> => {
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
    });

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
    const staleSession: SessionList[number] = {
      id: "stale",
      userId: "user-1",
      expiresAt: 0,
      createdAt: 0,
      lastActivityAt: 0,
      attributes: {},
    };
    resolveFirst([staleSession]);
    await nextTick();

    // Stale response discarded — data still reflects the second refetch.
    expect(seen[seen.length - 1]?.data?.length).toBe(0);
    unsubscribe();
  });
});
