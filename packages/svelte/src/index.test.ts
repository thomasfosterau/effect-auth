import { describe, it, expect, vi } from "vite-plus/test";
import { Atom, AtomRegistry } from "effect/reactivity";
import { createAuthClient } from "@thomasfosterau/effect-auth/client";
import { makeSessionAtoms } from "@thomasfosterau/effect-auth/client/atoms";
import { atomStore, listSessionsStore, sessionStore, type ListSessionsState } from "./index.ts";

const EMAIL = "alice@svelte.test";
const PW = "password-123";

const json = (body: object): Response =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

const notFound = () => new Response(null, { status: 404 });

/**
 * A client backed by a stand-in server covering only the endpoints these
 * stores touch (`/users`, `/sessions/current`, `/sessions`). The
 * bindings care about nothing but the session Atoms moving, so the in-process
 * auth server the client package tests against would only add a dependency
 * here.
 */
const makeClient = (onList: () => void = () => {}) => {
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

  const signedInSession = () => json({ data: sessionResource(), included: [userResource()] });
  const routes: Record<string, () => Response> = {
    "POST /users": () => {
      signedIn = true;
      return json({
        data: sessionResource(),
        included: [userResource()],
        meta: { needsEmailVerification: false },
      });
    },
    "DELETE /sessions/current": () => {
      signedIn = false;
      return new Response(null, { status: 204 });
    },
    "GET /sessions/current": () =>
      signedIn ? signedInSession() : new Response(null, { status: 401 }),
    // The session Atoms list only while signed in.
    "GET /sessions": () => {
      onList();
      return json({ data: [sessionResource()] });
    },
  };

  return createAuthClient({
    baseUrl: "http://svelte.test",
    fetch: (input, init) => {
      const { pathname } = new URL(new Request(input).url);
      const route = routes[`${init?.method ?? "GET"} ${pathname}`] ?? notFound;
      return Promise.resolve(route());
    },
  });
};

const nextTick = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("atomStore", () => {
  it("emits at once, follows changes and unmounts on unsubscribe", async () => {
    const registry = AtomRegistry.make();
    let mounted = 0;
    const count = Atom.make((get) => {
      mounted++;
      get.addFinalizer(() => {
        mounted--;
      });
      return 1;
    });
    const writable = Atom.make(0);
    const doubled = Atom.make((get) => get(writable) * 2 + get(count));

    const seen: number[] = [];
    const unsubscribe = atomStore(registry, doubled).subscribe((value) => seen.push(value));
    expect(seen).toEqual([1]);
    expect(mounted).toBe(1);

    registry.set(writable, 2);
    expect(seen).toEqual([1, 5]);

    unsubscribe();
    await nextTick();
    expect(mounted).toBe(0);
    registry.set(writable, 3);
    expect(seen).toEqual([1, 5]);
    registry.dispose();
  });
});

describe("svelte sessionStore", () => {
  it("pushes session state to subscribers (readable-store contract)", async () => {
    const client = makeClient();
    const registry = AtomRegistry.make();
    const store = sessionStore(registry, makeSessionAtoms(client));

    const seen: Array<string | null | undefined> = [];
    const pending: boolean[] = [];
    const unsubscribe = store.subscribe((state) => {
      seen.push(state.data === null ? null : state.data.user.email);
      pending.push(state.isPending);
    });

    // Immediate synchronous emission with the current value: pending, no session.
    expect(seen).toEqual([null]);
    expect(pending).toEqual([true]);

    await client.signUp({ email: EMAIL, password: PW });
    expect(seen.at(-1)).toBe(EMAIL);

    await client.signOut();
    expect(seen.at(-1)).toBeNull();
    expect(pending.at(-1)).toBe(false);

    unsubscribe();
    registry.dispose();
  });
});

describe("svelte listSessionsStore", () => {
  it("lists the sessions, follows the session and supports refetch", async () => {
    let lists = 0;
    const client = makeClient(() => lists++);
    const registry = AtomRegistry.make();
    const atoms = makeSessionAtoms(client);
    await client.signUp({ email: EMAIL, password: PW });

    const store = listSessionsStore(registry, atoms);
    const seen: ListSessionsState[] = [];
    const unsubscribe = store.subscribe((state) => {
      seen.push(state);
    });

    expect(seen[0]?.isPending).toBe(true);
    await vi.waitFor(() => expect(seen.at(-1)?.isPending).toBe(false));
    expect(seen.at(-1)).toEqual({ data: [expect.anything()], isPending: false, error: null });
    expect(lists).toBe(1);

    store.refetch();
    await vi.waitFor(() => expect(lists).toBe(2));
    await vi.waitFor(() => expect(seen.at(-1)?.isPending).toBe(false));
    expect(seen.at(-1)?.data?.length).toBe(1);

    // Signing out reaches the list through the Atom graph: empty, no request.
    await client.signOut();
    await vi.waitFor(() => expect(seen.at(-1)?.data).toEqual([]));
    expect(lists).toBe(2);

    unsubscribe();
    registry.dispose();
  });
});
