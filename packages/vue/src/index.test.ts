import { describe, it, expect, vi } from "vite-plus/test";
import { createAuthClient, type AuthClient } from "@thomasfosterau/effect-auth-client";
import { useListSessions, useSession } from "./index.ts";

const EMAIL = "alice@vue.test";
const PW = "password-123";

type SessionList = Awaited<ReturnType<AuthClient["listSessions"]>>;

const json = (body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

/**
 * A client backed by a stand-in server covering only the endpoints these
 * composables touch (`/sign-up`, `/sign-out`, `/session`, `/sessions`). The
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

  return createAuthClient({
    baseUrl: "http://vue.test",
    fetch: (input, init) => {
      const { pathname } = new URL(String(input));
      switch (`${init?.method ?? "GET"} ${pathname}`) {
        case "POST /sign-up":
          signedIn = true;
          return Promise.resolve(json({ user, needsEmailVerification: false }));
        case "POST /sign-out":
          signedIn = false;
          return Promise.resolve(new Response(null, { status: 204 }));
        case "GET /session":
          return Promise.resolve(
            signedIn ? json({ session, user }) : new Response(null, { status: 401 }),
          );
        case "GET /sessions":
          return Promise.resolve(json(signedIn ? [session] : []));
        default:
          return Promise.resolve(new Response(null, { status: 404 }));
      }
    },
  });
};

const nextTick = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("vue useSession", () => {
  it("keeps a ref in sync with the session store", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = makeClient();
    const session = useSession(client);

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

    useSession(client).dispose();

    expect(warnSpy).toHaveBeenCalledOnce();
    expect(warnSpy.mock.calls[0]![0]).toMatch(/effect-auth/);
    expect(warnSpy.mock.calls[0]![0]).toMatch(/dispose\(\)/);
    warnSpy.mockRestore();
  });

  it("dispose() stops receiving session updates", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = makeClient();
    const session = useSession(client);

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

describe("vue useListSessions", () => {
  it("fetches sessions into refs and supports refetch", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = makeClient();
    await client.signUp({ email: EMAIL, password: PW });

    const { data, isPending, error, refetch, dispose } = useListSessions(client);
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

    const { dispose } = useListSessions(client);
    dispose();

    expect(warnSpy).toHaveBeenCalledOnce();
    expect(warnSpy.mock.calls[0]![0]).toMatch(/effect-auth/);
    expect(warnSpy.mock.calls[0]![0]).toMatch(/dispose\(\)/);
    warnSpy.mockRestore();
  });

  it("dispose() prevents stale promise updates", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    let resolveDelayed!: (sessions: SessionList) => void;
    let callCount = 0;

    const fakeClient = {
      listSessions: (): Promise<SessionList> => {
        callCount++;
        if (callCount === 2) {
          return new Promise((resolve) => {
            resolveDelayed = resolve;
          });
        }
        return Promise.resolve([]);
      },
    } as unknown as AuthClient;

    const { data, isPending, dispose } = useListSessions(fakeClient);
    await nextTick(); // initial fetch settles: []

    // Kick off a slow refetch, then dispose before it resolves.
    const { refetch } = useListSessions(fakeClient);
    refetch();
    dispose();

    const stale = { id: "stale" } as unknown as SessionList[number];
    resolveDelayed([stale]);
    await nextTick();

    // Stale update was blocked by the disposed flag.
    expect(data.value?.length).toBe(0);
    expect(isPending.value).toBe(false);
    warnSpy.mockRestore();
  });
});
