import { describe, expect, it } from "vite-plus/test";
import { render, screen } from "@solidjs/testing-library";
import { createRoot } from "solid-js";
import type { AuthClient, SessionState, SessionStore } from "@thomasfosterau/effect-auth-client";
import {
  AuthClientProvider,
  createListSessions,
  createSession,
  useAuthClient,
  useSession,
} from "./index.ts";

const EMAIL = "alice@solid.test";

const signedOut: SessionState = { data: null, isPending: true, error: null };

const signedIn = (email: string): SessionState => ({
  data: {
    session: {
      id: "session-1",
      userId: "user-1",
      expiresAt: 0,
      createdAt: 0,
      lastActivityAt: 0,
      attributes: {},
    },
    user: { id: "user-1", email, createdAt: 0, updatedAt: 0, attributes: {} },
  },
  isPending: false,
  error: null,
});

/**
 * A stand-in for the client's session store: the bindings care about nothing
 * but `get`/`subscribe`, so driving those directly keeps each assertion about
 * the binding rather than about the client's HTTP layer.
 */
const makeStore = () => {
  let state = signedOut;
  const listeners = new Set<() => void>();
  const store: SessionStore = {
    get: () => state,
    subscribe: (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    refetch: () => Promise.resolve(),
  };
  return {
    store,
    subscriberCount: () => listeners.size,
    emit: (next: SessionState) => {
      state = next;
      for (const listener of listeners) listener();
    },
  };
};

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

describe("createSession", () => {
  it("tracks the store and re-renders when it emits", () => {
    const { store, emit } = makeStore();
    const client = stub({ session: store });

    render(() => {
      const session = createSession(client);
      return <span data-testid="email">{session().data?.user.email ?? "signed out"}</span>;
    });

    expect(screen.getByTestId("email").textContent).toBe("signed out");
    emit(signedIn(EMAIL));
    expect(screen.getByTestId("email").textContent).toBe(EMAIL);
  });

  it("unsubscribes when the owner is disposed", () => {
    const { store, subscriberCount } = makeStore();
    const client = stub({ session: store });

    const dispose = createRoot((disposeRoot) => {
      createSession(client);
      return disposeRoot;
    });

    expect(subscriberCount()).toBe(1);
    dispose();
    expect(subscriberCount()).toBe(0);
  });
});

describe("useSession", () => {
  it("reads the client from the provider", () => {
    const { store, emit } = makeStore();
    const client = stub({ session: store });

    const Consumer = () => {
      const session = useSession();
      return <span data-testid="email">{session().data?.user.email ?? "signed out"}</span>;
    };

    render(() => (
      <AuthClientProvider client={client}>
        <Consumer />
      </AuthClientProvider>
    ));

    emit(signedIn(EMAIL));
    expect(screen.getByTestId("email").textContent).toBe(EMAIL);
  });
});

describe("useAuthClient", () => {
  it("throws outside a provider", () => {
    expect(() => createRoot(() => useAuthClient())).toThrow(/No auth client in context/);
  });

  it("returns the provided client inside one", () => {
    const client = stub({ session: makeStore().store });
    let seen: AuthClient | null = null;

    const Consumer = () => {
      seen = useAuthClient();
      return null;
    };

    render(() => (
      <AuthClientProvider client={client}>
        <Consumer />
      </AuthClientProvider>
    ));

    expect(seen).toBe(client);
  });
});

describe("createListSessions", () => {
  it("fetches on creation and refetches on demand", async () => {
    let calls = 0;
    const client = stub({
      listSessions: () => {
        calls += 1;
        return Promise.resolve([
          {
            id: `session-${calls}`,
            userId: "user-1",
            expiresAt: 0,
            createdAt: 0,
            lastActivityAt: 0,
            attributes: {},
          },
        ]);
      },
    });

    const query = createRoot(() => createListSessions(client));
    expect(query.isPending()).toBe(true);

    await Promise.resolve();
    expect(query.error()).toBeNull();
    expect(query.data()?.length).toBe(1);

    query.refetch();
    expect(query.isPending()).toBe(true);
    await Promise.resolve();
    expect(calls).toBe(2);

    query.dispose();
  });

  it("records a failure", async () => {
    const failure = new Error("nope");
    const query = createRoot(() =>
      createListSessions(stub({ listSessions: () => Promise.reject(failure) })),
    );

    await Promise.resolve();
    await Promise.resolve();
    expect(query.error()).toBe(failure);
    expect(query.data()).toBeNull();
    expect(query.isPending()).toBe(false);

    query.dispose();
  });
});
