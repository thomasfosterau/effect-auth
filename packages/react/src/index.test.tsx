// @vitest-environment jsdom
import { describe, it, expect } from "vite-plus/test";
import { act, renderHook, waitFor } from "@testing-library/react";
import { createAuthClient } from "@thomasfosterau/effect-auth-client";
import { useListSessions, useSession } from "./index.ts";

const EMAIL = "alice@react.test";
const PW = "password-123";

const json = (body: object): Response =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

/**
 * A client backed by a stand-in server covering only the endpoints these
 * hooks touch (`/sign-up`, `/sign-out`, `/session`, `/sessions`). The bindings
 * care about nothing but the session store moving, so the in-process auth
 * server the client package tests against would only add a dependency here.
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
    baseUrl: "http://react.test",
    fetch: (input, init) => {
      const { pathname } = new URL(String(input));
      switch (`${init?.method ?? "GET"} ${pathname}`) {
        case "POST /sign-up":
          signedIn = true;
          return Promise.resolve(json({ user, needsEmailVerification: false }));
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

describe("react useSession", () => {
  it("tracks the session store through sign-up and sign-out", async () => {
    const client = makeClient();
    const { result, unmount } = renderHook(() => useSession(client));

    await waitFor(() => expect(result.current.isPending).toBe(false));
    expect(result.current.data).toBeNull();

    await act(async () => {
      await client.signUp({ email: EMAIL, password: PW });
    });
    expect(result.current.data?.user.email).toBe(EMAIL);

    await act(async () => {
      await client.signOut();
    });
    expect(result.current.data).toBeNull();

    unmount();
  });
});

describe("react useListSessions", () => {
  it("fetches sessions and refetches on demand", async () => {
    const client = makeClient();
    await client.signUp({ email: EMAIL, password: PW });

    const { result, unmount } = renderHook(() => useListSessions(client));
    expect(result.current.isPending).toBe(true);

    await waitFor(() => expect(result.current.isPending).toBe(false));
    expect(result.current.error).toBeNull();
    expect(result.current.data?.length).toBe(1);

    // refetch() re-runs the query.
    act(() => result.current.refetch());
    expect(result.current.isPending).toBe(true);
    await waitFor(() => expect(result.current.isPending).toBe(false));
    expect((result.current.data?.length ?? 0) >= 1).toBe(true);

    unmount();
  });
});
