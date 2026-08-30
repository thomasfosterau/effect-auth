// @vitest-environment jsdom
import { describe, it, expect } from "vite-plus/test";
import { act, renderHook, waitFor } from "@testing-library/react";
import { createAuthClient } from "./Client.ts";
import { useListSessions, useSession } from "./react.ts";
import { makeCookieJarFetch, makeServerFixture } from "./testing/fixture.ts";

const EMAIL = "alice@react.test";
const PW = "password-123";

const makeClient = () => {
  const server = makeServerFixture();
  return createAuthClient({
    baseUrl: "http://react.test",
    fetch: makeCookieJarFetch(server.handler),
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
