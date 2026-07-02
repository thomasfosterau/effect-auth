// @vitest-environment jsdom
import { describe, it, expect } from "vite-plus/test";
import { act, render, screen, waitFor } from "@testing-library/react";
import { createAuthClient, type AuthClient } from "./Client.js";
import { useSession, useListSessions } from "./react.js";
import { makeCookieJarFetch, makeServerFixture } from "./testing/fixture.js";

const EMAIL = "alice@react.test";
const PW = "password-123";

const makeClient = (): AuthClient => {
  const server = makeServerFixture();
  return createAuthClient({
    baseUrl: "http://react.test",
    fetch: makeCookieJarFetch(server.handler),
  });
};

function SessionProbe({ client }: { readonly client: AuthClient }) {
  const { data, isPending } = useSession(client);
  if (isPending) return <span data-testid="state">pending</span>;
  return <span data-testid="state">{data === null ? "signed-out" : data.user.email}</span>;
}

function SessionListProbe({ client }: { readonly client: AuthClient }) {
  const { data, isPending } = useListSessions(client);
  if (isPending) return <span data-testid="count">pending</span>;
  return <span data-testid="count">{data === null ? "error" : data.length}</span>;
}

describe("useSession", () => {
  it("tracks the session through sign-in and sign-out", async () => {
    const client = makeClient();
    render(<SessionProbe client={client} />);

    // Mounting subscribes and triggers the initial fetch -> signed out.
    await waitFor(() => expect(screen.getByTestId("state").textContent).toBe("signed-out"));

    await act(async () => {
      await client.signUp({ email: EMAIL, password: PW });
    });
    await waitFor(() => expect(screen.getByTestId("state").textContent).toBe(EMAIL));

    await act(async () => {
      await client.signOut();
    });
    await waitFor(() => expect(screen.getByTestId("state").textContent).toBe("signed-out"));
  });
});

describe("useListSessions", () => {
  it("lists the authenticated user's sessions", async () => {
    const client = makeClient();
    await client.signUp({ email: EMAIL, password: PW });

    render(<SessionListProbe client={client} />);
    await waitFor(() => expect(screen.getByTestId("count").textContent).toBe("1"));
  });
});
