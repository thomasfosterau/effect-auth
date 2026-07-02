import { describe, it, expect } from "vite-plus/test";
import { createAuthClient, AuthClientError } from "./Client.js";
import { makeCookieJarFetch, makeServerFixture } from "./testing/fixture.js";

const EMAIL = "alice@client.test";
const PW = "password-123";

const makeClient = () => {
  const server = makeServerFixture();
  const client = createAuthClient({
    baseUrl: "http://client.test",
    fetch: makeCookieJarFetch(server.handler),
  });
  return { client, server };
};

describe("createAuthClient", () => {
  it("signs up, reads the session, and signs out", async () => {
    const { client } = makeClient();

    const signedUp = await client.signUp({ email: EMAIL, password: PW, name: "Alice" });
    expect(signedUp.user.email).toBe(EMAIL);

    const session = await client.getSession();
    expect(session?.user.email).toBe(EMAIL);

    await client.signOut();
    expect(await client.getSession()).toBeNull();
  });

  it("signs in with credentials and surfaces failures as AuthClientError", async () => {
    const { client } = makeClient();
    await client.signUp({ email: EMAIL, password: PW });
    await client.signOut();

    const err = await client.signIn({ email: EMAIL, password: "wrong" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthClientError);
    expect((err as AuthClientError).status).toBe(401);

    const ok = await client.signIn({ email: EMAIL, password: PW });
    expect(ok.user.email).toBe(EMAIL);
  });

  it("keeps the session store in sync across auth mutations", async () => {
    const { client } = makeClient();

    const states: Array<{ email: string | undefined; isPending: boolean }> = [];
    const unsubscribe = client.session.subscribe(() => {
      const s = client.session.get();
      states.push({ email: s.data?.user.email, isPending: s.isPending });
    });

    // Initial fetch (triggered by the subscription) resolves to signed out.
    await client.session.refetch();
    expect(client.session.get().data).toBeNull();
    expect(client.session.get().isPending).toBe(false);

    await client.signUp({ email: EMAIL, password: PW });
    expect(client.session.get().data?.user.email).toBe(EMAIL);

    await client.signOut();
    expect(client.session.get().data).toBeNull();

    unsubscribe();
    const count = states.length;
    await client.signIn({ email: EMAIL, password: PW });
    // Unsubscribed listeners stop firing, but the store still updates.
    expect(states.length).toBe(count);
    expect(client.session.get().data?.user.email).toBe(EMAIL);
  });

  it("manages the user and their sessions across two devices", async () => {
    const { client, server } = makeClient();
    await client.signUp({ email: EMAIL, password: PW });

    const updated = await client.updateUser({ name: "Alice Cooper" });
    expect(updated.name).toBe("Alice Cooper");

    // A second device (own cookie jar, same server) signs in.
    const other = createAuthClient({
      baseUrl: "http://client.test",
      fetch: makeCookieJarFetch(server.handler),
    });
    await other.signIn({ email: EMAIL, password: PW });

    expect((await client.listSessions()).length).toBe(2);

    // Revoke the other device's session from the first device.
    await client.revokeOtherSessions();
    expect((await client.listSessions()).length).toBe(1);
    expect(await other.getSession()).toBeNull();

    await client.changePassword({ currentPassword: PW, newPassword: "new-password-456" });
    await client.signOut();
    const back = await client.signIn({ email: EMAIL, password: "new-password-456" });
    expect(back.user.email).toBe(EMAIL);
  });

  it("answers 404 feature errors for unconfigured optional modules", async () => {
    const { client } = makeClient();
    const err = await client.magicLink.send({ email: EMAIL }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthClientError);
    expect((err as AuthClientError).status).toBe(404);
  });
});
