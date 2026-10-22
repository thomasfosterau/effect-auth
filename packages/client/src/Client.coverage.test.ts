/**
 * Endpoint-coverage tests for the surfaces added in M7.
 *
 * Groups whose server modules the in-process fixture can mount (identifiers,
 * username/anonymous sign-in, multi-session, multi-factor, account management,
 * phone OTP, device authorization, organizations) run end to end against the
 * real handler over a cookie jar. The remaining admin-shaped groups (API keys,
 * JWT/JWKS, admin, SSO, OIDC client management) would need a second server
 * fixture each for little more than method/path/body wiring, so they are
 * covered with a recording `fetch` instead.
 */
import * as Auth from "@thomasfosterau/effect-auth";
import { Array as Arr, Effect, Order, Predicate, Schema } from "effect";
import { assert, describe, expect, it } from "vite-plus/test";
import { AuthClientError, SecondFactorChallengeError, createAuthClient } from "./Client.ts";
import {
  makeCookieJarFetch,
  makeServerFixture,
  type ServerFixtureOptions,
} from "./testing/fixture.ts";

const PW = "password-123";
const BASE = "http://client.test";

const toJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

/** What `promise` rejected with, asserted to be an instance of `type`. */
const rejectionOf = <E>(
  promise: Promise<unknown>,
  type: abstract new (...args: never) => E,
): Promise<E> =>
  promise.then(
    () => assert.fail("expected the promise to reject"),
    (error) =>
      error instanceof type
        ? error
        : assert.fail(`expected a ${type.name} rejection, got ${String(error)}`),
  );

/**
 * A server plus a `browser()` factory: every call returns a client with its
 * own cookie jar, i.e. a separate device/browser hitting the same server.
 */
const withServer = (options?: ServerFixtureOptions) => {
  const server = makeServerFixture(options);
  const browser = () =>
    createAuthClient({ baseUrl: BASE, fetch: makeCookieJarFetch(server.handler) });
  return { server, browser, client: browser() };
};

/** A `fetch` that records the calls it saw and answers with `body`. */
const recordingFetch = (body: Schema.Json) => {
  const calls: Array<{ method: string; path: string; body: unknown }> = [];
  const fetchImpl: typeof globalThis.fetch = async (input, init) => {
    const request = new Request(input as RequestInfo, init);
    calls.push({
      method: request.method,
      path: new URL(request.url).pathname,
      body: request.body === null ? undefined : ((await request.json()) as unknown),
    });
    return new Response(toJson(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  return { calls, fetch: fetchImpl };
};

// -----------------------------------------------------------------------------
// Identifiers
// -----------------------------------------------------------------------------

describe("identifiers", () => {
  it("lists the user's login handles and deletes one", async () => {
    const { server, client } = withServer();
    const { user } = await client.signUp({ email: "ids@client.test", password: PW });

    expect((await client.identifiers.list()).map((i) => i.type)).toEqual(["email"]);

    // A username handle is registered by the app, not over HTTP.
    server.registerUsername(user.id, "ids-user");
    const both = await client.identifiers.list();
    expect(
      Arr.sort(
        both.map((i) => i.value),
        Order.String,
      ),
    ).toEqual(["ids-user", "ids@client.test"]);

    const username = both.find((i) => i.type === "username")!;
    await client.identifiers.delete(username.id);
    expect((await client.identifiers.list()).map((i) => i.type)).toEqual(["email"]);
  });

  it("refuses to delete the only identifier on an account", async () => {
    const { client } = withServer();
    await client.signUp({ email: "solo@client.test", password: PW });
    const [only] = await client.identifiers.list();

    const error = await rejectionOf(client.identifiers.delete(only!.id), AuthClientError);
    expect(error).toBeInstanceOf(AuthClientError);
    expect((error as AuthClientError).status).toBe(400);
  });
});

// -----------------------------------------------------------------------------
// Alternative sign-in surfaces
// -----------------------------------------------------------------------------

describe("username and anonymous sign-in", () => {
  it("signs in with a username + password", async () => {
    const { server, client } = withServer({ features: true });
    const { user } = await client.signUp({ email: "name@client.test", password: PW });
    server.registerUsername(user.id, "cooluser");
    await client.signOut();

    const signedIn = await client.signInUsername({ username: "cooluser", password: PW });
    expect(signedIn.user.id).toBe(user.id);
    expect((await client.getSession())?.user.id).toBe(user.id);
  });

  it("signs in anonymously and keeps the guest session", async () => {
    const { client } = withServer({ features: true });

    const guest = await client.signInAnonymous();
    expect(guest.user.attributes["isAnonymous"]).toBe(true);
    expect((await client.getSession())?.user.id).toBe(guest.user.id);
  });
});

describe("phone OTP", () => {
  it("sends an SMS code and signs in with it", async () => {
    const { server, client } = withServer({ features: true });

    expect(await client.phoneOtp.send({ phoneNumber: "+15550001", purpose: "sign-in" })).toEqual({
      status: true,
    });
    expect(server.sentPhoneOtps).toHaveLength(1);

    const signedIn = await client.phoneOtp.signIn({
      phoneNumber: "+15550001",
      otp: server.sentPhoneOtps[0]!.otp,
    });
    expect(signedIn.user.id).toBeTypeOf("string");
    expect(await client.getSession()).not.toBeNull();
  });
});

describe("device authorization", () => {
  it("runs code -> approve -> token across two devices", async () => {
    const { browser } = withServer({ features: true });
    const device = browser();
    const phone = browser();

    const code = await device.device.code();
    expect(code.verificationUri).toBe("https://client.test/device");

    // Polling before the user decides answers 400 authorization_pending.
    const pending = await device.device.token({ deviceCode: code.deviceCode }).catch((e) => e);
    expect(pending).toBeInstanceOf(AuthClientError);
    expect((pending as AuthClientError).status).toBe(400);

    await phone.signUp({ email: "device@client.test", password: PW });
    expect(await phone.device.approve({ userCode: code.userCode })).toEqual({ status: true });

    const authorized = await device.device.token({ deviceCode: code.deviceCode });
    expect(authorized.user.email).toBe("device@client.test");
    expect(await device.getSession()).not.toBeNull();
  });
});

// -----------------------------------------------------------------------------
// Multi-session
// -----------------------------------------------------------------------------

describe("multi-session", () => {
  it("lists both accounts on the device and switches the active one", async () => {
    const { client } = withServer({ multiSession: { maximumSessions: 5 } });

    const first = await client.signUp({ email: "a@client.test", password: PW });
    const second = await client.signUp({ email: "b@client.test", password: PW });
    expect((await client.getSession())?.user.id).toBe(second.user.id);

    const list = await client.multiSession.list();
    expect(
      Arr.sort(
        Arr.filter(
          list.map((entry) => entry.user.email),
          Predicate.isString,
        ),
        Order.String,
      ),
    ).toEqual(["a@client.test", "b@client.test"]);

    const firstEntry = list.find((entry) => entry.user.id === first.user.id)!;
    expect(await client.multiSession.setActive({ sessionId: firstEntry.session.id })).toEqual({
      status: true,
    });
    expect((await client.getSession())?.user.id).toBe(first.user.id);

    await client.multiSession.revoke({ sessionId: firstEntry.session.id });
    expect((await client.multiSession.list()).map((entry) => entry.user.id)).toEqual([
      second.user.id,
    ]);
  });
});

// -----------------------------------------------------------------------------
// Multi-factor: the challenge-continuation helper
// -----------------------------------------------------------------------------

const totpFor = (secret: string) => Effect.runPromise(Auth.MultiFactor.generateTotp(secret));
/**
 * The previous time step's code (still inside the ±1 window). Confirming
 * enrollment with it leaves the current step's code unused, so the replay
 * guard does not reject the later challenge redemption.
 */
const previousTotpFor = (secret: string) =>
  Effect.runPromise(Auth.MultiFactor.generateHotp(secret, Math.floor(Date.now() / 1000 / 30) - 1));

/** Enrol `email` in multi-factor and return the enrollment view. */
const enrol = async (client: ReturnType<typeof createAuthClient>, email: string) => {
  await client.signUp({ email, password: PW });
  const enrollment = await client.multiFactor.enable({ password: PW });
  await client.multiFactor.confirm({ code: await previousTotpFor(enrollment.secret) });
  await client.signOut();
  return enrollment;
};

describe("multi-factor challenge continuation", () => {
  it("carries a gated sign-in into verifyTotp", async () => {
    const { client } = withServer({ features: true });
    const enrollment = await enrol(client, "totp@client.test");

    const gated = await client.signIn({ email: "totp@client.test", password: PW });
    expect(gated.secondFactor).toBeDefined();
    expect(await client.getSession()).toBeNull(); // no session until redeemed

    const challenge = client.multiFactor.continueChallenge(gated);
    expect(challenge.token).toBe(gated.secondFactor!.token);
    expect(challenge.isExpired()).toBe(false);

    const verified = await challenge.verifyTotp(await totpFor(enrollment.secret));
    expect(verified.user.email).toBe("totp@client.test");
    expect((await client.getSession())?.user.email).toBe("totp@client.test");
  });

  it("carries a gated sign-in into verifyBackupCode", async () => {
    const { client } = withServer({ features: true });
    const enrollment = await enrol(client, "backup@client.test");

    const gated = await client.signIn({ email: "backup@client.test", password: PW });
    const challenge = client.multiFactor.continueChallenge(gated);

    const verified = await challenge.verifyBackupCode(enrollment.backupCodes[0]!);
    expect(verified.user.email).toBe("backup@client.test");

    // Backup codes are single-use: a fresh challenge rejects the same code.
    await client.signOut();
    const again = await client.signIn({ email: "backup@client.test", password: PW });
    const replay = await rejectionOf(
      client.multiFactor.continueChallenge(again).verifyBackupCode(enrollment.backupCodes[0]!),
      AuthClientError,
    );
    expect(replay).toBeInstanceOf(AuthClientError);
    expect((replay as AuthClientError).status).toBe(401);
  });

  it("throws a typed error when the result carries no challenge", async () => {
    const { client } = withServer({ features: true });
    const plain = await client.signUp({ email: "nochallenge@client.test", password: PW });

    expect(() => client.multiFactor.continueChallenge(plain)).toThrow(SecondFactorChallengeError);
    expect(() => client.multiFactor.continueChallenge(plain)).toThrow(
      expect.objectContaining({ reason: "missing" }),
    );
  });

  it("rejects an expired challenge without issuing a request", async () => {
    const { calls, fetch } = recordingFetch({});
    const client = createAuthClient({ baseUrl: BASE, fetch });

    const challenge = client.multiFactor.challenge({
      token: "stale-token",
      expiresAt: Date.now() - 1_000,
    });
    expect(challenge.isExpired()).toBe(true);

    const error = await rejectionOf(challenge.verifyTotp("123456"), SecondFactorChallengeError);
    expect(error).toBeInstanceOf(SecondFactorChallengeError);
    expect((error as SecondFactorChallengeError).reason).toBe("expired");
    expect(calls).toHaveLength(0);
  });
});

// -----------------------------------------------------------------------------
// Account management
// -----------------------------------------------------------------------------

describe("change email and delete user", () => {
  it("requests and confirms an email change", async () => {
    const { server, client } = withServer({ features: true });
    await client.signUp({ email: "old@client.test", password: PW });

    expect(await client.changeEmail.request({ newEmail: "new@client.test" })).toEqual({
      status: true,
    });
    expect(server.sentChangeEmail).toHaveLength(1);

    await client.changeEmail.confirm({ token: server.sentChangeEmail[0]!.token });

    // Confirming revokes the old session; the new address is now the handle.
    const signedIn = await client.signIn({ email: "new@client.test", password: PW });
    expect(signedIn.user.email).toBe("new@client.test");
  });

  it("requests and confirms account deletion", async () => {
    const { server, client } = withServer({ features: true });
    await client.signUp({ email: "gone@client.test", password: PW });

    expect(await client.deleteUser.request()).toEqual({ status: true });
    expect(server.sentDeleteTokens).toHaveLength(1);

    await client.deleteUser.confirm({ token: server.sentDeleteTokens[0]! });
    expect(await client.getSession()).toBeNull();
  });
});

// -----------------------------------------------------------------------------
// Organizations
// -----------------------------------------------------------------------------

describe("organizations", () => {
  it("runs an organization lifecycle: create, members, invitations, delete", async () => {
    const { browser } = withServer({ organization: true });
    const owner = browser();
    const invitee = browser();

    await owner.signUp({ email: "owner@client.test", password: PW });
    const guest = await invitee.signUp({ email: "invitee@client.test", password: PW });

    const org = await owner.organization.create({ name: "Acme", slug: "acme" });
    expect(org.slug).toBe("acme");
    expect((await owner.organization.list()).map((o) => o.id)).toEqual([org.id]);

    const full = await owner.organization.get(org.id);
    expect(full.members.map((m) => m.role)).toEqual(["owner"]);

    expect((await owner.organization.update(org.id, { name: "Acme Inc" })).name).toBe("Acme Inc");

    // Invitation round trip: invite -> list -> accept.
    const invitation = await owner.organization.invite(org.id, {
      email: "invitee@client.test",
      role: "member",
    });
    expect(invitation.status).toBe("pending");
    expect((await owner.organization.listInvitations(org.id)).map((i) => i.id)).toEqual([
      invitation.id,
    ]);

    const member = await invitee.organization.acceptInvitation(invitation.id);
    expect(member).toMatchObject({ organizationId: org.id, userId: guest.user.id, role: "member" });

    // Direct role management, then removal.
    const promoted = await owner.organization.updateMemberRole(org.id, {
      userId: guest.user.id,
      role: "admin",
    });
    expect(promoted.role).toBe("admin");
    await owner.organization.removeMember(org.id, guest.user.id);
    expect((await owner.organization.get(org.id)).members).toHaveLength(1);

    // A second invitation, cancelled instead of accepted.
    const cancelled = await owner.organization.invite(org.id, {
      email: "someone@client.test",
      role: "member",
    });
    expect((await owner.organization.cancelInvitation(cancelled.id)).status).toBe("canceled");

    expect(await owner.organization.setActive({ organizationId: org.id })).toEqual({
      status: true,
    });
    await owner.organization.delete(org.id);
    expect(await owner.organization.list()).toEqual([]);
  });

  it("manages teams and per-organization roles", async () => {
    const { browser } = withServer({ organization: true });
    const owner = browser();
    const teammate = browser();

    await owner.signUp({ email: "lead@client.test", password: PW });
    const mate = await teammate.signUp({ email: "mate@client.test", password: PW });

    const org = await owner.organization.create({ name: "Globex", slug: "globex" });
    await owner.organization.addMember(org.id, { userId: mate.user.id, role: "member" });

    const team = await owner.organization.createTeam(org.id, { name: "Engineering" });
    expect(team.organizationId).toBe(org.id);
    expect((await teammate.organization.listTeams(org.id)).map((t) => t.id)).toEqual([team.id]);

    const teamMember = await owner.organization.addTeamMember(team.id, { userId: mate.user.id });
    expect(teamMember).toMatchObject({ teamId: team.id, userId: mate.user.id });
    expect((await owner.organization.listTeamMembers(team.id)).map((m) => m.userId)).toEqual([
      mate.user.id,
    ]);
    expect(
      (await owner.organization.listTeamsForMember(org.id, mate.user.id)).map((t) => t.id),
    ).toEqual([team.id]);

    expect((await owner.organization.updateTeam(team.id, { name: "Platform" })).name).toBe(
      "Platform",
    );

    // Dynamic access control: give `member` the team:create permission.
    const role = await owner.organization.upsertRole(org.id, "member", {
      permissions: ["team:create"],
    });
    expect(role).toMatchObject({ role: "member", permissions: ["team:create"] });
    expect((await teammate.organization.listRoles(org.id)).map((r) => r.role)).toEqual(["member"]);

    const memberTeam = await teammate.organization.createTeam(org.id, { name: "Design" });
    expect(memberTeam.name).toBe("Design");

    // Dropping the definition removes the granted permission again.
    await owner.organization.deleteRole(org.id, "member");
    const denied = await rejectionOf(
      teammate.organization.createTeam(org.id, { name: "Growth" }),
      AuthClientError,
    );
    expect(denied).toBeInstanceOf(AuthClientError);
    expect((denied as AuthClientError).status).toBe(403);

    await owner.organization.removeTeamMember(team.id, mate.user.id);
    expect(await owner.organization.listTeamMembers(team.id)).toEqual([]);
    await owner.organization.deleteTeam(team.id);
    expect((await owner.organization.listTeams(org.id)).map((t) => t.name)).toEqual(["Design"]);
  });

  it("deactivates and reactivates a member, restoring their role", async () => {
    const { browser } = withServer({ organization: true });
    const owner = browser();
    const staff = browser();

    await owner.signUp({ email: "boss@client.test", password: PW });
    const employee = await staff.signUp({ email: "staff@client.test", password: PW });

    const org = await owner.organization.create({ name: "Initech", slug: "initech" });
    await owner.organization.addMember(org.id, { userId: employee.user.id, role: "admin" });

    const deactivated = await owner.organization.deactivateMember(org.id, employee.user.id);
    expect(deactivated).toMatchObject({
      status: "inactive",
      role: "member",
      previousRole: "admin",
    });

    // Inactive members are non-members for authorization...
    const denied = await rejectionOf(
      staff.organization.createTeam(org.id, { name: "Nope" }),
      AuthClientError,
    );
    expect(denied).toBeInstanceOf(AuthClientError);
    expect((denied as AuthClientError).status).toBe(403);
    // ...but the row is still on the organization.
    expect((await owner.organization.get(org.id)).members).toHaveLength(2);
    // The session survives: deactivation is organization-scoped.
    expect((await staff.getSession())?.user.id).toBe(employee.user.id);

    const reactivated = await owner.organization.reactivateMember(org.id, employee.user.id);
    expect(reactivated).toMatchObject({ status: "active", role: "admin" });
    expect((await staff.organization.createTeam(org.id, { name: "Platform" })).name).toBe(
      "Platform",
    );

    // The last active owner cannot be deactivated.
    const lastOwner = await rejectionOf(
      owner.organization.deactivateMember(org.id, (await owner.getSession())!.user.id),
      AuthClientError,
    );
    expect(lastOwner).toBeInstanceOf(AuthClientError);
    expect((lastOwner as AuthClientError).status).toBe(403);
  });

  it("sets a default role that addMember and the org view both use", async () => {
    const { browser } = withServer({ organization: true });
    const owner = browser();
    const newcomer = browser();

    await owner.signUp({ email: "founder@client.test", password: PW });
    const hire = await newcomer.signUp({ email: "hire@client.test", password: PW });

    const org = await owner.organization.create({ name: "Hooli", slug: "hooli" });
    expect(org.defaultRole).toBe("member");
    expect(org.jitProvisioning).toBe(false);

    await owner.organization.upsertRole(org.id, "contributor", { permissions: ["team:create"] });
    const updated = await owner.organization.setDefaultRole(org.id, { role: "contributor" });
    expect(updated.defaultRole).toBe("contributor");

    const member = await owner.organization.addMember(org.id, { userId: hire.user.id });
    expect(member.role).toBe("contributor");
    expect(member.status).toBe("active");

    // A role no map defines is refused.
    const unknown = await rejectionOf(
      owner.organization.setDefaultRole(org.id, { role: "auditor" }),
      AuthClientError,
    );
    expect(unknown).toBeInstanceOf(AuthClientError);
    expect((unknown as AuthClientError).status).toBe(403);
  });

  it("resends a pending invitation on the same id", async () => {
    const { browser } = withServer({ organization: true });
    const owner = browser();

    await owner.signUp({ email: "host@client.test", password: PW });
    const org = await owner.organization.create({ name: "Umbrella", slug: "umbrella" });

    const invitation = await owner.organization.invite(org.id, {
      email: "guest@client.test",
      role: "member",
    });
    const resent = await owner.organization.resendInvitation(invitation.id);
    expect(resent.id).toBe(invitation.id);
    expect(resent.status).toBe("pending");
    expect(resent.expiresAt).toBeGreaterThanOrEqual(invitation.expiresAt);
    expect(await owner.organization.listInvitations(org.id)).toHaveLength(1);

    await owner.organization.cancelInvitation(invitation.id);
    const canceled = await rejectionOf(
      owner.organization.resendInvitation(invitation.id),
      AuthClientError,
    );
    expect(canceled).toBeInstanceOf(AuthClientError);
    expect((canceled as AuthClientError).status).toBe(403);
  });

  it("claims a domain, verifies it over DNS, and keeps it unique across orgs", async () => {
    const { server, browser } = withServer({ organization: true });
    const owner = browser();

    await owner.signUp({ email: "admin@client.test", password: PW });
    const org = await owner.organization.create({ name: "Acme", slug: "acme" });

    const claim = await owner.organization.addDomain(org.id, { domain: "Acme.test" });
    expect(claim).toMatchObject({
      domain: "acme.test",
      verificationState: "pending",
      verificationStrategy: "dns",
    });
    expect(claim.verificationToken).toBeTypeOf("string");
    expect((await owner.organization.listDomains(org.id)).map((d) => d.domain)).toEqual([
      "acme.test",
    ]);

    // The TXT record is not published yet.
    expect((await owner.organization.verifyDomain(org.id, claim.id)).verificationState).toBe(
      "failed",
    );

    server.publishedDnsDomains.add("acme.test");
    const verified = await owner.organization.verifyDomain(org.id, claim.id);
    expect(verified.verificationState).toBe("verified");
    expect(verified.verifiedAt).toBeTypeOf("number");

    // A second organization cannot claim the same domain.
    const rival = browser();
    await rival.signUp({ email: "rival@client.test", password: PW });
    const other = await rival.organization.create({ name: "Globex", slug: "globex" });
    const conflict = await rejectionOf(
      rival.organization.addDomain(other.id, { domain: "acme.test" }),
      AuthClientError,
    );
    expect(conflict).toBeInstanceOf(AuthClientError);
    expect((conflict as AuthClientError).status).toBe(403);

    // Releasing the claim frees the domain again.
    await owner.organization.removeDomain(org.id, claim.id);
    expect(await owner.organization.listDomains(org.id)).toEqual([]);
    expect((await rival.organization.addDomain(other.id, { domain: "acme.test" })).domain).toBe(
      "acme.test",
    );
  });

  it("answers 404 when the organization module is absent", async () => {
    const { client } = withServer();
    await client.signUp({ email: "noorg@client.test", password: PW });

    const error = await rejectionOf(client.organization.list(), AuthClientError);
    expect(error).toBeInstanceOf(AuthClientError);
    expect((error as AuthClientError).status).toBe(404);
  });
});

// -----------------------------------------------------------------------------
// Wiring-only groups (recording fetch)
// -----------------------------------------------------------------------------

describe("api keys, JWT, admin, SSO and OIDC wiring", () => {
  it("maps API-key calls onto /api-keys", async () => {
    const { calls, fetch } = recordingFetch({ key: "sk_live", apiKey: { id: "k1" } });
    const client = createAuthClient({ baseUrl: BASE, fetch });

    await client.apiKeys.create({ name: "CI" });
    await client.apiKeys.list();
    await client.apiKeys.update("k 1", { enabled: false });
    await client.apiKeys.delete("k 1");

    expect(calls).toEqual([
      { method: "POST", path: "/api-keys", body: { name: "CI" } },
      { method: "GET", path: "/api-keys", body: undefined },
      { method: "PATCH", path: "/api-keys/k%201", body: { enabled: false } },
      { method: "DELETE", path: "/api-keys/k%201", body: undefined },
    ]);
  });

  it("maps JWT calls onto /token and /jwks", async () => {
    const { calls, fetch } = recordingFetch({ keys: [] });
    const client = createAuthClient({ baseUrl: BASE, fetch });

    await client.jwtToken();
    await client.jwks();

    expect(calls.map((call) => `${call.method} ${call.path}`)).toEqual(["GET /token", "GET /jwks"]);
  });

  it("maps admin calls onto /admin/*", async () => {
    const { calls, fetch } = recordingFetch({ users: [], total: 0 });
    const client = createAuthClient({ baseUrl: BASE, fetch });

    await client.admin.listUsers({ limit: 10 });
    await client.admin.setRole({ userId: "u1", role: "admin" });
    await client.admin.banUser({ userId: "u1", reason: "spam" });
    await client.admin.unbanUser({ userId: "u1" });
    await client.admin.revokeSessions({ userId: "u1" });
    await client.admin.removeUser({ userId: "u1" });
    await client.admin.impersonate({ userId: "u1" });
    await client.admin.stopImpersonating();

    expect(calls.map((call) => call.path)).toEqual([
      "/admin/users/list",
      "/admin/users/set-role",
      "/admin/users/ban",
      "/admin/users/unban",
      "/admin/users/revoke-sessions",
      "/admin/users/remove",
      "/admin/impersonate",
      "/admin/stop-impersonating",
    ]);
    expect(calls.every((call) => call.method === "POST")).toBe(true);
  });

  it("maps SSO and OIDC client management onto their endpoints", async () => {
    const { calls, fetch } = recordingFetch({ url: "https://idp.test/authorize" });
    const client = createAuthClient({ baseUrl: BASE, fetch });

    await client.sso.signIn({ email: "user@corp.test" });
    await client.sso.callback({ code: "abc", state: "xyz" });
    await client.oidc.listClients();
    await client.oidc.updateClient("c1", { name: "App" });
    await client.oidc.deleteClient("c1");
    await client.oidc.consent({ consentCode: "code", accept: true });

    expect(calls.map((call) => `${call.method} ${call.path}`)).toEqual([
      "POST /sign-in/sso",
      "POST /sso/callback",
      "GET /oauth2/clients",
      "PATCH /oauth2/clients/c1",
      "DELETE /oauth2/clients/c1",
      "POST /oauth2/consent",
    ]);
  });
});
