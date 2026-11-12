/**
 * Domain claims over HTTP (#598): an organization proves a domain through DNS
 * only, and manual attestation is the operator's, at the admin-gated
 * `POST /admin/organization-domains`, as is the release of any claim at
 * `DELETE /admin/organization-domains/:id` (#680). Runs the real `Http.make`
 * handler of the `./client/testing` fixture.
 */
import { MutableHashMap, MutableHashSet } from "effect";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import { assert, describe, expect, it } from "vite-plus/test";
import { AuthClientError, createAuthClient } from "../client/Client.ts";
import { makeCookieJarFetch, makeServerFixture } from "../client/testing/fixture.ts";

const BASE = "http://domains.test";
const PW = "password-123";

/** A server with the organization module, and a browser factory over it. */
const withServer = () => {
  const server = makeServerFixture({ organization: true });
  const browser = () => {
    const fetch = makeCookieJarFetch(server.handler);
    return { fetch, client: createAuthClient({ baseUrl: BASE, fetch }) };
  };
  return { server, browser };
};

const toJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

/** A bodiless JSON:API delete through a browser's cookie jar. */
const del = (fetch: typeof globalThis.fetch, path: string) =>
  fetch(`${BASE}${path}`, { method: "DELETE", headers: { accept: "application/vnd.api+json" } });

/** The status a client call was refused with. */
const refusal = (call: Promise<unknown>) =>
  call.then(
    () => assert.fail("expected a refusal"),
    (cause: unknown) => {
      assert.instanceOf(cause, AuthClientError);
      return cause.status;
    },
  );

/** A JSON:API write through a browser's cookie jar. */
const post = (fetch: typeof globalThis.fetch, path: string, body: Schema.Json) =>
  fetch(`${BASE}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/vnd.api+json",
      accept: "application/vnd.api+json",
    },
    body: toJson(body),
  });

/** The attestation document for `domain` and `organizationId`. */
const attestation = (organizationId: string, domain: string) => ({
  data: {
    type: "organization-domains",
    attributes: { domain },
    relationships: { organization: { data: { type: "organizations", id: organizationId } } },
  },
});

/** Signed-up browser; with `admin`, its user is a platform admin (`attributes.role`). */
const signUp = async (
  server: ReturnType<typeof makeServerFixture>,
  browser: ReturnType<typeof withServer>["browser"],
  email: string,
  admin = false,
) => {
  const session = browser();
  const { user } = await session.client.signUp({ email, password: PW });
  assert(user !== undefined, "sign-up answers the new user");
  if (admin) {
    MutableHashMap.modify(server.usersById, user.id, (stored) => ({
      ...stored,
      attributes: { ...stored.attributes, role: "admin" },
    }));
  }
  return session;
};

describe("HTTP domain claims (#598)", () => {
  it("refuses a tenant's manual claim, and never verifies a claim on domain:manage alone", async () => {
    const { server, browser } = withServer();
    const owner = await signUp(server, browser, "owner@attacker.test");
    const org = await owner.client.organization.create({ name: "Attacker", slug: "attacker" });

    const manual = await post(owner.fetch, `/organizations/${org.id}/domains`, {
      data: {
        type: "organization-domains",
        attributes: { domain: "victim.test", verificationStrategy: "manual" },
      },
    });
    expect(manual.status).toBe(400);
    expect(MutableHashMap.size(server.domainRecords)).toBe(0);

    // The DNS claim the owner can make stays unverified without the record.
    const claim = await owner.client.organization.addDomain(org.id, { domain: "victim.test" });
    expect(claim.verificationStrategy).toBe("dns");
    const check = await owner.client.organization.verifyDomain(claim.id);
    expect(check.verificationState).toBe("failed");
  });

  it("answers another organization's claim on a domain with nothing but a fresh claim", async () => {
    const { server, browser } = withServer();
    const first = await signUp(server, browser, "first@a.test");
    const firstOrg = await first.client.organization.create({ name: "A", slug: "a" });
    await first.client.organization.addDomain(firstOrg.id, { domain: "shared.test" });

    const second = await signUp(server, browser, "second@b.test");
    const secondOrg = await second.client.organization.create({ name: "B", slug: "b" });
    const claim = await second.client.organization.addDomain(secondOrg.id, {
      domain: "shared.test",
    });
    expect(claim.verificationState).toBe("pending");
    expect((await second.client.organization.listDomains(secondOrg.id)).map((d) => d.id)).toEqual([
      claim.id,
    ]);
  });

  it("lets a platform admin attest a domain for an organization", async () => {
    const { server, browser } = withServer();
    const owner = await signUp(server, browser, "owner@acme.test");
    const org = await owner.client.organization.create({ name: "Acme", slug: "acme" });
    const pending = await owner.client.organization.addDomain(org.id, { domain: "acme.test" });

    const operator = await signUp(server, browser, "ops@platform.test", true);
    const attested = await operator.client.admin.attestDomain({
      organizationId: org.id,
      domain: "acme.test",
    });
    expect(attested).toMatchObject({
      id: pending.id,
      organizationId: org.id,
      domain: "acme.test",
      verificationState: "verified",
      verificationStrategy: "manual",
    });
    expect(attested.verificationToken).toBeUndefined();

    const created = await post(operator.fetch, "/admin/organization-domains", {
      ...attestation(org.id, "acme-corp.test"),
    });
    expect(created.status).toBe(201);
    expect((await owner.client.organization.listDomains(org.id)).map((d) => d.domain)).toEqual(
      expect.arrayContaining(["acme.test", "acme-corp.test"]),
    );

    // A refusal (an unknown organization) is a 400.
    const unknown = await post(
      operator.fetch,
      "/admin/organization-domains",
      attestation("org-nope", "x.test"),
    );
    expect(unknown.status).toBe(400);
  });

  it("refuses the attestation endpoint to anyone but a platform admin", async () => {
    const { server, browser } = withServer();
    const owner = await signUp(server, browser, "owner@acme.test");
    const org = await owner.client.organization.create({ name: "Acme", slug: "acme" });

    // The organization's own owner holds every organization permission, and is still refused.
    const error = await owner.client.admin
      .attestDomain({ organizationId: org.id, domain: "acme.test" })
      .then(
        () => assert.fail("expected a refusal"),
        (cause: unknown) => cause,
      );
    assert.instanceOf(error, AuthClientError);
    expect(error.status).toBe(403);

    const anonymous = await post(
      makeCookieJarFetch(server.handler),
      "/admin/organization-domains",
      attestation(org.id, "acme.test"),
    );
    expect(anonymous.status).toBe(401);
    expect(MutableHashMap.size(server.domainRecords)).toBe(0);
  });

  it("records the attesting admin on the claim, as its attester (#680)", async () => {
    const { server, browser } = withServer();
    const owner = await signUp(server, browser, "owner@acme.test");
    const org = await owner.client.organization.create({ name: "Acme", slug: "acme" });
    const pending = await owner.client.organization.addDomain(org.id, { domain: "acme.test" });
    expect(pending.attestedBy).toBeUndefined();

    const operator = await signUp(server, browser, "ops@platform.test", true);
    const current = await operator.client.getSession();
    assert(current !== null, "the operator is signed in");
    const { user } = current;
    const attested = await operator.client.admin.attestDomain({
      organizationId: org.id,
      domain: "acme.test",
    });
    expect(attested.attestedBy).toBe(user.id);
    expect(
      Option.getOrUndefined(MutableHashMap.get(server.domainRecords, pending.id)),
    ).toMatchObject({
      attestedBy: user.id,
    });
    // The organization reads who attested its claim; a DNS claim names no one.
    const listed = await owner.client.organization.listDomains(org.id);
    expect(listed).toEqual([expect.objectContaining({ id: pending.id, attestedBy: user.id })]);
    const dns = await owner.client.organization.addDomain(org.id, { domain: "acme-corp.test" });
    MutableHashSet.add(server.publishedDnsDomains, "acme-corp.test");
    const proved = await owner.client.organization.verifyDomain(dns.id);
    expect(proved.verificationState).toBe("verified");
    expect("attestedBy" in proved).toBe(false);
  });

  it("lets a platform admin release any organization's claim, settling a dispute (#680)", async () => {
    const { server, browser } = withServer();
    const first = await signUp(server, browser, "owner@first.test");
    const firstOrg = await first.client.organization.create({ name: "First", slug: "first" });
    const second = await signUp(server, browser, "owner@second.test");
    const secondOrg = await second.client.organization.create({ name: "Second", slug: "second" });
    const operator = await signUp(server, browser, "ops@platform.test", true);

    const held = await operator.client.admin.attestDomain({
      organizationId: firstOrg.id,
      domain: "acme.test",
    });
    const blocked = await post(
      operator.fetch,
      "/admin/organization-domains",
      attestation(secondOrg.id, "acme.test"),
    );
    expect(blocked.status).toBe(400);

    await operator.client.admin.releaseDomain(held.id);
    expect(await first.client.organization.listDomains(firstOrg.id)).toEqual([]);
    const handedOver = await operator.client.admin.attestDomain({
      organizationId: secondOrg.id,
      domain: "acme.test",
    });
    expect(handedOver).toMatchObject({
      organizationId: secondOrg.id,
      verificationState: "verified",
    });

    // A pending claim is released the same way, through the raw endpoint.
    const pending = await first.client.organization.addDomain(firstOrg.id, {
      domain: "first.test",
    });
    expect((await del(operator.fetch, `/admin/organization-domains/${pending.id}`)).status).toBe(
      204,
    );
    expect(MutableHashMap.has(server.domainRecords, pending.id)).toBe(false);
    // An id that names no claim, or one already released, is a 404.
    expect((await del(operator.fetch, `/admin/organization-domains/${pending.id}`)).status).toBe(
      404,
    );
    expect(await refusal(operator.client.admin.releaseDomain("nope"))).toBe(404);
  });

  it("refuses the release endpoint to anyone but a platform admin (#680)", async () => {
    const { server, browser } = withServer();
    const owner = await signUp(server, browser, "owner@acme.test");
    const org = await owner.client.organization.create({ name: "Acme", slug: "acme" });
    const claim = await owner.client.organization.addDomain(org.id, { domain: "acme.test" });

    // The organization's owner holds `domain:manage`, and is still refused:
    // its own release is `DELETE /organization-domains/:id`.
    expect(await refusal(owner.client.admin.releaseDomain(claim.id))).toBe(403);
    // A non-admin is refused before the id is looked up, so an unknown id
    // answers the same.
    expect(await refusal(owner.client.admin.releaseDomain("nope"))).toBe(403);
    const anonymous = await del(
      makeCookieJarFetch(server.handler),
      `/admin/organization-domains/${claim.id}`,
    );
    expect(anonymous.status).toBe(401);
    expect(MutableHashMap.has(server.domainRecords, claim.id)).toBe(true);
  });

  it("refuses an unknown claim id exactly as another tenant's claim and a member without domain:manage (#718)", async () => {
    const { server, browser } = withServer();
    const owner = await signUp(server, browser, "owner@acme.test");
    const org = await owner.client.organization.create({ name: "Acme", slug: "acme" });
    const claim = await owner.client.organization.addDomain(org.id, { domain: "acme.test" });
    const member = await signUp(server, browser, "member@acme.test");
    const memberSession = await member.client.getSession();
    assert(memberSession !== null, "the member is signed in");
    await owner.client.organization.addMember(org.id, {
      userId: memberSession.user.id,
      role: "member",
    });
    // The stranger owns another tenant, so holds `domain:manage` there.
    const stranger = await signUp(server, browser, "owner@other.test");
    await stranger.client.organization.create({ name: "Other", slug: "other" });

    const answer = async (response: Promise<Response>) => {
      const res = await response;
      return { status: res.status, body: await res.text() };
    };
    const remove = (fetch: typeof globalThis.fetch, id: string) =>
      answer(del(fetch, `/organization-domains/${id}`));
    const verify = (fetch: typeof globalThis.fetch, id: string) =>
      answer(
        fetch(`${BASE}/organization-domains/${id}/verifications`, {
          method: "POST",
          headers: { accept: "application/vnd.api+json" },
        }),
      );

    const unknownRemove = await remove(owner.fetch, "no-such-claim");
    expect(unknownRemove.status).toBe(403);
    expect(unknownRemove.body).toContain("Missing permission 'domain:manage'");
    expect(await remove(stranger.fetch, claim.id)).toEqual(unknownRemove);
    expect(await remove(member.fetch, claim.id)).toEqual(unknownRemove);
    const unknownVerify = await verify(owner.fetch, "no-such-claim");
    expect(unknownVerify).toEqual(unknownRemove);
    expect(await verify(stranger.fetch, claim.id)).toEqual(unknownVerify);
    expect(await verify(member.fetch, claim.id)).toEqual(unknownVerify);
    expect(MutableHashMap.has(server.domainRecords, claim.id)).toBe(true);

    // The owner, holding the permission, verifies and releases the claim.
    MutableHashSet.add(server.publishedDnsDomains, "acme.test");
    expect((await verify(owner.fetch, claim.id)).status).toBe(200);
    expect((await remove(owner.fetch, claim.id)).status).toBe(204);
    expect(MutableHashMap.has(server.domainRecords, claim.id)).toBe(false);
  });

  it("verifies a tenant's claim only through its published DNS record", async () => {
    const { server, browser } = withServer();
    const owner = await signUp(server, browser, "owner@acme.test");
    const org = await owner.client.organization.create({ name: "Acme", slug: "acme" });
    const claim = await owner.client.organization.addDomain(org.id, { domain: "acme.test" });

    MutableHashSet.add(server.publishedDnsDomains, "acme.test");
    const verified = await owner.client.organization.verifyDomain(claim.id);
    expect(verified).toMatchObject({ verificationState: "verified", verificationStrategy: "dns" });
  });
});
