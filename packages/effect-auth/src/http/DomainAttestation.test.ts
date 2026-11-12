/**
 * Domain claims over HTTP (#598): an organization proves a domain through DNS
 * only, and manual attestation is the operator's, at the `isAdmin`-gated
 * `POST /admin/organization-domains`. Runs the real `Http.make` handler of the
 * `./client/testing` fixture.
 */
import { MutableHashMap, MutableHashSet } from "effect";
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
