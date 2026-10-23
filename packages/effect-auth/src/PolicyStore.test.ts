import { describe, it, expect } from "vite-plus/test";
import { DateTime, Effect, Schema } from "effect";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import * as AuthorizationModel from "./AuthorizationModel.ts";
import * as Policy from "./Policy.ts";
import * as PolicyStore from "./PolicyStore.ts";

const Json = Schema.fromJsonString(Schema.Unknown);

const alice = Entity.ref("User", "alice");
const bob = Entity.ref("User", "bob");
const carol = Entity.ref("User", "carol");
const readDoc = Entity.ref("Action", "doc:read");
const doc1 = Entity.ref("Document", "doc-1");
const doc2 = Entity.ref("Document", "doc-2");

const at = (iso: string) => DateTime.toDateUtc(DateTime.makeUnsafe(iso));

/** `permit(principal == ?principal, action doc:read, resource == ?resource)`. */
const shareTemplate = PolicyStore.template({
  id: "share-doc",
  principal: PolicyStore.eqSlot,
  action: Policy.eq(readDoc),
  resource: PolicyStore.eqSlot,
  description: "Share a document with a user",
});

const link = (id: string, principal: Entity.EntityRef, resource: Entity.EntityRef) =>
  PolicyStore.makeLink({
    id,
    templateId: shareTemplate.id,
    principal,
    resource,
    now: at("2026-08-30T00:00:00.000Z"),
  });

const run = <A, E>(effect: Effect.Effect<A, E>) => Effect.runPromise(effect);

describe("PolicyStore CRUD", () => {
  it("stores, reads, updates and deletes policies", async () => {
    const store = PolicyStore.memoryPolicyStore();
    const policy = Policy.permit({ id: "p1", action: Policy.eq(readDoc) });

    expect(await run(store.getPolicy("p1"))).toBeNull();
    expect(await run(store.createPolicy(policy))).toEqual(policy);
    expect(await run(store.getPolicy("p1"))).toEqual(policy);
    expect(await run(store.listPolicies())).toEqual([policy]);

    const updated = Policy.forbid({ id: "p1", action: Policy.eq(readDoc) });
    expect(await run(store.updatePolicy(updated))).toEqual(updated);
    expect(await run(store.getPolicy("p1"))).toEqual(updated);

    await run(store.deletePolicy("p1"));
    expect(await run(store.getPolicy("p1"))).toBeNull();
    // Deleting an absent policy is a no-op, not a failure.
    await run(store.deletePolicy("p1"));
  });

  it("updatePolicy/updateTemplate return null when the row is absent", async () => {
    const store = PolicyStore.memoryPolicyStore();
    expect(await run(store.updatePolicy(Policy.permit({ id: "ghost" })))).toBeNull();
    expect(await run(store.updateTemplate(shareTemplate))).toBeNull();
  });

  it("creating a policy or template with an existing id fails like a unique index", async () => {
    const store = PolicyStore.memoryPolicyStore();
    const policy = Policy.permit({ id: "p1" });
    await run(store.createPolicy(policy));

    const policyResult = await run(Effect.result(store.createPolicy(policy)));
    expect(policyResult._tag).toBe("Failure");

    await run(store.createTemplate(shareTemplate));
    const templateResult = await run(Effect.result(store.createTemplate(shareTemplate)));
    expect(templateResult._tag).toBe("Failure");

    const record = link("l1", alice, doc1);
    await run(store.createLink(record));
    const linkResult = await run(Effect.result(store.createLink(record)));
    expect(linkResult._tag).toBe("Failure");
  });

  it("lists links, optionally filtered by template", async () => {
    const store = PolicyStore.memoryPolicyStore();
    const other = PolicyStore.template({ id: "other", principal: PolicyStore.eqSlot });
    await run(store.createTemplate(shareTemplate));
    await run(store.createTemplate(other));

    const shared = link("l1", alice, doc1);
    const elsewhere = PolicyStore.makeLink({
      id: "l2",
      templateId: "other",
      principal: bob,
      now: at("2026-08-30T00:00:00.000Z"),
    });
    await run(store.createLink(shared));
    await run(store.createLink(elsewhere));

    expect(await run(store.getLink("l1"))).toEqual(shared);
    expect(await run(store.getLink("nope"))).toBeNull();
    expect(await run(store.listLinks())).toHaveLength(2);
    expect(await run(store.listLinks("share-doc"))).toEqual([shared]);

    await run(store.deleteLink("l1"));
    expect(await run(store.listLinks())).toEqual([elsewhere]);
    // Deleting an absent link is a no-op.
    await run(store.deleteLink("l1"));
  });

  it("deleting a template cascades to its links, leaving other templates' links alone", async () => {
    const links = new Map<string, PolicyStore.TemplateLink>();
    const store = PolicyStore.memoryPolicyStore({ links });
    const other = PolicyStore.template({ id: "other", principal: PolicyStore.eqSlot });
    await run(store.createTemplate(shareTemplate));
    await run(store.createTemplate(other));
    await run(store.createLink(link("l1", alice, doc1)));
    await run(store.createLink(link("l2", bob, doc1)));
    await run(
      store.createLink(PolicyStore.makeLink({ id: "l3", templateId: "other", principal: carol })),
    );

    await run(store.deleteTemplate("share-doc"));
    expect(await run(store.getTemplate("share-doc"))).toBeNull();
    expect([...links.keys()]).toEqual(["l3"]);
    // No-op for an unknown template.
    await run(store.deleteTemplate("share-doc"));
  });

  it("accepts pre-seeded maps", async () => {
    const policy = Policy.permit({ id: "seeded" });
    const policies = new Map([[policy.id, policy]]);
    const store = PolicyStore.memoryPolicyStore({ policies });
    expect(await run(store.getPolicy("seeded"))).toEqual(policy);
    await run(store.createPolicy(Policy.permit({ id: "added" })));
    expect([...policies.keys()]).toEqual(["seeded", "added"]);
  });
});

describe("instantiate", () => {
  it("substitutes eq slots and gives the policy a stable, unique id", () => {
    const result = PolicyStore.instantiate(shareTemplate, link("l1", alice, doc1));
    expect(result).toEqual({
      ok: true,
      value: {
        _tag: "DeclarativePolicy",
        id: "share-doc#l1",
        effect: "permit",
        principal: Policy.eq(alice),
        action: Policy.eq(readDoc),
        resource: Policy.eq(doc1),
        description: "Share a document with a user",
      },
    });
  });

  it("substitutes in slots (hierarchy membership) and carries the when clause", () => {
    const orgTemplate = PolicyStore.template({
      id: "org-members",
      principal: PolicyStore.inSlot,
      resource: PolicyStore.inSlot,
      when: Condition.eq(Condition.attr("context", "mfa"), Condition.lit(true)),
    });
    const result = PolicyStore.instantiate(
      orgTemplate,
      PolicyStore.makeLink({
        id: "l1",
        templateId: "org-members",
        principal: Entity.ref("Role", "admin"),
        resource: Entity.ref("Org", "acme"),
      }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.principal).toEqual(Policy.inScope(Entity.ref("Role", "admin")));
    expect(result.value.resource).toEqual(Policy.inScope(Entity.ref("Org", "acme")));
    expect(result.value.when).toEqual(
      Condition.eq(Condition.attr("context", "mfa"), Condition.lit(true)),
    );
  });

  it("errors when a slot has no value", () => {
    const result = PolicyStore.instantiate(
      shareTemplate,
      PolicyStore.makeLink({ id: "l1", templateId: "share-doc", principal: alice }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.message).toContain("?resource");
  });

  it("a slotless template instantiates unchanged from a valueless link", () => {
    const flat = PolicyStore.template({ id: "flat", action: Policy.eq(readDoc) });
    const result = PolicyStore.instantiate(
      flat,
      PolicyStore.makeLink({ id: "l1", templateId: "flat" }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.id).toBe("flat#l1");
    expect(result.value.principal).toEqual(Policy.any);
    expect(result.value.resource).toEqual(Policy.any);
  });

  it("errors on a value the template has no slot for (never a silent widening)", () => {
    const flat = PolicyStore.template({ id: "flat", principal: PolicyStore.eqSlot });
    const result = PolicyStore.instantiate(
      flat,
      PolicyStore.makeLink({ id: "l1", templateId: "flat", principal: alice, resource: doc1 }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.message).toContain("no ?resource slot");
  });

  it("errors when the link targets another template", () => {
    const result = PolicyStore.instantiate(
      shareTemplate,
      PolicyStore.makeLink({ id: "l1", templateId: "elsewhere", principal: alice, resource: doc1 }),
    );
    expect(result.ok).toBe(false);
  });
});

describe("effectivePolicies", () => {
  it("combines stored policies with instantiated links", async () => {
    const store = PolicyStore.memoryPolicyStore();
    const stored = Policy.permit({ id: "p1", action: Policy.eq(readDoc) });
    await run(store.createPolicy(stored));
    await run(store.createTemplate(shareTemplate));
    await run(store.createLink(link("l1", alice, doc1)));
    await run(store.createLink(link("l2", bob, doc2)));

    const policies = await run(PolicyStore.effectivePolicies(store));
    expect(policies.map((policy) => policy.id)).toEqual(["p1", "share-doc#l1", "share-doc#l2"]);
  });

  it("reflects template edits in every link (retroactive updates)", async () => {
    const store = PolicyStore.memoryPolicyStore();
    await run(store.createTemplate(shareTemplate));
    await run(store.createLink(link("l1", alice, doc1)));

    await run(store.updateTemplate({ ...shareTemplate, effect: "forbid" }));
    const policies = await run(PolicyStore.effectivePolicies(store));
    expect(policies.map((policy) => policy.effect)).toEqual(["forbid"]);
  });

  it("fails (naming the link) when a link's template is missing", async () => {
    const links = new Map<string, PolicyStore.TemplateLink>();
    const store = PolicyStore.memoryPolicyStore({ links });
    // A link that outlived its template (a store that skipped the cascade).
    links.set("l1", link("l1", alice, doc1));

    const failure = await run(Effect.flip(PolicyStore.effectivePolicies(store)));
    expect(failure._tag).toBe("AuthError");
    expect(failure.message).toContain('"l1"');
    expect(failure.message).toContain("share-doc");
  });

  it("fails (naming the link) when a link cannot be instantiated", async () => {
    const store = PolicyStore.memoryPolicyStore();
    await run(store.createTemplate(shareTemplate));
    await run(
      store.createLink(
        PolicyStore.makeLink({ id: "broken", templateId: "share-doc", principal: alice }),
      ),
    );

    const failure = await run(Effect.flip(PolicyStore.effectivePolicies(store)));
    expect(failure._tag).toBe("AuthError");
    expect(failure.message).toContain('"broken"');
    // Fail-closed: the broken link does not simply vanish from the policy set.
    expect(failure.message).toContain("?resource");
  });

  it("a broken forbid link takes the whole policy set down rather than vanishing", async () => {
    const store = PolicyStore.memoryPolicyStore();
    await run(store.createPolicy(Policy.permit({ id: "allow-all" })));
    await run(
      store.createTemplate(
        PolicyStore.template({
          id: "ban",
          effect: "forbid",
          principal: PolicyStore.eqSlot,
        }),
      ),
    );
    await run(store.createLink(PolicyStore.makeLink({ id: "ban-bob", templateId: "ban" })));

    const failure = await run(Effect.flip(PolicyStore.effectivePolicies(store)));
    expect(failure._tag).toBe("AuthError");
  });
});

describe("document format", () => {
  it("roundtrips a policy document through JSON", async () => {
    const policy = Policy.permit({
      id: "doc-owner-read",
      principal: Policy.isType("User"),
      action: Policy.eq(readDoc),
      resource: Policy.isType("Document"),
      when: Condition.eq(Condition.attr("resource", "owner"), Condition.principal),
      description: "Owners may read their documents",
    });
    const document = PolicyStore.policyDocument(policy);

    const encoded = await run(PolicyStore.encodePolicyDocument(document));
    const json = Schema.decodeUnknownSync(Json)(Schema.encodeSync(Json)(encoded));
    const decoded = await run(PolicyStore.decodePolicyDocument(json));

    expect(decoded).toEqual(document);
    expect(decoded.version).toBe(1);
  });

  it("roundtrips a template document through JSON, slots and all", async () => {
    const document = PolicyStore.templateDocument(shareTemplate);
    const encoded = await run(PolicyStore.encodeTemplateDocument(document));
    const json = Schema.decodeUnknownSync(Json)(Schema.encodeSync(Json)(encoded));
    const decoded = await run(PolicyStore.decodeTemplateDocument(json));
    expect(decoded).toEqual(document);
    expect(decoded.template.principal).toEqual(PolicyStore.eqSlot);
  });

  it("rejects an unknown version and a malformed body", async () => {
    const wrongVersion = await run(
      Effect.result(
        PolicyStore.decodePolicyDocument({
          version: 2,
          policy: Policy.permit({ id: "p" }),
        }),
      ),
    );
    expect(wrongVersion._tag).toBe("Failure");

    const malformed = await run(
      Effect.result(
        PolicyStore.decodeTemplateDocument({
          version: 1,
          template: {
            _tag: "PolicyTemplate",
            id: "t",
            effect: "permit",
            principal: { _tag: "eqSlot" },
            // Action slots do not exist: the action position takes a Scope only.
            action: { _tag: "eqSlot" },
            resource: { _tag: "any" },
          },
        }),
      ),
    );
    expect(malformed._tag).toBe("Failure");
  });
});

describe("template-linked sharing (integration)", () => {
  it("two links grant exactly two principals on exactly that document", async () => {
    const store = PolicyStore.memoryPolicyStore();
    await run(store.createTemplate(shareTemplate));
    await run(store.createLink(link("share-alice", alice, doc1)));
    await run(store.createLink(link("share-bob", bob, doc1)));

    const policies = await run(PolicyStore.effectivePolicies(store));
    const allows = (principal: Entity.EntityRef, resource: Entity.EntityRef) =>
      Policy.decidePure(policies, Policy.request({ principal, action: readDoc, resource })).allowed;

    expect(allows(alice, doc1)).toBe(true);
    expect(allows(bob, doc1)).toBe(true);
    // Not shared with carol, and the grant does not leak to another document.
    expect(allows(carol, doc1)).toBe(false);
    expect(allows(alice, doc2)).toBe(false);
    // Nor to another action.
    expect(
      Policy.decidePure(
        policies,
        Policy.request({
          principal: alice,
          action: Entity.ref("Action", "doc:delete"),
          resource: doc1,
        }),
      ).allowed,
    ).toBe(false);

    // Revoking one link revokes exactly that grant.
    await run(store.deleteLink("share-bob"));
    const after = await run(PolicyStore.effectivePolicies(store));
    expect(
      Policy.decidePure(after, Policy.request({ principal: bob, action: readDoc, resource: doc1 }))
        .allowed,
    ).toBe(false);
    expect(
      Policy.decidePure(
        after,
        Policy.request({ principal: alice, action: readDoc, resource: doc1 }),
      ).allowed,
    ).toBe(true);
  });
});

describe("validateTemplates", () => {
  const model = AuthorizationModel.make({
    entities: {
      User: {},
      Document: { memberOf: ["Folder"] },
      Folder: {},
    },
    actions: {
      "doc:read": { appliesTo: { principal: ["User"], resource: ["Document"] } },
    },
  });

  it("accepts a well-formed template: slots validate trivially", () => {
    expect(PolicyStore.validateTemplates(model, [shareTemplate])).toEqual([]);
  });

  it("flags undeclared entity types and actions, keyed by template id", () => {
    const bad = PolicyStore.template({
      id: "bad",
      principal: Policy.isType("Robot"),
      action: Policy.eq(Entity.ref("Action", "doc:teleport")),
      resource: PolicyStore.eqSlot,
      when: Condition.eq(Condition.principal, Condition.entityLit(Entity.ref("Ghost", "g1"))),
    });
    const issues = PolicyStore.validateTemplates(model, [bad]);
    expect(issues.map((issue) => issue.policyId)).toEqual(["bad", "bad", "bad"]);
    expect(issues.map((issue) => issue.message)).toEqual([
      expect.stringContaining("Robot"),
      expect.stringContaining("doc:teleport"),
      expect.stringContaining("Ghost"),
    ]);
  });

  it("does not constrain a slot against the action's appliesTo", () => {
    // A pinned wrong type is flagged...
    const pinned = PolicyStore.template({
      id: "pinned",
      principal: Policy.isType("Folder"),
      action: Policy.eq(readDoc),
    });
    expect(PolicyStore.validateTemplates(model, [pinned])).toHaveLength(1);

    // ...while the slot form carries no type to check yet.
    const slotted = PolicyStore.template({
      id: "slotted",
      principal: PolicyStore.eqSlot,
      action: Policy.eq(readDoc),
      resource: PolicyStore.eqSlot,
    });
    expect(PolicyStore.validateTemplates(model, [slotted])).toEqual([]);
  });
});
