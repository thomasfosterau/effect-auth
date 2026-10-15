import { describe, expect, it } from "vite-plus/test";
import { Context, Effect, Exit, Logger, Option, Result, Schema } from "effect";
import * as Condition from "./Condition.ts";
import * as AuthorizationModel from "./AuthorizationModel.ts";
import * as Authorizer from "./Authorizer.ts";
import * as Entity from "./Entity.ts";
import * as Guard from "./Guard.ts";
import * as Ladder from "./Ladder.ts";
import * as OwnedAccess from "./OwnedAccess.ts";
import * as Policy from "./Policy.ts";
import { protectedField } from "./Protected.ts";
import * as Rbac from "./Rbac.ts";
import * as System from "./System.ts";

interface AppUser {
  readonly id: string;
  readonly role: string;
}

class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
  "@test/System/CurrentViewer",
) {}

const Roles = Ladder.make(["user", "contributor", "moderator", "admin"]);
const Axes = Roles.axes({ corpusWrite: "contributor" });
const guards = Guard.make({ ladder: Roles, viewer: CurrentViewer });

const billing = System.ref("billing-cron");
const retry = System.ref("billing-retry");
const alice = Entity.ref("User", "alice");
const billingUser = Entity.ref("User", "billing-cron");
const systemAlice = System.ref("alice");
const invoice = Entity.ref("Invoice", "inv-1");
const refund = Entity.ref("Refund", "ref-1");

/** The grant under test: billing may charge invoices, and nothing else. */
const chargeInvoices = System.grant("billing-cron", {
  id: "billing-cron:charge-invoices",
  action: "invoice:charge",
  resource: Policy.isType("Invoice"),
});

/** The model a deployment declares. `System` is declared so the grants validate. */
const model = AuthorizationModel.make({
  entities: {
    User: {},
    System: System.declaration,
    Invoice: {},
    Refund: {},
  },
  actions: {
    "invoice:charge": { appliesTo: { principal: ["System"], resource: ["Invoice"] } },
    "invoice:void": { appliesTo: { principal: ["User"], resource: ["Invoice"] } },
    "refund:issue": { appliesTo: { principal: ["System", "User"], resource: ["Refund"] } },
  },
});

/** Decide `action` on `resource` as `principal`, under `policies`, with `resolved` entities. */
const checkAs = (
  principal: Entity.EntityRef,
  policies: ReadonlyArray<Policy.Policy>,
  action: string,
  resource: Entity.EntityRef,
  resolved: ReadonlyArray<Entity.Entity> = [],
  declared: AuthorizationModel.Model = model,
): Promise<boolean> =>
  Effect.runPromise(
    Effect.gen(function* () {
      const authorizer = yield* Authorizer.Authorizer;
      return yield* authorizer.check({ action, resource });
    }).pipe(
      Authorizer.CurrentPrincipal.provide(principal),
      Effect.provide(Authorizer.Authorizer.layer({ policies, model: declared })),
      Effect.provideService(Authorizer.EntityResolver, Authorizer.memoryEntityResolver(resolved)),
    ),
  );

/** Run `authorize` as `principal`, returning the failure (if any) for inspection. */
const authorizeAs = (
  principal: Entity.EntityRef,
  policies: ReadonlyArray<Policy.Policy>,
  action: string,
  resource: Entity.EntityRef,
) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const authorizer = yield* Authorizer.Authorizer;
      return yield* authorizer.authorize({ action, resource });
    }).pipe(
      Authorizer.CurrentPrincipal.provide(principal),
      Effect.provide(Authorizer.Authorizer.layer({ policies, model })),
      Effect.result,
    ),
  );

/** Collect every log record emitted while `effect` runs. */
const captureLogs = <A, E>(effect: Effect.Effect<A, E>) => {
  const records: Array<{ readonly level: string; readonly text: string }> = [];
  const collector = Logger.make((options) => {
    records.push({
      level: String(options.logLevel),
      text: JSON.stringify(options.message),
    });
  });
  return Effect.runPromise(effect.pipe(Effect.provide(Logger.layer([collector])))).then(
    () => records,
  );
};

/** The error tag of a failed exit, or `undefined`. */
const tagOf = (exit: Exit.Exit<unknown, unknown>): string | undefined =>
  Exit.isFailure(exit)
    ? Option.getOrUndefined(
        Option.map(Exit.findErrorOption(exit), (error) => (error as { _tag: string })._tag),
      )
    : undefined;

/** The principal the current execution holds. */
const currentPrincipal = Effect.gen(function* () {
  return yield* Authorizer.CurrentPrincipal;
});

describe("System.ref", () => {
  it("names the reserved System type, with the given name as its id", () => {
    expect(System.ref("billing-cron")).toEqual({ type: "System", id: "billing-cron" });
    expect(System.entityType).toBe("System");
  });

  it("tells system principals from user principals by type alone", () => {
    expect(System.isSystem(billing)).toBe(true);
    expect(System.isSystem(alice)).toBe(false);
  });

  it("refuses an empty or blank name", () => {
    expect(() => System.ref("")).toThrow(/non-empty name/);
    expect(() => System.ref("   ")).toThrow(/non-empty name/);
  });
});

describe("providing a system principal", () => {
  it("System.provide makes CurrentPrincipal the System entity, with no session or user", async () => {
    const principal = await Effect.runPromise(
      currentPrincipal.pipe(System.provide("billing-cron")),
    );
    expect(principal).toEqual(billing);
  });

  it("System.layer provides the same principal to a runtime", async () => {
    const principal = await Effect.runPromise(
      currentPrincipal.pipe(Effect.provide(System.layer("billing-cron"))),
    );
    expect(principal).toEqual(billing);
  });
});

describe("a system principal is denied by default", () => {
  it("with no policy naming it, it is allowed nothing", async () => {
    expect(await checkAs(billing, [], "invoice:charge", invoice)).toBe(false);
  });

  it("a denial names the system principal and the reason", async () => {
    const failure = await authorizeAs(billing, [], "invoice:charge", invoice);
    expect(failure._tag).toBe("Failure");
    if (failure._tag !== "Failure") return;
    expect(failure.failure._tag).toBe("AuthorizationDeniedError");
    if (failure.failure._tag !== "AuthorizationDeniedError") return;
    expect(failure.failure.message).toContain('System::"billing-cron"');
    expect(failure.failure.message).toContain("default-deny");
    expect(failure.failure.decision.determining).toEqual([]);
  });

  it("a user-scoped permit for every action does not reach it", async () => {
    const everythingForUsers = Policy.permit({
      id: "users-may-do-anything",
      principal: Policy.isType("User"),
    });
    expect(await checkAs(billing, [everythingForUsers], "invoice:charge", invoice)).toBe(false);
  });
});

describe("a system principal is allowed exactly what its grant names", () => {
  it("is allowed the granted action on the granted resource type", async () => {
    expect(await checkAs(billing, [chargeInvoices], "invoice:charge", invoice)).toBe(true);
  });

  it("is refused a different action on the same resource", async () => {
    expect(await checkAs(billing, [chargeInvoices], "invoice:void", invoice)).toBe(false);
  });

  it("is refused the granted action on a resource outside the grant's scope", async () => {
    expect(await checkAs(billing, [chargeInvoices], "invoice:charge", refund)).toBe(false);
  });

  it("another system principal is not covered by this grant", async () => {
    expect(await checkAs(retry, [chargeInvoices], "invoice:charge", invoice)).toBe(false);
  });

  it("a grant may carry a condition that must also hold on the request", async () => {
    const withMfa = System.grant("billing-cron", {
      id: "billing-cron:charge-with-mfa",
      action: "invoice:charge",
      resource: Policy.isType("Invoice"),
      when: Condition.eq(Condition.attr("context", "mfa"), Condition.lit(true)),
    });
    const checkWithContext = (context: Record<string, boolean>) =>
      Effect.runPromise(
        Effect.gen(function* () {
          const authorizer = yield* Authorizer.Authorizer;
          return yield* authorizer.check({ action: "invoice:charge", resource: invoice, context });
        }).pipe(
          Authorizer.CurrentPrincipal.provide(billing),
          Effect.provide(Authorizer.Authorizer.layer({ policies: [withMfa], model })),
        ),
      );
    expect(await checkWithContext({ mfa: true })).toBe(true);
    expect(await checkWithContext({ mfa: false })).toBe(false);
  });
});

describe("the principal types stay separate", () => {
  it("a user policy naming the same id does not grant the system principal", async () => {
    // `refund:issue` applies to both principal types, so the policy validates.
    const userPolicy = Policy.permit({
      id: "user-policy",
      principal: Policy.eq(billingUser),
      action: Policy.eq(Entity.ref("Action", "refund:issue")),
    });
    expect(await checkAs(billing, [userPolicy], "refund:issue", refund)).toBe(false);
    expect(await checkAs(billingUser, [userPolicy], "refund:issue", refund)).toBe(true);
  });

  it("a system policy does not grant a user with the same name", async () => {
    const systemGrantForAlice = System.grant("alice", {
      id: "alice-system-grant",
      action: "invoice:charge",
      resource: Policy.any,
    });
    expect(await checkAs(alice, [systemGrantForAlice], "invoice:charge", invoice)).toBe(false);
    expect(await checkAs(systemAlice, [systemGrantForAlice], "invoice:charge", invoice)).toBe(true);
  });

  it("a Guard rung policy does not match a system principal carrying a rung attribute", async () => {
    // The resolver gives the system entity a top-rung `role`. The policy is the
    // one `Guard` builds for users; it must not grant the system principal.
    const rungPolicies = guards.policies.roleAtLeast(Axes.corpusWrite);
    const systemWithRung = Entity.entity(billing, { attributes: { role: "admin" } });
    const userWithRung = Entity.entity(alice, { attributes: { role: "admin" } });
    expect(
      await checkAs(billing, rungPolicies, "role:corpusWrite", invoice, [systemWithRung]),
    ).toBe(false);
    expect(await checkAs(alice, rungPolicies, "role:corpusWrite", invoice, [userWithRung])).toBe(
      true,
    );
  });

  it("a Guard ownership policy does not treat a system principal as the owner", async () => {
    // A system principal named like the owning user is not that user.
    const ownerPolicies = guards.policies.ownerOrRole(Axes.corpusWrite);
    const ownedByAlice = Entity.entity(Entity.ref("Owned", "doc-1"), {
      attributes: { owner: Entity.entityValue(alice) },
    });
    const systemNamedAlice = Entity.entity(systemAlice, { attributes: { role: "user" } });
    const ownedModel = AuthorizationModel.make({
      entities: { User: {}, System: System.declaration, Owned: {} },
      actions: {},
    });
    expect(
      await checkAs(
        systemAlice,
        ownerPolicies,
        "owner-or-role:corpusWrite",
        ownedByAlice.ref,
        [ownedByAlice, systemNamedAlice],
        ownedModel,
      ),
    ).toBe(false);
    // Control: the owning user is the owner.
    const userNamedAlice = Entity.entity(alice, { attributes: { role: "user" } });
    expect(
      await checkAs(
        alice,
        ownerPolicies,
        "owner-or-role:corpusWrite",
        ownedByAlice.ref,
        [ownedByAlice, userNamedAlice],
        ownedModel,
      ),
    ).toBe(true);
  });

  it("Guard refuses System as a viewer's principal type", () => {
    expect(() =>
      Guard.make({ ladder: Roles, viewer: CurrentViewer, principalType: "System" }),
    ).toThrow(/reserved for system principals/);
  });
});

describe("grants validate against a model that declares System", () => {
  it("a grant validates when the model declares System", () => {
    expect(AuthorizationModel.validatePolicies(model, [chargeInvoices])).toEqual([]);
  });

  it("a grant fails validation when the model does not declare System", () => {
    const withoutSystem = AuthorizationModel.make({
      entities: { User: {}, Invoice: {} },
      actions: {
        "invoice:charge": { appliesTo: { principal: ["User"], resource: ["Invoice"] } },
      },
    });
    const issues = AuthorizationModel.validatePolicies(withoutSystem, [chargeInvoices]);
    expect(issues.map((issue) => issue.policyId)).toContain("billing-cron:charge-invoices");
  });
});

describe("a runtime providing no principal is refused", () => {
  it("a rung gate with no viewer and no system principal fails Unauthorized", () => {
    const exit = Effect.runSyncExit(
      guards
        .requireRoleAtLeast(Axes.corpusWrite)
        .pipe(Effect.provideService(CurrentViewer, Option.none())),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(tagOf(exit)).toBe("Unauthorized");
  });
});

describe("decisions about a system principal are audited by name", () => {
  it("an allow is logged at info with the principal, the action and the granting policy", async () => {
    const records = await captureLogs(
      Effect.gen(function* () {
        const authorizer = yield* Authorizer.Authorizer;
        return yield* authorizer.check({ action: "invoice:charge", resource: invoice });
      }).pipe(
        Authorizer.CurrentPrincipal.provide(billing),
        Effect.provide(Authorizer.Authorizer.layer({ policies: [chargeInvoices], model })),
      ),
    );
    const decision = records.find((record) => record.text.includes("authorization.decision"));
    expect(decision?.level).toBe("Info");
    expect(decision?.text).toContain('System::\\"billing-cron\\"');
    expect(decision?.text).toContain("billing-cron:charge-invoices");
    expect(decision?.text).toContain('"allowed":true');
  });

  it("a denial is logged at warning with the principal and the default-deny reason", async () => {
    const records = await captureLogs(
      Effect.gen(function* () {
        const authorizer = yield* Authorizer.Authorizer;
        return yield* authorizer.check({ action: "invoice:charge", resource: invoice });
      }).pipe(
        Authorizer.CurrentPrincipal.provide(billing),
        Effect.provide(Authorizer.Authorizer.layer({ policies: [], model })),
      ),
    );
    const decision = records.find((record) => record.text.includes("authorization.decision"));
    expect(decision?.level).toBe("Warn");
    expect(decision?.text).toContain('System::\\"billing-cron\\"');
    expect(decision?.text).toContain("default-deny");
  });

  it("a human's decision is not logged by this module", async () => {
    const records = await captureLogs(
      Effect.gen(function* () {
        const authorizer = yield* Authorizer.Authorizer;
        return yield* authorizer.check({ action: "invoice:void", resource: invoice });
      }).pipe(
        Authorizer.CurrentPrincipal.provide(alice),
        Effect.provide(Authorizer.Authorizer.layer({ policies: [], model })),
      ),
    );
    expect(records.some((record) => record.text.includes("authorization.decision"))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Default deny under every library-shipped policy set and helper default (#377)
// ---------------------------------------------------------------------------

/** Every action a probe asks about: reads, writes, and one no policy mentions. */
const everyAction = ["read", "update", "delete", "invoice:charge", "owned:purge"] as const;

/**
 * Decide `action` on `resource` as `principal` under `policies`, with no model
 * (library policy sets name attributes and types a test model need not
 * declare) and `resolved` as the entity graph.
 */
const decideAs = (
  principal: Entity.EntityRef,
  policies: ReadonlyArray<Policy.Policy>,
  action: string,
  resource: Entity.EntityRef,
  resolved: ReadonlyArray<Entity.Entity> = [],
  context: Readonly<Record<string, Entity.AttributeValue>> = {},
): Promise<boolean> =>
  Effect.runPromise(
    Effect.gen(function* () {
      const authorizer = yield* Authorizer.Authorizer;
      return yield* authorizer.check({ action, resource, context });
    }).pipe(
      Authorizer.CurrentPrincipal.provide(principal),
      Effect.provide(Authorizer.Authorizer.layer({ policies })),
      Effect.provideService(Authorizer.EntityResolver, Authorizer.memoryEntityResolver(resolved)),
    ),
  );

/** The actions in {@link everyAction} that `principal` is allowed on `resource`. */
const allowedActions = async (
  principal: Entity.EntityRef,
  policies: ReadonlyArray<Policy.Policy>,
  resource: Entity.EntityRef,
  resolved: ReadonlyArray<Entity.Entity> = [],
  context: Readonly<Record<string, Entity.AttributeValue>> = {},
): Promise<ReadonlyArray<string>> => {
  const allowed: string[] = [];
  for (const action of everyAction) {
    if (await decideAs(principal, policies, action, resource, resolved, context)) {
      allowed.push(action);
    }
  }
  return allowed;
};

/** The system principal as the resolver sees it: a top rung, so rung conditions would hold. */
const billingAsAdmin = Entity.entity(billing, { attributes: { role: "admin" } });
const aliceAsAdmin = Entity.entity(alice, { attributes: { role: "admin" } });

describe("a system principal is denied under every library policy set with no grant (#377)", () => {
  const owned = OwnedAccess.make({ guards, viewPrivate: Axes.corpusWrite });

  /** An owned row with the given visibility, owned by `owner`. */
  const ownedRow = (
    id: string,
    owner: Entity.EntityRef,
    visibility: OwnedAccess.Visibility,
    draft = false,
  ) =>
    Entity.entity(Entity.ref("Owned", id), {
      attributes: { owner: Entity.entityValue(owner), visibility, draft },
    });

  it("OwnedAccess.policies: no action on a public, followers, private or draft row", async () => {
    // Every arm's condition holds for the system principal: the row is public,
    // it is the owner, it holds the viewPrivate rung, and it follows the owner.
    for (const [visibility, draft] of [
      ["public", false],
      ["followers", false],
      ["private", false],
      ["public", true],
    ] as const) {
      const ownedBySystem = ownedRow("by-system", billing, visibility, draft);
      expect(
        await allowedActions(
          billing,
          owned.policies,
          ownedBySystem.ref,
          [ownedBySystem, billingAsAdmin],
          { follows: true },
        ),
      ).toEqual([]);
    }
  });

  it("OwnedAccess.policies: a user's decisions are unchanged", async () => {
    const publicRow = ownedRow("public", Entity.ref("User", "carol"), "public");
    const privateRow = ownedRow("private", Entity.ref("User", "carol"), "private");
    const bob = Entity.entity(Entity.ref("User", "bob"), { attributes: { role: "user" } });
    // `owned:public` is action-agnostic for users, as before.
    expect(await allowedActions(bob.ref, owned.policies, publicRow.ref, [publicRow, bob])).toEqual(
      everyAction,
    );
    expect(
      await allowedActions(bob.ref, owned.policies, privateRow.ref, [privateRow, bob]),
    ).toEqual([]);
    expect(
      await allowedActions(alice, owned.policies, privateRow.ref, [privateRow, aliceAsAdmin]),
    ).toEqual(everyAction);
  });

  it("Guard policies: neither the rung nor the owner policy reaches it", async () => {
    const ownedBySystem = ownedRow("by-system", billing, "private");
    const guardPolicies = [
      ...guards.policies.roleAtLeast("user"),
      ...guards.policies.ownerOrRole("user"),
    ];
    expect(
      await allowedActions(billing, guardPolicies, ownedBySystem.ref, [
        ownedBySystem,
        billingAsAdmin,
      ]),
    ).toEqual([]);
    expect(
      await allowedActions(alice, guardPolicies, ownedBySystem.ref, [ownedBySystem, aliceAsAdmin]),
    ).toEqual(everyAction);
  });

  it("Rbac: a role permit never reaches it, even when a resolver gives it the role", async () => {
    const config = {
      userRoles: { alice: ["admin"] },
      rolePermissions: { admin: [{ resource: "*", action: "*" }] },
    };
    const policies = Rbac.policies(config);
    // An application resolver that (wrongly) makes the system principal an admin.
    const systemAdmin = Entity.entity(billing, { parents: [Rbac.roleRef("admin")] });
    const resolved = [...Rbac.entities(config), systemAdmin];
    expect(await allowedActions(billing, policies, invoice, resolved)).toEqual([]);
    expect(await allowedActions(alice, policies, invoice, resolved)).toEqual(everyAction);
  });

  it("Rbac refuses System as the principal type", () => {
    const config = {
      userRoles: { "billing-cron": ["admin"] },
      rolePermissions: { admin: [{ resource: "*", action: "*" }] },
      principalType: "System",
    };
    expect(() => Rbac.entities(config)).toThrow(/reserved for system principals/);
    expect(() => Rbac.model(config)).toThrow(/reserved for system principals/);
    expect(() => Rbac.layer(config)).toThrow(/reserved for system principals/);
  });

  it('Policy.permission({ action: "*", resource: "*" }) is not an allow-all for it', async () => {
    const everything = [Policy.permission({ action: "*", resource: "*" })];
    expect(await allowedActions(billing, everything, invoice)).toEqual([]);
    expect(await allowedActions(alice, everything, invoice)).toEqual(everyAction);
  });

  it("Policy.action's default principal scope does not reach it", async () => {
    const charge = [Policy.action("invoice:charge")];
    expect(await allowedActions(billing, charge, invoice)).toEqual([]);
    expect(await allowedActions(alice, charge, invoice)).toEqual(["invoice:charge"]);
  });

  it("Policy.roleAtLeast's default principal scope does not reach it, whatever its role", async () => {
    const ladder = [Policy.roleAtLeast(Roles, "user")];
    expect(await allowedActions(billing, ladder, invoice, [billingAsAdmin])).toEqual([]);
    expect(await allowedActions(alice, ladder, invoice, [aliceAsAdmin])).toEqual(everyAction);
  });

  it("a bare Policy.permit and a Policy.custom permit do not reach it", async () => {
    const bare = [Policy.permit({ id: "everything" })];
    const custom = [
      Policy.custom({ id: "always", predicate: () => Effect.succeed(true) }) as Policy.Policy,
    ];
    expect(await allowedActions(billing, bare, invoice)).toEqual([]);
    expect(await allowedActions(billing, custom, invoice)).toEqual([]);
    expect(await allowedActions(alice, bare, invoice)).toEqual(everyAction);
    expect(await allowedActions(alice, custom, invoice)).toEqual(everyAction);
  });

  it("protectedField: an unscoped policy neither shows nor accepts the field", async () => {
    const View = Schema.Struct({
      id: Schema.String,
      secret: protectedField(Schema.String, {
        policies: Policy.permission({ action: "*", resource: "*" }),
        action: "account:read-secret",
        resource: invoice,
      }),
    });
    const value = { id: "a-1", secret: "s3cret" };
    const as = <A, E>(
      effect: Effect.Effect<A, E, Authorizer.CurrentPrincipal>,
      who: Entity.EntityRef,
    ) => Effect.runPromise(effect.pipe(Authorizer.CurrentPrincipal.provide(who)));
    expect(await as(Schema.encodeEffect(View)(value), billing)).toEqual({ id: "a-1" });
    const refused = await as(Effect.result(Schema.decodeUnknownEffect(View)(value)), billing);
    expect(Result.isFailure(refused)).toBe(true);
    expect(await as(Schema.encodeEffect(View)(value), alice)).toEqual(value);
  });
});

describe("with an explicit grant, a system principal gets exactly that (#377)", () => {
  const owned = OwnedAccess.make({ guards, viewPrivate: Axes.corpusWrite });
  const row = Entity.entity(Entity.ref("Owned", "row-1"), {
    attributes: { owner: Entity.entityValue(billing), visibility: "public", draft: false },
  });
  const purge = System.grant("billing-cron", {
    id: "billing-cron:purge-owned",
    action: "owned:purge",
    resource: Policy.isType("Owned"),
  });

  it("beside every library policy set, only the granted action is allowed", async () => {
    const policies = [
      ...owned.policies,
      ...guards.policies.ownerOrRole("user"),
      ...Rbac.policies({
        userRoles: {},
        rolePermissions: { admin: [{ resource: "*", action: "*" }] },
      }),
      Policy.permission({ action: "*", resource: "*" }),
      Policy.action("delete"),
      Policy.roleAtLeast(Roles, "user"),
      purge,
    ];
    const resolved = [
      row,
      Entity.entity(billing, { attributes: { role: "admin" }, parents: [Rbac.roleRef("admin")] }),
    ];
    expect(await allowedActions(billing, policies, row.ref, resolved, { follows: true })).toEqual([
      "owned:purge",
    ]);
    // Another system principal gets nothing from billing's grant.
    expect(await allowedActions(retry, policies, row.ref, [row])).toEqual([]);
  });

  it("a permit scoped to the System type, or to a group of system principals, reaches it", async () => {
    const anyJob = Policy.permit({
      id: "jobs:read",
      principal: Policy.isType(System.entityType),
      action: Policy.eq(Entity.ref("Action", "read")),
    });
    const jobs = Entity.ref(System.entityType, "jobs");
    const groupJobs = Policy.permit({
      id: "jobs-group:update",
      principal: Policy.inScope(jobs),
      action: Policy.eq(Entity.ref("Action", "update")),
    });
    const inGroup = Entity.entity(billing, { parents: [jobs] });
    expect(await allowedActions(billing, [anyJob, groupJobs], invoice, [inGroup])).toEqual([
      "read",
      "update",
    ]);
    expect(await allowedActions(retry, [anyJob, groupJobs], invoice)).toEqual(["read"]);
    expect(await allowedActions(alice, [anyJob, groupJobs], invoice)).toEqual([]);
  });

  it("an unscoped forbid still binds it, declarative or custom", async () => {
    const charge = [chargeInvoices];
    expect(await decideAs(billing, charge, "invoice:charge", invoice)).toBe(true);
    const freeze = Policy.forbid({
      id: "freeze",
      action: Policy.eq(Entity.ref("Action", "invoice:charge")),
    });
    expect(await decideAs(billing, [...charge, freeze], "invoice:charge", invoice)).toBe(false);
    const customFreeze = Policy.custom({
      id: "custom-freeze",
      effect: "forbid",
      predicate: () => Effect.succeed(true),
    }) as Policy.Policy;
    expect(await decideAs(billing, [...charge, customFreeze], "invoice:charge", invoice)).toBe(
      false,
    );
  });

  it("protectedField: a grant for the field's action shows and accepts it", async () => {
    const View = Schema.Struct({
      id: Schema.String,
      secret: protectedField(Schema.String, {
        policies: [
          Policy.permission({ action: "*", resource: "*" }),
          System.grant("billing-cron", {
            id: "billing-cron:read-secret",
            action: "account:read-secret",
            resource: Policy.isType("Invoice"),
          }),
        ],
        action: "account:read-secret",
        resource: invoice,
      }),
    });
    const value = { id: "a-1", secret: "s3cret" };
    const as = <A, E>(
      effect: Effect.Effect<A, E, Authorizer.CurrentPrincipal>,
      who: Entity.EntityRef,
    ) => Effect.runPromise(effect.pipe(Authorizer.CurrentPrincipal.provide(who)));
    expect(await as(Schema.encodeEffect(View)(value), billing)).toEqual(value);
    expect(await as(Schema.decodeUnknownEffect(View)(value), billing)).toEqual(value);
    expect(await as(Schema.encodeEffect(View)(value), retry)).toEqual({ id: "a-1" });
  });
});

describe("protectedField decisions about a system principal are audited by name (#377)", () => {
  const field = (policies: ReadonlyArray<Policy.Policy>) =>
    Schema.Struct({
      secret: protectedField(Schema.String, {
        policies,
        action: "invoice:charge",
        resource: invoice,
      }),
    });

  const encodeLogged = (policies: ReadonlyArray<Policy.Policy>, who: Entity.EntityRef) =>
    captureLogs(
      Schema.encodeEffect(field(policies))({ secret: "s" }).pipe(
        Authorizer.CurrentPrincipal.provide(who),
      ),
    );

  it("an allow is logged at info with the granting policy", async () => {
    const records = await encodeLogged([chargeInvoices], billing);
    const decision = records.find((record) => record.text.includes("authorization.decision"));
    expect(decision?.level).toBe("Info");
    expect(decision?.text).toContain('System::\\"billing-cron\\"');
    expect(decision?.text).toContain("billing-cron:charge-invoices");
  });

  it("a denial is logged at warning", async () => {
    const records = await encodeLogged(
      [Policy.permission({ action: "*", resource: "*" })],
      billing,
    );
    const decision = records.find((record) => record.text.includes("authorization.decision"));
    expect(decision?.level).toBe("Warn");
    expect(decision?.text).toContain("default-deny");
  });

  it("a resolver failure denies and is logged at warning", async () => {
    const records = await captureLogs(
      Schema.encodeEffect(field([chargeInvoices]))({ secret: "s" }).pipe(
        Authorizer.CurrentPrincipal.provide(billing),
        Effect.provideService(Authorizer.EntityResolver, {
          resolve: () => Effect.fail(new Authorizer.PolicyValidationError({ message: "down" })),
        }),
      ),
    );
    const decision = records.find((record) => record.text.includes("authorization.decision"));
    expect(decision?.level).toBe("Warn");
    expect(decision?.text).toContain("resolver-error");
  });

  it("a human's field decision is not logged", async () => {
    const records = await encodeLogged([chargeInvoices], alice);
    expect(records.some((record) => record.text.includes("authorization.decision"))).toBe(false);
  });
});
