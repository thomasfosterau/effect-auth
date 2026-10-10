import { describe, expect, it } from "vite-plus/test";
import { Context, Effect, Exit, Logger, Option } from "effect";
import * as Condition from "./Condition.ts";
import * as AuthorizationModel from "./AuthorizationModel.ts";
import * as Authorizer from "./Authorizer.ts";
import * as Entity from "./Entity.ts";
import * as Guard from "./Guard.ts";
import * as Ladder from "./Ladder.ts";
import * as Policy from "./Policy.ts";
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
