import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer, Result, Schema } from "effect";
import * as Entity from "./Entity.ts";
import * as Policy from "./Policy.ts";
import { CurrentPrincipal, EntityResolver, memoryEntityResolver } from "./Authorizer.ts";
import { protectedField } from "./Protected.ts";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const alice = Entity.ref("User", "alice"); // in Role::"admin"
const bob = Entity.ref("User", "bob"); // no roles

/** Alice is an admin; Bob is not in the hierarchy at all. */
const resolverLayer = Layer.succeed(
  EntityResolver,
  memoryEntityResolver([Entity.entity(alice, { parents: [Entity.ref("Role", "admin")] })]),
);

const adminReadsEmail = Policy.role("admin", {
  action: Policy.eq(Entity.ref("Action", "user:read-email")),
});

const UserView = Schema.Struct({
  id: Schema.String,
  email: protectedField(Schema.String, {
    policies: adminReadsEmail,
    action: "user:read-email",
  }),
});

const withPrincipal = <A, E, R>(effect: Effect.Effect<A, E, R>, principal: Entity.EntityRef) =>
  effect.pipe(CurrentPrincipal.provide(principal), Effect.provide(resolverLayer));

const encodeAs = (principal: Entity.EntityRef, value: typeof UserView.Type) =>
  Effect.runPromise(withPrincipal(Schema.encodeEffect(UserView)(value), principal));

const decodeAs = (principal: Entity.EntityRef, input: unknown) =>
  Effect.runPromise(
    Effect.result(withPrincipal(Schema.decodeUnknownEffect(UserView)(input), principal)),
  );

// ---------------------------------------------------------------------------
// Viewer projection (encode)
// ---------------------------------------------------------------------------

describe("protectedField – viewer projection on encode", () => {
  it("keeps the field for a privileged principal", async () => {
    expect(await encodeAs(alice, { id: "u-1", email: "alice@example.com" })).toEqual({
      id: "u-1",
      email: "alice@example.com",
    });
  });

  it("drops the key entirely for a non-privileged principal", async () => {
    const encoded = await encodeAs(bob, { id: "u-1", email: "alice@example.com" });
    expect(encoded).toEqual({ id: "u-1" });
    // Redaction removes the key rather than yielding `undefined`.
    expect("email" in encoded).toBe(false);
  });

  it("an absent value is untouched for everyone", async () => {
    expect(await encodeAs(alice, { id: "u-1" })).toEqual({ id: "u-1" });
    expect(await encodeAs(bob, { id: "u-1" })).toEqual({ id: "u-1" });
  });
});

// ---------------------------------------------------------------------------
// Write-side guard (decode)
// ---------------------------------------------------------------------------

describe("protectedField – write-side guard on decode", () => {
  it("fails with a schema error when a non-privileged principal supplies the field", async () => {
    const result = await decodeAs(bob, { id: "u-1", email: "bob@example.com" });
    expect(result._tag).toBe("Failure");
  });

  it("the failure names the principal, action and resource", async () => {
    const exit = await Effect.runPromiseExit(
      withPrincipal(
        Schema.decodeUnknownEffect(UserView)({ id: "u-1", email: "bob@example.com" }),
        bob,
      ),
    );
    const rendered = JSON.stringify(exit);
    expect(rendered).toContain("Authorization denied");
    expect(rendered).toContain('User::\\"bob\\"');
    expect(rendered).toContain('Action::\\"user:read-email\\"');
  });

  it("succeeds and passes the value through for a privileged principal", async () => {
    const result = await decodeAs(alice, { id: "u-1", email: "alice@example.com" });
    expect(result._tag).toBe("Success");
    expect(Result.getOrUndefined(result)).toEqual({ id: "u-1", email: "alice@example.com" });
  });

  it("an absent field decodes fine for everyone", async () => {
    for (const principal of [alice, bob]) {
      const result = await decodeAs(principal, { id: "u-1" });
      expect(result._tag).toBe("Success");
      expect(Result.getOrUndefined(result)).toEqual({ id: "u-1" });
    }
  });
});

// ---------------------------------------------------------------------------
// onDecodeDeny: "redact"
// ---------------------------------------------------------------------------

describe("protectedField – redact-on-decode", () => {
  const Patch = Schema.Struct({
    id: Schema.String,
    banned: protectedField(Schema.Boolean, {
      policies: adminReadsEmail,
      action: "user:read-email",
      onDecodeDeny: "redact",
    }),
  });

  it("ignores a value the principal may not set instead of failing", async () => {
    const decoded = await Effect.runPromise(
      withPrincipal(Schema.decodeUnknownEffect(Patch)({ id: "u-1", banned: true }), bob),
    );
    expect(decoded).toEqual({ id: "u-1" });
    expect("banned" in decoded).toBe(false);
  });

  it("still passes the value through for a privileged principal", async () => {
    const decoded = await Effect.runPromise(
      withPrincipal(Schema.decodeUnknownEffect(Patch)({ id: "u-1", banned: true }), alice),
    );
    expect(decoded).toEqual({ id: "u-1", banned: true });
  });
});

// ---------------------------------------------------------------------------
// onEncodeDeny: "fail"
// ---------------------------------------------------------------------------

describe("protectedField – fail-on-encode", () => {
  const Strict = Schema.Struct({
    secret: protectedField(Schema.String, {
      policies: adminReadsEmail,
      action: "user:read-email",
      onEncodeDeny: "fail",
    }),
  });

  it("rejects the encode rather than hiding the field", async () => {
    const denied = await Effect.runPromise(
      Effect.result(withPrincipal(Schema.encodeEffect(Strict)({ secret: "s" }), bob)),
    );
    expect(denied._tag).toBe("Failure");
    const allowed = await Effect.runPromise(
      withPrincipal(Schema.encodeEffect(Strict)({ secret: "s" }), alice),
    );
    expect(allowed).toEqual({ secret: "s" });
  });
});

// ---------------------------------------------------------------------------
// Custom policies and defaults
// ---------------------------------------------------------------------------

describe("protectedField – custom policies", () => {
  const seenRequests: Policy.PolicyRequest[] = [];
  const onlySelf = Policy.custom({
    id: "custom:self-only",
    predicate: (request) => {
      seenRequests.push(request);
      return Effect.succeed(Entity.refEquals(request.principal, request.resource));
    },
  });

  // No `resource`: it defaults to the principal's own ref (self-referential).
  const SelfView = Schema.Struct({
    email: protectedField(Schema.String, { policies: onlySelf, action: "user:read-email" }),
  });

  it("a custom policy works in the same position, over the principal's own ref", async () => {
    const encoded = await Effect.runPromise(
      withPrincipal(Schema.encodeEffect(SelfView)({ email: "a@b" }), alice),
    );
    expect(encoded).toEqual({ email: "a@b" });
    // The request the custom predicate saw defaults resource === principal.
    const last = seenRequests.at(-1)!;
    expect(last.principal).toEqual(alice);
    expect(last.resource).toEqual(alice);
    expect(last.action).toEqual(Entity.ref("Action", "user:read-email"));
  });

  it("denies when the custom predicate says no", async () => {
    const OtherView = Schema.Struct({
      email: protectedField(Schema.String, {
        policies: onlySelf,
        action: "user:read-email",
        resource: bob,
      }),
    });
    expect(
      await Effect.runPromise(
        withPrincipal(Schema.encodeEffect(OtherView)({ email: "a@b" }), alice),
      ),
    ).toEqual({});
  });

  it("mixes declarative and custom policies in one field", async () => {
    const Mixed = Schema.Struct({
      email: protectedField(Schema.String, {
        policies: [adminReadsEmail, Policy.forbid({ id: "kill-switch" })],
        action: "user:read-email",
      }),
    });
    // The forbid overrides the admin permit even for alice.
    expect(
      await Effect.runPromise(withPrincipal(Schema.encodeEffect(Mixed)({ email: "a@b" }), alice)),
    ).toEqual({});
  });
});

describe("protectedField – context and resolver-free operation", () => {
  it("passes `context` through to declarative conditions", async () => {
    const Gated = Schema.Struct({
      email: protectedField(Schema.String, {
        policies: Policy.custom({
          id: "ctx",
          predicate: (request) => Effect.succeed(request.context["mfa"] === true),
        }),
        action: "user:read-email",
        context: { mfa: true },
      }),
    });
    expect(
      await Effect.runPromise(withPrincipal(Schema.encodeEffect(Gated)({ email: "a@b" }), bob)),
    ).toEqual({ email: "a@b" });
  });

  it("works with no EntityResolver in context (empty slice, still fail-closed)", async () => {
    // Without a resolver alice is not `in Role::"admin"`, so the permit cannot match.
    const encoded = await Effect.runPromise(
      Schema.encodeEffect(UserView)({ id: "u-1", email: "a@b" }).pipe(
        CurrentPrincipal.provide(alice),
      ),
    );
    expect(encoded).toEqual({ id: "u-1" });
  });
});

// ---------------------------------------------------------------------------
// Requirements channel
// ---------------------------------------------------------------------------

describe("protectedField – requirements channel", () => {
  it("surfaces CurrentPrincipal in the struct's decoding/encoding services", () => {
    type Assert<A extends true> = A;
    type DecodingIsPrincipal = Assert<
      [typeof UserView.DecodingServices] extends [CurrentPrincipal] ? true : false
    >;
    type PrincipalIsDecoding = Assert<
      [CurrentPrincipal] extends [typeof UserView.DecodingServices] ? true : false
    >;
    type EncodingIsPrincipal = Assert<
      [typeof UserView.EncodingServices] extends [CurrentPrincipal] ? true : false
    >;
    type DecodeEffectServices = Effect.Services<
      ReturnType<ReturnType<typeof Schema.decodeUnknownEffect<typeof UserView>>>
    >;
    type DecodeRequiresPrincipal = Assert<
      [DecodeEffectServices] extends [CurrentPrincipal] ? true : false
    >;
    const _typeChecks: [
      DecodingIsPrincipal,
      PrincipalIsDecoding,
      EncodingIsPrincipal,
      DecodeRequiresPrincipal,
    ] = [true, true, true, true];
    expect(_typeChecks).toEqual([true, true, true, true]);
  });

  it("accepts the principal via Effect.provideService as well", async () => {
    const encoded = await Effect.runPromise(
      Schema.encodeEffect(UserView)({ id: "u-1", email: "a@b" }).pipe(
        Effect.provideService(CurrentPrincipal, alice),
        Effect.provide(resolverLayer),
      ),
    );
    expect(encoded).toEqual({ id: "u-1", email: "a@b" });
  });
});
