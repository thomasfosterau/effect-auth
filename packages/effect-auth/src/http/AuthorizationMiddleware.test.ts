import { describe, it, expect } from "vite-plus/test";
import { Effect, Exit, Layer } from "effect";
import { HttpServerRequest, HttpServerResponse } from "effect/unstable/http";
import * as Entity from "../Entity.ts";
import * as Condition from "../Condition.ts";
import * as Errors from "../Errors.ts";
import * as Policy from "../Policy.ts";
import {
  Authorizer,
  CurrentPrincipal,
  EntityResolver,
  memoryEntityResolver,
} from "../Authorizer.ts";
import {
  makeAuthorizationMiddleware,
  type AuthorizationMiddlewareClass,
} from "./AuthorizationMiddleware.ts";
import * as S from "./HttpApiSchema.ts";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const alice = Entity.ref("User", "alice");
const bob = Entity.ref("User", "bob");
const doc1 = Entity.ref("Document", "doc-1");
const doc2 = Entity.ref("Document", "doc-2");
const readDoc = "doc:read";

// `alice` owns `doc-1`; `bob` owns `doc-2`. Read is permitted to the owner
// only, so the same policy set both allows and denies depending on which
// principal asks and which doc is named (the dynamic-input tests vary the
// latter per request).
const ownerPolicy = Policy.permit({
  id: "owner-can-read",
  action: Policy.eq(Entity.ref("Action", readDoc)),
  when: Condition.eq(Condition.attr("resource", "owner"), Condition.principal),
});

const resolver = memoryEntityResolver([
  Entity.entity(doc1, { attributes: { owner: Entity.entityValue(alice) } }),
  Entity.entity(doc2, { attributes: { owner: Entity.entityValue(bob) } }),
]);

const authorizerLayer = Authorizer.layer({ policies: [ownerPolicy] }).pipe(
  Layer.provide(Layer.succeed(EntityResolver)(resolver)),
);

const ok = HttpServerResponse.empty({ status: 200 });

const makeWebRequest = (headers: Record<string, string> = {}) =>
  HttpServerRequest.fromWeb(new Request("http://localhost/docs", { headers }));

/**
 * Run one `makeAuthorizationMiddleware(...)` instance's handler against a fixture
 * request, optionally with a `CurrentPrincipal` already resolved (as
 * `AuthMiddleware` would have provided it) and a custom `Authorizer.layer`.
 */
const runGate = (
  Guard: AuthorizationMiddlewareClass,
  options: {
    readonly principal?: Entity.EntityRef;
    readonly request?: HttpServerRequest.HttpServerRequest;
    readonly overrideAuthorizerLayer?: Layer.Layer<Authorizer, Errors.AuthError>;
  } = {},
): Effect.Effect<typeof ok, S.Forbidden | Errors.AuthError> => {
  const request = options.request ?? makeWebRequest();
  const program = Effect.gen(function* () {
    const svc = yield* Guard;
    // `HttpApiMiddleware.Service` types the wrapped handler against the whole
    // `HttpApi` surface, which this unit test deliberately does not build —
    // hence the `any` call. Re-annotating the result keeps what the middleware
    // still needs from context visible instead of letting `any` erase it.
    const applied: Effect.Effect<
      typeof ok,
      S.Forbidden,
      Authorizer | CurrentPrincipal | HttpServerRequest.HttpServerRequest
    > = (svc as any)(Effect.succeed(ok), undefined);
    return yield* applied.pipe(Effect.provideService(HttpServerRequest.HttpServerRequest, request));
  }).pipe(
    Effect.provide(Layer.mergeAll(Guard.layer, options.overrideAuthorizerLayer ?? authorizerLayer)),
  );

  // The no-principal case leaves `CurrentPrincipal` deliberately unprovided to
  // prove the gate fails closed rather than silently allowing; that is a
  // runtime defect, so the requirement is erased here — in one documented
  // place — rather than with a cast at every call site. Only the context is
  // erased; the error channel stays honest.
  return (
    options.principal !== undefined
      ? program.pipe(CurrentPrincipal.provide(options.principal))
      : program
  ) as Effect.Effect<typeof ok, S.Forbidden | Errors.AuthError>;
};

// ---------------------------------------------------------------------------
// Allow path
// ---------------------------------------------------------------------------

describe("makeAuthorizationMiddleware – allow path", () => {
  it("the resource owner is authorized and the handler runs unchanged", async () => {
    const Guard = makeAuthorizationMiddleware({ action: readDoc, resource: doc1 });
    const response = await Effect.runPromise(runGate(Guard, { principal: alice }));
    expect((response as HttpServerResponse.HttpServerResponse).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Deny path
// ---------------------------------------------------------------------------

describe("makeAuthorizationMiddleware – deny path", () => {
  it("a non-owner is refused with 403 Forbidden naming the decision reason (default-deny)", async () => {
    const Guard = makeAuthorizationMiddleware({ action: readDoc, resource: doc1 });
    const error = await Effect.runPromise(runGate(Guard, { principal: bob }).pipe(Effect.flip));
    expect(error._tag).toBe("Forbidden");
    expect(error.message).toContain("default-deny");
  });

  it("the wire error carries only message/code — never the policy trace (determining/outcomes)", async () => {
    const Guard = makeAuthorizationMiddleware({ action: readDoc, resource: doc1 });
    const error = await Effect.runPromise(runGate(Guard, { principal: bob }).pipe(Effect.flip));
    expect(error._tag).toBe("Forbidden");
    expect(typeof error.message).toBe("string");
    expect(error).not.toHaveProperty("decision");
    expect(error).not.toHaveProperty("determining");
    expect(error).not.toHaveProperty("outcomes");
  });

  it('an explicit forbid policy is reported with reason "forbid" (distinct from default-deny)', async () => {
    const forbidPolicy = Policy.forbid({
      id: "no-doc1",
      action: Policy.eq(Entity.ref("Action", readDoc)),
    });
    const layer = Authorizer.layer({ policies: [ownerPolicy, forbidPolicy] }).pipe(
      Layer.provide(Layer.succeed(EntityResolver)(resolver)),
    );
    const Guard = makeAuthorizationMiddleware({ action: readDoc, resource: doc1 });
    const error = await Effect.runPromise(
      runGate(Guard, { principal: alice, overrideAuthorizerLayer: layer }).pipe(Effect.flip),
    );
    expect(error._tag).toBe("Forbidden");
    expect(error.message).toContain("forbid");
    expect(error.code).toBe("forbid");
  });
});

// ---------------------------------------------------------------------------
// Composition: must run after CurrentPrincipal is established
// ---------------------------------------------------------------------------

describe("makeAuthorizationMiddleware – composition with AuthMiddleware", () => {
  it("without CurrentPrincipal in context (not composed after AuthMiddleware), the gate fails rather than silently allowing", async () => {
    const Guard = makeAuthorizationMiddleware({ action: readDoc, resource: doc1 });
    // No `CurrentPrincipal.provide(...)` anywhere in the pipeline — simulating
    // a route that attached this middleware without first resolving a
    // principal (e.g. forgot `AuthMiddleware`, or ran outside its scope).
    // `CurrentPrincipal` is a required `Context.Service` with no default, so
    // accessing it unprovided is a defect, not a typed `Forbidden` — either
    // way the request must not reach the handler.
    const exit = await Effect.runPromiseExit(runGate(Guard));
    expect(Exit.isFailure(exit)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Dynamic (per-request) AuthorizeInput
// ---------------------------------------------------------------------------

describe("makeAuthorizationMiddleware – dynamic AuthorizeInput", () => {
  // Resource named by an `x-doc-id` header — stands in for a path param a
  // real route would read via `HttpRouter.params`/`RouteContext`, which is
  // reachable the same way inside an effectful dynamic input (see the
  // "effectful" case below).
  const byHeader = makeAuthorizationMiddleware((request) => ({
    action: readDoc,
    resource: Entity.ref("Document", request.headers["x-doc-id"] ?? "doc-1"),
  }));

  it("sync function-of-request: the resource differs per request (allow)", async () => {
    const response = await Effect.runPromise(
      runGate(byHeader, {
        principal: alice,
        request: makeWebRequest({ "x-doc-id": "doc-1" }),
      }),
    );
    expect((response as HttpServerResponse.HttpServerResponse).status).toBe(200);
  });

  it("sync function-of-request: the resource differs per request (deny — alice does not own doc-2)", async () => {
    const error = await Effect.runPromise(
      runGate(byHeader, {
        principal: alice,
        request: makeWebRequest({ "x-doc-id": "doc-2" }),
      }).pipe(Effect.flip),
    );
    expect(error._tag).toBe("Forbidden");
  });

  it("effectful function-of-request (request) => Effect<AuthorizeInput>: allow and deny both resolve correctly", async () => {
    const byHeaderEffectful = makeAuthorizationMiddleware((request) =>
      Effect.succeed({
        action: readDoc,
        resource: Entity.ref("Document", request.headers["x-doc-id"] ?? "doc-1"),
      }),
    );

    const allowedResponse = await Effect.runPromise(
      runGate(byHeaderEffectful, {
        principal: bob,
        request: makeWebRequest({ "x-doc-id": "doc-2" }),
      }),
    );
    expect((allowedResponse as HttpServerResponse.HttpServerResponse).status).toBe(200);

    const deniedError = await Effect.runPromise(
      runGate(byHeaderEffectful, {
        principal: bob,
        request: makeWebRequest({ "x-doc-id": "doc-1" }),
      }).pipe(Effect.flip),
    );
    expect(deniedError._tag).toBe("Forbidden");
  });
});

// ---------------------------------------------------------------------------
// Distinct middleware instances do not collide
// ---------------------------------------------------------------------------

describe("makeAuthorizationMiddleware – instance isolation", () => {
  it("two instances guarding different resources are independent (no shared tag collision)", async () => {
    const GuardDoc1 = makeAuthorizationMiddleware({ action: readDoc, resource: doc1 });
    const GuardDoc2 = makeAuthorizationMiddleware({ action: readDoc, resource: doc2 });

    const aliceOnDoc1 = await Effect.runPromiseExit(runGate(GuardDoc1, { principal: alice }));
    const aliceOnDoc2 = await Effect.runPromiseExit(runGate(GuardDoc2, { principal: alice }));

    expect(Exit.isSuccess(aliceOnDoc1)).toBe(true);
    expect(Exit.isFailure(aliceOnDoc2)).toBe(true);
  });
});
