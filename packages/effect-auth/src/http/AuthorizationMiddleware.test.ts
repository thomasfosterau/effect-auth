import { describe, it, expect } from "vite-plus/test";
import { Cause, Effect, Exit, FileSystem, Layer, Path, Schema } from "effect";
import { Etag, HttpPlatform, HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/http";
import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "effect/http-api";
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
import { AuthMiddleware } from "./HttpMiddleware.ts";

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
const runGate = <Id extends string>(
  Guard: AuthorizationMiddlewareClass<never, Id>,
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
    const Guard = makeAuthorizationMiddleware("Guard", { action: readDoc, resource: doc1 });
    const response = await Effect.runPromise(runGate(Guard, { principal: alice }));
    expect((response as HttpServerResponse.HttpServerResponse).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Deny path
// ---------------------------------------------------------------------------

describe("makeAuthorizationMiddleware – deny path", () => {
  it("a non-owner is refused with 403 Forbidden naming the decision reason (default-deny)", async () => {
    const Guard = makeAuthorizationMiddleware("Guard", { action: readDoc, resource: doc1 });
    const error = await Effect.runPromise(runGate(Guard, { principal: bob }).pipe(Effect.flip));
    expect(error._tag).toBe("Forbidden");
    expect(error.message).toContain("default-deny");
  });

  it("the wire error carries only message/code — never the policy trace (determining/outcomes)", async () => {
    const Guard = makeAuthorizationMiddleware("Guard", { action: readDoc, resource: doc1 });
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
    const Guard = makeAuthorizationMiddleware("Guard", { action: readDoc, resource: doc1 });
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
    const Guard = makeAuthorizationMiddleware("Guard", { action: readDoc, resource: doc1 });
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
  const byHeader = makeAuthorizationMiddleware("byHeader", (request) => ({
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
    const byHeaderEffectful = makeAuthorizationMiddleware("byHeaderEffectful", (request) =>
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
    const GuardDoc1 = makeAuthorizationMiddleware("GuardDoc1", { action: readDoc, resource: doc1 });
    const GuardDoc2 = makeAuthorizationMiddleware("GuardDoc2", { action: readDoc, resource: doc2 });

    const aliceOnDoc1 = await Effect.runPromiseExit(runGate(GuardDoc1, { principal: alice }));
    const aliceOnDoc2 = await Effect.runPromiseExit(runGate(GuardDoc2, { principal: alice }));

    expect(Exit.isSuccess(aliceOnDoc1)).toBe(true);
    expect(Exit.isFailure(aliceOnDoc2)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Attaching to an HttpApi (#313)
// ---------------------------------------------------------------------------

// Both forms must attach with `.middleware(...)`: a fixed input and a
// per-request one that reads `HttpRouter.params`. Before the factory's return
// type named the instance, `.middleware` rejected either with TS2345.
const RequireDocRead = makeAuthorizationMiddleware("RequireDocRead", {
  action: readDoc,
  resource: doc1,
});
const RequireDocReadByParam = makeAuthorizationMiddleware("RequireDocReadByParam", (_request) =>
  Effect.gen(function* () {
    const params = yield* HttpRouter.params;
    return { action: readDoc, resource: Entity.ref("Document", params["docId"] ?? "doc-1") };
  }),
);

describe("makeAuthorizationMiddleware – attaching to an endpoint", () => {
  it("the fixed and per-request forms attach to an endpoint and a group", () => {
    const fixed = HttpApiEndpoint.get("getDoc", "/docs/:docId", {})
      .middleware(AuthMiddleware)
      .middleware(RequireDocRead);
    const perRequest = HttpApiEndpoint.get("getDoc", "/docs/:docId", {})
      .middleware(AuthMiddleware)
      .middleware(RequireDocReadByParam);
    const group = HttpApiGroup.make("docs").middleware(RequireDocRead).add(fixed);

    expect(fixed.middlewares.has(RequireDocRead)).toBe(true);
    expect(perRequest.middlewares.has(RequireDocReadByParam)).toBe(true);
    expect(Object.keys(group.endpoints)).toEqual(["getDoc"]);
  });
});

describe("makeAuthorizationMiddleware – served through an HttpApi", () => {
  const DocsApi = HttpApi.make("docs").add(
    HttpApiGroup.make("docs").add(
      HttpApiEndpoint.get("getDoc", "/docs/:docId", { success: Schema.String }).middleware(
        RequireDocReadByParam,
      ),
    ),
  );

  // The principal is fixed by the test layer and stands in for `AuthMiddleware`
  // (its own composition is covered in `HttpMiddleware.test.ts`).
  const serveDocs = (principal: Entity.EntityRef) => {
    const platform = Layer.mergeAll(
      Path.layer,
      Etag.layerWeak,
      HttpPlatform.layer.pipe(Layer.provide(FileSystem.layerNoop({}))),
      FileSystem.layerNoop({}),
    );
    const docsGroup = HttpApiBuilder.group(DocsApi, "docs", (handlers) =>
      handlers.handle("getDoc", () => Effect.succeed("ok")),
    );
    const app = HttpApiBuilder.layer(DocsApi).pipe(
      Layer.provide(docsGroup),
      Layer.provide(
        Layer.mergeAll(
          RequireDocReadByParam.layer,
          authorizerLayer,
          Layer.succeed(CurrentPrincipal, principal),
        ),
      ),
      Layer.provide(platform),
    );
    return HttpRouter.toWebHandler(app);
  };

  it("the owner is served the handler for their own doc and refused another's with 403", async () => {
    const { handler, dispose } = serveDocs(alice);
    try {
      const own = await handler(new Request("http://localhost/docs/doc-1"));
      expect(own.status).toBe(200);
      const other = await handler(new Request("http://localhost/docs/doc-2"));
      expect(other.status).toBe(403);
      expect(await other.text()).toContain("default-deny");
    } finally {
      await dispose();
    }
  });

  it("the resource is read per request from the path: a different principal gets the reverse", async () => {
    const { handler, dispose } = serveDocs(bob);
    try {
      const denied = await handler(new Request("http://localhost/docs/doc-1"));
      expect(denied.status).toBe(403);
      const allowed = await handler(new Request("http://localhost/docs/doc-2"));
      expect(allowed.status).toBe(200);
    } finally {
      await dispose();
    }
  });
});

// ---------------------------------------------------------------------------
// Guard identity (#320): a guard's type is its name, so a wrong layer is caught
// ---------------------------------------------------------------------------

describe("makeAuthorizationMiddleware – guard identity", () => {
  // Two guards with the same requirements `R` and the same shape. Only their
  // names differ, and the names are their types.
  const RequireDocWrite = makeAuthorizationMiddleware("RequireDocWrite", {
    action: "doc:write",
    resource: doc1,
  });

  const platform = Layer.mergeAll(
    Path.layer,
    Etag.layerWeak,
    HttpPlatform.layer.pipe(Layer.provide(FileSystem.layerNoop({}))),
    FileSystem.layerNoop({}),
  );

  // `GET /docs/:docId` attached to `RequireDocRead`. The handler is trivial:
  // the test is about what the layer graph must provide.
  const DocsApi = HttpApi.make("docs").add(
    HttpApiGroup.make("docs").add(
      HttpApiEndpoint.get("getDoc", "/docs/:docId", { success: Schema.String }).middleware(
        RequireDocRead,
      ),
    ),
  );
  const docsImpl = HttpApiBuilder.group(DocsApi, "docs", (handlers) =>
    handlers.handle("getDoc", () => Effect.succeed("ok")),
  );

  it("attaching RequireDocRead and providing its own layer type-checks, builds and serves a request", async () => {
    const app = HttpApiBuilder.layer(DocsApi).pipe(
      Layer.provide(docsImpl),
      Layer.provide(
        Layer.mergeAll(
          RequireDocRead.layer,
          authorizerLayer,
          Layer.succeed(CurrentPrincipal, alice),
        ),
      ),
      Layer.provide(platform),
    );
    const { handler, dispose } = HttpRouter.toWebHandler(app);
    try {
      // `alice` owns doc-1, the resource RequireDocRead guards, so the handler runs.
      const response = await handler(new Request("http://localhost/docs/doc-1"));
      expect(response.status).toBe(200);
    } finally {
      await dispose();
    }
  });

  it("attaching RequireDocRead and providing only RequireDocWrite's layer is a type error, and the build names the missing guard", async () => {
    const app = HttpApiBuilder.layer(DocsApi).pipe(
      Layer.provide(docsImpl),
      Layer.provide(
        Layer.mergeAll(
          RequireDocWrite.layer,
          authorizerLayer,
          Layer.succeed(CurrentPrincipal, alice),
        ),
      ),
      Layer.provide(platform),
      Layer.provide(HttpRouter.layer),
    );
    // @ts-expect-error -- RequireDocRead's layer is missing: only RequireDocWrite.layer is provided.
    // @effect-diagnostics-next-line missingEffectContext:off
    const exit = await Effect.runPromiseExit(Effect.scoped(Layer.build(app)));
    expect(Exit.isFailure(exit)).toBe(true);
    // The defect names the guard whose layer is missing (`#<n>` is the factory call count).
    expect(Exit.isFailure(exit) ? Cause.pretty(exit.cause) : "").toMatch(
      /Service not found: @effect-auth\/AuthorizationMiddleware\/RequireDocRead#\d+/,
    );
  });
});

// ---------------------------------------------------------------------------
// Guard names: a literal, so each guard has its own type
// ---------------------------------------------------------------------------

describe("makeAuthorizationMiddleware – guard names", () => {
  const input = { action: readDoc, resource: doc1 };

  it("a literal name compiles, and the runtime key is the name plus the factory call count", () => {
    const Guard = makeAuthorizationMiddleware("RequireA", input);
    expect(Guard.key).toMatch(/^@effect-auth\/AuthorizationMiddleware\/RequireA#\d+$/);
  });

  it("a widened name is a compile error: string, a template pattern and a union each widen the guard's type", () => {
    const dynamicName = "RequireA" as string;
    const patternName = "RequireAGuard" as `${string}Guard`;
    const unionName = "RequireA" as "RequireA" | "RequireB";
    // The calls only need to type-check; each one is a valid runtime call too.
    // @ts-expect-error -- `string` widens the guard's type.
    void makeAuthorizationMiddleware(dynamicName, input);
    // @ts-expect-error -- a template pattern widens it too.
    void makeAuthorizationMiddleware(patternName, input);
    // @ts-expect-error -- a union names several guards at once.
    void makeAuthorizationMiddleware(unionName, input);
  });

  it("the empty string is a compile error: it names no guard", () => {
    // @ts-expect-error -- `""` is not a guard name.
    void makeAuthorizationMiddleware("", input);
  });

  it("an any-typed name is a compile error, inferred or explicit: any would type the guard as any", () => {
    const anyName: any = "RequireA";
    // @ts-expect-error -- `any` is not a guard name.
    void makeAuthorizationMiddleware(anyName, input);
    // @ts-expect-error -- an explicit `any` type argument is not a guard name either.
    void makeAuthorizationMiddleware<any>("RequireA", input);
  });

  it("a widened name's rejection message is the parameter's type, pinned to its exact text", () => {
    // Fails to type-check if the message is replaced by `never` or any other text.
    const message: Parameters<typeof makeAuthorizationMiddleware<string>>[0] =
      "a guard name must be one non-empty string literal, not string, a template pattern or a union";
    expect(message).toMatch(/non-empty string literal/);
  });

  it("tricky non-empty literals still compile: punctuation and non-ASCII names", () => {
    const slashHash = makeAuthorizationMiddleware("a/b#c", input);
    const dotColon = makeAuthorizationMiddleware("A.B:C", input);
    const nonAscii = makeAuthorizationMiddleware("Lesen-Übersicht", input);
    expect(slashHash.key).toMatch(/^@effect-auth\/AuthorizationMiddleware\/a\/b#c#\d+$/);
    expect(dotColon.key).toMatch(/^@effect-auth\/AuthorizationMiddleware\/A\.B:C#\d+$/);
    expect(nonAscii.key).toMatch(/^@effect-auth\/AuthorizationMiddleware\/Lesen-Übersicht#\d+$/);
  });
});
