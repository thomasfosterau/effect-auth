import { describe, expect, it, onTestFinished } from "vite-plus/test";
import * as Arr from "effect/Array";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as Struct from "effect/Struct";
import * as MutableHashSet from "effect/MutableHashSet";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import { Etag, HttpPlatform, HttpRouter } from "effect/http";
import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "effect/http-api";
import * as Errors from "../Errors.ts";
import { Hooks } from "../Hooks.ts";
import { SessionService } from "../SessionService.ts";
import type * as Types from "../Types.ts";
import {
  AuthMiddleware,
  CurrentUser,
  layer as authLayer,
  optionalLayer,
} from "./HttpMiddleware.ts";
import { MaybeCurrentSession, OptionalAuthMiddleware } from "./HttpMiddleware.ts";

const now = DateTime.toDateUtc(DateTime.nowUnsafe());
const later = DateTime.toDateUtc(DateTime.add(DateTime.nowUnsafe(), { hours: 1 }));
const user: Types.User = { id: "u-1", createdAt: now, updatedAt: now, attributes: {} };
const session = (id: string): Types.Session => ({
  id,
  userId: user.id,
  expiresAt: later,
  createdAt: now,
  lastActivityAt: now,
  attributes: {},
});

/**
 * A session service whose credential changes as it is read, as a sealed cookie
 * holding a refreshed access token does: each token validates once, and
 * answers its successor in `reissued`.
 */
const rotatingSessions = () => {
  const live = MutableHashSet.make("token-1");
  let issued = 1;
  const service: typeof SessionService.Service = {
    createSession: () => Effect.die("unused"),
    validateSession: (token) =>
      Effect.suspend(() => {
        if (!MutableHashSet.has(live, token)) {
          return Effect.fail(
            new Errors.SessionNotFoundError({ message: "spent", sessionId: token }),
          );
        }
        MutableHashSet.remove(live, token);
        issued += 1;
        const next = `token-${issued}`;
        MutableHashSet.add(live, next);
        return Effect.succeed({
          session: session("s-1"),
          user,
          reissued: { session: session("s-1"), token: next },
        });
      }),
    invalidateSession: () => Effect.die("unused"),
    invalidateUserSessions: () => Effect.die("unused"),
    listSessions: () => Effect.die("unused"),
    revokeSessionById: () => Effect.die("unused"),
    revokeOtherSessions: () => Effect.die("unused"),
    setSessionAttributes: () => Effect.die("unused"),
  };
  return service;
};

const Api = HttpApi.make("Api").add(
  HttpApiGroup.make("account")
    .add(
      HttpApiEndpoint.get("account", "/account", {
        success: Schema.Struct({ id: Schema.String, keys: Schema.Array(Schema.String) }),
      }).middleware(AuthMiddleware),
    )
    .add(
      HttpApiEndpoint.get("maybe", "/maybe", {
        success: Schema.Struct({ keys: Schema.Array(Schema.String) }),
      }).middleware(OptionalAuthMiddleware),
    ),
);

const serve = (service: typeof SessionService.Service, bearerMode?: "opt-in") => {
  const group = HttpApiBuilder.group(Api, "account", (handlers) =>
    handlers
      .handle("account", () => Effect.map(CurrentUser, (u) => ({ id: u.id, keys: Struct.keys(u) })))
      .handle("maybe", () =>
        Effect.map(MaybeCurrentSession, (maybe) => ({
          keys: Option.match(maybe, { onNone: () => [], onSome: R.keys }),
        })),
      ),
  );
  const cookie = { secure: false, ...(bearerMode !== undefined && { bearerMode }) };
  const { handler, dispose } = HttpRouter.toWebHandler(
    HttpApiBuilder.layer(Api).pipe(
      Layer.provide(group),
      Layer.provide(authLayer(cookie)),
      Layer.provide(optionalLayer(cookie)),
      Layer.provide(Layer.mergeAll(Layer.succeed(SessionService, service), Hooks.Default)),
      Layer.provide(
        Layer.mergeAll(
          Path.layer,
          Etag.layerWeak,
          HttpPlatform.layer.pipe(Layer.provide(FileSystem.layerNoop({}))),
          FileSystem.layerNoop({}),
        ),
      ),
    ),
  );
  onTestFinished(() => dispose());
  return handler;
};

const cookieOf = (response: Response): Option.Option<string> =>
  Option.map(
    Arr.findFirst(response.headers.getSetCookie(), (line) => line.startsWith("conduit_session=")),
    (line) => (line.split(";")[0] ?? "").slice("conduit_session=".length),
  );

describe("a credential reissued by validateSession", () => {
  it("replaces the session cookie, is no-store, and never reaches the body", async () => {
    const handler = serve(rotatingSessions());
    const first = await handler(
      new Request("http://localhost/account", { headers: { cookie: "conduit_session=token-1" } }),
    );
    expect(first.status).toBe(200);
    expect(cookieOf(first)).toEqual(Option.some("token-2"));
    expect(first.headers.get("cache-control")).toContain("no-store");
    expect(await first.clone().text()).not.toContain("token-2");
    expect(await first.json()).toEqual({
      id: "u-1",
      keys: ["id", "createdAt", "updatedAt", "attributes"],
    });

    // The spent token no longer validates; its replacement does.
    const spent = await handler(
      new Request("http://localhost/account", { headers: { cookie: "conduit_session=token-1" } }),
    );
    expect(spent.status).toBe(401);
    const second = await handler(
      new Request("http://localhost/account", { headers: { cookie: "conduit_session=token-2" } }),
    );
    expect(second.status).toBe(200);
    expect(cookieOf(second)).toEqual(Option.some("token-3"));
  });

  it("hands the optional middleware's handler no reissued token", async () => {
    const handler = serve(rotatingSessions());
    const response = await handler(
      new Request("http://localhost/maybe", { headers: { cookie: "conduit_session=token-1" } }),
    );
    expect(response.status).toBe(200);
    expect(cookieOf(response)).toEqual(Option.some("token-2"));
    expect(await response.json()).toEqual({ keys: ["session", "user"] });
  });

  it("answers a bearer caller in set-auth-token, without planting a cookie", async () => {
    const handler = serve(rotatingSessions(), "opt-in");
    const response = await handler(
      new Request("http://localhost/account", {
        headers: { authorization: "Bearer token-1" },
      }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("set-auth-token")).toBe("token-2");
    expect(Option.isNone(cookieOf(response))).toBe(true);
  });
});
