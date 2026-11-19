/**
 * A session-store or user-store fault is never a `401` (#612): the browser
 * client reads `401` as signed out, so a database blip would look like a mass
 * sign-out. Only a refused session (none, expired, its user gone, banned) is a
 * `401`; a fault is a logged `500`, on the required-auth middleware, on the
 * optional-auth middleware (unless the app asked to degrade it) and in
 * `Http.make`'s own handlers.
 */
import { describe, expect, it } from "vite-plus/test";
import { DateTime, Effect, FileSystem, Layer, Logger, Path } from "effect";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import { Etag, HttpPlatform, HttpRouter } from "effect/http";
import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "effect/http-api";
import * as Errors from "../Errors.ts";
import { Hooks } from "../Hooks.ts";
import { SessionService } from "../SessionService.ts";
import type * as Types from "../Types.ts";
import { makeServerFixture } from "../client/testing/fixture.ts";
import {
  AuthMiddleware,
  CurrentUser,
  MaybeCurrentSession,
  OptionalAuthMiddleware,
  layer as authLayer,
  optionalLayer,
} from "./HttpMiddleware.ts";

const TOKEN = "valid-token";
const now = DateTime.toDateUtc(DateTime.nowUnsafe());
const user: Types.User = { id: "u-1", createdAt: now, updatedAt: now, attributes: {} };
const session: Types.Session = {
  id: "stored-id",
  userId: user.id,
  expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(now.getTime() + 3_600_000)),
  createdAt: now,
  lastActivityAt: now,
  attributes: {},
};

/** A session service whose store is down while `state.down` is set. */
const sessionServiceLayer = (state: { down: boolean }) =>
  Layer.succeed(SessionService, {
    createSession: () => Effect.die("unused"),
    validateSession: (token) =>
      state.down
        ? Effect.fail(new Errors.AuthError({ message: "session store unreachable" }))
        : token === TOKEN
          ? Effect.succeed({ session, user })
          : Effect.fail(
              new Errors.SessionNotFoundError({ message: "not found", sessionId: token }),
            ),
    invalidateSession: () => Effect.die("unused"),
    invalidateUserSessions: () => Effect.die("unused"),
    listSessions: () => Effect.die("unused"),
    revokeSessionById: () => Effect.die("unused"),
    revokeOtherSessions: () => Effect.die("unused"),
    setSessionAttributes: () => Effect.die("unused"),
  });

/** Collect the log as `{ level, line }` records, `line` its JSON form. */
const logCollector = () => {
  const logs: Array<{ readonly level: string; readonly line: string }> = [];
  const layer = Logger.layer([
    Logger.make((options) => {
      logs.push({ level: options.logLevel, line: Logger.formatJson.log(options) });
    }),
  ]);
  return { logs, layer };
};

const Viewer = Schema.Struct({ viewer: Schema.NullOr(Schema.String) });
const Api = HttpApi.make("Api")
  .add(
    HttpApiGroup.make("private").add(
      HttpApiEndpoint.get("me", "/me", { success: Viewer }).middleware(AuthMiddleware),
    ),
  )
  .add(
    HttpApiGroup.make("public").add(
      HttpApiEndpoint.get("feed", "/feed", { success: Viewer }).middleware(OptionalAuthMiddleware),
    ),
  );

const PrivateLive = HttpApiBuilder.group(Api, "private", (handlers) =>
  handlers.handle("me", () =>
    Effect.gen(function* () {
      return { viewer: (yield* CurrentUser).id };
    }),
  ),
);
const PublicLive = HttpApiBuilder.group(Api, "public", (handlers) =>
  handlers.handle("feed", () =>
    Effect.gen(function* () {
      const maybe = yield* MaybeCurrentSession;
      return { viewer: Option.isSome(maybe) ? maybe.value.user.id : null };
    }),
  ),
);

/** The two-route app, its session store down while `state.down` is set. */
const app = (
  state: { down: boolean },
  optional: Layer.Layer<OptionalAuthMiddleware> = optionalLayer({ secure: false }),
) => {
  const { logs, layer: loggerLayer } = logCollector();
  const services = Layer.mergeAll(sessionServiceLayer(state), Hooks.Default, loggerLayer);
  const appLayer = HttpApiBuilder.layer(Api).pipe(
    Layer.provide([PrivateLive, PublicLive]),
    Layer.provide([authLayer({ secure: false }), optional]),
    Layer.provide(
      Layer.mergeAll(
        Path.layer,
        Etag.layerWeak,
        HttpPlatform.layer.pipe(Layer.provide(FileSystem.layerNoop({}))),
        FileSystem.layerNoop({}),
      ),
    ),
    Layer.provideMerge(services),
  );
  const { handler } = HttpRouter.toWebHandler(appLayer, { disableLogger: true });
  return { handler, logs };
};

const get = (path: string, headers: Record<string, string> = {}) =>
  new Request(`http://localhost${path}`, { headers });
const cookie = (token: string) => ({ cookie: `conduit_session=${token}` });
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

describe("AuthMiddleware on a store fault (#612)", () => {
  it("answers a logged 500, not a 401, for a session cookie", async () => {
    const { handler, logs } = app({ down: true });
    const res = await handler(get("/me", cookie(TOKEN)));
    expect(res.status).toBe(500);
    expect(logs.some((log) => log.level === "Error")).toBe(true);
  });

  it("answers a 500 for a bearer token", async () => {
    const { handler } = app({ down: true });
    expect((await handler(get("/me", bearer(TOKEN)))).status).toBe(500);
  });

  it("still answers 401 for an unknown token and for no token", async () => {
    const { handler } = app({ down: false });
    expect((await handler(get("/me", cookie("unknown")))).status).toBe(401);
    expect((await handler(get("/me", bearer("unknown")))).status).toBe(401);
    expect((await handler(get("/me"))).status).toBe(401);
    expect((await handler(get("/me", cookie(TOKEN)))).status).toBe(200);
  });
});

describe("OptionalAuthMiddleware on a store fault (#612)", () => {
  it("answers a logged 500 rather than serving the caller as anonymous", async () => {
    const { handler, logs } = app({ down: true });
    const res = await handler(get("/feed", cookie(TOKEN)));
    expect(res.status).toBe(500);
    expect(logs.some((log) => log.level === "Error")).toBe(true);
  });

  it("serves an unknown or absent token as anonymous", async () => {
    const { handler } = app({ down: false });
    const unknown = await handler(get("/feed", cookie("unknown")));
    expect(unknown.status).toBe(200);
    expect(await unknown.json()).toEqual({ viewer: null });
    expect(await (await handler(get("/feed"))).json()).toEqual({ viewer: null });
    expect(await (await handler(get("/feed", cookie(TOKEN)))).json()).toEqual({ viewer: "u-1" });
  });

  it("degrades to anonymous through onDegraded, which sees the fault", async () => {
    const reported: Array<string> = [];
    const { handler } = app(
      { down: true },
      optionalLayer(
        { secure: false },
        {
          onDegraded: (cause) =>
            Effect.sync(() => {
              reported.push(String(cause));
            }),
        },
      ),
    );
    const res = await handler(get("/feed", cookie(TOKEN)));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ viewer: null });
    expect(reported).toHaveLength(1);
    expect(reported[0]).toContain("session store unreachable");
  });
});

describe("Http.make on a store fault (#612)", () => {
  it("answers GET /sessions/current with a logged 500, not a 401", async () => {
    const state = { down: true };
    const { logs, layer } = logCollector();
    const { handler } = makeServerFixture({
      layer: Layer.merge(sessionServiceLayer(state), layer),
    });
    const res = await handler(
      get("/sessions/current", { ...cookie(TOKEN), accept: "application/vnd.api+json" }),
    );
    expect(res.status).toBe(500);
    expect(
      logs.some(
        (log) =>
          log.level === "Error" &&
          log.line.includes("[effect-auth] internal error") &&
          log.line.includes("session store unreachable"),
      ),
    ).toBe(true);

    state.down = false;
    const refused = await handler(get("/sessions/current", cookie("unknown")));
    expect(refused.status).toBe(401);
  });
});
