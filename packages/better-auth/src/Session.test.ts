import { assert, describe, expect, it } from "vite-plus/test";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import * as Auth from "@thomasfosterau/effect-auth";
import { fromNow, makeAuth, requestWith, rowOf, run, runExit, signUp } from "./testing/Fixtures.ts";
import { BetterAuthInstance } from "./BetterAuth.ts";
import { BetterAuthSessions, credentialConfig } from "./Session.ts";

const failureTag = (exit: Exit.Exit<unknown, unknown>) =>
  Exit.isFailure(exit) ? Option.getOrUndefined(Exit.findErrorOption(exit)) : undefined;

describe("BetterAuthSessions.lookup", () => {
  it("resolves a signed-in cookie to the session and user, named by the stored id", async () => {
    const { auth } = makeAuth();
    const { cookie, token, user } = await signUp(auth);
    const lookup = await run(
      auth,
      Effect.flatMap(Effect.service(BetterAuthSessions), (s) => s.lookup(requestWith({ cookie }))),
    );
    assert(Option.isSome(lookup.session));
    const found = lookup.session.value;
    expect(found.user.id).toBe(user.id);
    expect(found.user.name).toBe("Ada");
    expect(found.session.userId).toBe(user.id);
    expect(found.session.id).not.toBe(token);
    expect(found.session).not.toHaveProperty("token");
    expect(R.values(found.session.attributes)).not.toContain(token);
    expect(Auth.sessionCredentialClass(found.session)).toBe("interactive");
  });

  it("is anonymous without a cookie, and for a cookie whose signature does not verify", async () => {
    const { auth } = makeAuth();
    const { token } = await signUp(auth);
    const anonymous = await run(
      auth,
      Effect.flatMap(Effect.service(BetterAuthSessions), (s) => s.lookup(requestWith({}))),
    );
    expect(Option.isNone(anonymous.session)).toBe(true);
    const forged = await run(
      auth,
      Effect.flatMap(Effect.service(BetterAuthSessions), (s) =>
        s.lookup(requestWith({ cookie: `better-auth.session_token=${token}.forged` })),
      ),
    );
    expect(Option.isNone(forged.session)).toBe(true);
  });

  it("marks a bearer caller as a machine credential", async () => {
    const { auth } = makeAuth();
    const { cookie } = await signUp(auth);
    // The bearer plugin takes the signed cookie value as the bearer token.
    const signed = decodeURIComponent(cookie.split("=").slice(1).join("="));
    const lookup = await run(
      auth,
      Effect.flatMap(Effect.service(BetterAuthSessions), (s) =>
        s.lookup(requestWith({ authorization: `Bearer ${signed}` })),
      ),
    );
    assert(Option.isSome(lookup.session));
    expect(Auth.sessionCredentialClass(lookup.session.value.session)).toBe("machine");
  });

  it("reads a banned user as anonymous, until the ban expires", async () => {
    const { auth, db } = makeAuth();
    const { cookie, user } = await signUp(auth);
    const row = rowOf(db, "user", (u) => u["id"] === user.id);
    row["banned"] = true;
    const lookup = (headers: Record<string, string>) =>
      run(
        auth,
        Effect.flatMap(Effect.service(BetterAuthSessions), (s) => s.lookup(requestWith(headers))),
      );
    expect(Option.isNone((await lookup({ cookie })).session)).toBe(true);
    row["banExpires"] = fromNow(-1000);
    expect(Option.isSome((await lookup({ cookie })).session)).toBe(true);
  });

  it("relays BetterAuth's Set-Cookie when it slides the session", async () => {
    const { auth, db } = makeAuth({ session: { updateAge: 0 } });
    const { cookie } = await signUp(auth);
    const row = rowOf(db, "session");
    row["updatedAt"] = fromNow(-60_000);
    const lookup = await run(
      auth,
      Effect.flatMap(Effect.service(BetterAuthSessions), (s) => s.lookup(requestWith({ cookie }))),
    );
    expect(Option.isSome(lookup.session)).toBe(true);
    expect(lookup.setCookie.some((line) => line.startsWith("better-auth.session_token="))).toBe(
      true,
    );
  });

  it("is a fault, never anonymous, when BetterAuth's adapter fails", async () => {
    const { auth, db } = makeAuth();
    const { cookie } = await signUp(auth);
    Object.defineProperty(db, "session", {
      get: () => {
        throw new TypeError("database down");
      },
    });
    const exit = await runExit(
      auth,
      Effect.flatMap(Effect.service(BetterAuthSessions), (s) => s.lookup(requestWith({ cookie }))),
    );
    expect(failureTag(exit)).toBeInstanceOf(Auth.AuthError);
  });
});

describe("credentialConfig", () => {
  it("names BetterAuth's cookie as the instance sets it, plain over http", async () => {
    const { auth } = makeAuth();
    const config = credentialConfig(await auth.$context);
    expect(Auth.SessionCookies.cookieNames(config).session).toBe("better-auth.session_token");
  });

  it("names the __Secure- cookie over https and a custom prefix, with no __Host- prefix", async () => {
    const { auth } = makeAuth({
      baseURL: "https://app.example.test",
      advanced: { cookiePrefix: "app" },
    });
    const config = credentialConfig(await auth.$context);
    expect(Auth.SessionCookies.cookieNames(config).session).toBe("__Secure-app.session_token");
  });

  it("lets the cookieless skip see a signed-in request and skip an anonymous one", async () => {
    const { auth } = makeAuth();
    const { cookie } = await signUp(auth);
    const config = await run(
      auth,
      Effect.map(Effect.service(BetterAuthSessions), (s) => s.credentialConfig),
    );
    const detect = (headers: Record<string, string>) =>
      Auth.SessionResolution.detectCredential(
        Auth.SessionResolution.fromRequest(requestWith(headers)),
        config,
      ).present;
    expect(detect({ cookie })).toBe(true);
    expect(detect({ cookie: "other=1" })).toBe(false);
  });
});

describe("SessionService over BetterAuth", () => {
  const sessions = Effect.service(Auth.SessionService);

  it("validates a raw token, and refuses an unknown, expired or banned one", async () => {
    const { auth, db } = makeAuth();
    const { token, user } = await signUp(auth);
    const valid = await run(
      auth,
      Effect.flatMap(sessions, (s) => s.validateSession(token)),
    );
    expect(valid.user.id).toBe(user.id);
    expect(valid.session.id).not.toBe(token);

    const unknown = await runExit(
      auth,
      Effect.flatMap(sessions, (s) => s.validateSession("nope")),
    );
    expect(failureTag(unknown)).toBeInstanceOf(Auth.SessionNotFoundError);

    const userRow = rowOf(db, "user");
    userRow["banned"] = true;
    const banned = await runExit(
      auth,
      Effect.flatMap(sessions, (s) => s.validateSession(token)),
    );
    expect(failureTag(banned)).toBeInstanceOf(Auth.UserBannedError);
    userRow["banned"] = false;

    const sessionRow = rowOf(db, "session");
    sessionRow["expiresAt"] = fromNow(-1000);
    const expired = await runExit(
      auth,
      Effect.flatMap(sessions, (s) => s.validateSession(token)),
    );
    expect(failureTag(expired)).toBeInstanceOf(Auth.SessionExpiredError);
  });

  it("lists only live sessions, and revokes by stored id or all but one", async () => {
    const { auth, db } = makeAuth();
    const first = await signUp(auth);
    const second = await auth.api.signInEmail({
      body: { email: first.email, password: first.password },
    });
    const third = await auth.api.signInEmail({
      body: { email: first.email, password: first.password },
    });
    const userId = first.user.id;
    const stale = rowOf(db, "session", (s) => s["token"] === third.token);
    stale["expiresAt"] = fromNow(-1000);

    const listed = await run(
      auth,
      Effect.flatMap(sessions, (s) => s.listSessions(userId)),
    );
    expect(listed).toHaveLength(2);

    const keep = await run(
      auth,
      Effect.flatMap(sessions, (s) => s.validateSession(first.token)),
    );
    expect(
      await run(
        auth,
        Effect.flatMap(sessions, (s) => s.revokeSessionById(userId, "no-such-id")),
      ),
    ).toBe(false);
    expect(
      await run(
        auth,
        Effect.flatMap(sessions, (s) => s.revokeSessionById("someone-else", keep.session.id)),
      ),
    ).toBe(false);

    await run(
      auth,
      Effect.flatMap(sessions, (s) => s.revokeOtherSessions(userId, keep.session.id)),
    );
    expect(db["session"]?.map((s) => s["token"])).toEqual([first.token]);
    expect(second.token).not.toBe(first.token);

    expect(
      await run(
        auth,
        Effect.flatMap(sessions, (s) => s.revokeSessionById(userId, keep.session.id)),
      ),
    ).toBe(true);
    expect(db["session"]).toHaveLength(0);
  });

  it("invalidates one session by token, and every session of a user", async () => {
    const { auth, db } = makeAuth();
    const a = await signUp(auth);
    const b = await signUp(auth);
    await run(
      auth,
      Effect.flatMap(sessions, (s) => s.invalidateSession(a.token)),
    );
    expect(db["session"]?.map((s) => s["token"])).toEqual([b.token]);
    await run(
      auth,
      Effect.flatMap(sessions, (s) => s.invalidateUserSessions(b.user.id)),
    );
    expect(db["session"]).toHaveLength(0);
  });

  it("writes declared session columns only, by stored id", async () => {
    const { auth } = makeAuth();
    const { token } = await signUp(auth);
    const { session } = await run(
      auth,
      Effect.flatMap(sessions, (s) => s.validateSession(token)),
    );
    const updated = await run(
      auth,
      Effect.flatMap(sessions, (s) => s.setSessionAttributes(session.id, { device: "laptop" })),
    );
    expect(updated.attributes["device"]).toBe("laptop");
    expect(updated.id).toBe(session.id);

    const refused = await Promise.all(
      Arr.map(["undeclared", "userId", "token", "impersonatedBy", "expiresAt"], (key) =>
        runExit(
          auth,
          Effect.flatMap(sessions, (s) => s.setSessionAttributes(session.id, { [key]: "x" })),
        ),
      ),
    );
    Arr.forEach(refused, (exit) => expect(failureTag(exit)).toBeInstanceOf(Auth.AuthError));
    const missing = await runExit(
      auth,
      Effect.flatMap(sessions, (s) => s.setSessionAttributes("no-such-id", { device: "x" })),
    );
    expect(failureTag(missing)).toBeInstanceOf(Auth.SessionNotFoundError);
  });

  it("refuses to create a session: BetterAuth's routes issue them", async () => {
    const { auth } = makeAuth();
    const { user } = await signUp(auth);
    const exit = await runExit(
      auth,
      Effect.flatMap(sessions, (s) => s.createSession(user.id)),
    );
    expect(failureTag(exit)).toBeInstanceOf(Auth.AuthError);
  });
});

describe("BetterAuthInstance.layer", () => {
  it("takes a plugin-augmented instance, typed structurally", async () => {
    const { auth } = makeAuth();
    const context = await Effect.runPromise(
      Effect.provide(Effect.service(BetterAuthInstance), BetterAuthInstance.layer(auth)),
    );
    expect(context.context.tables["user"]?.fields).toHaveProperty("role");
  });
});
