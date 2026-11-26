import { assert, describe, expect, it } from "vite-plus/test";
import { Effect, Layer, Redacted } from "effect";
import * as Option from "effect/Option";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import { KeyValueStore } from "effect/persistence";
import { TestClock } from "effect/testing";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Fake from "./FakeWorkOS.fixtures.ts";
import * as Backend from "./index.ts";
import { RevokedSessions, SessionAttribute, WorkOSSessions } from "./Session.ts";
import type { WorkOSConfig } from "./WorkOS.ts";

const email = "ada@example.com";
const password = "correct horse battery staple";
const MINUTE = 60_000;

const appLayer = Layer.mergeAll(
  Auth.Hooks.Default,
  Auth.OAuthStateStoreKV.pipe(Layer.provide(KeyValueStore.layerMemory)),
  Auth.RootSecret.RootSecret.layer("a-root-secret-of-at-least-32-bytes-long").pipe(Layer.orDie),
  RevokedSessions.layerMemory,
  Auth.PlatformCrypto.layer,
);

/** Run `program` over the backend on a fresh fake, under the test clock. */
const run = <A, E>(
  program: (
    fake: Fake.FakeWorkOS,
  ) => Effect.Effect<A, E, Backend.Services | Layer.Success<typeof appLayer>>,
  options: { readonly fake?: Fake.FakeOptions; readonly config?: Partial<WorkOSConfig> } = {},
) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const fake = yield* Fake.make(options.fake);
      const backend = Backend.layerHttpClient(Fake.testConfig(options.config)).pipe(
        Layer.provideMerge(Layer.mergeAll(fake.layer, appLayer)),
      );
      return yield* program(fake).pipe(Effect.provide(backend));
    }).pipe(Effect.provide(TestClock.layer())),
  );

const signUpAndIn = Effect.fn("signUpAndIn")(function* () {
  const auth = yield* Auth.Email.EmailPasswordService;
  yield* auth.signUp({ email, password, name: "Ada Lovelace" });
  return yield* auth.signIn({ email, password });
});

const refreshCalls = (fake: Fake.FakeWorkOS) =>
  fake.calls.filter((c) => c.body?.grant_type === "refresh_token").length;

describe("sessions", () => {
  it("signs in with a sealed cookie that validates without calling WorkOS", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        const result = yield* signUpAndIn();
        assert(result.token !== undefined && result.session !== undefined);
        expect(result.token.startsWith("w1~")).toBe(true);
        expect(result.token).not.toContain("refresh_");
        expect(result.user.name).toBe("Ada Lovelace");
        const before = fake.calls.length;
        const validated = yield* (yield* Auth.SessionService).validateSession(result.token);
        expect(fake.calls.length).toBe(before);
        expect(validated.reissued).toBeUndefined();
        expect(validated.user.id).toBe(result.user.id);
        expect(validated.session.id).toBe(result.session.id);
      }),
    );
  });

  it("sends the API key only as the bearer credential and client secret", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        yield* signUpAndIn();
        const calls = fake.calls.filter((c) => c.path.startsWith("/user_management"));
        expect(calls.map((c) => c.authorization)).toEqual(
          calls.map(() => `Bearer ${Fake.API_KEY}`),
        );
        const grant = fake.calls.find((c) => c.body?.grant_type === "password");
        expect(grant?.body).toMatchObject({
          client_id: Fake.CLIENT_ID,
          client_secret: Fake.API_KEY,
        });
      }),
    );
  });

  it("refreshes an expired access token and reissues the cookie", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        const { token } = yield* signUpAndIn();
        assert(token !== undefined);
        const sessions = yield* Auth.SessionService;
        yield* TestClock.adjust(10 * MINUTE);
        const validated = yield* sessions.validateSession(token);
        assert(validated.reissued !== undefined);
        expect(validated.reissued.token).not.toBe(token);
        expect(refreshCalls(fake)).toBe(1);
        // The reissued cookie is fresh: no second refresh.
        const again = yield* sessions.validateSession(validated.reissued.token);
        expect(again.reissued).toBeUndefined();
        expect(refreshCalls(fake)).toBe(1);
      }),
    );
  });

  it("shares one refresh between concurrent requests holding one cookie", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        const { token } = yield* signUpAndIn();
        assert(token !== undefined);
        const sessions = yield* Auth.SessionService;
        yield* TestClock.adjust(10 * MINUTE);
        const results = yield* Effect.all(
          [
            sessions.validateSession(token),
            sessions.validateSession(token),
            sessions.validateSession(token),
          ],
          { concurrency: "unbounded" },
        );
        expect(results.every((r) => r.reissued !== undefined)).toBe(true);
        expect(refreshCalls(fake)).toBe(1);
      }),
    );
  });

  it("refuses a cookie whose refresh token was already spent", async () => {
    await run(() =>
      Effect.gen(function* () {
        const { token } = yield* signUpAndIn();
        assert(token !== undefined);
        const sessions = yield* Auth.SessionService;
        yield* TestClock.adjust(10 * MINUTE);
        yield* sessions.validateSession(token);
        // Past the sharing window, the old cookie's refresh token is spent.
        yield* TestClock.adjust(10 * MINUTE);
        const replay = yield* Effect.result(sessions.validateSession(token));
        assert(Result.isFailure(replay));
        expect(replay.failure._tag).toBe("SessionExpiredError");
      }),
    );
  });

  it("refuses a revoked session before its access token expires", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        const { token, session } = yield* signUpAndIn();
        assert(token !== undefined && session !== undefined);
        const sessions = yield* Auth.SessionService;
        yield* sessions.invalidateSession(token);
        expect(fake.sessionStatus(session.id)).toBe("inactive");
        const after = yield* Effect.result(sessions.validateSession(token));
        assert(Result.isFailure(after));
        expect(after.failure._tag).toBe("SessionNotFoundError");
      }),
    );
  });

  it("refuses a tampered, foreign or plaintext cookie", async () => {
    await run(() =>
      Effect.gen(function* () {
        const { token } = yield* signUpAndIn();
        assert(token !== undefined);
        const sessions = yield* Auth.SessionService;
        const flipped = token.slice(0, -2) + (token.endsWith("A") ? "BA" : "AA");
        const results = yield* Effect.forEach(
          [flipped, "w1~00000000~AAAA", "{}", ""],
          (bad) => Effect.flip(sessions.validateSession(bad)),
          { concurrency: 1 },
        );
        expect(results.map((e) => e._tag)).toEqual(Array(4).fill("SessionNotFoundError"));
      }),
    );
  });

  it("ends a session at sessionMaxAge however fresh its token", async () => {
    await run(
      () =>
        Effect.gen(function* () {
          const { token } = yield* signUpAndIn();
          assert(token !== undefined);
          yield* TestClock.adjust(2 * MINUTE);
          const result = yield* Effect.result((yield* Auth.SessionService).validateSession(token));
          assert(Result.isFailure(result));
          expect(result.failure._tag).toBe("SessionExpiredError");
        }),
      { config: { sessionMaxAge: MINUTE } },
    );
  });

  it("marks an impersonated session as the core's impersonation", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        yield* (yield* Auth.Email.EmailPasswordService).signUp({ email, password });
        fake.impersonateNext("admin@example.com", "support ticket");
        const { session } = yield* (yield* Auth.Email.EmailPasswordService).signIn({
          email,
          password,
        });
        assert(session !== undefined);
        expect(session.attributes.impersonatedBy).toBe("admin@example.com");
        expect(session.attributes[SessionAttribute.impersonator]).toEqual({
          email: "admin@example.com",
          reason: "support ticket",
        });
      }),
    );
  });

  it("lists only active sessions, an impersonation marked as one", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        const auth = yield* Auth.Email.EmailPasswordService;
        const first = yield* signUpAndIn();
        fake.impersonateNext("admin@example.com", null);
        const second = yield* auth.signIn({ email, password });
        assert(first.token !== undefined && first.session !== undefined);
        assert(second.session !== undefined);
        const sessions = yield* Auth.SessionService;
        yield* sessions.invalidateSession(first.token);
        const listed = yield* sessions.listSessions(first.user.id);
        expect(listed.map((s) => s.id)).not.toContain(first.session.id);
        const impersonated = listed.find((s) => s.id === second.session?.id);
        assert(impersonated !== undefined);
        expect(impersonated.userId).toBe(first.user.id);
        expect(impersonated.attributes.impersonatedBy).toBe("admin@example.com");
        expect(impersonated.attributes[SessionAttribute.impersonator]).toEqual({
          email: "admin@example.com",
          reason: null,
        });
      }),
    );
  });

  it("refuses an access token from another issuer or for another user", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        const user = yield* fake.addUser("eve@example.com", "x");
        const issue = (claims: Schema.JsonObject) =>
          Effect.flatMap(fake.sign(claims), (access_token) =>
            Effect.flatMap(WorkOSSessions, (s) =>
              Effect.result(
                s.issue({
                  user,
                  organization_id: null,
                  access_token,
                  refresh_token: "r",
                  authentication_method: null,
                  impersonator: null,
                }),
              ),
            ),
          );
        const base = { sub: user.id, sid: "session_x", iat: 0, exp: 300 };
        const wrongIssuer = yield* issue({ ...base, iss: "https://evil.test" });
        assert(Result.isFailure(wrongIssuer));
        const otherUser = yield* issue({ ...base, iss: Fake.ISSUER, sub: "user_other" });
        assert(Result.isFailure(otherUser));
        const machine = yield* issue({ ...base, iss: Fake.ISSUER, sub_type: "m2m" });
        assert(Result.isFailure(machine));
        const good = yield* issue({ ...base, iss: Fake.ISSUER });
        assert(Result.isSuccess(good));
      }),
    );
  });

  it("switches organization by refreshing with organization_id", async () => {
    await run(
      () =>
        Effect.gen(function* () {
          const { token } = yield* signUpAndIn();
          assert(token !== undefined);
          const switched = yield* (yield* WorkOSSessions).switchOrganization(token, "org_2");
          expect(switched.session.attributes[SessionAttribute.organizationId]).toBe("org_2");
          expect(switched.session.attributes[SessionAttribute.role]).toBe("admin");
        }),
      { fake: { role: "admin" } },
    );
  });
});

describe("email and password", () => {
  it("maps WorkOS refusals to the core's errors", async () => {
    await run(() =>
      Effect.gen(function* () {
        const auth = yield* Auth.Email.EmailPasswordService;
        yield* auth.signUp({ email, password });
        const wrong = yield* Effect.result(auth.signIn({ email, password: "nope" }));
        assert(Result.isFailure(wrong));
        expect(wrong.failure._tag).toBe("InvalidCredentialsError");
        const unknown = yield* Effect.result(auth.signIn({ email: "x@example.com", password }));
        assert(Result.isFailure(unknown));
        expect(unknown.failure._tag).toBe("InvalidCredentialsError");
        const taken = yield* Effect.result(auth.signUp({ email, password }));
        assert(Result.isFailure(taken));
        expect(taken.failure._tag).toBe("EmailInUseError");
      }),
    );
  });

  it("changes a password only with the current one, ending the other sessions", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        const auth = yield* Auth.Email.EmailPasswordService;
        const first = yield* signUpAndIn();
        const second = yield* auth.signIn({ email, password });
        assert(first.session !== undefined && second.session !== undefined);
        const refused = yield* Effect.result(
          auth.changePassword({
            userId: first.user.id,
            currentPassword: "nope",
            newPassword: "n3w",
          }),
        );
        assert(Result.isFailure(refused));
        yield* auth.changePassword({
          userId: first.user.id,
          currentPassword: password,
          newPassword: "a new password",
          currentSessionId: first.session.id,
        });
        expect(fake.sessionStatus(first.session.id)).toBe("active");
        expect(fake.sessionStatus(second.session.id)).toBe("inactive");
        expect(fake.activeSessionIds()).toEqual([first.session.id]);
        yield* auth.signIn({ email, password: "a new password" });
      }),
    );
  });
});

describe("email verification", () => {
  it("signs up without a session, then verifies with <userId>:<code>", async () => {
    await run(
      () =>
        Effect.gen(function* () {
          const lifecycle = yield* Auth.AuthLifecycleService;
          const signUp = yield* lifecycle.signUp({ email, password });
          expect(signUp.needsEmailVerification).toBe(true);
          expect(signUp.session).toBeUndefined();
          const blocked = yield* Effect.result(lifecycle.signIn({ email, password }));
          assert(Result.isFailure(blocked));
          expect(blocked.failure._tag).toBe("EmailVerificationError");
          const wrong = yield* Effect.result(
            lifecycle.verifyEmail({ token: `${signUp.user.id}:000000` }),
          );
          assert(Result.isFailure(wrong));
          expect(wrong.failure._tag).toBe("EmailVerificationError");
          yield* lifecycle.verifyEmail({ token: `${signUp.user.id}:123456` });
          const signedIn = yield* lifecycle.signIn({ email, password });
          expect(signedIn.session).toBeDefined();
        }),
      { fake: { requireEmailVerification: true } },
    );
  });
});

describe("password reset", () => {
  it("answers an unknown address as a known one", async () => {
    await run(() =>
      Effect.gen(function* () {
        yield* (yield* Auth.Password.PasswordResetService).requestPasswordReset(
          "nobody@example.com",
        );
      }),
    );
  });

  it("resets with the WorkOS token and ends every session", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        const { session } = yield* signUpAndIn();
        assert(session !== undefined);
        const reset = yield* Auth.Password.PasswordResetService;
        yield* reset.requestPasswordReset(email);
        const [token] = fake.resetTokens();
        assert(token !== undefined);
        const bad = yield* Effect.result(reset.resetPassword("reset_token_bogus", "x"));
        assert(Result.isFailure(bad));
        expect(bad.failure._tag).toBe("PasswordResetError");
        yield* reset.resetPassword(token, "a reset password");
        expect(fake.sessionStatus(session.id)).toBe("inactive");
        const replay = yield* Effect.result(reset.resetPassword(token, "again"));
        assert(Result.isFailure(replay));
      }),
    );
  });
});

describe("Magic Auth", () => {
  it("signs in with the emailed code, once", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        const otp = yield* Auth.Email.EmailOtpService;
        yield* otp.send(email, "sign-in");
        const code = fake.magicCode(email);
        assert(code !== undefined);
        const wrong = yield* Effect.result(otp.signIn(email, "000000"));
        assert(Result.isFailure(wrong));
        const result = yield* otp.signIn(email, code);
        expect(result.user.id).toMatch(/^user_/);
        const replay = yield* Effect.result(otp.signIn(email, code));
        assert(Result.isFailure(replay));
        const other = yield* Effect.result(otp.send(email, "email-verification"));
        assert(Result.isFailure(other));
      }),
    );
  });
});

describe("AuthKit", () => {
  it("binds the authorize URL to a one-use state and its PKCE challenge", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        const user = yield* fake.addUser(email, undefined);
        const oauth = yield* Auth.OAuth.OAuthService;
        const { url, state } = yield* oauth.generateAuthorizationUrl("google");
        const params = new URL(url).searchParams;
        expect(new URL(url).origin + new URL(url).pathname).toBe(
          `${Fake.BASE_URL}/user_management/authorize`,
        );
        expect(params.get("provider")).toBe("GoogleOAuth");
        expect(params.get("client_id")).toBe(Fake.CLIENT_ID);
        expect(params.get("state")).toBe(state);
        expect(params.get("code_challenge_method")).toBe("S256");
        const challenge = params.get("code_challenge") ?? "";
        const code = fake.authorizationCode(user.id, challenge);
        const signedIn = yield* oauth.signInWithCallback(state, code);
        expect(signedIn.user.id).toBe(user.id);
        expect(signedIn.account.accessToken).toBe("");
        const replay = yield* Effect.result(
          oauth.signInWithCallback(state, fake.authorizationCode(user.id, challenge)),
        );
        assert(Result.isFailure(replay));
        expect(replay.failure._tag).toBe("OAuthStateNotFoundError");
      }),
    );
  });

  it("refuses a code issued for another PKCE challenge", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        const user = yield* fake.addUser(email, undefined);
        const oauth = yield* Auth.OAuth.OAuthService;
        const { state } = yield* oauth.generateAuthorizationUrl("authkit");
        const result = yield* Effect.result(
          oauth.signInWithCallback(state, fake.authorizationCode(user.id, "another-challenge")),
        );
        assert(Result.isFailure(result));
        expect(result.failure._tag).toBe("OAuthProviderError");
      }),
    );
  });

  it("refuses an expired state and an unknown provider", async () => {
    await run((fake) =>
      Effect.gen(function* () {
        const user = yield* fake.addUser(email, undefined);
        const oauth = yield* Auth.OAuth.OAuthService;
        const unknown = yield* Effect.result(oauth.generateAuthorizationUrl("myspace"));
        assert(Result.isFailure(unknown));
        const { url, state } = yield* oauth.generateAuthorizationUrl("connection:conn_1");
        expect(new URL(url).searchParams.get("connection_id")).toBe("conn_1");
        yield* TestClock.adjust(11 * MINUTE);
        const code = fake.authorizationCode(
          user.id,
          new URL(url).searchParams.get("code_challenge") ?? "",
        );
        const late = yield* Effect.result(oauth.signInWithCallback(state, code));
        assert(Result.isFailure(late));
        expect(late.failure._tag).toBe("OAuthStateExpiredError");
      }),
    );
  });

  it("starts SSO from a connection or organization id only", async () => {
    await run(() =>
      Effect.gen(function* () {
        const sso = yield* Auth.SsoService;
        const org = yield* sso.signIn({ providerId: "org_1" });
        expect(new URL(org.url).searchParams.get("organization_id")).toBe("org_1");
        const byEmail = yield* Effect.result(sso.signIn({ email }));
        assert(Result.isFailure(byEmail));
        expect(byEmail.failure._tag).toBe("SsoError");
      }),
    );
  });
});

describe("Authorization", () => {
  it("gives the current session's user its WorkOS roles", async () => {
    await run(
      () =>
        Effect.gen(function* () {
          const { session, user } = yield* signUpAndIn();
          assert(session !== undefined);
          const resolved = yield* Effect.gen(function* () {
            const resolver = yield* Auth.EntityResolver;
            return yield* resolver.resolve([
              Auth.Entity.ref("User", user.id),
              Auth.Entity.ref("User", "user_someone_else"),
            ]);
          }).pipe(
            Effect.provide(
              Backend.Authorization.entityResolverLayer({ roleHierarchy: { admin: ["member"] } }),
            ),
            Effect.provideService(Auth.CurrentSession, session),
          );
          const caller = resolved.find((e) => e.ref.type === "User");
          expect(caller?.ref.id).toBe(user.id);
          expect(caller?.parents.map((p) => p.id)).toEqual(["admin", "billing"]);
          expect(resolved.some((e) => e.ref.id === "user_someone_else")).toBe(false);
          expect(resolved.find((e) => e.ref.id === "admin")?.parents.map((p) => p.id)).toEqual([
            "member",
          ]);
        }),
      { fake: { role: "admin", roles: ["admin", "billing"] } },
    );
  });
});

describe("Seal", () => {
  const sealer = (passwords: ReadonlyArray<string>) =>
    Backend.Seal.make(passwords.map((p) => Redacted.make(p))).pipe(
      Effect.provide(Auth.PlatformCrypto.layer),
    );
  const a = "a".repeat(32);
  const b = "b".repeat(32);

  it("opens what it sealed, and nothing tampered with or sealed by another key", async () => {
    await Effect.runPromise(
      Effect.gen(function* () {
        const one = yield* sealer([a]);
        const other = yield* sealer([b]);
        const sealed = yield* one.seal("payload");
        expect(Option.getOrUndefined(yield* one.open(sealed))).toBe("payload");
        expect(Option.isNone(yield* other.open(sealed))).toBe(true);
        const [prefix, kid, body] = sealed.split("~");
        const flipped = `${prefix}~${kid}~${body.slice(0, 20)}${body[20] === "A" ? "B" : "A"}${body.slice(21)}`;
        expect(Option.isNone(yield* one.open(flipped))).toBe(true);
        expect(Option.isNone(yield* one.open("payload"))).toBe(true);
        expect(yield* one.seal("payload")).not.toBe(sealed);
      }),
    );
  });

  it("keeps opening a rotated-out password's cookies", async () => {
    await Effect.runPromise(
      Effect.gen(function* () {
        const old = yield* (yield* sealer([a])).seal("old");
        const rotated = yield* sealer([b, a]);
        expect(Option.getOrUndefined(yield* rotated.open(old))).toBe("old");
        const fresh = yield* rotated.seal("new");
        expect(Option.isNone(yield* (yield* sealer([a])).open(fresh))).toBe(true);
      }),
    );
  });

  it("refuses a password under 32 bytes", async () => {
    const result = await Effect.runPromise(Effect.result(sealer(["short"])));
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("CookiePasswordError");
  });
});
