import { assert, describe, expect, it } from "vite-plus/test";
import { Array as Arr, Effect, Layer, Redacted } from "effect";
import { EmailPasswordService } from "../email/EmailPassword.ts";
import { Hooks } from "../Hooks.ts";
import { IdentifierStore, memoryIdentifierStore } from "../Identifier.ts";
import { JwtService } from "../Jwt.ts";
import { MultiFactorService } from "../multifactor/MultiFactor.ts";
import { OtpSecondFactorService } from "../multifactor/OtpSecondFactor.ts";
import { GoogleProvider, OAuthService } from "../oauth/index.ts";
import { mcpProviderPreset, OidcProviderService } from "../OidcProvider.ts";
import { PasswordHasher } from "../password/Password.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { SessionService } from "../SessionService.ts";
import { SessionStore } from "../SessionStore.ts";
import { TrustedDeviceService } from "../TrustedDevice.ts";
import type * as Types from "../Types.ts";
import { UserStore } from "../UserStore.ts";
import * as Testing from "./index.ts";

const register = <E, R>(
  suite: Testing.ConformanceSuite<E, R>,
  layer: () => Layer.Layer<R>,
): void => {
  describe(`${suite.contract} conformance over the memory store`, () => {
    Arr.forEach(suite.cases, (testCase) => {
      it(testCase.name, () => Effect.runPromise(testCase.run.pipe(Effect.provide(layer()))));
    });
  });
};

const table = Testing.memoryUserTable();
register(Testing.sessionStoreConformance(), () =>
  Layer.succeed(SessionStore, Testing.memorySessionStore()),
);
register(
  Testing.userStoreConformance({
    seedUser: (user: Types.User) => Effect.sync(() => void table.users.set(user.id, user)),
  }),
  () => Layer.succeed(UserStore, Testing.memoryUserStore(table)),
);
register(Testing.identifierStoreConformance(), () =>
  Layer.succeed(IdentifierStore, memoryIdentifierStore()),
);

const sessionConfig: Types.SessionConfig = {
  sessionExpiresIn: { activePeriod: 24 * 60 * 60 * 1000, idlePeriod: 60 * 60 * 1000 },
};

const services = Layer.mergeAll(
  EmailPasswordService.layer(),
  MultiFactorService.layer({ issuer: "Test" }),
  OtpSecondFactorService.layer({ sendOtp: () => Effect.void }),
  TrustedDeviceService.layer({ secret: Redacted.make("trusted-device-secret") }),
  OAuthService.layer({
    google: GoogleProvider({
      clientId: "client",
      clientSecret: Redacted.make("secret"),
      redirectUri: "https://app.test/callback/google",
    }),
  }),
  OidcProviderService.layer(
    mcpProviderPreset({
      issuer: "https://app.test/api/auth",
      loginPage: "https://app.test/login",
      consentPage: "https://app.test/consent",
      dynamicRegistration: {
        initialAccessToken: Redacted.make("initial-access-token"),
      },
    }),
  ),
).pipe(
  Layer.provideMerge(JwtService.layer({ issuer: "https://app.test" })),
  Layer.provideMerge(SessionService.layer(sessionConfig)),
  Layer.provideMerge(
    Layer.mergeAll(
      Testing.memoryStores,
      PasswordHasher.layer(),
      Hooks.Default,
      PlatformCrypto.layer,
    ),
  ),
);

describe("memoryStores", () => {
  it("builds the service graphs the docs examples need, and they run", async () => {
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const emailPassword = yield* EmailPasswordService;
        const signedUp = yield* emailPassword.signUp({
          email: "ada@example.com",
          password: "correct horse battery staple",
        });
        const signedIn = yield* emailPassword.signIn({
          email: "ada@example.com",
          password: "correct horse battery staple",
        });
        const jwt = yield* JwtService;
        const { token } = yield* jwt.sign(signedIn.user);
        const claims = yield* jwt.verify(token);
        const users = yield* UserStore;
        return { signedUp, signedIn, claims, stored: yield* users.get(signedUp.user.id) };
      }).pipe(Effect.provide(services)),
    );

    expect(result.signedIn.user.id).toBe(result.signedUp.user.id);
    expect(result.signedIn.session?.userId).toBe(result.signedUp.user.id);
    expect(result.claims["sub"]).toBe(result.signedUp.user.id);
    expect(result.stored?.id).toBe(result.signedUp.user.id);
  });

  it("starts empty on every build", async () => {
    const count = SessionStore.use((store) =>
      store
        .create({
          id: "s",
          userId: "u",
          createdAt: new Date(),
          lastActivityAt: new Date(),
          expiresAt: new Date(),
          attributes: {},
        })
        .pipe(
          Effect.flatMap(() => store.listByUserId("u")),
          Effect.map((sessions) => sessions.length),
        ),
    );
    expect(await Effect.runPromise(count.pipe(Effect.provide(Testing.memoryStores)))).toBe(1);
    expect(await Effect.runPromise(count.pipe(Effect.provide(Testing.memoryStores)))).toBe(1);
  });

  it("shares one user table across the user-writing stores", async () => {
    const shared = Testing.memoryUserTable();
    const emailPassword = Testing.memoryEmailPasswordStore(shared);
    const oauthUsers = Testing.memoryOAuthUserStore(shared);
    const accounts = Testing.memoryOAuthAccountStore(shared);
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const { user } = yield* emailPassword.createUser({ name: "Ada" });
        assert(accounts.hasPassword !== undefined, "the memory store implements hasPassword");
        assert(oauthUsers.updateUser !== undefined, "the memory store implements updateUser");
        const before = yield* accounts.hasPassword(user.id);
        yield* emailPassword.setPasswordHash(user.id, "hash");
        return {
          user,
          before,
          after: yield* accounts.hasPassword(user.id),
          viaOAuth: yield* oauthUsers.getUser(user.id),
          viaUserStore: yield* Testing.memoryUserStore(shared).get(user.id),
          renamed: yield* oauthUsers.updateUser(user.id, { name: "Ada L." }),

          cleared: yield* emailPassword
            .clearPasswordHash(user.id)
            .pipe(Effect.andThen(emailPassword.getPasswordHash(user.id))),
        };
      }),
    );
    expect(result.before).toBe(false);
    expect(result.after).toBe(true);
    expect(result.viaOAuth).toEqual(result.user);
    expect(result.viaUserStore).toEqual(result.user);
    expect(result.renamed.name).toBe("Ada L.");
    expect(result.cleared).toBeNull();
  });

  it("the JWT key store makes the newest key active and lists them all", async () => {
    const store = Testing.memoryJwtKeyStore();
    const key = (id: string) => ({
      id,
      algorithm: "ES256" as const,
      publicKeyJwk: {},
      privateKeyPem: "",
      createdAt: 0,
    });
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const empty = yield* store.getActive();
        yield* store.create(key("old"));
        yield* store.create(key("new"));
        return { empty, active: yield* store.getActive(), listed: yield* store.list() };
      }),
    );
    expect(result.empty).toBeNull();
    expect(result.active?.id).toBe("new");
    expect(result.listed.map((pair) => pair.id)).toEqual(["old", "new"]);
  });
});
