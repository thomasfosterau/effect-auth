import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { UserNotFoundError, SessionNotFoundError } from "./Errors.js";
import { Hooks } from "./Hooks.js";
import { SessionManagerLayer, SessionStoreTag, UserStoreTag } from "./Session.js";
import { UserServiceLayer, UserServiceStoreTag } from "./User.js";
import { AuthLifecycleServiceTag } from "./AuthLifecycle.js";
import { EmailPasswordStoreTag } from "./EmailPassword.js";
import { PasswordHasherTag } from "./Password.js";
import { EmailVerificationServiceTag, EmailVerificationStoreTag } from "./EmailVerification.js";
import {
  PasswordResetServiceTag,
  PasswordResetStoreTag,
  PasswordResetUserStoreTag,
} from "./PasswordReset.js";
import { makeAuthWebHandler, type AuthServices } from "./HttpServer.js";
import {
  formatSiweMessage,
  parseSiweMessage,
  SiweServiceLayer,
  SiweNonceStoreTag,
  SiweUserStoreTag,
  SiweVerifierTag,
  SiweError,
  type SiweMessage,
  type SiweNonce,
  type SiweNonceStore,
  type SiweUserStore,
  type SiweVerifier,
} from "./Siwe.js";
import type * as Types from "./Types.js";

const ADDRESS = "0x1234567890AbcdEF1234567890aBcdef12345678";

const baseMessage = (nonce: string): SiweMessage => ({
  domain: "app.test",
  address: ADDRESS,
  statement: "Sign in to App",
  uri: "https://app.test",
  version: "1",
  chainId: 1,
  nonce,
  issuedAt: "2026-01-01T00:00:00.000Z",
});

describe("SIWE message format/parse", () => {
  it("round-trips every field", async () => {
    const message: SiweMessage = {
      ...baseMessage("abc123def456"),
      expirationTime: "2100-01-01T00:00:00.000Z",
      notBefore: "2020-01-01T00:00:00.000Z",
      requestId: "req-1",
      resources: ["https://app.test/tos", "ipfs://Qm123"],
    };
    const parsed = await Effect.runPromise(parseSiweMessage(formatSiweMessage(message)));
    expect(parsed).toEqual(message);
  });

  it("round-trips without optional fields", async () => {
    const message: SiweMessage = {
      domain: "app.test",
      address: ADDRESS,
      uri: "https://app.test",
      version: "1",
      chainId: 137,
      nonce: "n0nc3n0nc3",
      issuedAt: "2026-01-01T00:00:00.000Z",
    };
    const parsed = await Effect.runPromise(parseSiweMessage(formatSiweMessage(message)));
    expect(parsed).toEqual(message);
  });

  it("rejects malformed messages", async () => {
    for (const bad of [
      "not a siwe message",
      "app.test wants you to sign in with your Ethereum account:\nnot-an-address\n\nURI: x",
      formatSiweMessage(baseMessage("n1")).replace("Version: 1", "Version: 2"),
    ]) {
      const err = await Effect.runPromise(Effect.flip(parseSiweMessage(bad)));
      expect(err).toBeInstanceOf(SiweError);
    }
  });
});

// --- HTTP layer ----------------------------------------------------------------

/**
 * Web handler fixture with a FAKE verifier (accepts signature "valid-sig")
 * so the HTTP contract can be exercised without secp256k1. The real
 * cryptographic path is covered end to end in @effect-auth/siwe.
 */
const makeHttpFixture = () => {
  const usersById = new Map<string, Types.User>();
  const usersByWallet = new Map<string, Types.User>();
  const sessions = new Map<string, Types.Session>();
  const nonces = new Map<string, SiweNonce>();
  let userSeq = 0;

  const nonceStore: SiweNonceStore = {
    create: (n) => Effect.sync(() => (nonces.set(n.nonce, n), n)),
    get: (nonce) => Effect.succeed(nonces.get(nonce) ?? null),
    delete: (nonce) => Effect.sync(() => void nonces.delete(nonce)),
  };
  const siweUserStore: SiweUserStore = {
    getUserByWalletAddress: (walletAddress) =>
      Effect.succeed(usersByWallet.get(walletAddress) ?? null),
    createUser: ({ walletAddress }) =>
      Effect.sync(() => {
        const now = new Date();
        const user: Types.User = {
          id: `u${++userSeq}`,
          email: `${walletAddress}@wallet.invalid`,
          emailVerified: false,
          createdAt: now,
          updatedAt: now,
          attributes: { walletAddress },
        };
        usersById.set(user.id, user);
        usersByWallet.set(walletAddress, user);
        return user;
      }),
  };
  const fakeVerifier: SiweVerifier = {
    verifyMessage: ({ signature }) => Effect.succeed(signature === "valid-sig"),
  };

  const userStore = {
    get: (userId: string) => {
      const u = usersById.get(userId);
      return u ? Effect.succeed(u) : Effect.fail(new UserNotFoundError({ message: "nf", userId }));
    },
    getCredentials: (userId: string) =>
      Effect.fail(new UserNotFoundError({ message: "nc", userId })),
  };
  const userServiceStore = {
    get: userStore.get,
    getByEmail: () => Effect.succeed(null),
    update: (user: Types.User) => Effect.sync(() => (usersById.set(user.id, user), user)),
    delete: () => Effect.void,
  };
  const sessionStore = {
    create: (s: Types.Session) => Effect.sync(() => (sessions.set(s.id, s), s)),
    get: (id: string) => {
      const s = sessions.get(id);
      return s
        ? Effect.succeed(s)
        : Effect.fail(new SessionNotFoundError({ message: "nf", sessionId: id }));
    },
    update: (s: Types.Session) => Effect.sync(() => (sessions.set(s.id, s), s)),
    delete: (id: string) => Effect.sync(() => void sessions.delete(id)),
    deleteByUserId: () => Effect.void,
    listByUserId: () => Effect.succeed([]),
  };

  const base = Layer.mergeAll(
    SessionManagerLayer({
      sessionExpiresIn: { activePeriod: 3600_000, idlePeriod: 3600_000 },
    }).pipe(
      Layer.provide(
        Layer.mergeAll(
          Layer.succeed(SessionStoreTag)(sessionStore as never),
          Layer.succeed(UserStoreTag)(userStore),
        ),
      ),
    ),
    UserServiceLayer().pipe(Layer.provide(Layer.succeed(UserServiceStoreTag)(userServiceStore))),
    Layer.succeed(UserServiceStoreTag)(userServiceStore),
    Hooks.Default,
    Layer.succeed(AuthLifecycleServiceTag)(undefined as never),
    Layer.succeed(EmailPasswordStoreTag)(undefined as never),
    Layer.succeed(PasswordHasherTag)(undefined as never),
    Layer.succeed(EmailVerificationServiceTag)(undefined as never),
    Layer.succeed(EmailVerificationStoreTag)(undefined as never),
    Layer.succeed(PasswordResetServiceTag)(undefined as never),
    Layer.succeed(PasswordResetStoreTag)(undefined as never),
    Layer.succeed(PasswordResetUserStoreTag)(undefined as never),
  );

  const siweLayer = Layer.mergeAll(
    SiweServiceLayer({ domain: "app.test" }),
    Layer.succeed(SiweNonceStoreTag)(nonceStore),
    Layer.succeed(SiweUserStoreTag)(siweUserStore),
    Layer.succeed(SiweVerifierTag)(fakeVerifier),
  );

  const withSiwe = Layer.mergeAll(base, siweLayer) as Layer.Layer<AuthServices>;
  return {
    handler: makeAuthWebHandler({
      services: withSiwe,
      cookie: { secure: false, lastLoginMethod: true },
    }).handler,
    handlerWithoutSiwe: makeAuthWebHandler({
      services: base as Layer.Layer<AuthServices>,
      cookie: { secure: false },
    }).handler,
  };
};

const post = (path: string, body?: unknown): Request =>
  new Request(`http://test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });

describe("HTTP SIWE endpoints", () => {
  it("issues a nonce, signs in, and stamps the last-method cookie", async () => {
    const fx = makeHttpFixture();

    const nonceRes = await fx.handler(post("/siwe/nonce"));
    expect(nonceRes.status).toBe(200);
    const { nonce } = (await nonceRes.json()) as { nonce: string; expiresAt: number };
    expect(nonce.length).toBeGreaterThanOrEqual(8);

    const message = formatSiweMessage(baseMessage(nonce));
    const signIn = await fx.handler(post("/sign-in/siwe", { message, signature: "valid-sig" }));
    expect(signIn.status).toBe(200);
    const body = (await signIn.json()) as { user: { attributes: Record<string, unknown> } };
    expect(body.user.attributes["walletAddress"]).toBe(ADDRESS.toLowerCase());

    const cookies = signIn.headers.getSetCookie();
    expect(cookies.some((c) => c.startsWith("conduit_session="))).toBe(true);
    // The last-method hint is page-readable (no HttpOnly) and carries "siwe".
    const lastMethod = cookies.find((c) => c.startsWith("conduit_session_last_method="));
    expect(lastMethod).toBeDefined();
    expect(lastMethod).toContain("conduit_session_last_method=siwe");
    expect(lastMethod!.toLowerCase()).not.toContain("httponly");

    // Nonces are single use.
    const replay = await fx.handler(post("/sign-in/siwe", { message, signature: "valid-sig" }));
    expect(replay.status).toBe(401);
  });

  it("rejects an invalid signature with 401", async () => {
    const fx = makeHttpFixture();
    const { nonce } = (await (await fx.handler(post("/siwe/nonce"))).json()) as { nonce: string };
    const message = formatSiweMessage(baseMessage(nonce));
    const res = await fx.handler(post("/sign-in/siwe", { message, signature: "bad-sig" }));
    expect(res.status).toBe(401);
  });

  it("returns 404 when SIWE is not configured", async () => {
    const fx = makeHttpFixture();
    expect((await fx.handlerWithoutSiwe(post("/siwe/nonce"))).status).toBe(404);
    expect(
      (await fx.handlerWithoutSiwe(post("/sign-in/siwe", { message: "m", signature: "s" }))).status,
    ).toBe(404);
  });
});

describe("nonce generation", () => {
  it("issues unique nonces", async () => {
    const fx = makeHttpFixture();
    const nonces = new Set<string>();
    for (let i = 0; i < 10; i++) {
      const { nonce } = (await (await fx.handler(post("/siwe/nonce"))).json()) as {
        nonce: string;
      };
      nonces.add(nonce);
    }
    expect(nonces.size).toBe(10);
  });
});
