import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import { AuthError, OAuthLastCredentialError, OAuthEmailMismatchError } from "./Errors.js";
import { Hooks } from "./Hooks.js";
import { SessionManager } from "./Session.js";
import {
  makeOAuthProvider,
  makeOAuthService,
  makeAes256GcmCipher,
  verifyIdToken,
  discoverOAuthEndpoints,
  makeAppleClientSecret,
  OAuthStateStore,
  OAuthAccountStore,
  OAuthUserStore,
  type OAuthState,
  type OAuthAccount,
  type OAuthProvider,
  type OAuthTokenResponse,
  AppleProvider,
  FacebookProvider,
  TwitterProvider,
  LinkedInProvider,
  TwitchProvider,
  SpotifyProvider,
  GitLabProvider,
  RedditProvider,
  DropboxProvider,
  NotionProvider,
  SlackProvider,
  ZoomProvider,
  TikTokProvider,
  RobloxProvider,
  KickProvider,
  HuggingFaceProvider,
} from "./OAuth.js";

/** In-memory OAuth state store for authorization-URL tests. */
const StateStoreLive = () => {
  const map = new Map<string, OAuthState>();
  return Layer.succeed(OAuthStateStore, {
    create: (s: OAuthState) =>
      Effect.sync(() => {
        map.set(s.state, s);
        return s;
      }),
    get: (state: string) => {
      const v = map.get(state);
      return v ? Effect.succeed(v) : Effect.fail(new AuthError({ message: "not found" }));
    },
    delete: (state: string) =>
      Effect.sync(() => {
        map.delete(state);
      }),
  });
};

const runWithState = <A, E>(eff: Effect.Effect<A, E, OAuthStateStore>): Promise<A> =>
  Effect.runPromise(eff.pipe(Effect.provide(StateStoreLive())));

/** A single captured fetch call. */
interface Captured {
  url: string;
  method: string;
  headers: Headers;
  body: string | null;
}

/**
 * Swap `globalThis.fetch` for `handler`, run `thunk`, and restore. Records
 * every request into the returned array.
 */
const withFetch = async <A>(
  handler: (url: string, init: RequestInit | undefined) => Response,
  thunk: (calls: Captured[]) => Promise<A>,
): Promise<A> => {
  const calls: Captured[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({
      url,
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers),
      body: typeof init?.body === "string" ? init.body : null,
    });
    return Promise.resolve(handler(url, init));
  }) as typeof fetch;
  try {
    return await thunk(calls);
  } finally {
    globalThis.fetch = original;
  }
};

const json = (value: unknown): Response =>
  new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });

const CLIENT = {
  clientId: "client-123",
  clientSecret: "secret-xyz",
  redirectUri: "https://app/cb",
};

// --- Provider catalogue ------------------------------------------------------

const CATALOGUE: ReadonlyArray<{
  name: string;
  provider: OAuthProvider;
  authorizationHost: string;
  clientParam: string;
}> = [
  {
    name: "apple",
    provider: AppleProvider(CLIENT),
    authorizationHost: "appleid.apple.com",
    clientParam: "client_id",
  },
  {
    name: "facebook",
    provider: FacebookProvider(CLIENT),
    authorizationHost: "facebook.com",
    clientParam: "client_id",
  },
  {
    name: "twitter",
    provider: TwitterProvider(CLIENT),
    authorizationHost: "twitter.com",
    clientParam: "client_id",
  },
  {
    name: "linkedin",
    provider: LinkedInProvider(CLIENT),
    authorizationHost: "linkedin.com",
    clientParam: "client_id",
  },
  {
    name: "twitch",
    provider: TwitchProvider(CLIENT),
    authorizationHost: "id.twitch.tv",
    clientParam: "client_id",
  },
  {
    name: "spotify",
    provider: SpotifyProvider(CLIENT),
    authorizationHost: "accounts.spotify.com",
    clientParam: "client_id",
  },
  {
    name: "gitlab",
    provider: GitLabProvider(CLIENT),
    authorizationHost: "gitlab.com",
    clientParam: "client_id",
  },
  {
    name: "reddit",
    provider: RedditProvider(CLIENT),
    authorizationHost: "reddit.com",
    clientParam: "client_id",
  },
  {
    name: "dropbox",
    provider: DropboxProvider(CLIENT),
    authorizationHost: "dropbox.com",
    clientParam: "client_id",
  },
  {
    name: "notion",
    provider: NotionProvider(CLIENT),
    authorizationHost: "api.notion.com",
    clientParam: "client_id",
  },
  {
    name: "slack",
    provider: SlackProvider(CLIENT),
    authorizationHost: "slack.com",
    clientParam: "client_id",
  },
  {
    name: "zoom",
    provider: ZoomProvider(CLIENT),
    authorizationHost: "zoom.us",
    clientParam: "client_id",
  },
  {
    name: "tiktok",
    provider: TikTokProvider(CLIENT),
    authorizationHost: "tiktok.com",
    clientParam: "client_key",
  },
  {
    name: "roblox",
    provider: RobloxProvider(CLIENT),
    authorizationHost: "apis.roblox.com",
    clientParam: "client_id",
  },
  {
    name: "kick",
    provider: KickProvider(CLIENT),
    authorizationHost: "id.kick.com",
    clientParam: "client_id",
  },
  {
    name: "huggingface",
    provider: HuggingFaceProvider(CLIENT),
    authorizationHost: "huggingface.co",
    clientParam: "client_id",
  },
];

describe("OAuth provider catalogue", () => {
  for (const entry of CATALOGUE) {
    it(`${entry.name}: builds an authorization URL with state and client id`, async () => {
      const result = await runWithState(entry.provider.generateAuthorizationUrl());
      const url = new URL(result.url);
      expect(url.host).toContain(entry.authorizationHost);
      expect(url.searchParams.get(entry.clientParam)).toBe(CLIENT.clientId);
      expect(url.searchParams.get("redirect_uri")).toBe(CLIENT.redirectUri);
      expect(url.searchParams.get("state")).toBe(result.state);
      expect(url.searchParams.get("response_type")).toBe("code");
    });
  }

  it("apple: requests form_post response mode and carries an OIDC nonce", async () => {
    const result = await runWithState(AppleProvider(CLIENT).generateAuthorizationUrl());
    const url = new URL(result.url);
    expect(url.searchParams.get("response_mode")).toBe("form_post");
    expect(url.searchParams.get("nonce")).toBeTruthy();
  });

  it("reddit: appends duration=permanent", async () => {
    const result = await runWithState(RedditProvider(CLIENT).generateAuthorizationUrl());
    expect(new URL(result.url).searchParams.get("duration")).toBe("permanent");
  });

  it("twitter: emits a PKCE challenge", async () => {
    const result = await runWithState(TwitterProvider(CLIENT).generateAuthorizationUrl());
    expect(new URL(result.url).searchParams.get("code_challenge")).toBeTruthy();
    expect(result.codeVerifier).toBeTruthy();
  });
});

// --- Token exchange auth methods --------------------------------------------

describe("OAuth token exchange", () => {
  it("basic auth: sends HTTP Basic and omits client_secret from the body", async () => {
    const token: OAuthTokenResponse = { access_token: "at", token_type: "bearer" };
    await withFetch(
      () => json(token),
      async (calls) => {
        const result = await Effect.runPromise(SpotifyProvider(CLIENT).exchangeCode("the-code"));
        expect(result.access_token).toBe("at");
        const call = calls[0]!;
        const expected = `Basic ${Buffer.from(`${CLIENT.clientId}:${CLIENT.clientSecret}`).toString("base64")}`;
        expect(call.headers.get("authorization")).toBe(expected);
        expect(call.body).not.toContain("client_secret");
        expect(call.body).toContain("client_id=client-123");
      },
    );
  });

  it("body auth (default): sends client_secret in the form body", async () => {
    const token: OAuthTokenResponse = { access_token: "at", token_type: "bearer" };
    await withFetch(
      () => json(token),
      async (calls) => {
        await Effect.runPromise(GitLabProvider(CLIENT).exchangeCode("the-code", "verifier"));
        const call = calls[0]!;
        expect(call.headers.get("authorization")).toBeNull();
        expect(call.body).toContain("client_secret=secret-xyz");
        expect(call.body).toContain("code_verifier=verifier");
      },
    );
  });
});

// --- Provider-specific profile mapping --------------------------------------

describe("OAuth profile mapping", () => {
  const getProfile = (provider: OAuthProvider, body: unknown, method = "GET") =>
    withFetch(
      () => json(body),
      async (calls) => {
        const info = await Effect.runPromise(
          provider.getProfile({ access_token: "at", token_type: "bearer" }),
        );
        expect(calls[0]!.method).toBe(method);
        return info;
      },
    );

  it("facebook: flattens picture.data.url", async () => {
    const info = await getProfile(FacebookProvider(CLIENT), {
      id: "fb-1",
      name: "Zed",
      email: "z@e.com",
      picture: { data: { url: "https://img/z.jpg" } },
    });
    expect(info).toMatchObject({
      id: "fb-1",
      name: "Zed",
      email: "z@e.com",
      picture: "https://img/z.jpg",
    });
  });

  it("twitter: unwraps the data envelope and has no email", async () => {
    const info = await getProfile(TwitterProvider(CLIENT), {
      data: { id: "tw-1", name: "Bird", profile_image_url: "https://img/b.jpg" },
    });
    expect(info).toMatchObject({ id: "tw-1", name: "Bird", picture: "https://img/b.jpg" });
    expect(info.email).toBeUndefined();
  });

  it("spotify: maps display_name and images[0].url", async () => {
    const info = await getProfile(SpotifyProvider(CLIENT), {
      id: "sp-1",
      display_name: "DJ",
      email: "dj@e.com",
      images: [{ url: "https://img/dj.jpg" }],
    });
    expect(info).toMatchObject({
      id: "sp-1",
      name: "DJ",
      email: "dj@e.com",
      picture: "https://img/dj.jpg",
    });
  });

  it("dropbox: uses a POST userinfo request and account_id", async () => {
    const info = await getProfile(
      DropboxProvider(CLIENT),
      { account_id: "db-1", email: "d@e.com", name: { display_name: "Drop" } },
      "POST",
    );
    expect(info).toMatchObject({ id: "db-1", email: "d@e.com", name: "Drop" });
  });

  it("kick: pulls the first element of data[]", async () => {
    const info = await getProfile(KickProvider(CLIENT), {
      data: [
        {
          user_id: "k-1",
          name: "Streamer",
          email: "k@e.com",
          profile_picture: "https://img/k.jpg",
        },
      ],
    });
    expect(info).toMatchObject({
      id: "k-1",
      name: "Streamer",
      email: "k@e.com",
      picture: "https://img/k.jpg",
    });
  });

  it("tiktok: reads data.user and open_id", async () => {
    const info = await getProfile(TikTokProvider(CLIENT), {
      data: { user: { open_id: "tt-1", display_name: "Toker", avatar_url: "https://img/t.jpg" } },
    });
    expect(info).toMatchObject({ id: "tt-1", name: "Toker", picture: "https://img/t.jpg" });
  });

  it("zoom: joins first_name and last_name", async () => {
    const info = await getProfile(ZoomProvider(CLIENT), {
      id: "z-1",
      first_name: "Ada",
      last_name: "Lovelace",
      email: "a@e.com",
    });
    expect(info).toMatchObject({ id: "z-1", name: "Ada Lovelace", email: "a@e.com" });
  });
});

// --- OIDC id_token verification ---------------------------------------------

interface SigningKey {
  privateKey: crypto.KeyObject;
  jwks: { keys: unknown[] };
}

const makeSigningKey = (alg: "RS256" | "ES256" | "EdDSA", kid = "test-kid"): SigningKey => {
  const { publicKey, privateKey } =
    alg === "RS256"
      ? crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
      : alg === "ES256"
        ? crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
        : crypto.generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  return { privateKey, jwks: { keys: [{ ...jwk, kid, alg, use: "sig" }] } };
};

const b64u = (obj: unknown): string =>
  Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");

const signIdToken = (
  alg: "RS256" | "ES256" | "EdDSA",
  key: crypto.KeyObject,
  claims: Record<string, unknown>,
  kid = "test-kid",
): string => {
  const signingInput = `${b64u({ alg, kid, typ: "JWT" })}.${b64u(claims)}`;
  const data = Buffer.from(signingInput);
  const signature =
    alg === "RS256"
      ? crypto.sign("sha256", data, key)
      : alg === "ES256"
        ? crypto.sign("sha256", data, { key, dsaEncoding: "ieee-p1363" })
        : crypto.sign(null, data, key);
  return `${signingInput}.${signature.toString("base64url")}`;
};

const JWKS_URL = "https://idp/jwks";
const baseClaims = (now: number) => ({
  iss: "https://idp",
  aud: "client-123",
  sub: "user-1",
  email: "u@idp.com",
  email_verified: true,
  name: "Ida",
  exp: Math.floor(now / 1000) + 600,
  iat: Math.floor(now / 1000),
});

describe("verifyIdToken", () => {
  const now = 1_700_000_000_000;

  for (const alg of ["RS256", "ES256", "EdDSA"] as const) {
    it(`verifies a valid ${alg} id_token`, async () => {
      const key = makeSigningKey(alg);
      const token = signIdToken(alg, key.privateKey, baseClaims(now));
      const claims = await withFetch(
        () => json(key.jwks),
        () =>
          Effect.runPromise(
            verifyIdToken(token, {
              provider: "idp",
              jwksEndpoint: JWKS_URL,
              issuer: "https://idp",
              audience: "client-123",
              now,
            }),
          ),
      );
      expect(claims["sub"]).toBe("user-1");
      expect(claims["email"]).toBe("u@idp.com");
    });
  }

  const expectFailure = async (
    token: string,
    jwks: { keys: unknown[] },
    params: Parameters<typeof verifyIdToken>[1],
  ) =>
    withFetch(
      () => json(jwks),
      () => Effect.runPromise(Effect.flip(verifyIdToken(token, params))),
    );

  it("rejects a tampered signature", async () => {
    const key = makeSigningKey("ES256");
    const token = signIdToken("ES256", key.privateKey, baseClaims(now));
    const tampered = `${token.slice(0, -4)}AAAA`;
    const err = await expectFailure(tampered, key.jwks, {
      provider: "idp",
      jwksEndpoint: JWKS_URL,
      issuer: "https://idp",
      audience: "client-123",
      now,
    });
    expect(err.message).toMatch(/signature/i);
  });

  it("rejects an issuer mismatch", async () => {
    const key = makeSigningKey("ES256");
    const token = signIdToken("ES256", key.privateKey, baseClaims(now));
    const err = await expectFailure(token, key.jwks, {
      provider: "idp",
      jwksEndpoint: JWKS_URL,
      issuer: "https://evil",
      audience: "client-123",
      now,
    });
    expect(err.message).toMatch(/issuer/i);
  });

  it("rejects an audience mismatch", async () => {
    const key = makeSigningKey("ES256");
    const token = signIdToken("ES256", key.privateKey, baseClaims(now));
    const err = await expectFailure(token, key.jwks, {
      provider: "idp",
      jwksEndpoint: JWKS_URL,
      issuer: "https://idp",
      audience: "other-client",
      now,
    });
    expect(err.message).toMatch(/audience/i);
  });

  it("rejects an expired token", async () => {
    const key = makeSigningKey("ES256");
    const token = signIdToken("ES256", key.privateKey, {
      ...baseClaims(now),
      exp: Math.floor(now / 1000) - 10,
    });
    const err = await expectFailure(token, key.jwks, {
      provider: "idp",
      jwksEndpoint: JWKS_URL,
      issuer: "https://idp",
      audience: "client-123",
      now,
    });
    expect(err.message).toMatch(/expired/i);
  });

  it("rejects a nonce mismatch", async () => {
    const key = makeSigningKey("ES256");
    const token = signIdToken("ES256", key.privateKey, { ...baseClaims(now), nonce: "real" });
    const err = await expectFailure(token, key.jwks, {
      provider: "idp",
      jwksEndpoint: JWKS_URL,
      issuer: "https://idp",
      audience: "client-123",
      nonce: "expected",
      now,
    });
    expect(err.message).toMatch(/nonce/i);
  });
});

describe("getProfile via id_token", () => {
  it("resolves the profile from a verified id_token instead of userinfo", async () => {
    const now = 1_700_000_000_000;
    const key = makeSigningKey("ES256");
    // getProfile validates against the real clock, so use a far-future exp.
    const token = signIdToken("ES256", key.privateKey, { ...baseClaims(now), exp: 4_102_444_800 });
    const provider = makeOAuthProvider("idp", {
      clientId: "client-123",
      clientSecret: "s",
      redirectUri: "https://app/cb",
      authorizationEndpoint: "https://idp/authorize",
      tokenEndpoint: "https://idp/token",
      jwksEndpoint: JWKS_URL,
      issuer: "https://idp",
      getUserInfoFromIdToken: true,
      scopes: ["openid", "email"],
    });

    const info = await withFetch(
      () => json(key.jwks),
      (calls) =>
        Effect.runPromise(
          provider.getProfile({ access_token: "at", token_type: "bearer", id_token: token }),
        ).then((result) => {
          // Only the JWKS was fetched — no userinfo call.
          expect(calls.every((c) => c.url === JWKS_URL)).toBe(true);
          return result;
        }),
    );
    expect(info).toMatchObject({ id: "user-1", email: "u@idp.com", name: "Ida" });
  });
});

// --- Generic OIDC discovery --------------------------------------------------

describe("discoverOAuthEndpoints", () => {
  it("populates endpoints from an openid-configuration document", async () => {
    const doc = {
      issuer: "https://idp",
      authorization_endpoint: "https://idp/authorize",
      token_endpoint: "https://idp/token",
      userinfo_endpoint: "https://idp/userinfo",
      jwks_uri: "https://idp/jwks",
    };
    const endpoints = await withFetch(
      (url) => {
        expect(url).toBe("https://idp/.well-known/openid-configuration");
        return json(doc);
      },
      () => Effect.runPromise(discoverOAuthEndpoints("https://idp/")),
    );
    expect(endpoints).toEqual({
      issuer: "https://idp",
      authorizationEndpoint: "https://idp/authorize",
      tokenEndpoint: "https://idp/token",
      userInfoEndpoint: "https://idp/userinfo",
      jwksEndpoint: "https://idp/jwks",
    });

    // The discovered endpoints slot straight into a generic provider.
    const provider = makeOAuthProvider("generic", {
      ...endpoints,
      clientId: "c",
      clientSecret: "s",
      redirectUri: "https://app/cb",
      scopes: ["openid"],
    });
    expect(provider.config.authorizationEndpoint).toBe("https://idp/authorize");
  });

  it("fails when the document lacks required endpoints", async () => {
    const err = await withFetch(
      () => json({ issuer: "https://idp" }),
      () => Effect.runPromise(Effect.flip(discoverOAuthEndpoints("https://idp"))),
    );
    expect(err.message).toMatch(/missing/i);
  });
});

// --- Apple client secret -----------------------------------------------------

describe("makeAppleClientSecret", () => {
  it("produces a verifiable ES256 JWT with Apple's claims", async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const pem = privateKey.export({ format: "pem", type: "pkcs8" }) as string;
    const now = 1_700_000_000_000;
    const secret = await Effect.runPromise(
      makeAppleClientSecret({
        teamId: "TEAM123",
        clientId: "com.example.app",
        keyId: "KEY123",
        privateKey: pem,
        now,
      }),
    );

    const [headerSeg, payloadSeg, signatureSeg] = secret.split(".") as [string, string, string];
    const header = JSON.parse(Buffer.from(headerSeg, "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(payloadSeg, "base64url").toString("utf8"));
    expect(header).toMatchObject({ alg: "ES256", kid: "KEY123" });
    expect(payload).toMatchObject({
      iss: "TEAM123",
      sub: "com.example.app",
      aud: "https://appleid.apple.com",
    });
    expect(payload.exp).toBeGreaterThan(payload.iat);

    const valid = crypto.verify(
      "sha256",
      Buffer.from(`${headerSeg}.${payloadSeg}`),
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(signatureSeg, "base64url"),
    );
    expect(valid).toBe(true);
  });
});

// --- Token encryption --------------------------------------------------------

const TEST_SECRET = "test-secret-for-aes-256-gcm-cipher";

describe("makeAes256GcmCipher", () => {
  it("encrypts and decrypts round-trip", async () => {
    const cipher = makeAes256GcmCipher(TEST_SECRET);
    const token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345";
    const encrypted = await Effect.runPromise(cipher.encrypt(token));
    expect(encrypted).not.toBe(token);
    expect(await Effect.runPromise(cipher.decrypt(encrypted))).toBe(token);
  });

  it("produces a different ciphertext on each call (random IV)", async () => {
    const cipher = makeAes256GcmCipher(TEST_SECRET);
    const e1 = await Effect.runPromise(cipher.encrypt("same-plaintext"));
    const e2 = await Effect.runPromise(cipher.encrypt("same-plaintext"));
    expect(e1).not.toBe(e2);
  });

  it("fails loudly on tampered ciphertext (GCM auth-tag)", async () => {
    const cipher = makeAes256GcmCipher(TEST_SECRET);
    const encrypted = await Effect.runPromise(cipher.encrypt("hello"));
    const buf = Buffer.from(encrypted, "base64url");
    buf[buf.length - 1] ^= 0xff;
    const err = await Effect.runPromise(Effect.flip(cipher.decrypt(buf.toString("base64url"))));
    expect(err._tag).toBe("AuthError");
    expect(err.message).toMatch(/decrypt/i);
  });

  it("fails on ciphertext that is too short", async () => {
    const cipher = makeAes256GcmCipher(TEST_SECRET);
    const err = await Effect.runPromise(Effect.flip(cipher.decrypt("dG9vc2hvcnQ")));
    expect(err._tag).toBe("AuthError");
  });
});

describe("OAuthService encryptTokens", () => {
  const makeAccountStore = () => {
    const stored = new Map<string, OAuthAccount>();
    const layer = Layer.succeed(OAuthAccountStore, {
      create: (a) =>
        Effect.sync(() => {
          stored.set(`${a.provider}:${a.providerId}`, a);
          return a;
        }),
      get: (p, id) => Effect.succeed(stored.get(`${p}:${id}`) ?? null),
      getByUserId: (uid) => Effect.succeed([...stored.values()].filter((a) => a.userId === uid)),
      update: (a) =>
        Effect.sync(() => {
          stored.set(`${a.provider}:${a.providerId}`, a);
          return a;
        }),
      linkToUser: (uid, a) =>
        Effect.sync(() => {
          stored.set(`${a.provider}:${a.providerId}`, { ...a, userId: uid });
        }),
      unlinkFromUser: (uid, p) =>
        Effect.sync(() => {
          for (const [k, v] of stored) if (v.userId === uid && v.provider === p) stored.delete(k);
        }),
      delete: (p, id) =>
        Effect.sync(() => {
          stored.delete(`${p}:${id}`);
        }),
    });
    return { stored, layer };
  };

  const githubProvider = makeOAuthProvider(
    "github",
    {
      clientId: "c",
      clientSecret: "s",
      redirectUri: "https://app/cb",
      authorizationEndpoint: "https://github.com/login/oauth/authorize",
      tokenEndpoint: "https://github.com/login/oauth/access_token",
      userInfoEndpoint: "https://api.github.com/user",
      scopes: ["user:email"],
    },
    false,
  );

  it("stores encrypted tokens and refreshAccessToken returns plaintext", async () => {
    const { stored, layer: accountStoreLive } = makeAccountStore();
    const cipher = makeAes256GcmCipher(TEST_SECRET);

    const PLAIN_ACCESS = "plain-access-token";
    const PLAIN_REFRESH = "plain-refresh-token";
    const NEW_ACCESS = "new-access-token-after-refresh";

    // Pre-populate store with encrypted tokens (as the service would have stored them).
    const encAccess = await Effect.runPromise(cipher.encrypt(PLAIN_ACCESS));
    const encRefresh = await Effect.runPromise(cipher.encrypt(PLAIN_REFRESH));
    stored.set("github:gh-1", {
      id: "acc-1",
      userId: "user-1",
      provider: "github",
      providerId: "gh-1",
      accessToken: encAccess,
      refreshToken: encRefresh,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });

    const service = await Effect.runPromise(
      makeOAuthService({ github: githubProvider }, { encryptTokens: { secret: TEST_SECRET } }),
    );

    let capturedRefreshToken: string | null = null;
    const tokenResp: OAuthTokenResponse = { access_token: NEW_ACCESS, token_type: "bearer" };

    const newAccessToken = await withFetch(
      (_url, init) => {
        if (typeof init?.body === "string") {
          capturedRefreshToken = new URLSearchParams(init.body).get("refresh_token");
        }
        return json(tokenResp);
      },
      () =>
        Effect.runPromise(
          service.refreshAccessToken("user-1", "github").pipe(Effect.provide(accountStoreLive)),
        ),
    );

    // HTTP call must use the decrypted refresh token.
    expect(capturedRefreshToken).toBe(PLAIN_REFRESH);
    // Returned access token must be plaintext.
    expect(newAccessToken).toBe(NEW_ACCESS);
    // Stored access token must be encrypted (not the raw plaintext).
    const updated = stored.get("github:gh-1")!;
    expect(updated.accessToken).not.toBe(NEW_ACCESS);
    // And it must decrypt to the new plaintext access token.
    expect(await Effect.runPromise(cipher.decrypt(updated.accessToken))).toBe(NEW_ACCESS);
  });

  it("default (no encryptTokens) stores tokens as plaintext", async () => {
    const { stored, layer: accountStoreLive } = makeAccountStore();

    const PLAIN_ACCESS = "plain-access-token";
    const PLAIN_REFRESH = "plain-refresh-token";
    const NEW_ACCESS = "new-access-token-after-refresh";

    stored.set("github:gh-1", {
      id: "acc-1",
      userId: "user-1",
      provider: "github",
      providerId: "gh-1",
      accessToken: PLAIN_ACCESS,
      refreshToken: PLAIN_REFRESH,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });

    const service = await Effect.runPromise(makeOAuthService({ github: githubProvider }));
    const tokenResp: OAuthTokenResponse = { access_token: NEW_ACCESS, token_type: "bearer" };

    const newAccessToken = await withFetch(
      () => json(tokenResp),
      () =>
        Effect.runPromise(
          service.refreshAccessToken("user-1", "github").pipe(Effect.provide(accountStoreLive)),
        ),
    );

    expect(newAccessToken).toBe(NEW_ACCESS);
    // Without encryption the stored token is the raw string.
    expect(stored.get("github:gh-1")!.accessToken).toBe(NEW_ACCESS);
  });

  it("accepts a custom TokenCipher via { cipher }", async () => {
    const { stored, layer: accountStoreLive } = makeAccountStore();
    const customCipher = makeAes256GcmCipher(TEST_SECRET);

    const PLAIN_REFRESH = "custom-cipher-refresh-token";
    const NEW_ACCESS = "new-access-from-custom-cipher";

    const encRefresh = await Effect.runPromise(customCipher.encrypt(PLAIN_REFRESH));
    stored.set("github:gh-2", {
      id: "acc-2",
      userId: "user-2",
      provider: "github",
      providerId: "gh-2",
      accessToken: await Effect.runPromise(customCipher.encrypt("old-access")),
      refreshToken: encRefresh,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });

    const service = await Effect.runPromise(
      makeOAuthService({ github: githubProvider }, { encryptTokens: { cipher: customCipher } }),
    );

    let capturedRefreshToken: string | null = null;
    const tokenResp: OAuthTokenResponse = { access_token: NEW_ACCESS, token_type: "bearer" };

    await withFetch(
      (_url, init) => {
        if (typeof init?.body === "string") {
          capturedRefreshToken = new URLSearchParams(init.body).get("refresh_token");
        }
        return json(tokenResp);
      },
      () =>
        Effect.runPromise(
          service.refreshAccessToken("user-2", "github").pipe(Effect.provide(accountStoreLive)),
        ),
    );

    expect(capturedRefreshToken).toBe(PLAIN_REFRESH);
  });
});

// ---------------------------------------------------------------------------
// unlinkAccount — last-credential lockout guard
// ---------------------------------------------------------------------------

describe("OAuthService unlinkAccount guard", () => {
  const makeGithubProvider = () =>
    makeOAuthProvider(
      "github",
      {
        clientId: "c",
        clientSecret: "s",
        redirectUri: "https://app/cb",
        authorizationEndpoint: "https://github.com/login/oauth/authorize",
        tokenEndpoint: "https://github.com/login/oauth/access_token",
        userInfoEndpoint: "https://api.github.com/user",
        scopes: ["user:email"],
      },
      false,
    );

  const baseAccount = (overrides?: Partial<OAuthAccount>): OAuthAccount => ({
    id: "acc-1",
    userId: "user-1",
    provider: "github",
    providerId: "gh-1",
    accessToken: "at",
    createdAt: Date.now(),
    updatedAt: Date.now(),
    ...overrides,
  });

  const makeAccountLayer = (accounts: OAuthAccount[], hasPassword?: boolean) => {
    const stored = new Map<string, OAuthAccount>(
      accounts.map((a) => [`${a.provider}:${a.providerId}`, a]),
    );
    return Layer.succeed(OAuthAccountStore, {
      create: (a) =>
        Effect.sync(() => {
          stored.set(`${a.provider}:${a.providerId}`, a);
          return a;
        }),
      get: (p, id) => Effect.succeed(stored.get(`${p}:${id}`) ?? null),
      getByUserId: (uid) => Effect.succeed([...stored.values()].filter((a) => a.userId === uid)),
      update: (a) =>
        Effect.sync(() => {
          stored.set(`${a.provider}:${a.providerId}`, a);
          return a;
        }),
      linkToUser: (uid, a) =>
        Effect.sync(() => {
          stored.set(`${a.provider}:${a.providerId}`, { ...a, userId: uid });
        }),
      unlinkFromUser: (uid, p) =>
        Effect.sync(() => {
          for (const [k, v] of stored) if (v.userId === uid && v.provider === p) stored.delete(k);
        }),
      delete: (p, id) =>
        Effect.sync(() => {
          stored.delete(`${p}:${id}`);
        }),
      ...(hasPassword !== undefined && { hasPassword: () => Effect.succeed(hasPassword) }),
    });
  };

  it("fails with OAuthLastCredentialError when the account is the only credential", async () => {
    const service = await Effect.runPromise(makeOAuthService({ github: makeGithubProvider() }));
    const accountLayer = makeAccountLayer([baseAccount()]);

    const err = await Effect.runPromise(
      Effect.flip(service.unlinkAccount("user-1", "github").pipe(Effect.provide(accountLayer))),
    );

    expect(err).toBeInstanceOf(OAuthLastCredentialError);
  });

  it("succeeds when the user has another linked OAuth account", async () => {
    const service = await Effect.runPromise(makeOAuthService({ github: makeGithubProvider() }));
    const accountLayer = makeAccountLayer([
      baseAccount(),
      baseAccount({ id: "acc-2", provider: "google", providerId: "gl-1" }),
    ]);

    await Effect.runPromise(
      service.unlinkAccount("user-1", "github").pipe(Effect.provide(accountLayer)),
    );
  });

  it("succeeds when the user has a password (hasPassword returns true)", async () => {
    const service = await Effect.runPromise(makeOAuthService({ github: makeGithubProvider() }));
    const accountLayer = makeAccountLayer([baseAccount()], true);

    await Effect.runPromise(
      service.unlinkAccount("user-1", "github").pipe(Effect.provide(accountLayer)),
    );
  });

  it("succeeds with allowUnlinkingAll: true even when the account is the only credential", async () => {
    const service = await Effect.runPromise(makeOAuthService({ github: makeGithubProvider() }));
    const accountLayer = makeAccountLayer([baseAccount()]);

    await Effect.runPromise(
      service
        .unlinkAccount("user-1", "github", { allowUnlinkingAll: true })
        .pipe(Effect.provide(accountLayer)),
    );
  });

  it("fails with OAuthAccountNotFoundError when the provider is not linked", async () => {
    const service = await Effect.runPromise(makeOAuthService({ github: makeGithubProvider() }));
    const accountLayer = makeAccountLayer([]);

    const err = await Effect.runPromise(
      Effect.flip(service.unlinkAccount("user-1", "github").pipe(Effect.provide(accountLayer))),
    );

    expect(err._tag).toBe("OAuthAccountNotFoundError");
  });
});

// ---------------------------------------------------------------------------
// linkAccount — linking controls (allowDifferentEmails, trustedProviders,
// updateUserInfoOnLink)
// ---------------------------------------------------------------------------

describe("OAuthService linkAccount controls", () => {
  const makeTestProvider = (name: string) =>
    makeOAuthProvider(
      name,
      {
        clientId: "c",
        clientSecret: "s",
        redirectUri: "https://app/cb",
        authorizationEndpoint: `https://${name}.example/authorize`,
        tokenEndpoint: `https://${name}.example/token`,
        userInfoEndpoint: `https://${name}.example/userinfo`,
        scopes: ["profile"],
      },
      false,
    );

  const makeState = (provider: string, stateKey = "state-123"): OAuthState => ({
    state: stateKey,
    provider,
    expiresAt: Date.now() + 60_000,
    createdAt: Date.now(),
  });

  const makeStateLayer = (state: OAuthState) =>
    Layer.succeed(OAuthStateStore, {
      create: (s) => Effect.succeed(s),
      get: (k) => Effect.succeed(k === state.state ? state : null),
      delete: () => Effect.void,
    });

  const makeAccountLayer = (existing?: OAuthAccount) => {
    const stored = new Map<string, OAuthAccount>(
      existing ? [[`${existing.provider}:${existing.providerId}`, existing]] : [],
    );
    return Layer.succeed(OAuthAccountStore, {
      create: (a) =>
        Effect.sync(() => {
          stored.set(`${a.provider}:${a.providerId}`, a);
          return a;
        }),
      get: (p, id) => Effect.succeed(stored.get(`${p}:${id}`) ?? null),
      getByUserId: (uid) => Effect.succeed([...stored.values()].filter((a) => a.userId === uid)),
      update: (a) =>
        Effect.sync(() => {
          stored.set(`${a.provider}:${a.providerId}`, a);
          return a;
        }),
      linkToUser: (uid, a) =>
        Effect.sync(() => {
          stored.set(`${a.provider}:${a.providerId}`, { ...a, userId: uid });
        }),
      unlinkFromUser: () => Effect.void,
      delete: (p, id) =>
        Effect.sync(() => {
          stored.delete(`${p}:${id}`);
        }),
    });
  };

  type UserRecord = {
    id: string;
    email: string;
    name?: string;
    image?: string;
    emailVerified: boolean;
    createdAt: Date;
    updatedAt: Date;
    attributes: Record<string, unknown>;
  };

  const makeUserLayer = (
    user: UserRecord,
    onUpdate?: (id: string, u: { name?: string; image?: string }) => void,
  ) =>
    Layer.succeed(OAuthUserStore, {
      getUser: (id) =>
        id === user.id
          ? Effect.succeed(user)
          : Effect.fail(new AuthError({ message: "not found" })),
      getUserByEmail: (email) => Effect.succeed(email === user.email ? user : null),
      createUser: (input) => Effect.succeed({ ...user, ...input }),
      ...(onUpdate && {
        updateUser: (id, u) => {
          onUpdate(id, u);
          return Effect.succeed({ ...user, ...u });
        },
      }),
    });

  const makeSessionLayer = (userId: string) =>
    Layer.succeed(SessionManager, {
      createSession: () =>
        Effect.succeed({
          id: "sess-test",
          userId,
          expiresAt: new Date(Date.now() + 3600_000),
          createdAt: new Date(),
          lastActivityAt: new Date(),
          attributes: {},
        }),
      validateSession: () =>
        Effect.succeed({
          session: {
            id: "sess-test",
            userId,
            expiresAt: new Date(),
            createdAt: new Date(),
            lastActivityAt: new Date(),
            attributes: {},
          },
          user: {
            id: userId,
            email: "",
            emailVerified: false,
            createdAt: new Date(),
            updatedAt: new Date(),
            attributes: {},
          },
        }),
      invalidateSession: () => Effect.void,
      invalidateUserSessions: () => Effect.void,
      listSessions: () => Effect.succeed([]),
      revokeOtherSessions: () => Effect.void,
      setSessionAttributes: () =>
        Effect.succeed({
          id: "sess-test",
          userId,
          expiresAt: new Date(),
          createdAt: new Date(),
          lastActivityAt: new Date(),
          attributes: {},
        }),
    });

  const mockTokenResponse = { access_token: "at-new", token_type: "bearer" };

  const mockUserInfo = (
    overrides?: Partial<{
      email: string;
      name: string;
      picture: string;
      id: string;
      email_verified: boolean;
    }>,
  ) => ({
    id: "provider-uid-1",
    email: "user@example.com",
    name: "Test User",
    picture: "https://img/user.jpg",
    email_verified: true,
    ...overrides,
  });

  const withProviderFetch = <A>(
    userInfo: ReturnType<typeof mockUserInfo>,
    thunk: () => Promise<A>,
  ) =>
    withFetch((url) => (url.includes("/token") ? json(mockTokenResponse) : json(userInfo)), thunk);

  it("allowDifferentEmails: false (default) rejects linking when emails differ", async () => {
    const service = await Effect.runPromise(
      makeOAuthService({ github: makeTestProvider("github") }),
    );
    const user: UserRecord = {
      id: "u1",
      email: "other@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    const layers = Layer.mergeAll(
      makeStateLayer(makeState("github")),
      makeAccountLayer(),
      makeUserLayer(user),
    );

    const err = await withProviderFetch(mockUserInfo({ email: "user@example.com" }), () =>
      Effect.runPromise(
        Effect.flip(
          service.linkAccount("u1", "github", "code-abc", "state-123").pipe(Effect.provide(layers)),
        ),
      ),
    );

    expect(err).toBeInstanceOf(OAuthEmailMismatchError);
  });

  it("allowDifferentEmails: true allows linking when emails differ", async () => {
    const service = await Effect.runPromise(
      makeOAuthService({ github: makeTestProvider("github") }, { allowDifferentEmails: true }),
    );
    const user: UserRecord = {
      id: "u1",
      email: "other@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    const layers = Layer.mergeAll(
      makeStateLayer(makeState("github")),
      makeAccountLayer(),
      makeUserLayer(user),
    );

    await withProviderFetch(mockUserInfo({ email: "user@example.com" }), () =>
      Effect.runPromise(
        service.linkAccount("u1", "github", "code-abc", "state-123").pipe(Effect.provide(layers)),
      ),
    );
  });

  it("allowDifferentEmails: false succeeds when emails match", async () => {
    const service = await Effect.runPromise(
      makeOAuthService({ github: makeTestProvider("github") }),
    );
    const user: UserRecord = {
      id: "u1",
      email: "user@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    const layers = Layer.mergeAll(
      makeStateLayer(makeState("github")),
      makeAccountLayer(),
      makeUserLayer(user),
    );

    await withProviderFetch(mockUserInfo({ email: "user@example.com" }), () =>
      Effect.runPromise(
        service.linkAccount("u1", "github", "code-abc", "state-123").pipe(Effect.provide(layers)),
      ),
    );
  });

  it("trustedProviders: trusted provider auto-links without email_verified in signInWithCallback", async () => {
    const service = await Effect.runPromise(
      makeOAuthService({ github: makeTestProvider("github") }, { trustedProviders: ["github"] }),
    );

    const existingUser: UserRecord = {
      id: "user-existing",
      email: "user@example.com",
      emailVerified: false,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    const layers = Layer.mergeAll(
      makeStateLayer(makeState("github", "trust-state")),
      makeAccountLayer(),
      makeUserLayer(existingUser),
      makeSessionLayer(existingUser.id),
      Hooks.Default,
    );

    const result = await withProviderFetch(
      mockUserInfo({ email: "user@example.com", id: "gh-trusted", email_verified: false }),
      () =>
        Effect.runPromise(
          service.signInWithCallback("trust-state", "code-trust").pipe(Effect.provide(layers)),
        ),
    );

    expect(result.isNewUser).toBe(false);
    expect(result.user.id).toBe(existingUser.id);
  });

  it("trustedProviders: untrusted provider creates a new user without email_verified", async () => {
    const newUser: UserRecord = {
      id: "new-user-id",
      email: "user@example.com",
      emailVerified: false,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    const existingUser: UserRecord = {
      id: "existing-id",
      email: "user@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    const service = await Effect.runPromise(
      makeOAuthService({ github: makeTestProvider("github") }, { trustedProviders: [] }),
    );

    const userLayer = Layer.succeed(OAuthUserStore, {
      getUser: (id) => (id === newUser.id ? Effect.succeed(newUser) : Effect.succeed(existingUser)),
      getUserByEmail: () => Effect.succeed(existingUser),
      createUser: () => Effect.succeed(newUser),
    });

    const layers = Layer.mergeAll(
      makeStateLayer(makeState("github", "untrust-state")),
      makeAccountLayer(),
      userLayer,
      makeSessionLayer(newUser.id),
      Hooks.Default,
    );

    const result = await withProviderFetch(
      mockUserInfo({ email: "user@example.com", id: "gh-untrusted", email_verified: false }),
      () =>
        Effect.runPromise(
          service.signInWithCallback("untrust-state", "code-untrust").pipe(Effect.provide(layers)),
        ),
    );

    // Without trusted provider and without email_verified, a new user is created
    expect(result.isNewUser).toBe(true);
  });

  it("updateUserInfoOnLink: false (default) does not update user profile", async () => {
    const service = await Effect.runPromise(
      makeOAuthService({ github: makeTestProvider("github") }, { allowDifferentEmails: true }),
    );

    let updateCalled = false;
    const user: UserRecord = {
      id: "u1",
      email: "user@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    const layers = Layer.mergeAll(
      makeStateLayer(makeState("github")),
      makeAccountLayer(),
      makeUserLayer(user, () => {
        updateCalled = true;
      }),
    );

    await withProviderFetch(
      mockUserInfo({ email: "different@example.com", name: "New Name" }),
      () =>
        Effect.runPromise(
          service.linkAccount("u1", "github", "code-abc", "state-123").pipe(Effect.provide(layers)),
        ),
    );

    expect(updateCalled).toBe(false);
  });

  it("updateUserInfoOnLink: true updates user name and image from provider", async () => {
    const service = await Effect.runPromise(
      makeOAuthService(
        { github: makeTestProvider("github") },
        { allowDifferentEmails: true, updateUserInfoOnLink: true },
      ),
    );

    const updates: { name?: string; image?: string }[] = [];
    const user: UserRecord = {
      id: "u1",
      email: "user@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    const layers = Layer.mergeAll(
      makeStateLayer(makeState("github")),
      makeAccountLayer(),
      makeUserLayer(user, (_, u) => updates.push(u)),
    );

    await withProviderFetch(
      mockUserInfo({
        email: "different@example.com",
        name: "Updated Name",
        picture: "https://img/new.jpg",
      }),
      () =>
        Effect.runPromise(
          service.linkAccount("u1", "github", "code-abc", "state-123").pipe(Effect.provide(layers)),
        ),
    );

    expect(updates.length).toBe(1);
    expect(updates[0]).toMatchObject({ name: "Updated Name", image: "https://img/new.jpg" });
  });
});
