import { assert, describe, it, expect } from "vite-plus/test";
import { Array as Arr, Crypto, DateTime, Effect, Layer, Predicate, Redacted, Schema } from "effect";
import { AuthError, OAuthLastCredentialError, OAuthEmailMismatchError } from "../Errors.ts";
import * as Cipher from "../Cipher.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "../Identifier.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { SessionService } from "../SessionService.ts";
import { UserStore } from "../UserStore.ts";
import type * as Types from "../Types.ts";
import {
  verifyIdToken,
  discoverOAuthEndpoints,
  OAuthStateStore,
  OAuthAccountStore,
  OAuthUserStore,
  type OAuthCreateUserInput,
  str,
  nested,
  profile,
  ProfileMap,
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
} from "./OAuth.ts";
import * as OAuth from "./OAuth.ts";

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

const runWithState = <A, E>(
  eff: Effect.Effect<A, E, OAuthStateStore | Crypto.Crypto>,
): Promise<A> =>
  Effect.runPromise(
    eff.pipe(Effect.provide(Layer.mergeAll(StateStoreLive(), PlatformCrypto.layer))),
  );

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
  globalThis.fetch = (input, init) => {
    const url = Predicate.isString(input) ? input : input.toString();
    const body = init?.body;
    calls.push({
      url,
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers),
      body: Predicate.isString(body) ? body : null,
    });
    return Promise.resolve(handler(url, init));
  };
  return thunk(calls).finally(() => {
    globalThis.fetch = original;
  });
};

/** Serializes any value as `JSON.stringify` does. */
const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown));

/** Parses JSON text as `JSON.parse` does. */
const decodeJson = Schema.decodeSync(Schema.fromJsonString(Schema.Unknown));

const json = <A>(value: A): Response =>
  new Response(encodeJson(value), { headers: { "content-type": "application/json" } });

const CLIENT = {
  clientId: "client-123",
  clientSecret: Redacted.make("secret-xyz"),
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
  Arr.forEach(CATALOGUE, (entry) => {
    it(`${entry.name}: builds an authorization URL with state and client id`, async () => {
      const result = await runWithState(entry.provider.generateAuthorizationUrl());
      const url = new URL(result.url);
      expect(url.host).toContain(entry.authorizationHost);
      expect(url.searchParams.get(entry.clientParam)).toBe(CLIENT.clientId);
      expect(url.searchParams.get("redirect_uri")).toBe(CLIENT.redirectUri);
      expect(url.searchParams.get("state")).toBe(result.state);
      expect(url.searchParams.get("response_type")).toBe("code");
    });
  });

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
        const [call] = calls;
        assert(call !== undefined, "the provider called fetch");
        const expected = `Basic ${Buffer.from(`${CLIENT.clientId}:${Redacted.value(CLIENT.clientSecret)}`).toString("base64")}`;
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
        const [call] = calls;
        assert(call !== undefined, "the provider called fetch");
        expect(call.headers.get("authorization")).toBeNull();
        expect(call.body).toContain("client_secret=secret-xyz");
        expect(call.body).toContain("code_verifier=verifier");
      },
    );
  });
});

// --- Provider-specific profile mapping --------------------------------------

describe("OAuth profile mapping", () => {
  const getProfile = <A>(provider: OAuthProvider, body: A, method = "GET") =>
    withFetch(
      () => json(body),
      async (calls) => {
        const info = await Effect.runPromise(
          provider.getProfile({ access_token: "at", token_type: "bearer" }),
        );
        expect(calls[0]?.method).toBe(method);
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

// --- Profile-mapping helpers -------------------------------------------------

describe("profile-mapping helpers (str / nested / profile / ProfileMap)", () => {
  describe("str", () => {
    it("returns the value for a string", () => {
      expect(str("hello")).toBe("hello");
    });
    it("returns undefined for non-string values", () => {
      expect(str(42)).toBeUndefined();
      expect(str(null)).toBeUndefined();
      expect(str(undefined)).toBeUndefined();
      expect(str({})).toBeUndefined();
    });
  });

  describe("nested", () => {
    it("traverses a well-formed path", () => {
      expect(nested({ a: { b: { c: "deep" } } }, "a", "b", "c")).toBe("deep");
    });
    it("returns undefined when a key is missing", () => {
      expect(nested({ a: {} }, "a", "missing")).toBeUndefined();
    });
    it("returns undefined when an intermediate value is not an object", () => {
      expect(nested({ a: 42 }, "a", "b")).toBeUndefined();
    });
    it("returns the value itself when given no path segments", () => {
      expect(nested("leaf")).toBe("leaf");
    });
  });

  describe("profile", () => {
    it("spreads the base record and sets canonical fields", () => {
      const raw = { id: "u1", extra: true };
      const result = profile(raw, { id: "u1", email: "a@b.com", name: "Alice" });
      expect(result).toMatchObject({ id: "u1", email: "a@b.com", name: "Alice", extra: true });
    });
    it("omits optional fields when undefined (exactOptionalPropertyTypes)", () => {
      const result = profile({}, { id: "u2" });
      expect(result.id).toBe("u2");
      expect("email" in result).toBe(false);
      expect("name" in result).toBe(false);
      expect("picture" in result).toBe(false);
      expect("email_verified" in result).toBe(false);
    });
    it("coerces a numeric id to string", () => {
      expect(profile({}, { id: 99 }).id).toBe("99");
    });
  });

  describe("ProfileMap namespace", () => {
    it("re-exports the same functions", () => {
      expect(ProfileMap.str).toBe(str);
      expect(ProfileMap.nested).toBe(nested);
      expect(ProfileMap.profile).toBe(profile);
    });

    it("supports a custom mapProfile using ProfileMap ergonomics", async () => {
      const customProvider = OAuth.provider(
        "custom",
        {
          clientId: "id",
          clientSecret: Redacted.make("secret"),
          redirectUri: "https://app/cb",
          authorizationEndpoint: "https://custom.example/oauth/authorize",
          tokenEndpoint: "https://custom.example/oauth/token",
          userInfoEndpoint: "https://custom.example/api/me",
          scopes: ["read"],
          mapProfile: (raw) =>
            ProfileMap.profile(raw, {
              id: raw["uid"],
              email: ProfileMap.str(raw["email_address"]),
              name: ProfileMap.str(ProfileMap.nested(raw["profile"], "display_name")),
              picture: ProfileMap.str(raw["avatar"]),
            }),
        },
        false,
      );

      const rawPayload = {
        uid: "c-1",
        email_address: "custom@example.com",
        profile: { display_name: "Custom User" },
        avatar: "https://img/custom.jpg",
      };

      await withFetch(
        () => json(rawPayload),
        async () => {
          const info = await Effect.runPromise(
            customProvider.getProfile({ access_token: "tok", token_type: "bearer" }),
          );
          expect(info).toMatchObject({
            id: "c-1",
            email: "custom@example.com",
            name: "Custom User",
            picture: "https://img/custom.jpg",
          });
        },
      );
    });
  });
});

// --- OIDC id_token verification ---------------------------------------------

interface SigningKey {
  privateKey: CryptoKey;
  jwks: { keys: unknown[] };
}

/** Web Crypto keygen params per JWS alg (keeps test fixtures off the Node crypto module). */
const keyGenParams = (alg: "RS256" | "ES256" | "EdDSA") =>
  alg === "RS256"
    ? {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      }
    : alg === "ES256"
      ? { name: "ECDSA", namedCurve: "P-256" }
      : { name: "Ed25519" };

const signParams = (alg: "RS256" | "ES256" | "EdDSA") =>
  alg === "RS256"
    ? "RSASSA-PKCS1-v1_5"
    : alg === "ES256"
      ? { name: "ECDSA", hash: "SHA-256" }
      : "Ed25519";

const makeSigningKey = async (
  alg: "RS256" | "ES256" | "EdDSA",
  kid = "test-kid",
): Promise<SigningKey> => {
  const keyPair = await globalThis.crypto.subtle.generateKey(keyGenParams(alg), true, [
    "sign",
    "verify",
  ]);
  // Every algorithm `keyGenParams` names is asymmetric, so the result is a pair.
  assert("privateKey" in keyPair, `${alg} generates a key pair`);
  const jwk = await globalThis.crypto.subtle.exportKey("jwk", keyPair.publicKey);
  return { privateKey: keyPair.privateKey, jwks: { keys: [{ ...jwk, kid, alg, use: "sig" }] } };
};

const b64u = <A>(obj: A): string => Buffer.from(encodeJson(obj), "utf8").toString("base64url");

const signIdToken = async (
  alg: "RS256" | "ES256" | "EdDSA",
  key: CryptoKey,
  claims: Schema.JsonObject,
  kid = "test-kid",
): Promise<string> => {
  const signingInput = `${b64u({ alg, kid, typ: "JWT" })}.${b64u(claims)}`;
  const data = new TextEncoder().encode(signingInput);
  const signature = await globalThis.crypto.subtle.sign(signParams(alg), key, data);
  return `${signingInput}.${Buffer.from(signature).toString("base64url")}`;
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

  Arr.forEach(["RS256", "ES256", "EdDSA"] as const, (alg) => {
    it(`verifies a valid ${alg} id_token`, async () => {
      const key = await makeSigningKey(alg);
      const token = await signIdToken(alg, key.privateKey, baseClaims(now));
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
  });

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
    const key = await makeSigningKey("ES256");
    const token = await signIdToken("ES256", key.privateKey, baseClaims(now));
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
    const key = await makeSigningKey("ES256");
    const token = await signIdToken("ES256", key.privateKey, baseClaims(now));
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
    const key = await makeSigningKey("ES256");
    const token = await signIdToken("ES256", key.privateKey, baseClaims(now));
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
    const key = await makeSigningKey("ES256");
    const token = await signIdToken("ES256", key.privateKey, {
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
    const key = await makeSigningKey("ES256");
    const token = await signIdToken("ES256", key.privateKey, { ...baseClaims(now), nonce: "real" });
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
    const key = await makeSigningKey("ES256");
    // getProfile validates against the real clock, so use a far-future exp.
    const token = await signIdToken("ES256", key.privateKey, {
      ...baseClaims(now),
      exp: 4_102_444_800,
    });
    const provider = OAuth.provider("idp", {
      clientId: "client-123",
      clientSecret: Redacted.make("s"),
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
    const provider = OAuth.provider("generic", {
      ...endpoints,
      clientId: "c",
      clientSecret: Redacted.make("s"),
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

describe("OAuth.appleClientSecret", () => {
  it("produces a verifiable ES256 JWT with Apple's claims", async () => {
    const { publicKeyJwk, privateKeyPem } = Cipher.generateJwsKeyPair("ES256");
    const now = 1_700_000_000_000;
    const secret = await Effect.runPromise(
      OAuth.appleClientSecret({
        teamId: "TEAM123",
        clientId: "com.example.app",
        keyId: "KEY123",
        privateKey: Redacted.make(privateKeyPem),
        now,
      }),
    );

    const [headerSeg, payloadSeg, signatureSeg] = Schema.decodeUnknownSync(
      Schema.Tuple([Schema.String, Schema.String, Schema.String]),
    )(secret.split("."));
    const header = decodeJson(Buffer.from(headerSeg, "base64url").toString("utf8"));
    const payload = Schema.decodeSync(
      Schema.fromJsonString(
        Schema.Struct({
          iss: Schema.String,
          sub: Schema.String,
          aud: Schema.String,
          iat: Schema.Number,
          exp: Schema.Number,
        }),
      ),
    )(Buffer.from(payloadSeg, "base64url").toString("utf8"));
    expect(header).toMatchObject({ alg: "ES256", kid: "KEY123" });
    expect(payload).toMatchObject({
      iss: "TEAM123",
      sub: "com.example.app",
      aud: "https://appleid.apple.com",
    });
    expect(payload.exp).toBeGreaterThan(payload.iat);

    const valid = Cipher.verifyJws(
      "ES256",
      Buffer.from(`${headerSeg}.${payloadSeg}`),
      Buffer.from(signatureSeg, "base64url"),
      publicKeyJwk,
    );
    expect(valid).toBe(true);
  });
});

// --- Token encryption --------------------------------------------------------

const TEST_SECRET = "test-secret-for-aes-256-gcm-cipher";

describe("Cipher.aes256GcmCipher", () => {
  it("encrypts and decrypts round-trip", async () => {
    const cipher = Cipher.aes256GcmCipher(TEST_SECRET);
    const token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345";
    const encrypted = await Effect.runPromise(cipher.encrypt(token));
    expect(encrypted).not.toBe(token);
    expect(await Effect.runPromise(cipher.decrypt(encrypted))).toBe(token);
  });

  it("produces a different ciphertext on each call (random IV)", async () => {
    const cipher = Cipher.aes256GcmCipher(TEST_SECRET);
    const e1 = await Effect.runPromise(cipher.encrypt("same-plaintext"));
    const e2 = await Effect.runPromise(cipher.encrypt("same-plaintext"));
    expect(e1).not.toBe(e2);
  });

  it("fails loudly on tampered ciphertext (GCM auth-tag)", async () => {
    const cipher = Cipher.aes256GcmCipher(TEST_SECRET);
    const encrypted = await Effect.runPromise(cipher.encrypt("hello"));
    const buf = Buffer.from(encrypted, "base64url");
    buf[buf.length - 1] ^= 0xff;
    const err = await Effect.runPromise(Effect.flip(cipher.decrypt(buf.toString("base64url"))));
    expect(err._tag).toBe("AuthError");
    expect(err.message).toMatch(/decrypt/i);
  });

  it("fails on ciphertext that is too short", async () => {
    const cipher = Cipher.aes256GcmCipher(TEST_SECRET);
    const err = await Effect.runPromise(Effect.flip(cipher.decrypt("dG9vc2hvcnQ")));
    expect(err._tag).toBe("AuthError");
  });
});

describe("OAuthService encryptTokens", () => {
  // SAFETY: OAuth.make resolves OAuthStateStore | OAuthAccountStore |
  // OAuthUserStore | IdentifierStore | UserStore | SessionService at construction
  // time. These tests only exercise refreshAccessToken (which only touches
  // OAuthAccountStore, via closure), so the `undefined` others are never invoked.
  const unusedDepsLayer = Layer.mergeAll(
    Layer.succeed(OAuthStateStore)(undefined as never),
    Layer.succeed(OAuthUserStore)(undefined as never),
    Layer.succeed(IdentifierStore)(undefined as never),
    Layer.succeed(UserStore)(undefined as never),
    Layer.succeed(SessionService)(undefined as never),
    PlatformCrypto.layer,
  );

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
          stored.forEach((v, k) => {
            if (v.userId === uid && v.provider === p) stored.delete(k);
          });
        }),
      delete: (p, id) =>
        Effect.sync(() => {
          stored.delete(`${p}:${id}`);
        }),
    });
    return { stored, layer };
  };

  const githubProvider = OAuth.provider(
    "github",
    {
      clientId: "c",
      clientSecret: Redacted.make("s"),
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
    const cipher = Cipher.aes256GcmCipher(TEST_SECRET);

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
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      updatedAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
    });

    const service = await Effect.runPromise(
      OAuth.make(
        { github: githubProvider },
        { encryptTokens: { secret: Redacted.make(TEST_SECRET) } },
      ).pipe(Effect.provide(Layer.mergeAll(accountStoreLive, unusedDepsLayer))),
    );

    let capturedRefreshToken: string | null = null;
    const tokenResp: OAuthTokenResponse = { access_token: NEW_ACCESS, token_type: "bearer" };

    const newAccessToken = await withFetch(
      (_url, init) => {
        const body = init?.body;
        if (Predicate.isString(body)) {
          capturedRefreshToken = new URLSearchParams(body).get("refresh_token");
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
    const updated = stored.get("github:gh-1");
    assert(updated !== undefined, "the account is stored");
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
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      updatedAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
    });

    const service = await Effect.runPromise(
      OAuth.make({ github: githubProvider }).pipe(
        Effect.provide(Layer.mergeAll(accountStoreLive, unusedDepsLayer)),
      ),
    );
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
    expect(stored.get("github:gh-1")?.accessToken).toBe(NEW_ACCESS);
  });

  it("accepts a custom TokenCipher via { cipher }", async () => {
    const { stored, layer: accountStoreLive } = makeAccountStore();
    const customCipher = Cipher.aes256GcmCipher(TEST_SECRET);

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
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      updatedAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
    });

    const service = await Effect.runPromise(
      OAuth.make({ github: githubProvider }, { encryptTokens: { cipher: customCipher } }).pipe(
        Effect.provide(Layer.mergeAll(accountStoreLive, unusedDepsLayer)),
      ),
    );

    let capturedRefreshToken: string | null = null;
    const tokenResp: OAuthTokenResponse = { access_token: NEW_ACCESS, token_type: "bearer" };

    await withFetch(
      (_url, init) => {
        const body = init?.body;
        if (Predicate.isString(body)) {
          capturedRefreshToken = new URLSearchParams(body).get("refresh_token");
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
  const githubProvider = OAuth.provider(
    "github",
    {
      clientId: "c",
      clientSecret: Redacted.make("s"),
      redirectUri: "https://app/cb",
      authorizationEndpoint: "https://github.com/login/oauth/authorize",
      tokenEndpoint: "https://github.com/login/oauth/access_token",
      userInfoEndpoint: "https://api.github.com/user",
      scopes: ["user:email"],
    },
    false,
  );

  // SAFETY: unlinkAccount only touches OAuthAccountStore (resolved in `make`'s
  // closure); the `undefined` construction-time deps are never invoked here.
  const unusedDeps = Layer.mergeAll(
    Layer.succeed(OAuthStateStore)(undefined as never),
    Layer.succeed(OAuthUserStore)(undefined as never),
    Layer.succeed(IdentifierStore)(undefined as never),
    Layer.succeed(UserStore)(undefined as never),
    Layer.succeed(SessionService)(undefined as never),
    PlatformCrypto.layer,
  );

  const baseAccount = (overrides?: Partial<OAuthAccount>): OAuthAccount => ({
    id: "acc-1",
    userId: "user-1",
    provider: "github",
    providerId: "gh-1",
    accessToken: "at",
    createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
    updatedAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
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
          stored.forEach((v, k) => {
            if (v.userId === uid && v.provider === p) stored.delete(k);
          });
        }),
      delete: (p, id) =>
        Effect.sync(() => {
          stored.delete(`${p}:${id}`);
        }),
      ...(hasPassword !== undefined && { hasPassword: () => Effect.succeed(hasPassword) }),
    });
  };

  const buildService = (accountLayer: Layer.Layer<OAuthAccountStore>) =>
    Effect.runPromise(
      OAuth.make({ github: githubProvider }).pipe(
        Effect.provide(Layer.mergeAll(accountLayer, unusedDeps)),
      ),
    );

  it("fails with OAuthLastCredentialError when the account is the only credential (no password)", async () => {
    const service = await buildService(makeAccountLayer([baseAccount()], false));

    const err = await Effect.runPromise(Effect.flip(service.unlinkAccount("user-1", "github")));

    expect(err).toBeInstanceOf(OAuthLastCredentialError);
  });

  it("succeeds when the user has another linked OAuth account", async () => {
    const service = await buildService(
      makeAccountLayer(
        [baseAccount(), baseAccount({ id: "acc-2", provider: "google", providerId: "gl-1" })],
        false,
      ),
    );

    await Effect.runPromise(service.unlinkAccount("user-1", "github"));
  });

  it("succeeds when the user has a password (hasPassword returns true)", async () => {
    const service = await buildService(makeAccountLayer([baseAccount()], true));

    await Effect.runPromise(service.unlinkAccount("user-1", "github"));
  });

  it("fails open: permits unlinking the last account when hasPassword is not implemented", async () => {
    const service = await buildService(makeAccountLayer([baseAccount()]));

    await Effect.runPromise(service.unlinkAccount("user-1", "github"));
  });

  it("succeeds with allowUnlinkingAll: true even when the account is the only credential", async () => {
    const service = await buildService(makeAccountLayer([baseAccount()], false));

    await Effect.runPromise(service.unlinkAccount("user-1", "github", { allowUnlinkingAll: true }));
  });

  it("fails with OAuthAccountNotFoundError when the provider is not linked", async () => {
    const service = await buildService(makeAccountLayer([]));

    const err = await Effect.runPromise(Effect.flip(service.unlinkAccount("user-1", "github")));

    expect(err._tag).toBe("OAuthAccountNotFoundError");
  });
});

// ---------------------------------------------------------------------------
// linkAccount / signInWithCallback — linking controls (allowDifferentEmails,
// trustedProviders, updateUserInfoOnLink)
// ---------------------------------------------------------------------------

describe("OAuthService linking controls", () => {
  const makeTestProvider = (name: string) =>
    OAuth.provider(
      name,
      {
        clientId: "c",
        clientSecret: Redacted.make("s"),
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
    expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 60_000,
    createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
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

  const makeUser = (overrides?: Partial<Types.User>): Types.User => ({
    id: "u1",
    createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
    updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
    attributes: {},
    ...overrides,
  });

  const makeUserLayer = (
    user: Types.User,
    onUpdate?: (id: string, u: { name?: string; image?: string }) => void,
  ) =>
    Layer.succeed(OAuthUserStore, {
      getUser: (id) =>
        id === user.id
          ? Effect.succeed(user)
          : Effect.fail(new AuthError({ message: "not found" })),
      createUser: (input) => Effect.succeed({ user: makeUser(input), created: true }),
      ...(onUpdate && {
        updateUser: (id: string, u: { name?: string; image?: string }) => {
          onUpdate(id, u);
          return Effect.succeed({ ...user, ...u });
        },
      }),
    });

  /**
   * Identifier fixture: a memory store optionally pre-seeded with email
   * identifiers (the identifier-model equivalent of the old
   * `user.email`/`emailVerified` seeding).
   */
  const makeIdentifiers = (
    ...seeds: ReadonlyArray<{ userId: string; email: string; verified?: boolean }>
  ) => {
    const records = new Map<string, Identifier>();
    Arr.forEach(seeds, (seed) => {
      const identifier = makeIdentifier({
        userId: seed.userId,
        type: "email",
        value: seed.email,
        verified: seed.verified ?? true,
        now: DateTime.toDateUtc(DateTime.nowUnsafe()),
      });
      records.set(identifier.id, identifier);
    });
    const store = memoryIdentifierStore(records);
    return { records, store, layer: Layer.succeed(IdentifierStore)(store) };
  };

  /** Core user-by-id store used by signInWithCallback's auto-link resolution. */
  const makeCoreUserLayer = (...users: ReadonlyArray<Types.User>) =>
    Layer.succeed(UserStore, {
      get: (id) => Effect.succeed(users.find((u) => u.id === id) ?? null),
    });

  const makeSessionLayer = (userId: string) => {
    const session: Types.Session = {
      id: "sess-test",
      userId,
      expiresAt: DateTime.toDateUtc(DateTime.add(DateTime.nowUnsafe(), { milliseconds: 3600_000 })),
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      lastActivityAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    const user: Types.User = makeUser({ id: userId });
    return Layer.succeed(SessionService, {
      createSession: () => Effect.succeed(session),
      validateSession: () => Effect.succeed({ session, user }),
      invalidateSession: () => Effect.void,
      invalidateUserSessions: () => Effect.void,
      listSessions: () => Effect.succeed([]),
      revokeSessionById: () => Effect.succeed(false),
      revokeOtherSessions: () => Effect.void,
      setSessionAttributes: () => Effect.succeed(session),
    });
  };

  // SAFETY: linkAccount never touches SessionService, so the `undefined` stub is
  // never invoked by the tests that use it.
  const noSession = Layer.succeed(SessionService)(undefined as never);

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
    const user = makeUser();
    const identifiers = makeIdentifiers({ userId: user.id, email: "other@example.com" });
    const service = await Effect.runPromise(
      OAuth.make({ github: makeTestProvider("github") }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github")),
            makeAccountLayer(),
            makeUserLayer(user),
            identifiers.layer,
            makeCoreUserLayer(user),
            noSession,
            PlatformCrypto.layer,
          ),
        ),
      ),
    );

    const err = await withProviderFetch(mockUserInfo({ email: "user@example.com" }), () =>
      Effect.runPromise(Effect.flip(service.linkAccount("u1", "github", "code-abc", "state-123"))),
    );

    expect(err).toBeInstanceOf(OAuthEmailMismatchError);
  });

  it("allowDifferentEmails: true allows linking when emails differ", async () => {
    const user = makeUser();
    const identifiers = makeIdentifiers({ userId: user.id, email: "other@example.com" });
    const service = await Effect.runPromise(
      OAuth.make({ github: makeTestProvider("github") }, { allowDifferentEmails: true }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github")),
            makeAccountLayer(),
            makeUserLayer(user),
            identifiers.layer,
            makeCoreUserLayer(user),
            noSession,
            PlatformCrypto.layer,
          ),
        ),
      ),
    );

    const account = await withProviderFetch(mockUserInfo({ email: "user@example.com" }), () =>
      Effect.runPromise(service.linkAccount("u1", "github", "code-abc", "state-123")),
    );

    expect(account.userId).toBe("u1");
  });

  it("allowDifferentEmails: false succeeds when emails match", async () => {
    const user = makeUser();
    const identifiers = makeIdentifiers({ userId: user.id, email: "user@example.com" });
    const service = await Effect.runPromise(
      OAuth.make({ github: makeTestProvider("github") }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github")),
            makeAccountLayer(),
            makeUserLayer(user),
            identifiers.layer,
            makeCoreUserLayer(user),
            noSession,
            PlatformCrypto.layer,
          ),
        ),
      ),
    );

    const account = await withProviderFetch(mockUserInfo({ email: "user@example.com" }), () =>
      Effect.runPromise(service.linkAccount("u1", "github", "code-abc", "state-123")),
    );

    expect(account.provider).toBe("github");
  });

  it("trustedProviders: trusted provider auto-links without email_verified in signInWithCallback", async () => {
    const existingUser = makeUser({ id: "user-existing" });
    // The existing account's email identifier is itself unverified.
    const identifiers = makeIdentifiers({
      userId: existingUser.id,
      email: "user@example.com",
      verified: false,
    });
    const service = await Effect.runPromise(
      OAuth.make({ github: makeTestProvider("github") }, { trustedProviders: ["github"] }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github", "trust-state")),
            makeAccountLayer(),
            makeUserLayer(existingUser),
            identifiers.layer,
            makeCoreUserLayer(existingUser),
            makeSessionLayer(existingUser.id),
            PlatformCrypto.layer,
          ),
        ),
      ),
    );

    const result = await withProviderFetch(
      mockUserInfo({ email: "user@example.com", id: "gh-trusted", email_verified: false }),
      () => Effect.runPromise(service.signInWithCallback("trust-state", "code-trust")),
    );

    expect(result.isNewUser).toBe(false);
    expect(result.user.id).toBe(existingUser.id);
  });

  it("trustedProviders: untrusted provider refuses a claimed email without email_verified", async () => {
    const existingUser = makeUser({ id: "existing-id" });
    const identifiers = makeIdentifiers({ userId: existingUser.id, email: "user@example.com" });

    const service = await Effect.runPromise(
      OAuth.make({ github: makeTestProvider("github") }, { trustedProviders: [] }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github", "untrust-state")),
            makeAccountLayer(),
            makeUserLayer(existingUser),
            identifiers.layer,
            makeCoreUserLayer(existingUser),
            makeSessionLayer(existingUser.id),
            PlatformCrypto.layer,
          ),
        ),
      ),
    );

    const err = await withProviderFetch(
      mockUserInfo({ email: "user@example.com", id: "gh-untrusted", email_verified: false }),
      () =>
        Effect.runPromise(Effect.flip(service.signInWithCallback("untrust-state", "code-untrust"))),
    );

    // Without a trusted provider and without email_verified, the flow must not
    // auto-link — and it must not double-claim the email either.
    assert.instanceOf(err, AuthError);
    expect(err.message).toMatch(/already associated/i);
  });

  it("trustedProviders: unclaimed unverified email creates a new user with an unverified identifier", async () => {
    const newUser = makeUser({ id: "new-user-id" });
    const identifiers = makeIdentifiers();
    const createdWith: Array<OAuthCreateUserInput["identifier"]> = [];

    const userLayer = Layer.succeed(OAuthUserStore, {
      getUser: () => Effect.succeed(newUser),
      createUser: (input) => {
        createdWith.push(input.identifier);
        return Effect.succeed({ user: newUser, created: true });
      },
    });

    const service = await Effect.runPromise(
      OAuth.make({ github: makeTestProvider("github") }, { trustedProviders: [] }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github", "fresh-state")),
            makeAccountLayer(),
            userLayer,
            identifiers.layer,
            makeCoreUserLayer(newUser),
            makeSessionLayer(newUser.id),
            PlatformCrypto.layer,
          ),
        ),
      ),
    );

    const result = await withProviderFetch(
      mockUserInfo({ email: "user@example.com", id: "gh-fresh", email_verified: false }),
      () => Effect.runPromise(service.signInWithCallback("fresh-state", "code-fresh")),
    );

    expect(result.isNewUser).toBe(true);
    const claimed = await Effect.runPromise(
      identifiers.store.getByValue("email", "user@example.com"),
    );
    expect(claimed?.userId).toBe(newUser.id);
    expect(claimed?.verified).toBe(false);
    // The store was handed the address to create the user with (#380).
    expect(createdWith).toEqual([{ type: "email", value: "user@example.com", verified: false }]);
  });

  it("an unclaimed email the provider verified creates a new user with a verified identifier", async () => {
    const newUser = makeUser({ id: "new-user-id" });
    const identifiers = makeIdentifiers();
    const createdWith: Array<OAuthCreateUserInput["identifier"]> = [];

    const userLayer = Layer.succeed(OAuthUserStore, {
      getUser: () => Effect.succeed(newUser),
      createUser: (input) => {
        createdWith.push(input.identifier);
        return Effect.succeed({ user: newUser, created: true });
      },
    });

    const service = await Effect.runPromise(
      OAuth.make({ github: makeTestProvider("github") }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github", "verified-state")),
            makeAccountLayer(),
            userLayer,
            identifiers.layer,
            makeCoreUserLayer(newUser),
            makeSessionLayer(newUser.id),
            PlatformCrypto.layer,
          ),
        ),
      ),
    );

    const result = await withProviderFetch(
      mockUserInfo({ email: "user@example.com", id: "gh-verified", email_verified: true }),
      () => Effect.runPromise(service.signInWithCallback("verified-state", "code-verified")),
    );

    expect(result.isNewUser).toBe(true);
    const claimed = await Effect.runPromise(
      identifiers.store.getByValue("email", "user@example.com"),
    );
    expect(claimed?.userId).toBe(newUser.id);
    expect(claimed?.verified).toBe(true);
    expect(claimed?.verifiedAt).toBeInstanceOf(Date);
    expect(createdWith).toEqual([
      { type: "email", value: "user@example.com", verified: true, verifiedAt: expect.any(Date) },
    ]);
  });

  it("refuses when the store's writer returns the existing owner, and links nothing to the owner (#380)", async () => {
    const owner = makeUser({ id: "owner-id" });
    const identifiers = makeIdentifiers();
    const accounts = new Map<string, OAuthAccount>();
    const accountLayer = Layer.succeed(OAuthAccountStore, {
      create: (a) => Effect.sync(() => (accounts.set(a.id, a), a)),
      get: () => Effect.succeed(null),
      getByUserId: (uid) => Effect.succeed([...accounts.values()].filter((a) => a.userId === uid)),
      update: (a) => Effect.sync(() => (accounts.set(a.id, a), a)),
      linkToUser: (uid, a) => Effect.sync(() => void accounts.set(a.id, { ...a, userId: uid })),
      unlinkFromUser: () => Effect.void,
      delete: () => Effect.void,
    });
    // A writer that finds or creates on the address. The owner's row, holding
    // the address unverified, lands between the flow's lookup and its insert,
    // so the writer returns the owner and reports that it inserted nothing.
    const userLayer = Layer.succeed(OAuthUserStore, {
      getUser: () => Effect.succeed(owner),
      createUser: () =>
        Effect.sync(() => {
          const held = makeIdentifier({
            userId: owner.id,
            type: "email",
            value: "owner@example.com",
            verified: false,
            now: DateTime.toDateUtc(DateTime.nowUnsafe()),
          });
          identifiers.records.set(held.id, held);
          return { user: owner, created: false };
        }),
    });

    const service = await Effect.runPromise(
      OAuth.make({ github: makeTestProvider("github") }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github", "owner-state")),
            accountLayer,
            userLayer,
            identifiers.layer,
            makeCoreUserLayer(owner),
            makeSessionLayer(owner.id),
            PlatformCrypto.layer,
          ),
        ),
      ),
    );

    const err = await withProviderFetch(
      mockUserInfo({ email: "owner@example.com", id: "gh-attacker", email_verified: true }),
      () => Effect.runPromise(Effect.flip(service.signInWithCallback("owner-state", "code-owner"))),
    );

    assert.instanceOf(err, AuthError);
    expect(err.message).toMatch(/already associated/i);
    // No account linked to the owner, and the owner's address is still unverified.
    expect(accounts.size).toBe(0);
    const held = await Effect.runPromise(
      identifiers.store.getByValue("email", "owner@example.com"),
    );
    expect(held).toMatchObject({ userId: owner.id, verified: false });
  });

  it("updateUserInfoOnLink: false (default) does not update the user profile", async () => {
    let updateCalled = false;
    const user = makeUser();
    const service = await Effect.runPromise(
      OAuth.make({ github: makeTestProvider("github") }, { allowDifferentEmails: true }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github")),
            makeAccountLayer(),
            makeUserLayer(user, () => {
              updateCalled = true;
            }),
            makeIdentifiers().layer,
            makeCoreUserLayer(user),
            noSession,
            PlatformCrypto.layer,
          ),
        ),
      ),
    );

    await withProviderFetch(
      mockUserInfo({ email: "different@example.com", name: "New Name" }),
      () => Effect.runPromise(service.linkAccount("u1", "github", "code-abc", "state-123")),
    );

    expect(updateCalled).toBe(false);
  });

  it("updateUserInfoOnLink: true updates the user name and image from the provider", async () => {
    const updates: { name?: string; image?: string }[] = [];
    const user = makeUser();
    const service = await Effect.runPromise(
      OAuth.make(
        { github: makeTestProvider("github") },
        { allowDifferentEmails: true, updateUserInfoOnLink: true },
      ).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github")),
            makeAccountLayer(),
            makeUserLayer(user, (_, u) => updates.push(u)),
            makeIdentifiers().layer,
            makeCoreUserLayer(user),
            noSession,
            PlatformCrypto.layer,
          ),
        ),
      ),
    );

    await withProviderFetch(
      mockUserInfo({
        email: "different@example.com",
        name: "Updated Name",
        picture: "https://img/new.jpg",
      }),
      () => Effect.runPromise(service.linkAccount("u1", "github", "code-abc", "state-123")),
    );

    expect(updates.length).toBe(1);
    expect(updates[0]).toMatchObject({ name: "Updated Name", image: "https://img/new.jpg" });
  });
});
describe("OAuthService handleCallback and generateAuthorizationUrl", () => {
  const github = OAuth.provider(
    "github",
    {
      clientId: "c",
      clientSecret: Redacted.make("s"),
      redirectUri: "https://app/cb",
      authorizationEndpoint: "https://github.example/authorize",
      tokenEndpoint: "https://github.example/token",
      userInfoEndpoint: "https://github.example/userinfo",
      scopes: ["profile"],
    },
    false,
  );

  const makeStateStore = (...seed: ReadonlyArray<OAuthState>) => {
    const states = new Map<string, OAuthState>(seed.map((s) => [s.state, s]));
    const store: typeof OAuthStateStore.Service = {
      create: (s) =>
        Effect.sync(() => {
          states.set(s.state, s);
          return s;
        }),
      get: (k) => Effect.succeed(states.get(k) ?? null),
      delete: (k) =>
        Effect.sync(() => {
          states.delete(k);
        }),
    };
    return { states, store };
  };

  const makeAccounts = (...seed: ReadonlyArray<OAuthAccount>) => {
    const accounts = new Map<string, OAuthAccount>(
      seed.map((a) => [`${a.provider}:${a.providerId}`, a]),
    );
    const store: typeof OAuthAccountStore.Service = {
      create: (a) =>
        Effect.sync(() => {
          accounts.set(`${a.provider}:${a.providerId}`, a);
          return a;
        }),
      get: (p, id) => Effect.succeed(accounts.get(`${p}:${id}`) ?? null),
      getByUserId: (uid) => Effect.succeed([...accounts.values()].filter((a) => a.userId === uid)),
      update: (a) =>
        Effect.sync(() => {
          accounts.set(`${a.provider}:${a.providerId}`, a);
          return a;
        }),
      linkToUser: () => Effect.void,
      unlinkFromUser: () => Effect.void,
      delete: () => Effect.void,
    };
    return { accounts, store };
  };

  // handleCallback and generateAuthorizationUrl touch only the state and
  // account stores; the services below are resolved at construction only.
  const unusedByCallbackLayer = Layer.mergeAll(
    // SAFETY: never called by handleCallback or generateAuthorizationUrl.
    Layer.succeed(OAuthUserStore)(undefined as never),
    // SAFETY: never called by handleCallback or generateAuthorizationUrl.
    Layer.succeed(IdentifierStore)(undefined as never),
    // SAFETY: never called by handleCallback or generateAuthorizationUrl.
    Layer.succeed(UserStore)(undefined as never),
    // SAFETY: never called by handleCallback or generateAuthorizationUrl.
    Layer.succeed(SessionService)(undefined as never),
  );

  const makeService = (
    stateStore: typeof OAuthStateStore.Service,
    accountStore: typeof OAuthAccountStore.Service = makeAccounts().store,
  ) =>
    Effect.runPromise(
      OAuth.make({ github }).pipe(
        Effect.provide(
          Layer.mergeAll(
            Layer.succeed(OAuthStateStore)(stateStore),
            Layer.succeed(OAuthAccountStore)(accountStore),
            unusedByCallbackLayer,
            PlatformCrypto.layer,
          ),
        ),
      ),
    );

  const liveState = (overrides?: Partial<OAuthState>): OAuthState => ({
    state: "st-1",
    provider: "github",
    createdAt: 0,
    // Far in the future: 2100-01-01.
    expiresAt: 4_102_444_800_000,
    ...overrides,
  });

  const providerFetch = <A>(
    tokens: OAuthTokenResponse,
    userInfo: {
      readonly id: string;
      readonly email?: string;
      readonly name?: string;
      readonly picture?: string;
    },
    thunk: () => Promise<A>,
  ) => withFetch((url) => (url.includes("/token") ? json(tokens) : json(userInfo)), thunk);

  describe("handleCallback", () => {
    it("fails with OAuthStateNotFoundError for an unknown state", async () => {
      const service = await makeService(makeStateStore().store);
      const err = await Effect.runPromise(Effect.flip(service.handleCallback("nope", "code")));
      expect(err._tag).toBe("OAuthStateNotFoundError");
    });

    it("fails with OAuthStateExpiredError and drops an expired state", async () => {
      const { states, store } = makeStateStore(liveState({ expiresAt: 1 }));
      const service = await makeService(store);
      const err = await Effect.runPromise(Effect.flip(service.handleCallback("st-1", "code")));
      expect(err._tag).toBe("OAuthStateExpiredError");
      expect(states.has("st-1")).toBe(false);
    });

    it("fails with OAuthProviderError when the state names an unregistered provider", async () => {
      const { store } = makeStateStore(liveState({ provider: "gitlab" }));
      const service = await makeService(store);
      const err = await Effect.runPromise(Effect.flip(service.handleCallback("st-1", "code")));
      expect(err._tag).toBe("OAuthProviderError");
    });

    it("creates an unlinked account for a new provider identity", async () => {
      const { states, store } = makeStateStore(liveState());
      const accounts = makeAccounts();
      const service = await makeService(store, accounts.store);

      const result = await providerFetch(
        { access_token: "at-1", token_type: "bearer" },
        { id: "gh-9", email: "new@example.com", name: "New" },
        () => Effect.runPromise(service.handleCallback("st-1", "code")),
      );

      expect(result.isNewUser).toBe(true);
      expect(result.user).toBeUndefined();
      expect(result.account).toMatchObject({
        userId: "",
        provider: "github",
        providerId: "gh-9",
        email: "new@example.com",
        name: "New",
        accessToken: "at-1",
      });
      expect(result.account.refreshToken).toBeUndefined();
      expect(result.account.expiresAt).toBeUndefined();
      expect(accounts.accounts.get("github:gh-9")).toEqual(result.account);
      // The state is single-use.
      expect(states.has("st-1")).toBe(false);
    });

    it("links a new account to linkToUserId and reports the user", async () => {
      const { store } = makeStateStore(liveState());
      const service = await makeService(store);

      const result = await providerFetch(
        { access_token: "at-1", token_type: "bearer", refresh_token: "rt-1", expires_in: 60 },
        { id: "gh-9", email: "new@example.com", name: "New", picture: "https://img/p.png" },
        () => Effect.runPromise(service.handleCallback("st-1", "code", { linkToUserId: "u-7" })),
      );

      expect(result.isNewUser).toBe(true);
      expect(result.user).toEqual({ id: "u-7", email: "new@example.com", name: "New" });
      expect(result.account).toMatchObject({
        userId: "u-7",
        picture: "https://img/p.png",
        refreshToken: "rt-1",
      });
      expect(result.account.expiresAt).toBeGreaterThan(result.account.createdAt);
    });

    it("refreshes the tokens of an existing account", async () => {
      const { store } = makeStateStore(liveState());
      const existing: OAuthAccount = {
        id: "acc-1",
        userId: "u-1",
        provider: "github",
        providerId: "gh-9",
        accessToken: "old-at",
        createdAt: 1,
        updatedAt: 1,
      };
      const accounts = makeAccounts(existing);
      const service = await makeService(store, accounts.store);

      const result = await providerFetch(
        { access_token: "new-at", token_type: "bearer", refresh_token: "rt-2", expires_in: 60 },
        { id: "gh-9" },
        () => Effect.runPromise(service.handleCallback("st-1", "code")),
      );

      expect(result.isNewUser).toBe(false);
      expect(result.account).toMatchObject({
        id: "acc-1",
        userId: "u-1",
        accessToken: "new-at",
        refreshToken: "rt-2",
      });
      expect(result.account.updatedAt).toBeGreaterThan(1);
      expect(accounts.accounts.get("github:gh-9")).toEqual(result.account);
    });
  });

  describe("generateAuthorizationUrl", () => {
    it("fails with OAuthProviderError for an unregistered provider", async () => {
      const service = await makeService(makeStateStore().store);
      const err = await Effect.runPromise(Effect.flip(service.generateAuthorizationUrl("gitlab")));
      expect(err._tag).toBe("OAuthProviderError");
    });

    it("stores a state without returnTo by default, honouring custom scopes", async () => {
      const { states, store } = makeStateStore();
      const service = await makeService(store);
      const result = await Effect.runPromise(
        service.generateAuthorizationUrl("github", { scopes: ["read", "write"] }),
      );
      expect(new URL(result.url).searchParams.get("scope")).toBe("read write");
      expect(states.get(result.state)?.returnTo).toBeUndefined();
    });

    it("records returnTo on the stored state", async () => {
      const { states, store } = makeStateStore();
      const service = await makeService(store);
      const result = await Effect.runPromise(
        service.generateAuthorizationUrl("github", { returnTo: "/after" }),
      );
      expect(states.get(result.state)).toMatchObject({ provider: "github", returnTo: "/after" });
    });

    it("fails with AuthError when the state vanishes before returnTo is recorded", async () => {
      const { store } = makeStateStore();
      const service = await makeService({ ...store, get: () => Effect.succeed(null) });
      const err = await Effect.runPromise(
        Effect.flip(service.generateAuthorizationUrl("github", { returnTo: "/after" })),
      );
      expect(err).toBeInstanceOf(AuthError);
    });
  });
});
