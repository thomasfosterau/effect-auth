import { assert, describe, it, expect } from "vite-plus/test";
import { createHash } from "node:crypto";
import { testCryptoLayer, type TestCryptoServices } from "../testing/TestCrypto.ts";
import { Cause, DateTime, Effect, Exit, Layer, Logger, MutableHashMap, Redacted } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import { KeyValueStore } from "effect/persistence";
import { oauthStateStoreKV } from "../KeyValueStores.ts";
import { ApiKeyStore } from "../ApiKey.ts";
import { MultiFactorStore } from "../multifactor/MultiFactor.ts";
import { TrustedDeviceStore } from "../TrustedDevice.ts";
import {
  AuthError,
  EmailInUseError,
  OAuthLastCredentialError,
  OAuthEmailMismatchError,
  OAuthMissingEmailError,
} from "../Errors.ts";
import * as Cipher from "../Cipher.ts";
import { testJwsKeyPair, testVerifyJws } from "../testing/TestJws.ts";
import {
  IdentifierStore,
  lookupIdentifier,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "../Identifier.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import {
  EmailPasswordService,
  EmailPasswordStore,
  exemptFromSecondFactor,
  type SecondFactorGate,
} from "../email/EmailPassword.ts";
import { enrolledGate, testChallenge } from "../testing/SecondFactor.ts";
import { Hooks } from "../Hooks.ts";
import { PasswordHasher } from "../password/Password.ts";
import {
  layer as memoryStores,
  memoryEmailPasswordStore,
  memoryOAuthAccountStore,
  memoryUserTable,
} from "../testing/MemoryStores.ts";
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
import * as RootSecret from "../RootSecret.ts";
import * as OAuth from "./OAuth.ts";
import type { HttpClient } from "effect/http";
import { runPromiseExitHttp, runPromiseHttp } from "../testing/HttpClient.ts";
import * as RemoteJwks from "../RemoteJwks.ts";

/** The key the service stores a state under: its SHA-256 digest. */
const stateKey = (state: string): string => createHash("sha256").update(state).digest("hex");

/** In-memory OAuth state store for authorization-URL tests. */
const StateStoreLive = () => {
  const map = MutableHashMap.empty<string, OAuthState>();
  return Layer.succeed(OAuthStateStore, {
    create: (s: OAuthState) =>
      Effect.sync(() => {
        MutableHashMap.set(map, s.state, s);
        return s;
      }),
    consume: (state: string) =>
      Effect.sync(() => {
        const v = Option.getOrNull(MutableHashMap.get(map, state));
        MutableHashMap.remove(map, state);
        return Option.fromNullishOr(v);
      }),
  });
};

const runWithState = <A, E>(
  eff: Effect.Effect<A, E, OAuthStateStore | TestCryptoServices>,
): Promise<A> =>
  Effect.runPromise(eff.pipe(Effect.provide(Layer.mergeAll(StateStoreLive(), testCryptoLayer))));

/** A single captured fetch call. */
/** A request body as `fetch` received it, as text (`null` without one). */
const requestBodyText = (body: BodyInit | null | undefined): string | null =>
  P.isString(body)
    ? body
    : body instanceof Uint8Array
      ? new TextDecoder().decode(body)
      : body instanceof URLSearchParams
        ? body.toString()
        : null;

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
    const url = P.isString(input) ? input : input instanceof URL ? input.href : input.url;
    const body = init?.body;
    calls.push({
      url,
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers),
      body: requestBodyText(body),
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

/** Run `thunk` against a provider that answers every request with `400`. */
const failingIdp = <A>(thunk: () => Promise<A>): Promise<A> =>
  withFetch(() => new Response("bad code", { status: 400 }), thunk);

const json = (value: object): Response =>
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
        const result = await runPromiseHttp(SpotifyProvider(CLIENT).exchangeCode("the-code"));
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
        await runPromiseHttp(GitLabProvider(CLIENT).exchangeCode("the-code", "verifier"));
        const [call] = calls;
        assert(call !== undefined, "the provider called fetch");
        expect(call.headers.get("authorization")).toBeNull();
        expect(call.body).toContain("client_secret=secret-xyz");
        expect(call.body).toContain("code_verifier=verifier");
      },
    );
  });
});

// --- Invalid provider bodies -------------------------------------------------

describe("OAuth provider bodies", () => {
  const html = () =>
    new Response("<html>Service Unavailable</html>", {
      status: 200,
      headers: { "content-type": "text/html" },
    });

  const expectProviderError = async (
    run: Effect.Effect<unknown, unknown, HttpClient.HttpClient>,
  ) => {
    const exit = await runPromiseExitHttp(run);
    assert(Exit.isFailure(exit), "the call fails");
    // A typed failure, not a defect.
    const failure = Cause.findErrorOption(exit.cause);
    assert(Option.isSome(failure), "the failure is typed");
    expect(failure.value).toMatchObject({ _tag: "OAuthProviderError", provider: "gitlab" });
  };

  it("a 2xx token body that is not JSON is an OAuthProviderError", () =>
    withFetch(html, () => expectProviderError(GitLabProvider(CLIENT).exchangeCode("the-code"))));

  it("a 2xx token body without access_token is an OAuthProviderError", () =>
    withFetch(
      () => json({ token_type: "bearer" }),
      () => expectProviderError(GitLabProvider(CLIENT).exchangeCode("the-code")),
    ));

  it("a 2xx user info body that is not JSON is an OAuthProviderError", () =>
    withFetch(html, () => expectProviderError(GitLabProvider(CLIENT).getUserInfo("at"))));

  it("a 2xx JWKS body that is not JSON is an OAuthProviderError", async () => {
    const key = await makeSigningKey("ES256");
    const token = await signIdToken("ES256", key.privateKey, baseClaims(1_700_000_000_000));
    const error = await withFetch(html, () =>
      runPromiseHttp(
        Effect.flip(
          verifyIdToken(token, {
            provider: "gitlab",
            jwksEndpoint: JWKS_URL,
            now: 1_700_000_000_000,
          }),
        ),
      ),
    );
    expect(error).toMatchObject({ _tag: "OAuthProviderError", provider: "gitlab" });
  });

  it("logs an upstream error body and keeps it out of the error", async () => {
    const lines: Array<string> = [];
    const collector = Logger.make((options) => void lines.push(Logger.formatJson.log(options)));
    const error = await withFetch(
      () =>
        new Response('{"error":"invalid_grant","internal":"db-7 stack trace"}', { status: 400 }),
      () =>
        runPromiseHttp(
          Effect.flip(GitLabProvider(CLIENT).exchangeCode("the-code")).pipe(
            Effect.provide(Logger.layer([collector])),
          ),
        ),
    );
    expect(error).toMatchObject({ _tag: "OAuthProviderError", provider: "gitlab" });
    expect(error.message).toContain("400");
    expect(error.message).not.toContain("db-7");
    expect(lines.some((line) => line.includes("db-7"))).toBe(true);
  });

  it("reads a token response as providers send it", () =>
    withFetch(
      () =>
        json({
          access_token: "at",
          expires_in: "3600",
          scope: ["user:read:email", "openid"],
          refresh_token: null,
        }),
      async () => {
        const tokens = await runPromiseHttp(GitLabProvider(CLIENT).exchangeCode("the-code"));
        expect(tokens).toEqual({
          access_token: "at",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "user:read:email openid",
        });
      },
    ));
});

// --- Provider-specific profile mapping --------------------------------------

describe("OAuth profile mapping", () => {
  const getProfile = (provider: OAuthProvider, body: object, method = "GET") =>
    withFetch(
      () => json(body),
      async (calls) => {
        const info = await runPromiseHttp(
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
          const info = await runPromiseHttp(
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

const b64u = (obj: object): string => Buffer.from(encodeJson(obj), "utf8").toString("base64url");

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
          runPromiseHttp(
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

  it("fetches the JWKS once per endpoint where a service caches key sets", async () => {
    const key = await makeSigningKey("ES256");
    const token = await signIdToken("ES256", key.privateKey, baseClaims(now));
    const params = {
      provider: "idp",
      jwksEndpoint: JWKS_URL,
      issuer: "https://idp",
      audience: "client-123",
      now,
    };
    const calls = await withFetch(
      () => json(key.jwks),
      async (calls) => {
        await runPromiseHttp(
          Effect.gen(function* () {
            yield* verifyIdToken(token, params);
            yield* verifyIdToken(token, params);
          }).pipe(Effect.provideServiceEffect(RemoteJwks.KeySets, RemoteJwks.makeKeySets())),
        );
        return calls.length;
      },
    );
    expect(calls).toBe(1);
  });

  const expectFailure = async (
    token: string,
    jwks: { keys: unknown[] },
    params: Parameters<typeof verifyIdToken>[1],
  ) =>
    withFetch(
      () => json(jwks),
      () => runPromiseHttp(Effect.flip(verifyIdToken(token, params))),
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
        runPromiseHttp(
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
      () => runPromiseHttp(discoverOAuthEndpoints("https://idp/")),
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
      () => runPromiseHttp(Effect.flip(discoverOAuthEndpoints("https://idp"))),
    );
    expect(err.message).toMatch(/missing/i);
  });
});

// --- Apple client secret -----------------------------------------------------

describe("OAuth.appleClientSecret", () => {
  it("produces a verifiable ES256 JWT with Apple's claims", async () => {
    const { publicKeyJwk, privateKeyPem } = testJwsKeyPair("ES256");
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

    const valid = testVerifyJws(
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

/** The default cipher over `secret`, its methods bound to the platform's WebCrypto. */
const makeCipher = (secret: string) =>
  Effect.runPromise(PlatformCrypto.provide(Cipher.aes256GcmCipher(secret)));

describe("Cipher.aes256GcmCipher", () => {
  it("encrypts and decrypts round-trip", async () => {
    const cipher = await makeCipher(TEST_SECRET);
    const token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345";
    const encrypted = await Effect.runPromise(cipher.encrypt(token));
    expect(encrypted).not.toBe(token);
    expect(await Effect.runPromise(cipher.decrypt(encrypted))).toBe(token);
  });

  it("produces a different ciphertext on each call (random IV)", async () => {
    const cipher = await makeCipher(TEST_SECRET);
    const e1 = await Effect.runPromise(cipher.encrypt("same-plaintext"));
    const e2 = await Effect.runPromise(cipher.encrypt("same-plaintext"));
    expect(e1).not.toBe(e2);
  });

  it("fails loudly on tampered ciphertext (GCM auth-tag)", async () => {
    const cipher = await makeCipher(TEST_SECRET);
    const encrypted = await Effect.runPromise(cipher.encrypt("hello"));
    const buf = Buffer.from(encrypted, "base64url");
    buf[buf.length - 1] ^= 0xff;
    const err = await Effect.runPromise(Effect.flip(cipher.decrypt(buf.toString("base64url"))));
    expect(err._tag).toBe("AuthError");
    expect(err.message).toMatch(/decrypt/i);
  });

  it("fails on ciphertext that is too short", async () => {
    const cipher = await makeCipher(TEST_SECRET);
    const err = await Effect.runPromise(Effect.flip(cipher.decrypt("dG9vc2hvcnQ")));
    expect(err._tag).toBe("AuthError");
  });
});

describe("OAuthService encryptTokens", () => {
  // SAFETY: OAuth.make resolves OAuthStateStore | OAuthAccountStore |
  // OAuthUserStore | IdentifierStore | UserStore | EmailPasswordStore |
  // SessionService at construction time. These tests only exercise
  // refreshAccessToken (which only touches OAuthAccountStore, via closure), so
  // the `undefined` others are never invoked.
  const unusedDepsLayer = Layer.mergeAll(
    Layer.succeed(OAuthStateStore)(undefined as never),
    Layer.succeed(OAuthUserStore)(undefined as never),
    Layer.succeed(IdentifierStore)(undefined as never),
    Layer.succeed(UserStore)(undefined as never),
    Layer.succeed(EmailPasswordStore)(memoryEmailPasswordStore()),
    Layer.succeed(SessionService)(undefined as never),
    testCryptoLayer,
  );

  const makeAccountStore = () => {
    const stored = MutableHashMap.empty<string, OAuthAccount>();
    const layer = Layer.succeed(OAuthAccountStore, {
      create: (a) =>
        Effect.sync(() => {
          MutableHashMap.set(stored, `${a.provider}:${a.providerId}`, a);
          return a;
        }),
      get: (p, id) => Effect.succeed(MutableHashMap.get(stored, `${p}:${id}`)),
      getByUserId: (uid) =>
        Effect.succeed(
          Arr.fromIterable(MutableHashMap.values(stored)).filter((a) => a.userId === uid),
        ),
      update: (a) =>
        Effect.sync(() => {
          MutableHashMap.set(stored, `${a.provider}:${a.providerId}`, a);
          return Option.fromNullishOr(a);
        }),
      linkToUser: (uid, a) =>
        Effect.sync(() => {
          MutableHashMap.set(stored, `${a.provider}:${a.providerId}`, { ...a, userId: uid });
        }),
      deleteByUserId: () => Effect.void,
      unlinkFromUser: (uid, p) =>
        Effect.sync(() => {
          MutableHashMap.forEach(stored, (v, k) => {
            if (v.userId === uid && v.provider === p) MutableHashMap.remove(stored, k);
          });
        }),
      delete: (p, id) =>
        Effect.sync(() => {
          MutableHashMap.remove(stored, `${p}:${id}`);
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

  /** Open a stored token as the service would, under `encryption`. */
  const openStored = (
    stored: string,
    row: string,
    encryption?: RootSecret.Encryption,
  ): Promise<string> =>
    Effect.runPromise(
      Effect.flatMap(RootSecret.sealerFor("oauth-tokens", encryption), (sealer) =>
        sealer.open(stored, row),
      ).pipe(Effect.provide(testCryptoLayer)),
    );
  const accessRow = "github\u0000gh-1\u0000access";

  it("reads tokens the override secret's legacy cipher wrote, and rewrites them sealed to their row", async () => {
    const { stored, layer: accountStoreLive } = makeAccountStore();
    const cipher = await makeCipher(TEST_SECRET);

    const PLAIN_ACCESS = "plain-access-token";
    const PLAIN_REFRESH = "plain-refresh-token";
    const NEW_ACCESS = "new-access-token-after-refresh";

    // Pre-populate store with encrypted tokens (as the service would have stored them).
    const encAccess = await Effect.runPromise(cipher.encrypt(PLAIN_ACCESS));
    const encRefresh = await Effect.runPromise(cipher.encrypt(PLAIN_REFRESH));
    MutableHashMap.set(stored, "github:gh-1", {
      id: "acc-1",
      userId: "user-1",
      provider: "github",
      providerId: "gh-1",
      accessToken: encAccess,
      refreshToken: encRefresh,
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      updatedAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
    });

    const service = await runPromiseHttp(
      OAuth.make(
        { github: githubProvider },
        { encryptTokens: { secret: Redacted.make(TEST_SECRET) } },
      ).pipe(Effect.provide(Layer.mergeAll(accountStoreLive, unusedDepsLayer))),
    );

    let capturedRefreshToken: string | null = null;
    const tokenResp: OAuthTokenResponse = { access_token: NEW_ACCESS, token_type: "bearer" };

    const newAccessToken = await withFetch(
      (_url, init) => {
        const body = requestBodyText(init?.body);
        if (body !== null) {
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
    // The new token is sealed in the current format, which the legacy cipher cannot open.
    const updated = Option.getOrUndefined(MutableHashMap.get(stored, "github:gh-1"));
    assert(updated !== undefined, "the account is stored");
    expect(updated.accessToken.startsWith(Cipher.SEALED_PREFIX)).toBe(true);
    expect(await Effect.runPromise(Effect.isFailure(cipher.decrypt(updated.accessToken)))).toBe(
      true,
    );
    const encryption = { secret: Redacted.make(TEST_SECRET) };
    expect(await openStored(updated.accessToken, accessRow, encryption)).toBe(NEW_ACCESS);
    // The root secret's key is not the override's.
    await expect(openStored(updated.accessToken, accessRow)).rejects.toThrow(/Decryption failed/);
  });

  it("by default reads plaintext rows and seals new tokens under the root secret, bound to their row", async () => {
    const { stored, layer: accountStoreLive } = makeAccountStore();

    const PLAIN_ACCESS = "plain-access-token";
    const PLAIN_REFRESH = "plain-refresh-token";
    const NEW_ACCESS = "new-access-token-after-refresh";

    MutableHashMap.set(stored, "github:gh-1", {
      id: "acc-1",
      userId: "user-1",
      provider: "github",
      providerId: "gh-1",
      accessToken: PLAIN_ACCESS,
      refreshToken: PLAIN_REFRESH,
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      updatedAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
    });

    const service = await runPromiseHttp(
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
    const updated = Option.getOrUndefined(MutableHashMap.get(stored, "github:gh-1"));
    assert(updated !== undefined, "the account is stored");
    expect(updated.accessToken.startsWith(Cipher.SEALED_PREFIX)).toBe(true);
    expect(await openStored(updated.accessToken, accessRow)).toBe(NEW_ACCESS);
    // A ciphertext moved to another account or field does not open.
    await expect(openStored(updated.accessToken, "github\u0000gh-2\u0000access")).rejects.toThrow(
      /Decryption failed/,
    );
    await expect(openStored(updated.accessToken, "github\u0000gh-1\u0000refresh")).rejects.toThrow(
      /Decryption failed/,
    );
  });

  it("accepts a custom TokenCipher via { cipher }", async () => {
    const { stored, layer: accountStoreLive } = makeAccountStore();
    const customCipher = await makeCipher(TEST_SECRET);

    const PLAIN_REFRESH = "custom-cipher-refresh-token";
    const NEW_ACCESS = "new-access-from-custom-cipher";

    const encRefresh = await Effect.runPromise(customCipher.encrypt(PLAIN_REFRESH));
    MutableHashMap.set(stored, "github:gh-2", {
      id: "acc-2",
      userId: "user-2",
      provider: "github",
      providerId: "gh-2",
      accessToken: await Effect.runPromise(customCipher.encrypt("old-access")),
      refreshToken: encRefresh,
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      updatedAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
    });

    const service = await runPromiseHttp(
      OAuth.make({ github: githubProvider }, { encryptTokens: { cipher: customCipher } }).pipe(
        Effect.provide(Layer.mergeAll(accountStoreLive, unusedDepsLayer)),
      ),
    );

    let capturedRefreshToken: string | null = null;
    const tokenResp: OAuthTokenResponse = { access_token: NEW_ACCESS, token_type: "bearer" };

    await withFetch(
      (_url, init) => {
        const body = requestBodyText(init?.body);
        if (body !== null) {
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
    Layer.succeed(EmailPasswordStore)(memoryEmailPasswordStore()),
    Layer.succeed(SessionService)(undefined as never),
    testCryptoLayer,
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
    const stored = MutableHashMap.fromIterable<string, OAuthAccount>(
      accounts.map((a) => [`${a.provider}:${a.providerId}`, a]),
    );
    return Layer.succeed(OAuthAccountStore, {
      create: (a) =>
        Effect.sync(() => {
          MutableHashMap.set(stored, `${a.provider}:${a.providerId}`, a);
          return a;
        }),
      get: (p, id) => Effect.succeed(MutableHashMap.get(stored, `${p}:${id}`)),
      getByUserId: (uid) =>
        Effect.succeed(
          Arr.fromIterable(MutableHashMap.values(stored)).filter((a) => a.userId === uid),
        ),
      update: (a) =>
        Effect.sync(() => {
          MutableHashMap.set(stored, `${a.provider}:${a.providerId}`, a);
          return Option.fromNullishOr(a);
        }),
      linkToUser: (uid, a) =>
        Effect.sync(() => {
          MutableHashMap.set(stored, `${a.provider}:${a.providerId}`, { ...a, userId: uid });
        }),
      deleteByUserId: () => Effect.void,
      unlinkFromUser: (uid, p) =>
        Effect.sync(() => {
          MutableHashMap.forEach(stored, (v, k) => {
            if (v.userId === uid && v.provider === p) MutableHashMap.remove(stored, k);
          });
        }),
      delete: (p, id) =>
        Effect.sync(() => {
          MutableHashMap.remove(stored, `${p}:${id}`);
        }),
      ...(hasPassword !== undefined && { hasPassword: () => Effect.succeed(hasPassword) }),
    });
  };

  const buildService = (accountLayer: Layer.Layer<OAuthAccountStore>) =>
    runPromiseHttp(
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

/** An OAuth sign-in refused over a claimed email: a conflict on the address, nothing linked, minted or revoked, the password and the address as they were. */
const refusedClaim = (localVerified: boolean) => ({
  failure: expect.objectContaining({ _tag: "EmailInUseError", email: "user@example.com" }),
  accounts: 0,
  minted: [],
  journal: [],
  password: "squatter-hash",
  address: { userId: "user-existing", verified: localVerified },
});

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
      consume: (k) =>
        Effect.succeed(Option.fromNullishOr(k === stateKey(state.state) ? state : null)),
    });

  const makeAccountLayer = (
    existing?: OAuthAccount,
    stored = MutableHashMap.fromIterable<string, OAuthAccount>(
      existing ? [[`${existing.provider}:${existing.providerId}`, existing]] : [],
    ),
  ) => {
    return Layer.succeed(OAuthAccountStore, {
      create: (a) =>
        Effect.sync(() => {
          MutableHashMap.set(stored, `${a.provider}:${a.providerId}`, a);
          return a;
        }),
      get: (p, id) => Effect.succeed(MutableHashMap.get(stored, `${p}:${id}`)),
      getByUserId: (uid) =>
        Effect.succeed(
          Arr.fromIterable(MutableHashMap.values(stored)).filter((a) => a.userId === uid),
        ),
      update: (a) =>
        Effect.sync(() => {
          MutableHashMap.set(stored, `${a.provider}:${a.providerId}`, a);
          return Option.fromNullishOr(a);
        }),
      linkToUser: (uid, a) =>
        Effect.sync(() => {
          MutableHashMap.set(stored, `${a.provider}:${a.providerId}`, { ...a, userId: uid });
        }),
      deleteByUserId: () => Effect.void,
      unlinkFromUser: () => Effect.void,
      delete: (p, id) =>
        Effect.sync(() => {
          MutableHashMap.remove(stored, `${p}:${id}`);
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
      createUser: ({ attributes, ...input }) =>
        Effect.succeed({
          user: makeUser({ ...input, ...(attributes !== undefined && { attributes }) }),
          created: true,
        }),
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
    const records = MutableHashMap.empty<string, Identifier>();
    Arr.forEach(seeds, (seed) => {
      const identifier = makeIdentifier({
        userId: seed.userId,
        type: "email",
        value: seed.email,
        verified: seed.verified ?? true,
        now: DateTime.toDateUtc(DateTime.nowUnsafe()),
      });
      MutableHashMap.set(records, identifier.id, identifier);
    });
    const store = memoryIdentifierStore(records);
    return { records, store, layer: Layer.succeed(IdentifierStore)(store) };
  };

  /** Core user-by-id store used by signInWithCallback's auto-link resolution. */
  const makeCoreUserLayer = (...users: ReadonlyArray<Types.User>) =>
    Layer.succeed(UserStore, {
      get: (id) => Effect.succeed(Arr.findFirst(users, (u) => u.id === id)),
    });

  /**
   * A `SessionService` stub. `minted` collects the user ids sessions were
   * created for; `journal` records both mints and revocations, in order.
   */
  const makeSessionLayer = (
    userId: string,
    minted: Array<string> = [],
    journal: Array<string> = [],
  ) => {
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
      createSession: (id) =>
        Effect.sync(() => {
          minted.push(id);
          journal.push(`mint:${id}`);
          return { session, token: "token-test" };
        }),
      validateSession: () => Effect.succeed({ session, user }),
      invalidateSession: () => Effect.void,
      invalidateUserSessions: (id) => Effect.sync(() => void journal.push(`revoke:${id}`)),
      listSessions: () => Effect.succeed([]),
      revokeSessionById: () => Effect.succeed(false),
      revokeOtherSessions: () => Effect.void,
      setSessionAttributes: () => Effect.succeed(session),
    });
  };

  // SAFETY: linkAccount never touches SessionService, so the `undefined` stub is
  // never invoked by the tests that use it.
  const noSession = Layer.succeed(SessionService)(undefined as never);

  /** A password store holding no passwords, for the tests that never prove an address. */
  const noPasswordsLayer = Layer.succeed(EmailPasswordStore)(memoryEmailPasswordStore());

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
    const service = await runPromiseHttp(
      OAuth.make({ github: makeTestProvider("github") }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github")),
            makeAccountLayer(),
            makeUserLayer(user),
            identifiers.layer,
            makeCoreUserLayer(user),
            noSession,
            noPasswordsLayer,
            testCryptoLayer,
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
    const service = await runPromiseHttp(
      OAuth.make({ github: makeTestProvider("github") }, { allowDifferentEmails: true }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github")),
            makeAccountLayer(),
            makeUserLayer(user),
            identifiers.layer,
            makeCoreUserLayer(user),
            noSession,
            noPasswordsLayer,
            testCryptoLayer,
          ),
        ),
      ),
    );

    const account = await withProviderFetch(mockUserInfo({ email: "user@example.com" }), () =>
      Effect.runPromise(service.linkAccount("u1", "github", "code-abc", "state-123")),
    );

    expect(account.userId).toBe("u1");
  });

  it("a provider without email is link-only: it links, then signs that user in, but never signs up", async () => {
    const user = makeUser();
    const identifiers = makeIdentifiers({ userId: user.id, email: "user@example.com" });
    const stored = MutableHashMap.empty<string, OAuthAccount>();
    const minted: Array<string> = [];
    const layer = Layer.mergeAll(
      makeStateLayer(makeState("reddit")),
      makeAccountLayer(undefined, stored),
      makeUserLayer(user),
      identifiers.layer,
      makeCoreUserLayer(user),
      makeSessionLayer(user.id, minted),
      noPasswordsLayer,
      testCryptoLayer,
    );
    const service = await runPromiseHttp(
      OAuth.make({ reddit: makeTestProvider("reddit") }).pipe(Effect.provide(layer)),
    );
    const noEmail = (providerId: string) => (url: string) =>
      url.includes("/token") ? json(mockTokenResponse) : json({ id: providerId, name: "Snoo" });

    const strangerError = await withFetch(noEmail("someone-else"), () =>
      Effect.runPromise(Effect.flip(service.signInWithCallback("state-123", "code"))),
    );
    expect(strangerError).toBeInstanceOf(OAuthMissingEmailError);
    expect(minted).toEqual([]);

    const linked = await withFetch(noEmail("snoo-1"), () =>
      Effect.runPromise(service.linkAccount(user.id, "reddit", "code", "state-123")),
    );
    expect(linked.userId).toBe(user.id);

    const signedIn = await withFetch(noEmail("snoo-1"), () =>
      Effect.runPromise(service.signInWithCallback("state-123", "code")),
    );
    expect(signedIn.user.id).toBe(user.id);
    expect(signedIn.isNewUser).toBe(false);
  });

  it("allowDifferentEmails: false succeeds when emails match", async () => {
    const user = makeUser();
    const identifiers = makeIdentifiers({ userId: user.id, email: "user@example.com" });
    const service = await runPromiseHttp(
      OAuth.make({ github: makeTestProvider("github") }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github")),
            makeAccountLayer(),
            makeUserLayer(user),
            identifiers.layer,
            makeCoreUserLayer(user),
            noSession,
            noPasswordsLayer,
            testCryptoLayer,
          ),
        ),
      ),
    );

    const account = await withProviderFetch(mockUserInfo({ email: "user@example.com" }), () =>
      Effect.runPromise(service.linkAccount("u1", "github", "code-abc", "state-123")),
    );

    expect(account.provider).toBe("github");
  });

  /**
   * Run `signInWithCallback` for a provider identity that is new, against one
   * existing user holding `user@example.com` (verified or not) with a
   * password, and report what the flow wrote: the accounts it created, the
   * sessions it minted and revoked (in order), the password left on the
   * account and the address afterwards.
   */
  const signInOverClaimedEmail = async (
    options: OAuth.OAuthServiceOptions,
    claim: { readonly localVerified: boolean; readonly providerVerified: boolean },
  ) => {
    const existingUser = makeUser({ id: "user-existing" });
    const identifiers = makeIdentifiers({
      userId: existingUser.id,
      email: "user@example.com",
      verified: claim.localVerified,
    });
    const accounts = MutableHashMap.empty<string, OAuthAccount>();
    const minted: Array<string> = [];
    const journal: Array<string> = [];
    const table = memoryUserTable();
    MutableHashMap.set(table.passwordHashes, existingUser.id, "squatter-hash");
    const passwords = memoryEmailPasswordStore(table);
    const service = await runPromiseHttp(
      OAuth.make({ github: makeTestProvider("github") }, options).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github", "claimed-state")),
            makeAccountLayer(undefined, accounts),
            makeUserLayer(existingUser),
            identifiers.layer,
            makeCoreUserLayer(existingUser),
            makeSessionLayer(existingUser.id, minted, journal),
            Layer.succeed(EmailPasswordStore)(passwords),
            testCryptoLayer,
          ),
        ),
      ),
    );
    const result = await withProviderFetch(
      mockUserInfo({
        email: "user@example.com",
        id: "gh-claimed",
        email_verified: claim.providerVerified,
      }),
      () =>
        Effect.runPromise(
          Effect.result(service.signInWithCallback("claimed-state", "code-claimed")),
        ),
    );
    const address = await Effect.runPromise(
      identifiers.store.getByValue("email", "user@example.com"),
    );
    const password = await Effect.runPromise(passwords.getPasswordHash(existingUser.id));
    return {
      result,
      existingUser,
      accounts: MutableHashMap.size(accounts),
      minted,
      journal,
      password,
      address,
    };
  };
  type ClaimedEmailOutcome = Awaited<ReturnType<typeof signInOverClaimedEmail>>;

  /** What a sign-in left behind: the error it failed with and the writes it made. */
  const aftermath = ({
    result,
    accounts,
    minted,
    journal,
    password,
    address,
  }: ClaimedEmailOutcome) => ({
    failure: Result.isFailure(result) ? result.failure : null,
    accounts,
    minted,
    journal,
    password: Option.getOrNull(password),
    address: Option.getOrNull(
      Option.map(address, ({ userId, verified }) => ({ userId, verified })),
    ),
  });

  /** A first-proof takeover: the squatter's password and sessions cleared, then the link and the prover's session. */
  const provenClaim = {
    failure: null,
    accounts: 1,
    minted: ["user-existing"],
    journal: ["revoke:user-existing", "mint:user-existing"],
    password: null,
    address: { userId: "user-existing", verified: true },
  };

  it("auto-links a provider-verified email to a verified local address by default, keeping its password and sessions", async () => {
    const outcome = await signInOverClaimedEmail(
      {},
      { localVerified: true, providerVerified: true },
    );

    assert(Result.isSuccess(outcome.result));
    expect(outcome.result.success.isNewUser).toBe(false);
    expect(outcome.result.success.user.id).toBe(outcome.existingUser.id);
    expect(outcome.result.success.token).toBe("token-test");
    expect(aftermath(outcome)).toEqual({
      ...provenClaim,
      journal: ["mint:user-existing"],
      password: "squatter-hash",
    });
  });

  it("a provider-verified email proves an unverified local address: the squatter's password and sessions are cleared before the link", async () => {
    // The squatter signed up with the victim's address and a password; the
    // victim's provider verified it. That is the address's first proof: the
    // victim lands in the account, and the squatter keeps nothing.
    const outcome = await signInOverClaimedEmail(
      {},
      { localVerified: false, providerVerified: true },
    );

    assert(Result.isSuccess(outcome.result));
    expect(outcome.result.success.isNewUser).toBe(false);
    expect(outcome.result.success.user.id).toBe(outcome.existingUser.id);
    expect(aftermath(outcome)).toEqual(provenClaim);
  });

  it("trustedProviders: refuses to link an unverified provider email to a verified local address", async () => {
    expect(
      aftermath(
        await signInOverClaimedEmail(
          { trustedProviders: ["github"] },
          { localVerified: true, providerVerified: false },
        ),
      ),
    ).toEqual(refusedClaim(true));
  });

  it("trustedProviders: an unverified provider email never takes over an unverified local address", async () => {
    expect(
      aftermath(
        await signInOverClaimedEmail(
          { trustedProviders: ["github"] },
          { localVerified: false, providerVerified: false },
        ),
      ),
    ).toEqual(refusedClaim(false));
  });

  it("an unverified provider email never takes over an unverified local address by default", async () => {
    expect(
      aftermath(
        await signInOverClaimedEmail({}, { localVerified: false, providerVerified: false }),
      ),
    ).toEqual(refusedClaim(false));
  });

  it("trustedProviders: a trusted provider proves an unverified local address with auto-link off", async () => {
    expect(
      aftermath(
        await signInOverClaimedEmail(
          { autoLinkByVerifiedEmail: false, trustedProviders: ["github"] },
          { localVerified: false, providerVerified: true },
        ),
      ),
    ).toEqual(provenClaim);
  });

  it("trustedProviders: a trusted provider auto-links a verified match with auto-link off", async () => {
    const outcome = await signInOverClaimedEmail(
      { autoLinkByVerifiedEmail: false, trustedProviders: ["github"] },
      { localVerified: true, providerVerified: true },
    );

    assert(Result.isSuccess(outcome.result));
    expect(outcome.result.success.user.id).toBe(outcome.existingUser.id);
    expect(outcome.accounts).toBe(1);
  });

  it("autoLinkByVerifiedEmail: false refuses a verified match from an untrusted provider with a conflict", async () => {
    expect(
      aftermath(
        await signInOverClaimedEmail(
          { autoLinkByVerifiedEmail: false },
          { localVerified: true, providerVerified: true },
        ),
      ),
    ).toEqual(refusedClaim(true));
  });

  it("autoLinkByVerifiedEmail: false never takes over an unverified local address for an untrusted provider", async () => {
    expect(
      aftermath(
        await signInOverClaimedEmail(
          { autoLinkByVerifiedEmail: false },
          { localVerified: false, providerVerified: true },
        ),
      ),
    ).toEqual(refusedClaim(false));
  });

  it("trustedProviders: untrusted provider refuses a claimed email without email_verified", async () => {
    // Without email_verified the flow must not auto-link, and it must not
    // double-claim the email either.
    expect(
      aftermath(
        await signInOverClaimedEmail(
          { trustedProviders: [] },
          { localVerified: true, providerVerified: false },
        ),
      ),
    ).toEqual(refusedClaim(true));
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

    const service = await runPromiseHttp(
      OAuth.make({ github: makeTestProvider("github") }, { trustedProviders: [] }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github", "fresh-state")),
            makeAccountLayer(),
            userLayer,
            identifiers.layer,
            makeCoreUserLayer(newUser),
            makeSessionLayer(newUser.id),
            noPasswordsLayer,
            testCryptoLayer,
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
    expect(Option.getOrUndefined(claimed)?.userId).toBe(newUser.id);
    expect(Option.getOrUndefined(claimed)?.verified).toBe(false);
    // The store was handed the address to create the user with.
    expect(createdWith).toEqual([{ type: "email", value: "user@example.com", verified: false }]);
  });

  it("answers a second-factor challenge, and no session, for a linked user the gate requires one of", async () => {
    const user = makeUser({ id: "enrolled-user" });
    const now = DateTime.toEpochMillis(DateTime.nowUnsafe());
    const minted: Array<string> = [];
    const challenged: Array<string> = [];
    const signIn = (gate: Layer.Layer<SecondFactorGate>) =>
      Effect.gen(function* () {
        const service = yield* OAuth.make({ github: makeTestProvider("github") });
        return yield* service.signInWithCallback("linked-state", "code-linked");
      }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github", "linked-state")),
            makeAccountLayer({
              id: "acc-enrolled",
              userId: user.id,
              provider: "github",
              providerId: "gh-enrolled",
              accessToken: "at-old",
              createdAt: now,
              updatedAt: now,
            }),
            Layer.succeed(OAuthUserStore, {
              getUser: () => Effect.succeed(user),
              createUser: () => Effect.die("no user is created"),
            }),
            makeIdentifiers({ userId: user.id, email: "enrolled@example.com", verified: true })
              .layer,
            makeCoreUserLayer(user),
            makeSessionLayer(user.id, minted),
            noPasswordsLayer,
            testCryptoLayer,
            gate,
          ),
        ),
      );
    const userInfo = mockUserInfo({ email: "enrolled@example.com", id: "gh-enrolled" });

    const gated = await withProviderFetch(userInfo, () =>
      runPromiseHttp(signIn(enrolledGate(challenged))),
    );
    expect(gated.secondFactor).toEqual(testChallenge);
    expect(gated.session).toBeUndefined();
    expect(challenged).toEqual([user.id]);
    expect(minted).toEqual([]);

    const exempt = await withProviderFetch(userInfo, () =>
      runPromiseHttp(
        signIn(Layer.merge(enrolledGate(challenged), exemptFromSecondFactor("oauth"))),
      ),
    );
    expect(exempt.secondFactor).toBeUndefined();
    expect(exempt.token).toBe("token-test");
    expect(minted).toEqual([user.id]);
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

    const service = await runPromiseHttp(
      OAuth.make({ github: makeTestProvider("github") }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github", "verified-state")),
            makeAccountLayer(),
            userLayer,
            identifiers.layer,
            makeCoreUserLayer(newUser),
            makeSessionLayer(newUser.id),
            noPasswordsLayer,
            testCryptoLayer,
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
    expect(Option.getOrUndefined(claimed)?.userId).toBe(newUser.id);
    expect(Option.getOrUndefined(claimed)?.verified).toBe(true);
    expect(Option.getOrUndefined(claimed)?.verifiedAt).toBeInstanceOf(Date);
    expect(createdWith).toEqual([
      { type: "email", value: "user@example.com", verified: true, verifiedAt: expect.any(Date) },
    ]);
  });

  it("refuses when the store's writer returns the existing owner, and links nothing to the owner", async () => {
    const owner = makeUser({ id: "owner-id" });
    const identifiers = makeIdentifiers();
    const accounts = MutableHashMap.empty<string, OAuthAccount>();
    const accountLayer = Layer.succeed(OAuthAccountStore, {
      create: (a) => Effect.sync(() => (MutableHashMap.set(accounts, a.id, a), a)),
      get: () => Effect.succeedNone,
      getByUserId: (uid) =>
        Effect.succeed(
          Arr.fromIterable(MutableHashMap.values(accounts)).filter((a) => a.userId === uid),
        ),
      update: (a) =>
        Effect.sync(() => Option.fromNullishOr((MutableHashMap.set(accounts, a.id, a), a))),
      linkToUser: (uid, a) =>
        Effect.sync(() => void MutableHashMap.set(accounts, a.id, { ...a, userId: uid })),
      deleteByUserId: () => Effect.void,
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
          MutableHashMap.set(identifiers.records, held.id, held);
          return { user: owner, created: false };
        }),
    });

    const service = await runPromiseHttp(
      OAuth.make({ github: makeTestProvider("github") }).pipe(
        Effect.provide(
          Layer.mergeAll(
            makeStateLayer(makeState("github", "owner-state")),
            accountLayer,
            userLayer,
            identifiers.layer,
            makeCoreUserLayer(owner),
            makeSessionLayer(owner.id),
            noPasswordsLayer,
            testCryptoLayer,
          ),
        ),
      ),
    );

    const err = await withProviderFetch(
      mockUserInfo({ email: "owner@example.com", id: "gh-attacker", email_verified: true }),
      () => Effect.runPromise(Effect.flip(service.signInWithCallback("owner-state", "code-owner"))),
    );

    assert.instanceOf(err, EmailInUseError);
    expect(err.message).toMatch(/already associated/i);
    // No account linked to the owner, and the owner's address is still unverified.
    expect(MutableHashMap.size(accounts)).toBe(0);
    const held = await Effect.runPromise(
      identifiers.store.getByValue("email", "owner@example.com"),
    );
    expect(Option.getOrUndefined(held)).toMatchObject({ userId: owner.id, verified: false });
  });

  it("updateUserInfoOnLink: false (default) does not update the user profile", async () => {
    let updateCalled = false;
    const user = makeUser();
    const service = await runPromiseHttp(
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
            noPasswordsLayer,
            testCryptoLayer,
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
    const service = await runPromiseHttp(
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
            noPasswordsLayer,
            testCryptoLayer,
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
    const states = MutableHashMap.fromIterable<string, OAuthState>(
      seed.map((s) => [stateKey(s.state), s]),
    );
    const store: typeof OAuthStateStore.Service = {
      create: (s) =>
        Effect.sync(() => {
          MutableHashMap.set(states, s.state, s);
          return s;
        }),
      consume: (k) =>
        Effect.sync(() => {
          const entry = Option.getOrNull(MutableHashMap.get(states, k));
          MutableHashMap.remove(states, k);
          return Option.fromNullishOr(entry);
        }),
    };
    return { states, store };
  };

  const makeAccounts = (...seed: ReadonlyArray<OAuthAccount>) => {
    const accounts = MutableHashMap.fromIterable<string, OAuthAccount>(
      seed.map((a) => [`${a.provider}:${a.providerId}`, a]),
    );
    const store: typeof OAuthAccountStore.Service = {
      create: (a) =>
        Effect.sync(() => {
          MutableHashMap.set(accounts, `${a.provider}:${a.providerId}`, a);
          return a;
        }),
      get: (p, id) => Effect.succeed(MutableHashMap.get(accounts, `${p}:${id}`)),
      getByUserId: (uid) =>
        Effect.succeed(
          Arr.fromIterable(MutableHashMap.values(accounts)).filter((a) => a.userId === uid),
        ),
      update: (a) =>
        Effect.sync(() => {
          MutableHashMap.set(accounts, `${a.provider}:${a.providerId}`, a);
          return Option.fromNullishOr(a);
        }),
      linkToUser: () => Effect.void,
      deleteByUserId: () => Effect.void,
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
    Layer.succeed(EmailPasswordStore)(memoryEmailPasswordStore()),
    // SAFETY: never called by handleCallback or generateAuthorizationUrl.
    Layer.succeed(SessionService)(undefined as never),
  );

  const makeService = (
    stateStore: typeof OAuthStateStore.Service,
    accountStore: typeof OAuthAccountStore.Service = makeAccounts().store,
  ) =>
    runPromiseHttp(
      OAuth.make({ github }).pipe(
        Effect.provide(
          Layer.mergeAll(
            Layer.succeed(OAuthStateStore)(stateStore),
            Layer.succeed(OAuthAccountStore)(accountStore),
            unusedByCallbackLayer,
            testCryptoLayer,
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
      expect(MutableHashMap.has(states, stateKey("st-1"))).toBe(false);
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
      // The store holds the same account with its tokens sealed.
      const stored = Option.getOrUndefined(MutableHashMap.get(accounts.accounts, "github:gh-9"));
      expect(stored).toEqual({ ...result.account, accessToken: expect.stringMatching(/^v2\./) });
      // The state is single-use.
      expect(MutableHashMap.has(states, stateKey("st-1"))).toBe(false);
    });

    it("reports a provider account linked concurrently as OAuthAccountConflictError and keeps its user", async () => {
      const { store } = makeStateStore(liveState());
      const rival: OAuthAccount = {
        id: "acc-rival",
        userId: "u-rival",
        provider: "github",
        providerId: "gh-9",
        accessToken: "rival-at",
        createdAt: 1,
        updatedAt: 1,
      };
      const accounts = memoryOAuthAccountStore();
      await Effect.runPromise(accounts.create(rival));
      // The concurrent callback links the account after this one's lookup missed.
      let lookups = 0;
      const racing: typeof OAuthAccountStore.Service = {
        ...accounts,
        get: (provider, providerId) =>
          lookups++ === 0 ? Effect.succeedNone : accounts.get(provider, providerId),
      };
      const service = await makeService(store, racing);

      const err = await providerFetch(
        { access_token: "at-1", token_type: "bearer" },
        { id: "gh-9", email: "new@example.com" },
        () =>
          Effect.runPromise(
            Effect.flip(service.handleCallback("st-1", "code", { linkToUserId: "u-7" })),
          ),
      );

      expect(err._tag).toBe("OAuthAccountConflictError");
      expect(await Effect.runPromise(accounts.get("github", "gh-9"))).toEqual(Option.some(rival));
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
      // The store holds the same account with its tokens sealed.
      const stored = Option.getOrUndefined(MutableHashMap.get(accounts.accounts, "github:gh-9"));
      expect(stored).toEqual({
        ...result.account,
        accessToken: expect.stringMatching(/^v2\./),
        refreshToken: expect.stringMatching(/^v2\./),
      });
    });
  });

  /** The real `KeyValueStore`-backed store, holding one live state. */
  const kvStateStore = (): typeof OAuthStateStore.Service => {
    const store = Effect.runSync(oauthStateStoreKV.pipe(Effect.provide(KeyValueStore.layerMemory)));
    Effect.runSync(store.create({ ...liveState(), state: stateKey("st-1") }));
    return store;
  };

  describe("the callback state is single-use", () => {
    it("refuses handleCallback replayed after the first exchange failed", async () => {
      const service = await makeService(kvStateStore());
      const failed = await failingIdp(() =>
        Effect.runPromise(Effect.flip(service.handleCallback("st-1", "code-1"))),
      );
      expect(failed._tag).toBe("OAuthProviderError");

      const replay = await providerFetch(
        { access_token: "at-1", token_type: "bearer" },
        { id: "gh-9" },
        () => Effect.runPromise(Effect.flip(service.handleCallback("st-1", "code-2"))),
      );
      expect(replay._tag).toBe("OAuthStateNotFoundError");
    });

    it("refuses handleCallback replayed after a success", async () => {
      const service = await makeService(kvStateStore());
      const callback = () => service.handleCallback("st-1", "code-1");
      const tokens = { access_token: "at-1", token_type: "bearer" };
      const first = await providerFetch(tokens, { id: "gh-9" }, () =>
        Effect.runPromise(callback()),
      );
      expect(first.account.providerId).toBe("gh-9");
      const replay = await providerFetch(tokens, { id: "gh-9" }, () =>
        Effect.runPromise(Effect.flip(callback())),
      );
      expect(replay._tag).toBe("OAuthStateNotFoundError");
    });

    it("admits only one of two concurrent handleCallback calls with the same state", async () => {
      const service = await makeService(kvStateStore());
      const callback = Effect.result(service.handleCallback("st-1", "code-1"));
      const results = await providerFetch(
        { access_token: "at-1", token_type: "bearer" },
        { id: "gh-9" },
        () => Effect.runPromise(Effect.all([callback, callback], { concurrency: "unbounded" })),
      );
      const refusals = Arr.filter(results, Result.isFailure).map((r) => r.failure._tag);
      expect(Arr.filter(results, Result.isSuccess)).toHaveLength(1);
      expect(refusals).toEqual(["OAuthStateNotFoundError"]);
    });

    it("refuses linkAccount replayed after the first exchange failed", async () => {
      const service = await makeService(kvStateStore());
      const failed = await failingIdp(() =>
        Effect.runPromise(Effect.flip(service.linkAccount("u-1", "github", "code-1", "st-1"))),
      );
      expect(failed._tag).toBe("OAuthProviderError");

      const replay = await providerFetch(
        { access_token: "at-1", token_type: "bearer" },
        { id: "gh-9" },
        () =>
          Effect.runPromise(Effect.flip(service.linkAccount("u-1", "github", "code-2", "st-1"))),
      );
      expect(replay._tag).toBe("OAuthStateNotFoundError");
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
      expect(
        Option.getOrUndefined(MutableHashMap.get(states, stateKey(result.state)))?.returnTo,
      ).toBeUndefined();
    });

    it("records returnTo on the stored state", async () => {
      const { states, store } = makeStateStore();
      const service = await makeService(store);
      const result = await Effect.runPromise(
        service.generateAuthorizationUrl("github", { returnTo: "/after" }),
      );
      expect(
        Option.getOrUndefined(MutableHashMap.get(states, stateKey(result.state))),
      ).toMatchObject({
        provider: "github",
        returnTo: "/after",
      });
    });

    it("derives the PKCE verifier from the state rather than storing it, and sends it on the callback", async () => {
      const { states, store } = makeStateStore();
      const pkceGithub = OAuth.provider("github", github.config, true);
      const service = await runPromiseHttp(
        OAuth.make({ github: pkceGithub }).pipe(
          Effect.provide(
            Layer.mergeAll(
              Layer.succeed(OAuthStateStore)(store),
              Layer.succeed(OAuthAccountStore)(makeAccounts().store),
              unusedByCallbackLayer,
              testCryptoLayer,
            ),
          ),
        ),
      );
      const { url, state } = await Effect.runPromise(service.generateAuthorizationUrl("github"));
      const challenge = new URL(url).searchParams.get("code_challenge");
      const stored = Option.getOrUndefined(MutableHashMap.get(states, stateKey(state)));
      assert(stored !== undefined, "the state is stored under its digest");
      expect(stored.codeVerifier).toBeUndefined();

      const calls = await withFetch(
        (fetchUrl) =>
          fetchUrl.includes("/token")
            ? json({ access_token: "at-1", token_type: "bearer" })
            : json({ id: "gh-9" }),
        async (captured) => {
          await Effect.runPromise(service.handleCallback(state, "code"));
          return captured;
        },
      );
      const tokenCall = calls.find((call) => call.url.includes("/token"));
      const sentVerifier = new URLSearchParams(tokenCall?.body ?? "").get("code_verifier");
      assert(sentVerifier !== null, "the token request carries a code_verifier");
      expect(createHash("sha256").update(sentVerifier).digest("base64url")).toBe(challenge);
    });

    it("fails with AuthError when the state vanishes before returnTo is recorded", async () => {
      const { store } = makeStateStore();
      const service = await makeService({ ...store, consume: () => Effect.succeedNone });
      const err = await Effect.runPromise(
        Effect.flip(service.generateAuthorizationUrl("github", { returnTo: "/after" })),
      );
      expect(err).toBeInstanceOf(AuthError);
    });
  });
});

describe("OAuthService first proof over the real services", () => {
  const github = OAuth.provider(
    "github",
    {
      clientId: "c",
      clientSecret: Redacted.make("s"),
      redirectUri: "https://app/cb",
      authorizationEndpoint: "https://github.example/authorize",
      tokenEndpoint: "https://github.example/token",
      userInfoEndpoint: "https://github.example/userinfo",
      scopes: ["user:email"],
    },
    false,
  );

  const services = Layer.mergeAll(
    OAuth.OAuthService.layer({ github }),
    EmailPasswordService.layer(),
  ).pipe(
    Layer.provideMerge(
      SessionService.layer({
        sessionExpiresIn: { activePeriod: 86_400_000, idlePeriod: 3_600_000 },
      }),
    ),
    Layer.provideMerge(Layer.mergeAll(memoryStores, PasswordHasher.layer(), Hooks.Default)),
    Layer.provideMerge(testCryptoLayer),
  );

  it("a squatter's password sign-up is taken over by the address's holder signing in with a provider that verified it", async () => {
    const outcome = await withFetch(
      (url) =>
        url.includes("/token")
          ? json({ access_token: "at", token_type: "bearer" })
          : json({ id: "gh-victim", email: "victim@example.com", email_verified: true }),
      () =>
        runPromiseHttp(
          Effect.gen(function* () {
            const emailPassword = yield* EmailPasswordService;
            const sessions = yield* SessionService;
            const oauth = yield* OAuth.OAuthService;
            const identifiers = yield* IdentifierStore;

            // The squatter signs up with the victim's address and a password.
            const squatter = yield* emailPassword.signUp({
              email: "victim@example.com",
              password: "squatter password 123",
            });
            assert(squatter.token !== undefined, "the squatter's sign-up issued a session");

            // The victim signs in with a provider that verified the address.
            const { state } = yield* oauth.generateAuthorizationUrl("github");
            const victim = yield* oauth.signInWithCallback(state, "code");

            return {
              squatter,
              victim,
              squatterSession: yield* Effect.result(sessions.validateSession(squatter.token)),
              squatterPassword: yield* Effect.result(
                emailPassword.signIn({
                  email: "victim@example.com",
                  password: "squatter password 123",
                }),
              ),
              victimSession: yield* Effect.result(sessions.validateSession(victim.token ?? "")),
              address: yield* lookupIdentifier(identifiers, "email", "victim@example.com"),
            };
          }).pipe(Effect.provide(services)),
        ),
    );

    // The victim lands in the account the address names, now verified.
    expect(outcome.victim.isNewUser).toBe(false);
    expect(outcome.victim.user.id).toBe(outcome.squatter.user.id);
    expect(Option.getOrUndefined(outcome.address)).toMatchObject({
      userId: outcome.squatter.user.id,
      verified: true,
    });
    assert(Result.isSuccess(outcome.victimSession));
    expect(outcome.victimSession.success.user.id).toBe(outcome.squatter.user.id);
    // The squatter's session and password are gone.
    assert(Result.isFailure(outcome.squatterSession));
    assert(Result.isFailure(outcome.squatterPassword));
    expect(outcome.squatterPassword.failure).toMatchObject({ _tag: "InvalidCredentialsError" });
  });

  it("the address's holder signing in with a provider also removes the squatter's other links, API keys, multi-factor enrolment and trusted devices, and keeps the link made now", async () => {
    const outcome = await withFetch(
      (url) =>
        url.includes("/token")
          ? json({ access_token: "at", token_type: "bearer" })
          : json({ id: "gh-victim", email: "victim@example.com", email_verified: true }),
      () =>
        runPromiseHttp(
          Effect.gen(function* () {
            const emailPassword = yield* EmailPasswordService;
            const oauth = yield* OAuth.OAuthService;
            const accounts = yield* OAuthAccountStore;
            const apiKeys = yield* ApiKeyStore;
            const multiFactor = yield* MultiFactorStore;
            const trustedDevices = yield* TrustedDeviceStore;

            // The squatter signs up with the victim's address, links a
            // provider that reports the email unverified, mints an API key,
            // enrols a second factor and trusts a device.
            const { user } = yield* emailPassword.signUp({
              email: "victim@example.com",
              password: "squatter password 123",
            });
            yield* accounts.create({
              id: "squatter-link",
              userId: user.id,
              provider: "gitlab",
              providerId: "gl-squatter",
              accessToken: "squatter-access",
              createdAt: 0,
              updatedAt: 0,
            });
            yield* apiKeys.create({
              id: "squatter-key",
              start: "abcdef",
              keyHash: "squatter-key-hash",
              userId: user.id,
              enabled: true,
              metadata: {},
              createdAt: 0,
              updatedAt: 0,
            });
            yield* multiFactor.upsert({
              userId: user.id,
              secret: "JBSWY3DPEHPK3PXP",
              backupCodes: ["backup-code-hash"],
              verified: true,
              createdAt: 0,
            });
            yield* trustedDevices.upsert({
              tokenHash: "squatter-device",
              userId: user.id,
              createdAt: 0,
              expiresAt: Number.MAX_SAFE_INTEGER,
            });

            // The victim signs in with a provider that verified the address.
            const { state } = yield* oauth.generateAuthorizationUrl("github");
            const victim = yield* oauth.signInWithCallback(state, "code");

            return {
              squatterId: user.id,
              victim,
              links: (yield* accounts.getByUserId(user.id)).map((account) => account.providerId),
              apiKeys: yield* apiKeys.listByUserId(user.id),
              multiFactor: yield* multiFactor.get(user.id),
              trustedDevice: yield* trustedDevices.getByTokenHash("squatter-device"),
            };
          }).pipe(Effect.provide(services)),
        ),
    );

    expect(outcome.victim.user.id).toBe(outcome.squatterId);
    // Only the link the victim made now is left.
    expect(outcome.links).toEqual(["gh-victim"]);
    expect(outcome.apiKeys).toEqual([]);
    expect(Option.isNone(outcome.multiFactor)).toBe(true);
    expect(Option.isNone(outcome.trustedDevice)).toBe(true);
  });
});

describe("OAuth presets that read the address", () => {
  const profileFrom = (
    oauthProvider: OAuthProvider,
    handler: (url: string, init: RequestInit | undefined) => Response,
  ) =>
    withFetch(handler, () =>
      runPromiseHttp(oauthProvider.getProfile({ access_token: "at", token_type: "bearer" })),
    );

  it("google: reads verified_email as email_verified", async () => {
    const info = await profileFrom(OAuth.GoogleProvider(CLIENT), () =>
      json({ id: "g-1", email: "g@gmail.com", verified_email: true, name: "G" }),
    );
    expect(info).toMatchObject({ id: "g-1", email: "g@gmail.com", email_verified: true });
  });

  it("microsoft: takes mail, else an address-shaped userPrincipalName, never verified", async () => {
    const withMail = await profileFrom(OAuth.MicrosoftProvider(CLIENT), () =>
      json({ id: "m-1", mail: "m@contoso.com", userPrincipalName: "m@contoso.onmicrosoft.com" }),
    );
    expect(withMail).toMatchObject({ id: "m-1", email: "m@contoso.com" });
    expect(withMail.email_verified).toBeUndefined();

    const upnOnly = await profileFrom(OAuth.MicrosoftProvider(CLIENT), () =>
      json({ id: "m-2", mail: null, userPrincipalName: "n@contoso.com", displayName: "N" }),
    );
    expect(upnOnly).toMatchObject({ id: "m-2", email: "n@contoso.com", name: "N" });

    const guest = await profileFrom(OAuth.MicrosoftProvider(CLIENT), () =>
      json({ id: "m-3", userPrincipalName: "g_example.com#EXT#@contoso.onmicrosoft.com" }),
    );
    expect(guest.email).toBeUndefined();
  });

  it("github: takes the primary address from /user/emails with its verification", async () => {
    const info = await profileFrom(OAuth.GitHubProvider(CLIENT), (url) =>
      url.endsWith("/user/emails")
        ? new Response(
            encodeJson([
              { email: "old@e.com", primary: false, verified: true },
              { email: "private@users.noreply.github.com", primary: true, verified: true },
            ]),
            { headers: { "content-type": "application/json" } },
          )
        : json({ id: 42, login: "octo", email: null }),
    );
    expect(info).toMatchObject({
      id: "42",
      name: "octo",
      email: "private@users.noreply.github.com",
      email_verified: true,
    });
  });

  it("github: keeps the public address, unverified, when the lookup fails", async () => {
    const info = await profileFrom(OAuth.GitHubProvider(CLIENT), (url) =>
      url.endsWith("/user/emails")
        ? new Response("forbidden", { status: 403 })
        : json({ id: 42, login: "octo", email: "public@e.com" }),
    );
    expect(info).toMatchObject({ id: "42", email: "public@e.com" });
    expect(info.email_verified).toBeUndefined();
  });

  it("reads a string email_verified (Apple's) as a boolean", async () => {
    const now = DateTime.toEpochMillis(DateTime.nowUnsafe());
    const key = await makeSigningKey("ES256");
    const idToken = await signIdToken("ES256", key.privateKey, {
      ...baseClaims(now),
      email_verified: "true",
    });
    const idTokenProvider = OAuth.provider("apple-like", {
      ...CLIENT,
      authorizationEndpoint: "https://idp/authorize",
      tokenEndpoint: "https://idp/token",
      jwksEndpoint: JWKS_URL,
      issuer: "https://idp",
      getUserInfoFromIdToken: true,
      scopes: [],
    });
    const info = await withFetch(
      () => json(key.jwks),
      () =>
        runPromiseHttp(
          idTokenProvider.getProfile({
            access_token: "at",
            token_type: "bearer",
            id_token: idToken,
          }),
        ),
    );
    expect(info.email_verified).toBe(true);
  });
});

describe("OAuth profile and id_token refusals", () => {
  const now = 1_700_000_000_000;

  it("refuses a profile without an account id", async () => {
    const error = await withFetch(
      () => json({ error: "invalid_token" }),
      () =>
        runPromiseHttp(
          Effect.flip(
            FacebookProvider(CLIENT).getProfile({ access_token: "at", token_type: "bearer" }),
          ),
        ),
    );
    expect(error).toMatchObject({ _tag: "OAuthProviderError", provider: "facebook" });
    expect(error.message).toContain("account id");
  });

  it("refuses an id_token without exp", async () => {
    const key = await makeSigningKey("ES256");
    const { exp: _exp, ...claims } = baseClaims(now);
    const token = await signIdToken("ES256", key.privateKey, claims);
    const error = await withFetch(
      () => json(key.jwks),
      () =>
        runPromiseHttp(
          Effect.flip(
            verifyIdToken(token, {
              provider: "idp",
              jwksEndpoint: JWKS_URL,
              issuer: "https://idp",
              now,
            }),
          ),
        ),
    );
    expect(error.message).toBe("id_token has no exp");
  });

  it("refuses an id_token whose key is not of the header's algorithm", async () => {
    const rsa = await makeSigningKey("RS256");
    const ec = await makeSigningKey("ES256");
    const token = await signIdToken("ES256", ec.privateKey, baseClaims(now));
    // The set holds only an RSA key under the token's kid.
    const error = await withFetch(
      () => json(rsa.jwks),
      () =>
        runPromiseHttp(
          Effect.flip(
            verifyIdToken(token, {
              provider: "idp",
              jwksEndpoint: JWKS_URL,
              issuer: "https://idp",
              now,
            }),
          ),
        ),
    );
    expect(error.message).toBe("id_token key is not a ES256 key");
  });

  it("refuses to read an id_token profile without an issuer to check", async () => {
    const key = await makeSigningKey("ES256");
    const idToken = await signIdToken(
      "ES256",
      key.privateKey,
      baseClaims(DateTime.toEpochMillis(DateTime.nowUnsafe())),
    );
    const noIssuer = OAuth.provider("no-issuer", {
      ...CLIENT,
      authorizationEndpoint: "https://idp/authorize",
      tokenEndpoint: "https://idp/token",
      jwksEndpoint: JWKS_URL,
      getUserInfoFromIdToken: true,
      scopes: [],
    });
    const error = await withFetch(
      () => json(key.jwks),
      () =>
        runPromiseHttp(
          Effect.flip(
            noIssuer.getProfile({ access_token: "at", token_type: "bearer", id_token: idToken }),
          ),
        ),
    );
    expect(error.message).toContain("issuer");
  });
});
