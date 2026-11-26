/**
 * OAuth 2.0 and OpenID Connect types for effect-auth
 *
 * Provides type definitions for OAuth2 flows, provider configurations,
 * and related data structures.
 */

import { Clock, Config, Context, DateTime, Effect, Formatter, Layer, Redacted } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import { Aead, Digest, Kdf, Mac, SecureRandom } from "effect/crypto";
import { Base64, Base64Url, Hex } from "effect/encoding";
import { HttpClient, HttpClientRequest } from "effect/http";
import { optionalSecret } from "../OptionalSecretConfig.ts";
import { jwkSuitsAlgorithm, signWithPkcs8, verifiesWithJwk } from "../JwsSignature.ts";
import * as Obs from "../Observability.ts";
import * as OutboundHttp from "../OutboundHttp.ts";
import * as RemoteJwks from "../RemoteJwks.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import * as RootSecret from "../RootSecret.ts";
import { tokenHasher } from "../TokenHash.ts";
import type { TokenCipher } from "../Cipher.ts";
export type { TokenCipher } from "../Cipher.ts";
import {
  AuthError,
  EmailInUseError,
  OAuthProviderError,
  OAuthStateNotFoundError,
  OAuthStateExpiredError,
  OAuthAccountNotLinkedError,
  OAuthMissingEmailError,
  OAuthAccountConflictError,
  OAuthAccountNotFoundError,
  OAuthNoRefreshTokenError,
  OAuthLastCredentialError,
  OAuthEmailMismatchError,
  UserNotFoundError,
} from "../Errors.ts";
import { type HookError } from "../Hooks.ts";
import { type OAuthAccount, OAuthAccountStore } from "./OAuthAccount.ts";
export { type OAuthAccount, OAuthAccountStore } from "./OAuthAccount.ts";
import {
  EmailPasswordStore,
  sessionOrChallenge,
  type SessionOrChallenge,
} from "../email/EmailPassword.ts";
import { firstProofServices, proveAddress } from "../FirstProof.ts";
import { SessionService } from "../SessionService.ts";
import type * as Types from "../Types.ts";
import { normalizeEmail } from "../utils.ts";
import { IdentifierStore, lookupIdentifier } from "../Identifier.ts";
import {
  createUserWithIdentifier,
  type CreateUserResult,
  type NewUserIdentifier,
  UserStore,
} from "../UserStore.ts";

/**
 * OAuth2 provider configuration
 */
export interface OAuthProviderConfig {
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted;
  readonly redirectUri: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly userInfoEndpoint?: string;
  readonly scopes: readonly string[];
  /**
   * Resolve the user profile from the OIDC `id_token` returned by the token
   * endpoint instead of calling {@link userInfoEndpoint}. Required for
   * providers that only expose identity via the id_token (e.g. Apple).
   * Needs {@link jwksEndpoint} and {@link issuer} for verification; without
   * either, every sign-in fails.
   */
  readonly getUserInfoFromIdToken?: boolean;
  /** JWKS URL used to verify the OIDC `id_token` signature. */
  readonly jwksEndpoint?: string;
  /** Expected `iss` claim when verifying an OIDC `id_token`. */
  readonly issuer?: string;
  /**
   * How to authenticate at the token endpoint. `"body"` (default) sends
   * `client_id`/`client_secret` in the form body; `"basic"` uses HTTP Basic
   * (required by Reddit, X/Twitter confidential clients, Dropbox, ...).
   */
  readonly tokenAuthMethod?: "body" | "basic";
  /** HTTP method for the userinfo request (default `"GET"`; Dropbox uses POST). */
  readonly userInfoMethod?: "GET" | "POST";
  /** Extra headers for the userinfo request (e.g. Twitch's `Client-Id`). */
  readonly userInfoHeaders?: Readonly<Record<string, string>>;
  /** Extra static query parameters appended to the authorization URL. */
  readonly authorizationParams?: Readonly<Record<string, string>>;
  /** Name of the client-id parameter (default `"client_id"`; TikTok uses `"client_key"`). */
  readonly clientIdParam?: string;
  /**
   * Normalize a provider-specific profile payload into {@link OAuthUserInfo}
   * (maps nested shapes such as Facebook's `picture.data.url` or Twitter's
   * `data` envelope). Applied to both userinfo and id_token profiles.
   */
  readonly mapProfile?: (raw: Types.JsonObject) => OAuthUserInfo;
}

/**
 * OAuth2 state for CSRF protection
 */
export interface OAuthState {
  readonly state: string;
  readonly provider: string;
  readonly codeVerifier?: string; // For PKCE
  readonly nonce?: string; // For OIDC id_token replay protection
  readonly returnTo?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * OAuth2 token response
 */
export interface OAuthTokenResponse {
  readonly access_token: string;
  readonly token_type: string;
  readonly expires_in?: number;
  readonly refresh_token?: string;
  readonly scope?: string;
  readonly id_token?: string; // For OIDC
}

/**
 * User info from OAuth provider
 */
export interface OAuthUserInfo {
  readonly id: string;
  readonly email?: string;
  readonly email_verified?: boolean;
  readonly name?: string;
  readonly picture?: string;
  readonly given_name?: string;
  readonly family_name?: string;
  readonly locale?: string;
  readonly [key: string]: Types.Json;
}

/**
 * Authorization URL generation result
 */
export interface AuthorizationUrlResult {
  readonly url: string;
  readonly state: string;
  readonly codeVerifier?: string;
}

/**
 * OAuth callback result
 */
export interface OAuthCallbackResult {
  readonly account: OAuthAccount;
  readonly isNewUser: boolean;
  readonly user?: {
    readonly id: string;
    readonly email?: string;
    readonly name?: string;
  };
}

/**
 * Fields for a user created from an OAuth provider profile. The provider email
 * is recorded as an email `Identifier` by the service (with the provider's
 * `email_verified` claim carried over), and `identifier` carries it to the
 * store as well.
 */
export interface OAuthCreateUserInput {
  readonly name?: string;
  readonly image?: string;
  /**
   * Server-set attributes for the new user, such as the SSO provisioning
   * stamp. OAuth sign-up passes none.
   */
  readonly attributes?: Types.Attributes | undefined;
  /**
   * The login handle the user is created with: a store that keeps it on the
   * user row writes it there on insert, and any other store ignores it (see
   * {@link NewUserIdentifier}).
   */
  readonly identifier?: NewUserIdentifier | undefined;
}

/**
 * Result of a complete OAuth sign-in (callback handled, user resolved or
 * created, account linked, session issued).
 */
export type OAuthSignInResult = {
  readonly user: Types.User;
  readonly account: OAuthAccount;
  readonly isNewUser: boolean;
  readonly returnTo?: string;
} & SessionOrChallenge;

/**
 * OAuth provider interface
 */
export interface OAuthProvider {
  readonly name: string;
  readonly config: OAuthProviderConfig;
  /**
   * Whether the authorization request carries a PKCE challenge. Its verifier
   * is derived from the `state` and the root secret, never stored, so the
   * callback derives it again.
   */
  readonly usePKCE?: boolean;
  /**
   * `OAuthProvider` is a plain object built by {@link provider} — it
   * is never itself Layer-constructed, so there is no construction-time
   * scope to resolve `OAuthStateStore` in. `OAuthStateStore` is only ever
   * yielded here from inside `OAuthService`'s methods, which already resolve
   * it once at their own Layer-construction time (see `make`);
   * this per-call requirement is analogous to an ambient request context
   * (e.g. `HttpServerRequest`) rather than an implementation detail leaking
   * out. See `@effect-leakable-service` on {@link OAuthStateStore}.
   */
  readonly generateAuthorizationUrl: (
    scopes?: readonly string[],
  ) => Effect.Effect<
    AuthorizationUrlResult,
    OAuthProviderError | AuthError,
    OAuthStateStore | SecureRandom.SecureRandom | Digest.Digest | Mac.Mac | RootSecret.RootSecret
  >;
  /**
   * The token, userinfo and JWKS requests require an `HttpClient`;
   * `OAuthService` and `SsoService` provide the one their layer was built
   * with.
   */
  readonly exchangeCode: (
    code: string,
    codeVerifier?: string,
  ) => Effect.Effect<OAuthTokenResponse, OAuthProviderError, HttpClient.HttpClient>;
  readonly getUserInfo: (
    accessToken: string,
  ) => Effect.Effect<OAuthUserInfo, OAuthProviderError, HttpClient.HttpClient>;
  /**
   * Resolve the user profile from a token response. Dispatches on
   * {@link OAuthProviderConfig.getUserInfoFromIdToken}: verifies + decodes the
   * OIDC `id_token` (honouring `expectedNonce`) when set, otherwise calls the
   * userinfo endpoint with the access token. Prefer this over
   * {@link getUserInfo} in callback handling.
   */
  readonly getProfile: (
    tokens: OAuthTokenResponse,
    options?: { readonly expectedNonce?: string },
  ) => Effect.Effect<OAuthUserInfo, OAuthProviderError, HttpClient.HttpClient>;
}

/**
 * OAuth 2.0 and OpenID Connect implementation for effect-auth
 *
 * Provides a generic OAuth2 client with authorization code flow,
 * PKCE support, and pre-built provider configurations.
 *
 * @module oauth
 */

/**
 * Storage interface for OAuth state (temporary, Redis/memory)
 *
 * @effect-leakable-service
 * Intentionally allowed to leak into {@link OAuthProvider.generateAuthorizationUrl}'s
 * requirements: `OAuthProvider` values are plain objects (not Layer-constructed
 * services), so there is no construction-time scope to resolve this store in.
 * Every caller of that method is `OAuthService`, which already resolves this
 * store once at its own Layer-construction time.
 */
export class OAuthStateStore extends Context.Service<
  OAuthStateStore,
  {
    /** Record a pending state entry, replacing any entry with the same `state`. */
    readonly create: (state: OAuthState) => Effect.Effect<OAuthState, AuthError>;
    /**
     * Atomically fetch **and delete** a pending state entry, or `null`
     * when it is unknown or already consumed.
     *
     * This is the replay guard for every OAuth and OIDC SSO callback: the
     * services spend the state before they exchange the code, so a captured
     * callback works at most once, whether that first use succeeded or failed.
     * Two concurrent callers passing the same `state` must not both receive
     * the entry; the loser gets `null`. Implement it as a conditional
     * `DELETE ... RETURNING` (or a compare-and-swap, or Redis `GETDEL`), never
     * as a read followed by a delete.
     *
     * An expired entry may be returned or reported as `null`: the services
     * check `expiresAt` themselves and refuse an expired entry either way.
     */
    readonly consume: (state: string) => Effect.Effect<OAuthState | null, AuthError>;
  }
>()("@effect-auth/OAuthStateStore") {}

/**
 * Minimal user store the OAuth sign-in flow needs to create or look up users
 * from provider profiles. Implement alongside `typeof OAuthAccountStore.Service`.
 */
export class OAuthUserStore extends Context.Service<
  OAuthUserStore,
  {
    readonly getUser: (userId: string) => Effect.Effect<Types.User, AuthError | UserNotFoundError>;
    /**
     * Create a user. `created` in the result is `true` only when this call
     * inserted the user; a user that already existed (as a find-or-create on
     * the address returns) reports `false`, and sign-up then fails without
     * writing to it. The store must leave that row as it was: never an upsert
     * that updates it (see {@link CreateUserResult}).
     */
    readonly createUser: (
      input: OAuthCreateUserInput,
    ) => Effect.Effect<CreateUserResult, AuthError>;
    /**
     * Optional: update profile fields (`name` / `image`) on an existing user.
     * Consulted by {@link OAuthService.linkAccount} when
     * {@link OAuthServiceOptions.updateUserInfoOnLink} is set; silently skipped
     * when absent.
     */
    readonly updateUser?: (
      userId: string,
      update: { readonly name?: string; readonly image?: string },
    ) => Effect.Effect<Types.User, AuthError>;
  }
>()("@effect-auth/OAuthUserStore") {}

/**
 * Generate a cryptographically secure random state parameter
 */
export const generateState = (): Effect.Effect<string, never, SecureRandom.SecureRandom> =>
  Effect.gen(function* () {
    const crypto = yield* SecureRandom.SecureRandom;
    return yield* crypto.randomBytes(32).pipe(Effect.map((bytes) => Base64Url.encode(bytes)));
  });

/** The S256 PKCE challenge of `codeVerifier` (RFC 7636 §4.2). */
export const pkceChallenge = (codeVerifier: string): Effect.Effect<string, never, Digest.Digest> =>
  Effect.map(
    Digest.Digest.use((digest) =>
      digest.digest(Digest.sha256, new TextEncoder().encode(codeVerifier)),
    ),
    Base64Url.encode,
  );

/**
 * The PKCE verifier and challenge for `state`: the verifier is derived from
 * the state under the root secret, so the stored state never holds it.
 */
export const derivedPKCE = (
  state: string,
): Effect.Effect<
  { codeVerifier: string; codeChallenge: string },
  never,
  Digest.Digest | Mac.Mac | RootSecret.RootSecret
> =>
  Effect.gen(function* () {
    const codeVerifier = yield* (yield* RootSecret.pkceVerifier)(state);
    return { codeVerifier, codeChallenge: yield* pkceChallenge(codeVerifier) };
  });

/**
 * Generate a random PKCE code verifier and challenge
 */
export const generatePKCE = (): Effect.Effect<
  { codeVerifier: string; codeChallenge: string },
  never,
  SecureRandom.SecureRandom | Digest.Digest
> =>
  Effect.gen(function* () {
    const crypto = yield* SecureRandom.SecureRandom;
    const digest = yield* Digest.Digest;
    const codeVerifierBytes = yield* crypto.randomBytes(32);
    const codeVerifier = Base64Url.encode(codeVerifierBytes);
    const codeChallengeBytes = yield* digest.digest(
      Digest.sha256,
      new TextEncoder().encode(codeVerifier),
    );
    const codeChallenge = Base64Url.encode(codeChallengeBytes);
    return { codeVerifier, codeChallenge };
  });

/**
 * Generate a cryptographically secure random nonce for OIDC id_token replay
 * protection.
 */
export const generateNonce = (): Effect.Effect<string, never, SecureRandom.SecureRandom> =>
  Effect.gen(function* () {
    const crypto = yield* SecureRandom.SecureRandom;
    return yield* crypto.randomBytes(16).pipe(Effect.map((bytes) => Base64Url.encode(bytes)));
  });

/** Decodes a JWT segment's JSON object; throws on invalid JSON or a non-object. */
const decodeJwtSegmentJson = Schema.decodeSync(Schema.fromJsonString(Schema.JsonObject));

/** Decodes base64url text to its UTF-8 string; throws on invalid input. */
const decodeBase64UrlText = Schema.decodeSync(Schema.StringFromBase64Url);

const decodeJwtSegment = (segment: string): Types.JsonObject =>
  decodeJwtSegmentJson(decodeBase64UrlText(segment));

/** Serializes a JSON value, as `JSON.stringify` does. */
const encodeJsonString = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

/** A provider's JWKS document: its `keys` are JSON Web Keys. */
const ProviderJwks = Schema.Struct({ keys: Schema.optional(Schema.Array(Schema.JsonObject)) });

const decodeProviderJwks = Schema.decodeUnknownEffect(ProviderJwks);

/** A provider response whose body could not be read, or is not what it must be. */
const invalidBody = (provider: string, what: string, cause?: unknown) =>
  new OAuthProviderError({
    message: `Invalid ${what} from ${provider}`,
    provider,
    ...(cause !== undefined && { cause }),
  });

/**
 * A response body parsed as JSON. A body that is not JSON is an
 * `OAuthProviderError`, never a defect: the body is outside input.
 */
const readJson = (
  provider: string,
  response: OutboundHttp.Response,
  what = "response body",
): Effect.Effect<Schema.Json, OAuthProviderError> =>
  OutboundHttp.parseJson(response.body).pipe(
    Effect.mapError((cause) => invalidBody(provider, what, cause)),
  );

/** An optional member a provider may also send as `null`, which reads as absent. */
const optionalMember = <S extends Schema.Top>(schema: S) =>
  Schema.optionalKey(Schema.NullOr(schema));

/**
 * The RFC 6749 section 5.1 access token response, as providers actually send
 * it: `expires_in` may be a numeric string, `scope` an array (Twitch), and a
 * missing `token_type` reads as `Bearer`.
 */
const TokenResponseBody = Schema.Struct({
  access_token: Schema.NonEmptyString,
  token_type: optionalMember(Schema.String),
  expires_in: optionalMember(Schema.Union([Schema.Finite, Schema.FiniteFromString])),
  refresh_token: optionalMember(Schema.String),
  scope: optionalMember(Schema.Union([Schema.String, Schema.Array(Schema.String)])),
  id_token: optionalMember(Schema.String),
});

const decodeTokenResponseBody = Schema.decodeUnknownEffect(TokenResponseBody);

/** A 2xx token endpoint's body, decoded. Anything else is an `OAuthProviderError`. */
const readTokenResponse = (
  provider: string,
  response: OutboundHttp.Response,
): Effect.Effect<OAuthTokenResponse, OAuthProviderError> =>
  readJson(provider, response, "token response").pipe(
    Effect.flatMap((json) =>
      decodeTokenResponseBody(json).pipe(
        Effect.mapError((cause) => invalidBody(provider, "token response", cause)),
      ),
    ),
    Effect.map((body): OAuthTokenResponse => ({
      access_token: body.access_token,
      token_type: body.token_type ?? "Bearer",
      ...(P.isNotNullish(body.expires_in) && { expires_in: body.expires_in }),
      ...(P.isNotNullish(body.refresh_token) && { refresh_token: body.refresh_token }),
      ...(P.isNotNullish(body.scope) && {
        scope: P.isString(body.scope) ? body.scope : body.scope.join(" "),
      }),
      ...(P.isNotNullish(body.id_token) && { id_token: body.id_token }),
    })),
  );

/** Whether a JSON value is an object (not an array or `null`). */
const isJsonObject = (json: Schema.Json): json is Types.JsonObject => P.isObject(json);

/**
 * Verify and decode an OIDC `id_token` (compact JWS) against a provider's
 * JWKS. Validates the signature (RS256, ES256, or EdDSA), then `iss`, `aud`,
 * `exp`, and — when supplied — `nonce`. Returns the decoded claims.
 */
export const verifyIdToken = (
  idToken: string,
  params: {
    readonly provider: string;
    readonly jwksEndpoint: string;
    readonly issuer?: string;
    readonly audience?: string;
    readonly nonce?: string;
    readonly now?: number;
  },
): Effect.Effect<Types.JsonObject, OAuthProviderError, HttpClient.HttpClient> =>
  verifyIdTokenClaims(idToken, params);

type IdTokenParams = Parameters<typeof verifyIdToken>[1];

/** The three segments of a compact JWS, or `undefined` when it has another shape. */
const splitIdToken = (idToken: string): readonly [string, string, string] | undefined => {
  const [headerSeg, payloadSeg, signatureSeg, ...rest] = idToken.split(".");
  return headerSeg === undefined ||
    payloadSeg === undefined ||
    signatureSeg === undefined ||
    Arr.isReadonlyArrayNonEmpty(rest)
    ? undefined
    : [headerSeg, payloadSeg, signatureSeg];
};

/** Fetch a provider's JWKS document and read its keys. */
const fetchProviderJwks = (
  provider: string,
  jwksEndpoint: string,
): Effect.Effect<ReadonlyArray<Types.JsonObject>, OAuthProviderError, HttpClient.HttpClient> =>
  Effect.gen(function* () {
    const response = yield* OutboundHttp.sendWith(OutboundHttp.getJson(jwksEndpoint)).pipe(
      Effect.mapError(
        (cause) =>
          new OAuthProviderError({
            message: `Failed to fetch JWKS for ${provider}`,
            provider,
            cause,
          }),
      ),
    );
    if (!OutboundHttp.isOk(response)) {
      yield* OutboundHttp.logUpstreamFailure("JWKS request failed", response, { provider });
      return yield* new OAuthProviderError({
        message: `JWKS request failed with status ${response.status}`,
        provider,
      });
    }
    const jwks = yield* readJson(provider, response, "JWKS document").pipe(
      Effect.flatMap((json) => decodeProviderJwks(json)),
      Effect.mapError(
        (cause) =>
          new OAuthProviderError({
            message: `Invalid JWKS document for ${provider}`,
            provider,
            cause,
          }),
      ),
    );
    return jwks.keys ?? [];
  });

/**
 * The provider's key for the header's `kid` (or the only key when the
 * document holds just one). Under a service's {@link RemoteJwks.KeySets} the
 * JWKS is cached per URL, refetched for an unknown `kid` at most once per
 * refetch interval and kept when a refetch fails; without one (a direct
 * {@link verifyIdToken} call) it is fetched each time.
 */
const fetchIdTokenJwk = (
  params: IdTokenParams,
  header: Types.JsonObject,
): Effect.Effect<Types.JsonObject, OAuthProviderError, HttpClient.HttpClient> =>
  Effect.gen(function* () {
    const kid = header["kid"];
    const pick: RemoteJwks.Pick = (keys) =>
      keys.find((k) => k["kid"] === kid) ?? (keys.length === 1 ? keys[0] : undefined);
    const fetch = fetchProviderJwks(params.provider, params.jwksEndpoint);
    const keySets = yield* Effect.serviceOption(RemoteJwks.KeySets);
    const jwk = Option.isSome(keySets)
      ? yield* Effect.flatMap(OutboundHttp.provideCurrent(fetch), (cached) =>
          Effect.flatMap(keySets.value.forUrl(params.jwksEndpoint, cached), (set) => set.key(pick)),
        )
      : pick(yield* fetch);
    if (!jwk) {
      return yield* new OAuthProviderError({
        message: "No matching JWKS key for id_token",
        provider: params.provider,
      });
    }
    return jwk;
  });

/** The first id_token claim check (`iss`, `aud`, `exp`, `nonce`) the payload fails, if any. */
const idTokenClaimFailure = (
  payload: Types.JsonObject,
  params: IdTokenParams,
  now: number,
): string | undefined => {
  if (params.issuer !== undefined && payload["iss"] !== params.issuer) {
    return "id_token issuer mismatch";
  }
  if (params.audience !== undefined) {
    const aud = payload["aud"];
    const ok = aud === params.audience || (Array.isArray(aud) && aud.includes(params.audience));
    if (!ok) return "id_token audience mismatch";
  }
  const nowSec = now / 1000;
  const exp = payload["exp"];
  if (!P.isNumber(exp)) return "id_token has no exp";
  if (nowSec > exp) return "id_token expired";
  if (params.nonce !== undefined && payload["nonce"] !== params.nonce) {
    return "id_token nonce mismatch";
  }
  return undefined;
};

/** {@link verifyIdToken}, with the claims typed as the JSON object they are. */
const verifyIdTokenClaims = (
  idToken: string,
  params: IdTokenParams,
): Effect.Effect<Types.JsonObject, OAuthProviderError, HttpClient.HttpClient> =>
  Effect.gen(function* () {
    const fail = (message: string) =>
      new OAuthProviderError({ message, provider: params.provider });

    const segments = splitIdToken(idToken);
    if (segments === undefined) {
      return yield* fail("Malformed id_token");
    }
    const [headerSeg, payloadSeg] = segments;

    const { header, payload } = yield* Effect.try({
      try: (): { header: Types.JsonObject; payload: Types.JsonObject } => ({
        header: decodeJwtSegment(headerSeg),
        payload: decodeJwtSegment(payloadSeg),
      }),
      catch: (cause) =>
        new OAuthProviderError({
          message: "Failed to decode id_token",
          provider: params.provider,
          cause,
        }),
    });

    const alg = header["alg"];
    if (alg !== "RS256" && alg !== "ES256" && alg !== "EdDSA") {
      return yield* fail(`Unsupported id_token algorithm: ${Formatter.format(alg)}`);
    }

    const jwk = yield* fetchIdTokenJwk(params, header);
    if (!jwkSuitsAlgorithm(alg, jwk)) {
      return yield* fail(`id_token key is not a ${alg} key`);
    }

    const verified = yield* verifiesWithJwk(idToken, jwk, alg).pipe(
      Effect.mapError(
        (cause) =>
          new OAuthProviderError({
            message: "id_token signature verification failed",
            provider: params.provider,
            cause,
          }),
      ),
    );
    if (!verified) {
      return yield* fail("Invalid id_token signature");
    }

    const failure = idTokenClaimFailure(
      payload,
      params,
      params.now ?? (yield* Clock.currentTimeMillis),
    );
    if (failure !== undefined) {
      return yield* fail(failure);
    }

    return payload;
  });

/**
 * A provider's account id as a string: a string as is, a number (GitHub's,
 * Facebook's) in decimal, and anything else, a missing id included, as `""`,
 * which {@link provider} refuses.
 */
const idString = (id: unknown): string =>
  P.isString(id) ? id : P.isNumber(id) || P.isBigInt(id) ? `${id}` : "";

/**
 * `email_verified` as a boolean: providers send it as one, or (Apple) as the
 * string `"true"` / `"false"`. Anything else is left out, so unverified.
 */
const emailVerifiedClaim = (value: unknown): { readonly email_verified?: boolean } =>
  P.isBoolean(value)
    ? { email_verified: value }
    : value === "true" || value === "false"
      ? { email_verified: value === "true" }
      : {};

/**
 * Refuse a profile without an account id: `(provider, "")` would be one
 * account shared by every error-shaped profile the provider answers.
 */
const requireAccountId = (
  provider: string,
  info: OAuthUserInfo,
): Effect.Effect<OAuthUserInfo, OAuthProviderError> =>
  info.id === ""
    ? Effect.fail(
        new OAuthProviderError({
          message: `${provider} returned a profile without an account id`,
          provider,
        }),
      )
    : Effect.succeed(info);

/** Map OIDC id_token / userinfo claims to {@link OAuthUserInfo}. */
const claimsToUserInfo = (claims: Types.JsonObject): OAuthUserInfo => {
  const { email, email_verified, name, picture } = claims;
  return Object.assign(
    {},
    claims,
    { id: idString(claims["sub"] ?? claims["id"]) },
    P.isString(email) ? { email } : {},
    emailVerifiedClaim(email_verified),
    P.isString(name) ? { name } : {},
    P.isString(picture) ? { picture } : {},
  );
};

/**
 * An account record holding the provider profile (`email`, `name`,
 * `picture` when present) and the tokens just issued, stamped updated now.
 */
const profileAccount = (
  base: {
    readonly id: string;
    readonly userId: string;
    readonly provider: string;
    readonly createdAt: number;
  },
  tokens: OAuthTokenResponse,
  userInfo: OAuthUserInfo,
  now: number,
): OAuthAccount => ({
  id: base.id,
  userId: base.userId,
  provider: base.provider,
  providerId: userInfo.id,
  ...(userInfo.email && { email: userInfo.email }),
  ...(userInfo.name && { name: userInfo.name }),
  ...(userInfo.picture && { picture: userInfo.picture }),
  accessToken: tokens.access_token,
  ...(tokens.refresh_token && { refreshToken: tokens.refresh_token }),
  ...(tokens.expires_in && {
    expiresAt: now + tokens.expires_in * 1000,
  }),
  createdAt: base.createdAt,
  updatedAt: now,
});

/**
 * A token endpoint `POST` of `params`, the client authenticating in the body
 * or, with `tokenAuthMethod: "basic"`, in the `Authorization` header.
 */
const tokenRequest = (
  config: OAuthProviderConfig,
  params: URLSearchParams,
): HttpClientRequest.HttpClientRequest =>
  HttpClientRequest.post(config.tokenEndpoint, {
    headers: {
      Accept: "application/json",
      ...(config.tokenAuthMethod === "basic" && {
        Authorization: `Basic ${Base64.encode(
          `${config.clientId}:${Redacted.value(config.clientSecret)}`,
        )}`,
      }),
    },
  }).pipe(HttpClientRequest.bodyText(params.toString(), "application/x-www-form-urlencoded"));

/**
 * Send a request to a provider endpoint, failing with `fetchFailure` when the
 * request cannot be sent and with `statusFailure` on a non-2xx answer. The
 * answer's body goes to the log, never into the error: an IdP's error page
 * is not for the end user, and a tenant-registered URL must not read back
 * whatever it points at.
 */
const fetchProviderOk = (
  provider: string,
  request: HttpClientRequest.HttpClientRequest,
  failures: { readonly fetchFailure: string; readonly statusFailure: string },
): Effect.Effect<OutboundHttp.Response, OAuthProviderError, HttpClient.HttpClient> =>
  Effect.gen(function* () {
    const response = yield* OutboundHttp.sendWith(request).pipe(
      Effect.mapError(
        (cause) =>
          new OAuthProviderError({
            message: failures.fetchFailure,
            provider,
            cause,
          }),
      ),
    );

    if (!OutboundHttp.isOk(response)) {
      yield* OutboundHttp.logUpstreamFailure(failures.statusFailure, response, { provider });
      return yield* new OAuthProviderError({
        message: `${failures.statusFailure} with status ${response.status}`,
        provider,
      });
    }
    return response;
  });

/**
 * Create an OAuth provider
 */
export const provider = (
  name: string,
  config: OAuthProviderConfig,
  usePKCE = true,
): OAuthProvider => {
  const mapProfile = (claims: Types.JsonObject): Effect.Effect<OAuthUserInfo, OAuthProviderError> =>
    requireAccountId(name, (config.mapProfile ?? claimsToUserInfo)(claims));

  const getUserInfo = (
    accessToken: string,
  ): Effect.Effect<OAuthUserInfo, OAuthProviderError, HttpClient.HttpClient> =>
    Effect.gen(function* () {
      const userInfoEndpoint = config.userInfoEndpoint;
      if (!userInfoEndpoint) {
        return yield* new OAuthProviderError({
          message: `Provider ${name} does not have a user info endpoint`,
          provider: name,
        });
      }

      const response = yield* fetchProviderOk(
        name,
        HttpClientRequest.make(config.userInfoMethod ?? "GET")(userInfoEndpoint, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: "application/json",
            ...config.userInfoHeaders,
          },
        }),
        {
          fetchFailure: `Failed to get user info from ${name}`,
          statusFailure: "User info request failed",
        },
      );

      const data = yield* readJson(name, response, "user info response");
      if (!isJsonObject(data)) {
        return yield* new OAuthProviderError({
          message: `User info response from ${name} is not a JSON object`,
          provider: name,
        });
      }

      return yield* mapProfile(data);
    });

  return {
    name,
    config,
    usePKCE,

    generateAuthorizationUrl: (customScopes?: readonly string[]) =>
      Effect.gen(function* () {
        const stateStore = yield* OAuthStateStore;
        const state = yield* generateState();

        // PKCE, with the verifier derived from the state rather than stored.
        const pkce = usePKCE ? yield* derivedPKCE(state) : undefined;
        // OIDC id_token flows carry a nonce for replay protection.
        const nonce = config.getUserInfoFromIdToken ? yield* generateNonce() : undefined;

        // Create state entry
        const stateEntry: OAuthState = {
          state,
          provider: name,
          ...(nonce && { nonce }),
          createdAt: yield* Clock.currentTimeMillis,
          expiresAt: (yield* Clock.currentTimeMillis) + 10 * 60 * 1000, // 10 minutes
        };

        yield* stateStore.create(stateEntry);

        // Build authorization URL
        const clientIdParam = config.clientIdParam ?? "client_id";
        const scopes = customScopes ?? config.scopes;
        const params = new URLSearchParams({
          [clientIdParam]: config.clientId,
          redirect_uri: config.redirectUri,
          response_type: "code",
          scope: scopes.join(" "),
          state,
        });

        if (pkce) {
          params.set("code_challenge", pkce.codeChallenge);
          params.set("code_challenge_method", "S256");
        }
        if (nonce) {
          params.set("nonce", nonce);
        }
        Arr.forEach(R.toEntries(config.authorizationParams ?? {}), ([key, value]) =>
          params.set(key, value),
        );

        const url = `${config.authorizationEndpoint}?${params.toString()}`;

        return {
          url,
          state,
          ...(pkce?.codeVerifier && { codeVerifier: pkce.codeVerifier }),
        } satisfies AuthorizationUrlResult;
      }),

    exchangeCode: (code: string, codeVerifier?: string) =>
      Effect.gen(function* () {
        const useBasic = config.tokenAuthMethod === "basic";
        const params = new URLSearchParams({
          [config.clientIdParam ?? "client_id"]: config.clientId,
          code,
          grant_type: "authorization_code",
          redirect_uri: config.redirectUri,
        });
        if (!useBasic) {
          params.set("client_secret", Redacted.value(config.clientSecret));
        }

        if (codeVerifier) {
          params.set("code_verifier", codeVerifier);
        }

        const response = yield* fetchProviderOk(name, tokenRequest(config, params), {
          fetchFailure: `Failed to exchange code with ${name}`,
          statusFailure: "Token exchange failed",
        });

        return yield* readTokenResponse(name, response);
      }),

    getUserInfo,

    getProfile: (tokens, options) =>
      Effect.gen(function* () {
        if (config.getUserInfoFromIdToken) {
          if (!tokens.id_token) {
            return yield* new OAuthProviderError({
              message: `Provider ${name} did not return an id_token`,
              provider: name,
            });
          }
          if (!config.jwksEndpoint || config.issuer === undefined) {
            return yield* new OAuthProviderError({
              message: `Provider ${name} needs a jwksEndpoint and an issuer for id_token verification`,
              provider: name,
            });
          }
          const claims = yield* verifyIdTokenClaims(tokens.id_token, {
            provider: name,
            jwksEndpoint: config.jwksEndpoint,
            issuer: config.issuer,
            audience: config.clientId,
            ...(options?.expectedNonce !== undefined && { nonce: options.expectedNonce }),
          });
          return yield* mapProfile(claims);
        }

        return yield* getUserInfo(tokens.access_token);
      }),
  };
};

/**
 * OAuth service for managing OAuth flows
 */
export class OAuthService extends Context.Service<
  OAuthService,
  {
    readonly generateAuthorizationUrl: (
      provider: string,
      options?: { scopes?: readonly string[]; returnTo?: string },
    ) => Effect.Effect<AuthorizationUrlResult, AuthError | OAuthProviderError>;

    readonly handleCallback: (
      state: string,
      code: string,
      options?: { linkToUserId?: string },
    ) => Effect.Effect<
      OAuthCallbackResult,
      | AuthError
      | OAuthProviderError
      | OAuthStateNotFoundError
      | OAuthStateExpiredError
      | OAuthAccountConflictError
    >;

    /**
     * Complete OAuth sign-in: verifies the callback, resolves or creates the
     * user, links the account, and issues a session.
     *
     * A provider identity seen for the first time whose email matches an
     * existing user is auto-linked to that user only when the provider reports
     * the email verified and auto-linking applies to the provider
     * ({@link OAuthServiceOptions.autoLinkByVerifiedEmail},
     * {@link OAuthServiceOptions.trustedProviders}). When the local address is
     * still unverified, the provider's verification is its first proof, as in Google One Tap and SSO: the account's password is cleared
     * and its sessions revoked, the address is marked verified, and then the
     * identity is linked and the prover's session minted. Any other match (an
     * unverified provider email, auto-linking off for the provider, a dangling
     * identifier) fails with `EmailInUseError` and changes nothing. A
     * provider account another callback linked meanwhile fails with
     * `OAuthAccountConflictError`.
     *
     * This is the recommended high-level entrypoint; use {@link handleCallback}
     * only when managing users yourself.
     */
    readonly signInWithCallback: (
      state: string,
      code: string,
    ) => Effect.Effect<
      OAuthSignInResult,
      | AuthError
      | OAuthProviderError
      | OAuthStateNotFoundError
      | OAuthStateExpiredError
      | OAuthAccountNotLinkedError
      | OAuthAccountConflictError
      | OAuthMissingEmailError
      | EmailInUseError
      | UserNotFoundError
      | HookError
    >;

    readonly linkAccount: (
      userId: string,
      provider: string,
      code: string,
      state: string,
    ) => Effect.Effect<
      OAuthAccount,
      | AuthError
      | OAuthProviderError
      | OAuthStateNotFoundError
      | OAuthStateExpiredError
      | OAuthAccountConflictError
      | OAuthEmailMismatchError
      | UserNotFoundError
    >;

    readonly unlinkAccount: (
      userId: string,
      provider: string,
      options?: { readonly allowUnlinkingAll?: boolean },
    ) => Effect.Effect<void, AuthError | OAuthAccountNotFoundError | OAuthLastCredentialError>;

    readonly refreshAccessToken: (
      userId: string,
      provider: string,
    ) => Effect.Effect<
      string,
      AuthError | OAuthProviderError | OAuthAccountNotFoundError | OAuthNoRefreshTokenError
    >;
  }
>()("@effect-auth/OAuthService") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = (
    providers: Record<string, OAuthProvider>,
    options: OAuthServiceOptions = {},
  ) =>
    Layer.effect(OAuthService, make(providers, options)).pipe(Layer.provide(PlatformCrypto.layer));
}

/**
 * Effect `Config` for {@link OAuthServiceOptions}.
 *
 * Optional env vars: `OAUTH_AUTO_LINK_BY_VERIFIED_EMAIL`, `OAUTH_ENCRYPT_TOKENS_SECRET`.
 */
export const oauthServiceOptionsConfig = Config.all({
  autoLinkByVerifiedEmail: Config.Boolean("OAUTH_AUTO_LINK_BY_VERIFIED_EMAIL").pipe(
    Config.withDefault(true),
  ),
  encryptTokens: optionalSecret("OAUTH_ENCRYPT_TOKENS_SECRET").pipe(
    Config.map((secret) => (secret === undefined ? undefined : ({ secret } as const))),
  ),
});

/**
 * Options controlling `typeof OAuthService.Service` behaviour.
 */
export interface OAuthServiceOptions {
  /**
   * When a new OAuth account arrives with a provider-verified email that
   * matches an existing user's email, link the account to that user instead of
   * creating a new one. Defaults to `true`. An unverified local address is
   * proven first: its account's password is cleared and its sessions
   * revoked before the link. Never links when the provider reports the email
   * unverified; {@link OAuthService.signInWithCallback} refuses that
   * match, and every match when auto-linking is off for the provider, with
   * `EmailInUseError`.
   */
  readonly autoLinkByVerifiedEmail?: boolean;
  /**
   * Opt-in encryption-at-rest for `accessToken` and `refreshToken` fields
   * before they are handed to the account store. **Disabled by default** —
   * when omitted, tokens are stored as plaintext and the database / store is
   * solely responsible for protecting them.
   *
   * Pass `{ secret }` to use the built-in AES-256-GCM cipher (key derived
   * from the secret string with SHA-256, random IV per value, GCM auth-tag for
   * integrity). Pass `{ cipher }` to supply a custom {@link TokenCipher}
   * (envelope encryption, HSM-backed keys, etc.).
   *
   * **Recommended for production** when tokens are persisted in a plain
   * relational database or any store that does not encrypt at the column level.
   * Rotation requires re-encrypting every stored token with the new key.
   */
  readonly encryptTokens?:
    | { readonly secret: Redacted.Redacted }
    | { readonly cipher: TokenCipher };

  /**
   * Providers that auto-link in {@link OAuthService.signInWithCallback} even
   * when {@link autoLinkByVerifiedEmail} is `false`. The same rule holds for
   * them: the provider must report `email_verified: true`, or the sign-in is
   * refused with `EmailInUseError`, and an unverified local address is
   * proven first, clearing its account's password, credentials and sessions.
   * Defaults to `[]`.
   */
  readonly trustedProviders?: readonly string[];

  /**
   * Allow {@link OAuthService.linkAccount} to succeed even when the OAuth
   * provider's email differs from the user's current account email. Defaults to
   * `false` — cross-email linking is rejected with `OAuthEmailMismatchError`.
   */
  readonly allowDifferentEmails?: boolean;

  /**
   * Refresh the user's `name` and `image` fields from the provider profile when
   * {@link OAuthService.linkAccount} succeeds. Requires
   * `typeof OAuthUserStore.Service`'s optional `updateUser` capability; silently
   * skipped when it is not implemented. Defaults to `false`.
   */
  readonly updateUserInfoOnLink?: boolean;
}

/** The conflict an OAuth sign-in over an email another user holds fails with. */
const emailInUse = (email: string) =>
  new EmailInUseError({ message: "This email is already associated with an account", email });

/**
 * `store` keyed by the digest of each `state`, so a database read yields no
 * state a callback would accept.
 */
export const hashedStateStore = (
  store: typeof OAuthStateStore.Service,
  hash: (token: string) => Effect.Effect<string>,
): typeof OAuthStateStore.Service => ({
  create: (entry) =>
    Effect.flatMap(hash(entry.state), (state) => store.create({ ...entry, state })),
  consume: (state) => Effect.flatMap(hash(state), store.consume),
});

/**
 * Create an OAuth service with configured providers
 */
export const make = (
  providers: Record<string, OAuthProvider>,
  options: OAuthServiceOptions = {},
): Effect.Effect<
  typeof OAuthService.Service,
  never,
  | OAuthStateStore
  | OAuthAccountStore
  | OAuthUserStore
  | IdentifierStore
  | UserStore
  | EmailPasswordStore
  | SessionService
  | SecureRandom.SecureRandom
  | Aead.Aead
  | Digest.Digest
  | HttpClient.HttpClient
  | Kdf.Kdf
  | Mac.Mac
  | RootSecret.RootSecret
> =>
  Effect.gen(function* () {
    const outbound = yield* OutboundHttp.resolve();
    const autoLinkByVerifiedEmail = options.autoLinkByVerifiedEmail ?? true;
    const trustedProviders = options.trustedProviders ?? [];
    const allowDifferentEmails = options.allowDifferentEmails ?? false;
    const updateUserInfoOnLink = options.updateUserInfoOnLink ?? false;

    const sealer = yield* RootSecret.sealerFor("oauth-tokens", options.encryptTokens);
    const digestToken = yield* tokenHasher;
    const deriveVerifier = yield* RootSecret.pkceVerifier;
    const mac = yield* Mac.Mac;
    const rootSecret = yield* RootSecret.RootSecret;

    const stateStore = hashedStateStore(yield* OAuthStateStore, digestToken);
    const accountStore = yield* OAuthAccountStore;
    const userStore = yield* OAuthUserStore;
    const identifiers = yield* IdentifierStore;
    const coreUsers = yield* UserStore;
    const sessionManager = yield* SessionService;
    const passwords = yield* EmailPasswordStore;
    const firstProof = yield* firstProofServices({
      identifiers,
      passwords,
      sessions: sessionManager,
    });
    const crypto = yield* SecureRandom.SecureRandom;
    const digest = yield* Digest.Digest;

    const randomAccountId = (): Effect.Effect<string> =>
      crypto.randomBytes(16).pipe(Effect.map((bytes) => Hex.encode(bytes)));

    /** The row a token is sealed for: the account and which of its tokens. */
    const tokenRow = (account: OAuthAccount, which: "access" | "refresh") =>
      `${account.provider}\u0000${account.providerId}\u0000${which}`;

    const encryptAccount = (account: OAuthAccount): Effect.Effect<OAuthAccount, AuthError> =>
      Effect.gen(function* () {
        const accessToken = yield* sealer.seal(account.accessToken, tokenRow(account, "access"));
        const refreshToken =
          account.refreshToken !== undefined
            ? yield* sealer.seal(account.refreshToken, tokenRow(account, "refresh"))
            : undefined;
        return {
          ...account,
          accessToken,
          ...(refreshToken !== undefined && { refreshToken }),
        };
      });

    const decryptAccount = (account: OAuthAccount): Effect.Effect<OAuthAccount, AuthError> =>
      Effect.gen(function* () {
        const accessToken = yield* sealer.open(account.accessToken, tokenRow(account, "access"));
        const refreshToken =
          account.refreshToken !== undefined
            ? yield* sealer.open(account.refreshToken, tokenRow(account, "refresh"))
            : undefined;
        return {
          ...account,
          accessToken,
          ...(refreshToken !== undefined && { refreshToken }),
        };
      });

    /** The PKCE verifier a callback sends: stored by an earlier release, else derived. */
    const callbackVerifier = (
      providerInstance: OAuthProvider,
      state: string,
      entry: OAuthState,
    ): Effect.Effect<string | undefined> =>
      entry.codeVerifier !== undefined
        ? Effect.succeed(entry.codeVerifier)
        : providerInstance.usePKCE === true
          ? deriveVerifier(state)
          : Effect.void.pipe(Effect.as(undefined));

    /**
     * Spend a callback's state. It is consumed atomically before
     * anything else, so a replayed or concurrent callback carrying the same
     * state is refused, and a failed exchange does not leave it usable.
     * Fails when the state is unknown, already used or expired.
     */
    const consumeState = (state: string) =>
      Effect.gen(function* () {
        const stateEntry = yield* stateStore.consume(state);
        if (stateEntry === null) {
          return yield* new OAuthStateNotFoundError({
            message: "OAuth state not found, expired or already used",
            state,
          });
        }
        if ((yield* Clock.currentTimeMillis) > stateEntry.expiresAt) {
          return yield* new OAuthStateExpiredError({
            message: "OAuth state expired",
            state,
          });
        }
        return stateEntry;
      });

    /** Exchange the callback's code, then read the profile, over this layer's client. */
    const exchangeForProfile = (
      providerInstance: OAuthProvider,
      state: string,
      code: string,
      stateEntry: OAuthState,
    ): Effect.Effect<
      { readonly tokens: OAuthTokenResponse; readonly userInfo: OAuthUserInfo },
      OAuthProviderError
    > =>
      Effect.gen(function* () {
        const tokens = yield* providerInstance.exchangeCode(
          code,
          yield* callbackVerifier(providerInstance, state, stateEntry),
        );
        const profile = yield* providerInstance.getProfile(tokens, {
          ...(stateEntry.nonce !== undefined && { expectedNonce: stateEntry.nonce }),
        });
        // A hand-written provider is held to the account-id rule too.
        const userInfo = yield* requireAccountId(providerInstance.name, profile);
        return { tokens, userInfo };
      }).pipe(OutboundHttp.provide(outbound));

    /**
     * Shared callback plumbing: consume the state, exchange the code and
     * fetch the provider profile.
     */
    const resolveCallback = (state: string, code: string) =>
      Effect.gen(function* () {
        const stateEntry = yield* consumeState(state);

        const providerInstance = providers[stateEntry.provider];
        if (!providerInstance) {
          return yield* new OAuthProviderError({
            message: `Provider ${stateEntry.provider} not found`,
            provider: stateEntry.provider,
          });
        }

        const { tokens, userInfo } = yield* exchangeForProfile(
          providerInstance,
          state,
          code,
          stateEntry,
        );

        return { stateEntry, tokens, userInfo };
      });

    /**
     * Insert a new link. The store's `create` is a plain insert, so a provider
     * account linked concurrently is refused; re-read it, as `claimIdentifier`
     * does, so the caller sees a conflict rather than a store failure.
     */
    const createAccount = (
      account: OAuthAccount,
    ): Effect.Effect<OAuthAccount, AuthError | OAuthAccountConflictError> =>
      accountStore.create(account).pipe(
        Effect.catchTag("AuthError", (error) =>
          Effect.gen(function* () {
            const raced = yield* accountStore.get(account.provider, account.providerId);
            if (raced === null) return yield* error;
            return yield* new OAuthAccountConflictError({
              message: `This ${account.provider} account is already linked`,
              provider: account.provider,
            });
          }),
        ),
      );

    /** Store fresh tokens on an account a callback found already linked. */
    const refreshCallbackAccount = (existingAccount: OAuthAccount, tokens: OAuthTokenResponse) =>
      Effect.gen(function* () {
        const plainExisting = yield* decryptAccount(existingAccount);
        const updatedAccount: OAuthAccount = {
          ...plainExisting,
          accessToken: tokens.access_token,
          ...(tokens.refresh_token && {
            refreshToken: tokens.refresh_token,
          }),
          ...(tokens.expires_in && {
            expiresAt: (yield* Clock.currentTimeMillis) + tokens.expires_in * 1000,
          }),
          updatedAt: yield* Clock.currentTimeMillis,
        };
        yield* accountStore.update(yield* encryptAccount(updatedAccount));

        return {
          account: updatedAccount,
          isNewUser: false,
        } satisfies OAuthCallbackResult;
      });

    /**
     * Create the account for a callback whose provider identity is new.
     * Without `linkToUserId` the account is unlinked (empty `userId`): the
     * caller links it to a user after creating the user record in their
     * database.
     */
    const createCallbackAccount = (
      provider: string,
      tokens: OAuthTokenResponse,
      userInfo: OAuthUserInfo,
      options: { linkToUserId?: string } | undefined,
    ) =>
      Effect.gen(function* () {
        const newAccountId = yield* randomAccountId();
        const newAccount = profileAccount(
          {
            id: newAccountId,
            userId: options?.linkToUserId ?? "",
            provider,
            createdAt: yield* Clock.currentTimeMillis,
          },
          tokens,
          userInfo,
          yield* Clock.currentTimeMillis,
        );

        yield* createAccount(yield* encryptAccount(newAccount));

        return {
          account: newAccount,
          isNewUser: true,
          ...(options?.linkToUserId
            ? {
                user: {
                  id: newAccount.userId,
                  ...(userInfo.email && { email: userInfo.email }),
                  ...(userInfo.name && { name: userInfo.name }),
                },
              }
            : {}),
        } satisfies OAuthCallbackResult;
      });

    /**
     * The existing user a first sign-in with `providerName` auto-links to by its
     * email, or `null` when no identifier holds the address. Links only when
     * the provider verified the address and auto-linking applies to the
     * provider. An unverified local address may belong to whoever
     * signed up with it first, so the provider's verification is its first
     * proof: `proveAddress` clears the account's password,
     * its other credentials (the link made now is created after) and
     * revokes its sessions before the link, as Google One Tap and SSO do.
     * Anything else (an unverified provider email, auto-linking off for the
     * provider, a dangling identifier) fails with `EmailInUseError`; nothing
     * is linked and nothing is wiped.
     */
    const autoLinkTarget = (providerName: string, email: string, emailVerified: boolean) =>
      Effect.gen(function* () {
        const existing = yield* lookupIdentifier(identifiers, "email", email);
        if (existing === null) return null;
        const mayLink =
          emailVerified && (autoLinkByVerifiedEmail || trustedProviders.includes(providerName));
        const user = mayLink ? yield* coreUsers.get(existing.userId) : null;
        if (user === null) return yield* emailInUse(email);
        if (!existing.verified) {
          yield* proveAddress({ ...firstProof, oauthAccounts: accountStore }, existing);
        }
        return user;
      });

    /** Create the user for a first sign-in whose email no identifier holds. */
    const createSignInUser = (email: string, emailVerified: boolean, userInfo: OAuthUserInfo) =>
      Effect.gen(function* () {
        const created = yield* createUserWithIdentifier(
          identifiers,
          {
            type: "email",
            value: email,
            verified: emailVerified,
            ...(emailVerified ? { verifiedAt: yield* DateTime.nowAsDate } : {}),
          },
          (identifier) =>
            userStore.createUser({
              ...(userInfo.name !== undefined && { name: userInfo.name }),
              ...(userInfo.picture !== undefined && { image: userInfo.picture }),
              identifier,
            }),
        ).pipe(Effect.catchTag("IdentifierTakenError", () => Effect.fail(emailInUse(email))));
        return created.user;
      });

    return {
      generateAuthorizationUrl: Effect.fn("OAuthService.generateAuthorizationUrl")(
        (provider: string, options?: { scopes?: readonly string[]; returnTo?: string }) =>
          Effect.gen(function* () {
            const providerInstance = providers[provider];
            if (!providerInstance) {
              return yield* new OAuthProviderError({
                message: `Provider ${provider} not found`,
                provider,
              });
            }

            const result = yield* providerInstance
              .generateAuthorizationUrl(options?.scopes)
              .pipe(
                Effect.provideService(OAuthStateStore, stateStore),
                Effect.provideService(SecureRandom.SecureRandom, crypto),
                Effect.provideService(Digest.Digest, digest),
                Effect.provideService(Mac.Mac, mac),
                Effect.provideService(RootSecret.RootSecret, rootSecret),
              );

            // Update state with returnTo if provided
            if (options?.returnTo) {
              const stateEntry = yield* stateStore.consume(result.state);
              if (stateEntry === null) {
                return yield* new AuthError({ message: "OAuth state missing after creation" });
              }
              // Record the state again, now carrying returnTo.
              yield* stateStore.create({
                ...stateEntry,
                state: result.state,
                returnTo: options.returnTo,
              });
            }

            return result;
          }).pipe(Effect.withSpan(Obs.spanNames.oauthAuthorize, { attributes: { provider } })),
      ),

      handleCallback: Effect.fn("OAuthService.handleCallback")(function* (
        state: string,
        code: string,
        options?: { linkToUserId?: string },
      ) {
        // Verify and consume the state, exchange the code and fetch the
        // profile (userinfo endpoint or verified OIDC id_token).
        const { stateEntry, tokens, userInfo } = yield* resolveCallback(state, code);

        const existingAccount = yield* accountStore.get(stateEntry.provider, userInfo.id);
        if (existingAccount) {
          return yield* refreshCallbackAccount(existingAccount, tokens);
        }
        return yield* createCallbackAccount(stateEntry.provider, tokens, userInfo, options);
      }),

      signInWithCallback: Effect.fn("OAuthService.signInWithCallback")(
        (state: string, code: string) =>
          Effect.gen(function* () {
            const { stateEntry, tokens, userInfo } = yield* resolveCallback(state, code);
            const now = yield* Clock.currentTimeMillis;

            const tokenFields = {
              accessToken: tokens.access_token,
              ...(tokens.refresh_token && { refreshToken: tokens.refresh_token }),
              ...(tokens.expires_in && { expiresAt: now + tokens.expires_in * 1000 }),
            };

            const existingAccount = yield* accountStore.get(stateEntry.provider, userInfo.id);

            if (existingAccount) {
              if (existingAccount.userId === "") {
                return yield* new OAuthAccountNotLinkedError({
                  message: `This ${stateEntry.provider} account is not linked to a user`,
                  provider: stateEntry.provider,
                });
              }

              const plainExisting = yield* decryptAccount(existingAccount);
              const updatedAccount: OAuthAccount = {
                ...plainExisting,
                ...tokenFields,
                updatedAt: now,
              };
              yield* accountStore.update(yield* encryptAccount(updatedAccount));

              const user = yield* userStore.getUser(updatedAccount.userId);
              const issued = yield* sessionOrChallenge(sessionManager, user, "oauth");

              return {
                user,
                account: updatedAccount,
                ...issued,
                isNewUser: false,
                ...(stateEntry.returnTo !== undefined && { returnTo: stateEntry.returnTo }),
              } satisfies OAuthSignInResult;
            }

            // New account: resolve the user by verified email, or create one.
            const email = userInfo.email ? normalizeEmail(userInfo.email) : undefined;
            const emailVerified = userInfo.email_verified === true;

            if (email === undefined) {
              return yield* new OAuthMissingEmailError({
                message: `${stateEntry.provider} did not return an email address for this account`,
                provider: stateEntry.provider,
              });
            }

            const linked = yield* autoLinkTarget(stateEntry.provider, email, emailVerified);
            const isNewUser = linked === null;
            const user = linked ?? (yield* createSignInUser(email, emailVerified, userInfo));

            const newAccountId = yield* randomAccountId();
            const account: OAuthAccount = {
              id: newAccountId,
              userId: user.id,
              provider: stateEntry.provider,
              providerId: userInfo.id,
              ...(userInfo.email && { email }),
              ...(userInfo.name && { name: userInfo.name }),
              ...(userInfo.picture && { picture: userInfo.picture }),
              ...tokenFields,
              createdAt: now,
              updatedAt: now,
            };
            yield* createAccount(yield* encryptAccount(account));

            const issued = yield* sessionOrChallenge(sessionManager, user, "oauth");

            return {
              user,
              account,
              ...issued,
              isNewUser,
              ...(stateEntry.returnTo !== undefined && { returnTo: stateEntry.returnTo }),
            } satisfies OAuthSignInResult;
          }).pipe(
            Effect.withSpan(Obs.spanNames.oauthCallback),
            Effect.tap(() => Obs.recordOAuthCallback("success")),
            Effect.tapError(() => Obs.recordOAuthCallback("failure")),
          ),
      ),

      linkAccount: Effect.fn("OAuthService.linkAccount")(function* (
        userId: string,
        provider: string,
        code: string,
        state: string,
      ) {
        // Properly implement OAuth flow for account linking
        // This follows the same flow as handleCallback but links to existing user

        // Spend the state first: a replayed or concurrent link carrying
        // the same state is refused, and so is a retry after a failure.
        const stateEntry = yield* consumeState(state);

        if (stateEntry.provider !== provider) {
          return yield* new OAuthProviderError({
            message: `State provider mismatch: expected ${provider}, got ${stateEntry.provider}`,
            provider,
          });
        }

        const providerInstance = providers[provider];
        if (!providerInstance) {
          return yield* new OAuthProviderError({
            message: `Provider ${provider} not found`,
            provider,
          });
        }

        // Exchange the code, then read the profile (userinfo or a verified id_token).
        const { tokens, userInfo } = yield* exchangeForProfile(
          providerInstance,
          state,
          code,
          stateEntry,
        );

        // Email-mismatch guard: reject when the provider email differs from the
        // user's current account email (overridable with allowDifferentEmails).
        if (!allowDifferentEmails && userInfo.email) {
          const providerEmail = normalizeEmail(userInfo.email);
          const ownIdentifiers = yield* identifiers.listByUser(userId);
          const ownsEmail = ownIdentifiers.some(
            (id) => id.type === "email" && id.value === providerEmail,
          );
          if (!ownsEmail) {
            return yield* new OAuthEmailMismatchError({
              message: `Cannot link ${provider} account: provider email (${providerEmail}) does not belong to this account`,
              provider,
            });
          }
        }

        // Check if this OAuth account is already linked to another user
        const existingAccount = yield* accountStore.get(provider, userInfo.id);

        if (existingAccount && existingAccount.userId !== userId) {
          return yield* new OAuthAccountConflictError({
            message: `This ${provider} account is already linked to another user`,
            provider,
          });
        }

        // Create or update the account linked to this user
        const accountId = existingAccount?.id ?? (yield* randomAccountId());
        const account = profileAccount(
          {
            id: accountId,
            userId,
            provider,
            createdAt: existingAccount?.createdAt ?? (yield* Clock.currentTimeMillis),
          },
          tokens,
          userInfo,
          yield* Clock.currentTimeMillis,
        );

        if (existingAccount) {
          yield* accountStore.update(yield* encryptAccount(account));
        } else {
          yield* createAccount(yield* encryptAccount(account));
        }

        // Refresh the user's profile fields from the provider when requested.
        // Silently skipped when the store does not implement updateUser.
        if (updateUserInfoOnLink && userStore.updateUser) {
          const profileUpdate: { name?: string; image?: string } = {};
          if (userInfo.name !== undefined) profileUpdate.name = userInfo.name;
          if (userInfo.picture !== undefined) profileUpdate.image = userInfo.picture;
          if (profileUpdate.name !== undefined || profileUpdate.image !== undefined) {
            yield* userStore.updateUser(userId, profileUpdate);
          }
        }

        return account;
      }),

      unlinkAccount: Effect.fn("OAuthService.unlinkAccount")(function* (
        userId: string,
        provider: string,
        opts?: { readonly allowUnlinkingAll?: boolean },
      ) {
        const accounts = yield* accountStore.getByUserId(userId);
        const account = accounts.find((a) => a.provider === provider);

        if (!account) {
          return yield* new OAuthAccountNotFoundError({
            message: `No ${provider} account linked to this user`,
            provider,
          });
        }

        // Last-credential lockout guard: refuse to remove the user's only
        // sign-in credential (no other linked OAuth account AND no password).
        // Overridable with `allowUnlinkingAll`. When the store does not
        // implement `hasPassword`, the guard fails open — it assumes another
        // credential exists and permits the unlink.
        if (!(opts?.allowUnlinkingAll ?? false)) {
          const remainingOAuth = accounts.filter((a) => a.provider !== provider).length;
          const hasPass = accountStore.hasPassword ? yield* accountStore.hasPassword(userId) : true;
          if (remainingOAuth === 0 && !hasPass) {
            return yield* new OAuthLastCredentialError({
              message: `Cannot unlink the last sign-in credential for user ${userId}`,
              userId,
            });
          }
        }

        return yield* accountStore.delete(provider, account.providerId);
      }),

      refreshAccessToken: Effect.fn("OAuthService.refreshAccessToken")(
        (userId: string, provider: string) =>
          Effect.gen(function* () {
            const accounts = yield* accountStore.getByUserId(userId);
            const account = accounts.find((a) => a.provider === provider);

            if (!account) {
              return yield* new OAuthAccountNotFoundError({
                message: `No ${provider} account linked to this user`,
                provider,
              });
            }
            if (!account.refreshToken) {
              return yield* new OAuthNoRefreshTokenError({
                message: `No refresh token available for ${provider}`,
                provider,
              });
            }

            const plainAccount = yield* decryptAccount(account);
            // decryptAccount keeps the refresh token checked above; this only narrows it.
            const refreshToken = plainAccount.refreshToken;
            if (refreshToken === undefined) {
              return yield* new OAuthNoRefreshTokenError({
                message: `No refresh token available for ${provider}`,
                provider,
              });
            }

            const providerInstance = providers[provider];
            if (!providerInstance) {
              return yield* new OAuthProviderError({
                message: `Provider ${provider} not found`,
                provider,
              });
            }

            // Exchange refresh token for new access token
            const rConfig = providerInstance.config;
            const rUseBasic = rConfig.tokenAuthMethod === "basic";
            const params = new URLSearchParams({
              [rConfig.clientIdParam ?? "client_id"]: rConfig.clientId,
              grant_type: "refresh_token",
              refresh_token: refreshToken,
            });
            if (!rUseBasic) {
              params.set("client_secret", Redacted.value(rConfig.clientSecret));
            }

            const response = yield* fetchProviderOk(provider, tokenRequest(rConfig, params), {
              fetchFailure: `Failed to refresh token for ${provider}`,
              statusFailure: "Token refresh failed",
            }).pipe(OutboundHttp.provide(outbound));

            const data = yield* readTokenResponse(provider, response);

            // Update account with new tokens
            const updatedAccount: OAuthAccount = {
              ...plainAccount,
              accessToken: data.access_token,
              ...(data.refresh_token && { refreshToken: data.refresh_token }),
              ...(data.expires_in && {
                expiresAt: (yield* Clock.currentTimeMillis) + data.expires_in * 1000,
              }),
              updatedAt: yield* Clock.currentTimeMillis,
            };

            yield* accountStore.update(yield* encryptAccount(updatedAccount));

            return data.access_token;
          }).pipe(
            Effect.withSpan(Obs.spanNames.oauthRefresh, { attributes: { provider } }),
            Effect.tap(() => Obs.recordOAuthRefresh(provider, "success")),
            Effect.tapError(() => Obs.recordOAuthRefresh(provider, "failure")),
          ),
      ),
    };
  });

/**
 * Pre-built OAuth providers
 */

/**
 * Google provider preset. Its `oauth2/v2/userinfo` endpoint reports the
 * address's verification as `verified_email`, read here as `email_verified`,
 * so a Google-verified address can auto-link.
 */
export const GoogleProvider = (config: {
  clientId: string;
  clientSecret: Redacted.Redacted;
  redirectUri: string;
}): OAuthProvider =>
  provider(
    "google",
    {
      ...config,
      authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenEndpoint: "https://oauth2.googleapis.com/token",
      userInfoEndpoint: "https://www.googleapis.com/oauth2/v2/userinfo",
      scopes: ["openid", "email", "profile"],
      mapProfile: (raw) =>
        profile(raw, {
          id: raw["id"] ?? raw["sub"],
          email: str(raw["email"]),
          name: str(raw["name"]),
          picture: str(raw["picture"]),
          ...emailVerifiedClaim(raw["verified_email"] ?? raw["email_verified"]),
        }),
    },
    true, // Use PKCE
  );

/** The address GitHub's `/user/emails` lists as primary, with its verification. */
const githubPrimaryEmail = (
  accessToken: string,
): Effect.Effect<
  { readonly email: string; readonly verified: boolean } | undefined,
  OAuthProviderError,
  HttpClient.HttpClient
> =>
  fetchProviderOk(
    "github",
    HttpClientRequest.get("https://api.github.com/user/emails", {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
    }),
    { fetchFailure: "Failed to list GitHub emails", statusFailure: "GitHub email lookup failed" },
  ).pipe(
    Effect.flatMap((response) => readJson("github", response, "email list")),
    Effect.map((body) => {
      const primary = Array.isArray(body)
        ? body.find((entry) => isJsonObject(entry) && entry["primary"] === true)
        : undefined;
      const email = isJsonObject(primary) ? str(primary["email"]) : undefined;
      return email === undefined || !isJsonObject(primary)
        ? undefined
        : { email, verified: primary["verified"] === true };
    }),
  );

/**
 * GitHub OAuth 2.0 provider preset. `/user` shows only a public address, so
 * the profile takes the primary address from `/user/emails` (the
 * `user:email` scope), with GitHub's verification, which lets a private or
 * verified address sign in and auto-link. When that lookup fails, the public
 * address is used, unverified.
 */
export const GitHubProvider = (config: {
  clientId: string;
  clientSecret: Redacted.Redacted;
  redirectUri: string;
}): OAuthProvider => {
  const base = provider(
    "github",
    {
      ...config,
      authorizationEndpoint: "https://github.com/login/oauth/authorize",
      tokenEndpoint: "https://github.com/login/oauth/access_token",
      userInfoEndpoint: "https://api.github.com/user",
      scopes: ["user:email"],
      mapProfile: (raw) =>
        profile(raw, {
          id: raw["id"],
          email: str(raw["email"]),
          name: str(raw["name"]) ?? str(raw["login"]),
          picture: str(raw["avatar_url"]),
        }),
    },
    false, // GitHub doesn't support PKCE yet
  );
  const getUserInfo = (accessToken: string) =>
    Effect.gen(function* () {
      const info = yield* base.getUserInfo(accessToken);
      const primary = yield* githubPrimaryEmail(accessToken).pipe(
        Effect.catch((error) =>
          Effect.logWarning("GitHub email lookup failed; using the public address").pipe(
            Effect.annotateLogs({ error: error.message }),
            Effect.as(undefined),
          ),
        ),
      );
      if (primary === undefined) return info;
      return { ...info, email: primary.email, email_verified: primary.verified };
    });
  return {
    ...base,
    getUserInfo,
    getProfile: (tokens) => getUserInfo(tokens.access_token),
  };
};

/** Discord OAuth 2.0 provider preset. */
export const DiscordProvider = (config: {
  clientId: string;
  clientSecret: Redacted.Redacted;
  redirectUri: string;
}): OAuthProvider =>
  provider(
    "discord",
    {
      ...config,
      authorizationEndpoint: "https://discord.com/api/oauth2/authorize",
      tokenEndpoint: "https://discord.com/api/oauth2/token",
      userInfoEndpoint: "https://discord.com/api/users/@me",
      scopes: ["identify", "email"],
    },
    true, // Use PKCE
  );

/** Microsoft (Entra ID) provider preset; `tenant` selects the directory. */
export const MicrosoftProvider = (config: {
  clientId: string;
  clientSecret: Redacted.Redacted;
  redirectUri: string;
  tenant?: string;
}): OAuthProvider =>
  provider(
    "microsoft",
    {
      ...config,
      authorizationEndpoint: `https://login.microsoftonline.com/${config.tenant ?? "common"}/oauth2/v2.0/authorize`,
      tokenEndpoint: `https://login.microsoftonline.com/${config.tenant ?? "common"}/oauth2/v2.0/token`,
      userInfoEndpoint: "https://graph.microsoft.com/v1.0/me",
      scopes: ["openid", "email", "profile"],
      // Graph's `/me` has no `email`: the address is `mail`, else the sign-in
      // name when it is one (a guest's `#EXT#` name is not). Graph does not
      // say the address is verified, so it is not, and never auto-links.
      mapProfile: (raw) => {
        const upn = str(raw["userPrincipalName"]);
        return profile(raw, {
          id: raw["id"],
          email:
            str(raw["mail"]) ??
            (upn !== undefined && upn.includes("@") && !upn.includes("#EXT#") ? upn : undefined),
          name: str(raw["displayName"]),
        });
      },
    },
    true, // Use PKCE
  );

/** The `{ clientId, clientSecret, redirectUri }` triple every provider needs. */
export interface OAuthClientConfig {
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted;
  readonly redirectUri: string;
}

/** Coerce a value to `string` — returns `undefined` for non-strings. */
export const str = (v: unknown): string | undefined => (P.isString(v) ? v : undefined);

/**
 * Safely traverse a nested object by a chain of keys. Returns `undefined`
 * at the first missing or non-object step.
 *
 * @example
 * nested(raw["picture"], "data", "url") // → raw.picture?.data?.url
 */
export const nested = (v: unknown, ...path: string[]): unknown =>
  path.reduce<unknown>(
    (acc, key) => (P.isObjectOrArray(acc) && P.hasProperty(acc, key) ? acc[key] : undefined),
    v,
  );

/**
 * Build an {@link OAuthUserInfo} from a base record plus normalized identity
 * fields, omitting any that are `undefined` (satisfies
 * `exactOptionalPropertyTypes`).
 *
 * @example
 * profile(raw, { id: raw["id"], email: str(raw["email"]), name: str(raw["name"]) })
 */
export const profile = (
  base: Types.JsonObject,
  fields: {
    readonly id: unknown;
    readonly email?: string | undefined;
    readonly name?: string | undefined;
    readonly picture?: string | undefined;
    readonly email_verified?: boolean | undefined;
  },
): OAuthUserInfo => ({
  ...base,
  id: idString(fields.id),
  ...(fields.email !== undefined && { email: fields.email }),
  ...(fields.name !== undefined && { name: fields.name }),
  ...(fields.picture !== undefined && { picture: fields.picture }),
  ...(fields.email_verified !== undefined && { email_verified: fields.email_verified }),
});

/**
 * Profile-mapping helpers for use in custom {@link OAuthProviderConfig.mapProfile}
 * implementations. These are the same utilities used by every built-in provider
 * preset (Facebook, Twitter, Spotify, …), now exported so your own `mapProfile`
 * can be just as terse.
 *
 * @example
 * import { provider, ProfileMap } from "@thomasfosterau/effect-auth";
 *
 * const LinearProvider = (config: OAuthClientConfig): OAuthProvider =>
 *   provider("linear", {
 *     ...config,
 *     authorizationEndpoint: "https://linear.app/oauth/authorize",
 *     tokenEndpoint: "https://api.linear.app/oauth/token",
 *     userInfoEndpoint: "https://api.linear.app/graphql",
 *     scopes: ["read"],
 *     mapProfile: (raw) =>
 *       ProfileMap.profile(raw, {
 *         id: raw["id"],
 *         email: ProfileMap.str(raw["email"]),
 *         name: ProfileMap.str(raw["name"]),
 *         picture: ProfileMap.str(ProfileMap.nested(raw["avatarUrl"])),
 *       }),
 *   }, true);
 */
export const ProfileMap = { str, nested, profile } as const;

/**
 * Sign-in with Apple. Apple returns identity only via the OIDC `id_token`
 * (`response_mode=form_post`, `name`/`email` scopes). `clientSecret` must be a
 * signed ES256 JWT — generate it with {@link appleClientSecret}.
 */
export const AppleProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "apple",
    {
      ...config,
      authorizationEndpoint: "https://appleid.apple.com/auth/authorize",
      tokenEndpoint: "https://appleid.apple.com/auth/token",
      jwksEndpoint: "https://appleid.apple.com/auth/keys",
      issuer: "https://appleid.apple.com",
      getUserInfoFromIdToken: true,
      scopes: ["name", "email"],
      authorizationParams: { response_mode: "form_post" },
    },
    true,
  );

/**
 * Build the ES256-signed client-secret JWT Apple requires (valid up to 6
 * months; Apple caps `exp` at 15777000s). Pass the result as `clientSecret`
 * to {@link AppleProvider}.
 */
export const appleClientSecret = (params: {
  readonly teamId: string;
  readonly clientId: string;
  readonly keyId: string;
  /** PKCS#8 PEM of the private key downloaded from Apple. */
  readonly privateKey: Redacted.Redacted;
  /** Lifetime in seconds (default 6 months, Apple's maximum). */
  readonly expiresIn?: number;
  readonly now?: number;
}): Effect.Effect<string, OAuthProviderError> =>
  Effect.flatMap(Clock.currentTimeMillis, (millis) => {
    const iat = Math.floor((params.now ?? millis) / 1000);
    const payload = {
      iss: params.teamId,
      iat,
      exp: iat + (params.expiresIn ?? 15777000),
      aud: "https://appleid.apple.com",
      sub: params.clientId,
    };
    return signWithPkcs8(
      new TextEncoder().encode(encodeJsonString(payload)),
      Redacted.make(Redacted.value(params.privateKey)),
      "ES256",
      { kid: params.keyId, typ: "JWT" },
    ).pipe(
      PlatformCrypto.provide,
      Effect.mapError(
        (cause) =>
          new OAuthProviderError({
            message: "Failed to sign Apple client secret",
            provider: "apple",
            cause,
          }),
      ),
    );
  });

/** Facebook Login (Graph API userinfo; `picture` is nested under `data.url`). */
export const FacebookProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "facebook",
    {
      ...config,
      authorizationEndpoint: "https://www.facebook.com/v18.0/dialog/oauth",
      tokenEndpoint: "https://graph.facebook.com/v18.0/oauth/access_token",
      userInfoEndpoint: "https://graph.facebook.com/me?fields=id,name,email,picture",
      scopes: ["email", "public_profile"],
      mapProfile: (raw) =>
        profile(raw, {
          id: raw["id"],
          email: str(raw["email"]),
          name: str(raw["name"]),
          picture: str(nested(raw["picture"], "data", "url")),
        }),
    },
    false,
  );

/**
 * X/Twitter OAuth2 (PKCE + Basic auth required).
 *
 * **Link-only.** The provider returns no email address, so it cannot create
 * an account or sign in someone new (`signInWithCallback` fails with
 * `OAuthMissingEmailError`). Link it to the signed-in user's account with
 * `OAuthService.linkAccount`; from then on it signs that user in.
 */
export const TwitterProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "twitter",
    {
      ...config,
      authorizationEndpoint: "https://twitter.com/i/oauth2/authorize",
      tokenEndpoint: "https://api.twitter.com/2/oauth2/token",
      userInfoEndpoint: "https://api.twitter.com/2/users/me?user.fields=profile_image_url",
      scopes: ["users.read", "tweet.read"],
      tokenAuthMethod: "basic",
      mapProfile: (raw) => {
        // SAFETY: Twitter's users/me answers `{ data: user }`, the user an object;
        // a missing envelope falls back to the (object) payload itself.
        const data = (raw["data"] ?? raw) as Types.JsonObject;
        return profile(data, {
          id: data["id"],
          name: str(data["name"]),
          picture: str(data["profile_image_url"]),
        });
      },
    },
    true,
  );

/** LinkedIn (OpenID Connect userinfo). */
export const LinkedInProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "linkedin",
    {
      ...config,
      authorizationEndpoint: "https://www.linkedin.com/oauth/v2/authorization",
      tokenEndpoint: "https://www.linkedin.com/oauth/v2/accessToken",
      userInfoEndpoint: "https://api.linkedin.com/v2/userinfo",
      scopes: ["openid", "profile", "email"],
    },
    false,
  );

/** Twitch (OpenID Connect userinfo). */
export const TwitchProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "twitch",
    {
      ...config,
      authorizationEndpoint: "https://id.twitch.tv/oauth2/authorize",
      tokenEndpoint: "https://id.twitch.tv/oauth2/token",
      userInfoEndpoint: "https://id.twitch.tv/oauth2/userinfo",
      scopes: ["openid", "user:read:email"],
    },
    false,
  );

/** Spotify (Basic auth token exchange; `images[0].url`, `display_name`). */
export const SpotifyProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "spotify",
    {
      ...config,
      authorizationEndpoint: "https://accounts.spotify.com/authorize",
      tokenEndpoint: "https://accounts.spotify.com/api/token",
      userInfoEndpoint: "https://api.spotify.com/v1/me",
      scopes: ["user-read-email", "user-read-private"],
      tokenAuthMethod: "basic",
      mapProfile: (raw) => {
        const images = raw["images"];
        const picture = Array.isArray(images) ? str(nested(images[0], "url")) : undefined;
        return profile(raw, {
          id: raw["id"],
          email: str(raw["email"]),
          name: str(raw["display_name"]),
          picture,
        });
      },
    },
    false,
  );

/** GitLab (`gitlab.com` by default; pass `baseUrl` for self-hosted). */
export const GitLabProvider = (
  config: OAuthClientConfig & { readonly baseUrl?: string },
): OAuthProvider => {
  const base = (config.baseUrl ?? "https://gitlab.com").replace(/\/$/, "");
  return provider(
    "gitlab",
    {
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri: config.redirectUri,
      authorizationEndpoint: `${base}/oauth/authorize`,
      tokenEndpoint: `${base}/oauth/token`,
      userInfoEndpoint: `${base}/api/v4/user`,
      scopes: ["read_user"],
      mapProfile: (raw) =>
        profile(raw, {
          id: raw["id"],
          email: str(raw["email"]),
          name: str(raw["name"]),
          picture: str(raw["avatar_url"]),
        }),
    },
    true,
  );
};

/**
 * Reddit (Basic auth; `identity` scope; `duration=permanent`).
 *
 * **Link-only.** The provider returns no email address, so it cannot create
 * an account or sign in someone new (`signInWithCallback` fails with
 * `OAuthMissingEmailError`). Link it to the signed-in user's account with
 * `OAuthService.linkAccount`; from then on it signs that user in.
 */
export const RedditProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "reddit",
    {
      ...config,
      authorizationEndpoint: "https://www.reddit.com/api/v1/authorize",
      tokenEndpoint: "https://www.reddit.com/api/v1/access_token",
      userInfoEndpoint: "https://oauth.reddit.com/api/v1/me",
      scopes: ["identity"],
      tokenAuthMethod: "basic",
      authorizationParams: { duration: "permanent" },
      mapProfile: (raw) =>
        profile(raw, {
          id: raw["id"],
          name: str(raw["name"]),
          picture: str(raw["icon_img"]),
        }),
    },
    false,
  );

/** Dropbox (POST userinfo; `token_access_type=offline` for refresh tokens). */
export const DropboxProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "dropbox",
    {
      ...config,
      authorizationEndpoint: "https://www.dropbox.com/oauth2/authorize",
      tokenEndpoint: "https://api.dropboxapi.com/oauth2/token",
      userInfoEndpoint: "https://api.dropboxapi.com/2/users/get_current_account",
      userInfoMethod: "POST",
      scopes: ["account_info.read"],
      authorizationParams: { token_access_type: "offline" },
      mapProfile: (raw) =>
        profile(raw, {
          id: raw["account_id"],
          email: str(raw["email"]),
          name: str(nested(raw["name"], "display_name")),
          picture: str(raw["profile_photo_url"]),
        }),
    },
    true,
  );

/** Notion (Basic auth; profile via `/v1/users/me` bot owner). */
export const NotionProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "notion",
    {
      ...config,
      authorizationEndpoint: "https://api.notion.com/v1/oauth/authorize",
      tokenEndpoint: "https://api.notion.com/v1/oauth/token",
      userInfoEndpoint: "https://api.notion.com/v1/users/me",
      userInfoHeaders: { "Notion-Version": "2022-06-28" },
      scopes: [],
      tokenAuthMethod: "basic",
      authorizationParams: { owner: "user" },
      mapProfile: (raw) => {
        // SAFETY: Notion's users/me carries the user object at bot.owner.user;
        // without it, the (object) payload itself is the user.
        const user = (nested(raw, "bot", "owner", "user") ?? raw) as Types.JsonObject;
        return profile(raw, {
          id: user["id"] ?? raw["id"],
          email: str(nested(user, "person", "email")),
          name: str(user["name"]),
          picture: str(user["avatar_url"]),
        });
      },
    },
    false,
  );

/** Slack (Sign in with Slack / OpenID Connect). */
export const SlackProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "slack",
    {
      ...config,
      authorizationEndpoint: "https://slack.com/openid/connect/authorize",
      tokenEndpoint: "https://slack.com/api/openid.connect.token",
      userInfoEndpoint: "https://slack.com/api/openid.connect.userInfo",
      scopes: ["openid", "email", "profile"],
    },
    false,
  );

/** Zoom (Basic auth; `first_name`/`last_name`, `pic_url`). */
export const ZoomProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "zoom",
    {
      ...config,
      authorizationEndpoint: "https://zoom.us/oauth/authorize",
      tokenEndpoint: "https://zoom.us/oauth/token",
      userInfoEndpoint: "https://api.zoom.us/v2/users/me",
      scopes: ["user:read"],
      tokenAuthMethod: "basic",
      mapProfile: (raw) => {
        const name = [str(raw["first_name"]), str(raw["last_name"])].filter(Boolean).join(" ");
        return profile(raw, {
          id: raw["id"],
          email: str(raw["email"]),
          name: name === "" ? undefined : name,
          picture: str(raw["pic_url"]),
        });
      },
    },
    true,
  );

/**
 * TikTok (uses `client_key`; PKCE; profile under `data.user`).
 *
 * **Link-only.** The provider returns no email address, so it cannot create
 * an account or sign in someone new (`signInWithCallback` fails with
 * `OAuthMissingEmailError`). Link it to the signed-in user's account with
 * `OAuthService.linkAccount`; from then on it signs that user in.
 */
export const TikTokProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "tiktok",
    {
      ...config,
      clientIdParam: "client_key",
      authorizationEndpoint: "https://www.tiktok.com/v2/auth/authorize/",
      tokenEndpoint: "https://open.tiktokapis.com/v2/oauth/token/",
      userInfoEndpoint:
        "https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name,avatar_url",
      scopes: ["user.info.basic"],
      mapProfile: (raw) => {
        // SAFETY: TikTok's user/info carries the user object at data.user;
        // without it, the (object) payload itself is the user.
        const user = (nested(raw, "data", "user") ?? raw) as Types.JsonObject;
        return profile(user, {
          id: user["open_id"] ?? user["id"],
          name: str(user["display_name"]),
          picture: str(user["avatar_url"]),
        });
      },
    },
    true,
  );

/**
 * Roblox (OpenID Connect; PKCE required).
 *
 * **Link-only.** The provider returns no email address, so it cannot create
 * an account or sign in someone new (`signInWithCallback` fails with
 * `OAuthMissingEmailError`). Link it to the signed-in user's account with
 * `OAuthService.linkAccount`; from then on it signs that user in.
 */
export const RobloxProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "roblox",
    {
      ...config,
      authorizationEndpoint: "https://apis.roblox.com/oauth/v1/authorize",
      tokenEndpoint: "https://apis.roblox.com/oauth/v1/token",
      userInfoEndpoint: "https://apis.roblox.com/oauth/v1/userinfo",
      scopes: ["openid", "profile"],
    },
    true,
  );

/** Kick (PKCE required; profile under `data[0]`). */
export const KickProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "kick",
    {
      ...config,
      authorizationEndpoint: "https://id.kick.com/oauth/authorize",
      tokenEndpoint: "https://id.kick.com/oauth/token",
      userInfoEndpoint: "https://api.kick.com/public/v1/users",
      scopes: ["user:read"],
      mapProfile: (raw) => {
        const data = raw["data"];
        // SAFETY: Kick's users endpoint answers `{ data: [user] }`, each user an
        // object; without the array, the (object) payload itself is the user.
        const user = (Array.isArray(data) ? data[0] : raw) as Types.JsonObject;
        return profile(user, {
          id: user["user_id"] ?? user["id"],
          email: str(user["email"]),
          name: str(user["name"]),
          picture: str(user["profile_picture"]),
        });
      },
    },
    true,
  );

/** Hugging Face (OpenID Connect; PKCE). */
export const HuggingFaceProvider = (config: OAuthClientConfig): OAuthProvider =>
  provider(
    "huggingface",
    {
      ...config,
      authorizationEndpoint: "https://huggingface.co/oauth/authorize",
      tokenEndpoint: "https://huggingface.co/oauth/token",
      userInfoEndpoint: "https://huggingface.co/oauth/userinfo",
      scopes: ["openid", "profile", "email"],
    },
    true,
  );

/**
 * Endpoint set resolved from an OpenID Connect discovery document, in the
 * shape {@link OAuthProviderConfig} expects.
 */
export interface DiscoveredEndpoints {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly userInfoEndpoint?: string;
  readonly jwksEndpoint?: string;
}

/**
 * Populate a provider's endpoints from an issuer's
 * `/.well-known/openid-configuration`. Spread the result into a
 * {@link provider} config to build a generic OIDC provider.
 */
export const discoverOAuthEndpoints = (
  issuerUrl: string,
): Effect.Effect<DiscoveredEndpoints, OAuthProviderError, HttpClient.HttpClient> =>
  Effect.gen(function* () {
    const base = issuerUrl.replace(/\/$/, "");
    const url = `${base}/.well-known/openid-configuration`;
    const response = yield* OutboundHttp.sendWith(OutboundHttp.getJson(url)).pipe(
      Effect.mapError(
        (cause) =>
          new OAuthProviderError({
            message: `Failed to fetch OIDC discovery document from ${url}`,
            provider: issuerUrl,
            cause,
          }),
      ),
    );
    if (!OutboundHttp.isOk(response)) {
      yield* OutboundHttp.logUpstreamFailure("OIDC discovery request failed", response, {
        issuer: issuerUrl,
      });
      return yield* new OAuthProviderError({
        message: `OIDC discovery request failed with status ${response.status}`,
        provider: issuerUrl,
      });
    }
    const doc = yield* readJson(issuerUrl, response, "OIDC discovery document");
    if (!isJsonObject(doc)) {
      return yield* new OAuthProviderError({
        message: "OIDC discovery document is not a JSON object",
        provider: issuerUrl,
      });
    }
    const authorization = str(doc["authorization_endpoint"]);
    const token = str(doc["token_endpoint"]);
    if (!authorization || !token) {
      return yield* new OAuthProviderError({
        message: "OIDC discovery document is missing authorization_endpoint or token_endpoint",
        provider: issuerUrl,
      });
    }
    const userInfo = str(doc["userinfo_endpoint"]);
    const jwks = str(doc["jwks_uri"]);
    return {
      issuer: str(doc["issuer"]) ?? base,
      authorizationEndpoint: authorization,
      tokenEndpoint: token,
      ...(userInfo !== undefined && { userInfoEndpoint: userInfo }),
      ...(jwks !== undefined && { jwksEndpoint: jwks }),
    } satisfies DiscoveredEndpoints;
  });
