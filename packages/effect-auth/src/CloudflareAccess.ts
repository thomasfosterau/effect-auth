/**
 * Cloudflare Access: trust the identity Access puts on every request it lets
 * through.
 *
 * When an application sits behind [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/),
 * Access signs the caller in at the edge and forwards an application token, a
 * JWT, in the `Cf-Access-Jwt-Assertion` header (and, for browsers, the
 * `CF_Authorization` cookie). This module verifies that token and hands back
 * the identity it carries, so the application runs no sign-in of its own:
 *
 * - **Signature**: RS256 only, against the key whose `kid` the token names,
 *   from the team's own key set (`https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`).
 *   The key URL comes from the configuration, never from the token.
 * - **Issuer**: `iss` equals the team domain exactly.
 * - **Audience**: `aud` contains the application's AUD tag.
 * - **Lifetime**: `exp` is required; `exp` and `nbf` are checked with a
 *   bounded clock tolerance.
 *
 * The key set is cached in memory for `keysTtlMs` and refetched early when a
 * token names a `kid` the cache does not hold (Access rotates its keys), at
 * most once per `minRefreshIntervalMs`, so a forged `kid` cannot turn every
 * request into a fetch. Refetches are serialised: concurrent requests wait for
 * one fetch rather than each starting their own.
 *
 * The verified identity is either a user (with the email the identity
 * provider attested) or a service token (its client id as `commonName`).
 * {@link findUser} maps a user identity to an existing effect-auth user by
 * verified email, and {@link userContextLayer} provides it as the request's
 * `CurrentUser`, `CurrentPrincipal` and `CurrentCredential` (a service token is
 * `"machine"`), so gated code runs as it would under any other credential.
 *
 * ## Header or cookie
 *
 * Cloudflare recommends the header: Access adds it to every request it
 * forwards, while the cookie is not guaranteed. The default reads only the
 * header. Add `"cookie"` to `sources` when the application reads the identity
 * on paths Access does not gate (an edit control on a page readers also see),
 * where only the browser's cookie arrives. A cookie credential is ambient, so
 * a state-changing request authenticated by it needs the same CSRF defence as
 * any session cookie (a trusted-origin check, a `SameSite` cookie).
 *
 * This module runs on Workers (`nodejs_compat`), in Node and anywhere else the
 * core does: signature verification goes through `effect/jose`.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer, Option } from "effect"
 * import { FetchHttpClient } from "effect/http"
 * import { CloudflareAccess, SessionResolution } from "@thomasfosterau/effect-auth"
 *
 * const AccessLive = CloudflareAccess.CloudflareAccessVerifier.layer({
 *   teamDomain: "example-team.cloudflareaccess.com",
 *   audience: "4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2",
 * }).pipe(Layer.provide(FetchHttpClient.layer))
 *
 * // A request with no Access token is anonymous, and nothing is fetched.
 * const request = new Request("https://example.com/notes/1")
 * const identity = await Effect.runPromise(
 *   Effect.gen(function* () {
 *     const access = yield* CloudflareAccess.CloudflareAccessVerifier
 *     return yield* access.verifyRequest(SessionResolution.fromRequest(request))
 *   }).pipe(Effect.provide(AccessLive)),
 * )
 * assert.equal(Option.isNone(identity), true)
 * ```
 *
 * @since 0.6.0
 * @module cloudflare-access
 */
import { Clock, Context, Data, DateTime, Effect, Formatter, Layer, SynchronizedRef } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import type { HttpClient } from "effect/http";
import type { CredentialClass, CurrentCredential, CurrentPrincipal } from "./Authorizer.ts";
import { verifiesWithJwk } from "./JwsSignature.ts";
import type { AuthError } from "./Errors.ts";
import { IdentifierStore, lookupIdentifier } from "./Identifier.ts";
import * as OutboundHttp from "./OutboundHttp.ts";
import type { CredentialSource } from "./SessionResolution.ts";
import { type CurrentUser, userLayer } from "./SessionContext.ts";
import type * as Types from "./Types.ts";
import { UserStore } from "./UserStore.ts";
import { isInGoodStanding } from "./UserStanding.ts";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * The request header Access forwards the application token in.
 *
 * @since 0.6.0
 * @category constants
 */
export const ACCESS_JWT_HEADER = "cf-access-jwt-assertion";

/**
 * The cookie Access sets on the application's domain for browsers.
 *
 * @since 0.6.0
 * @category constants
 */
export const ACCESS_JWT_COOKIE = "CF_Authorization";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Why a token, or the configuration, was refused.
 *
 * @since 0.6.0
 * @category errors
 */
export type CloudflareAccessFailure =
  | "config"
  | "malformed"
  | "algorithm"
  | "key"
  | "jwks"
  | "signature"
  | "issuer"
  | "audience"
  | "expired"
  | "not-yet-valid"
  | "claims";

/**
 * A refused Access token, an unreachable key set, or an invalid configuration.
 * `reason` says which; `message` is safe to log and never carries the token.
 *
 * @since 0.6.0
 * @category errors
 */
export class CloudflareAccessError extends Data.TaggedError("CloudflareAccessError")<{
  readonly reason: CloudflareAccessFailure;
  readonly message: string;
  readonly cause?: unknown;
}> {}

// ---------------------------------------------------------------------------
// Config and identity
// ---------------------------------------------------------------------------

/**
 * Where {@link CloudflareAccessVerifier.verifyRequest} looks for the token.
 *
 * @since 0.6.0
 * @category models
 */
export type CloudflareAccessSource = "header" | "cookie";

/**
 * Configuration for {@link CloudflareAccessVerifier.layer}.
 *
 * @since 0.6.0
 * @category models
 */
export interface CloudflareAccessConfig {
  /**
   * The team domain, `<team>.cloudflareaccess.com`, with or without
   * `https://`. The token's `iss` must equal `https://<teamDomain>`.
   */
  readonly teamDomain: string;
  /**
   * The Access application's AUD tag (Zero Trust → Access → Applications →
   * the application → Additional settings), or several when one origin
   * serves more than one Access application. The token's `aud` must contain
   * one of them.
   */
  readonly audience: string | ReadonlyArray<string>;
  /**
   * Where the token is read from, in order; the first one present is used,
   * and an invalid one is refused rather than skipped. Default `["header"]`.
   */
  readonly sources?: ReadonlyArray<CloudflareAccessSource> | undefined;
  /** Override the key set URL (tests). Default `https://<teamDomain>/cdn-cgi/access/certs`. */
  readonly certsUrl?: string | undefined;
  /** Allowed clock skew for `exp` and `nbf`, in milliseconds. Default 60 000. */
  readonly clockToleranceMs?: number | undefined;
  /** How long a fetched key set is used before it is refetched, in milliseconds. Default 3 600 000. */
  readonly keysTtlMs?: number | undefined;
  /**
   * The least time between two key set fetches, in milliseconds, whatever
   * `kid` a token names. Default 30 000.
   */
  readonly minRefreshIntervalMs?: number | undefined;
  /** How long a key set fetch may take, in milliseconds. Default 5 000. */
  readonly fetchTimeoutMs?: number | undefined;
}

/**
 * The identity a verified Access token carries.
 *
 * @since 0.6.0
 * @category models
 */
export interface CloudflareAccessIdentity {
  /** A person signed in through the identity provider, or a service token. */
  readonly kind: "user" | "service-token";
  /** The user's stable Access id (`sub`), or the service token's client id. */
  readonly subject: string;
  /** The email the identity provider attested; users only. */
  readonly email?: string | undefined;
  /** The service token's client id (`common_name`); service tokens only. */
  readonly commonName?: string | undefined;
  /** The country Access saw the sign-in from (`country`), when present. */
  readonly country?: string | undefined;
  /** The `identity_nonce`, for `/cdn-cgi/access/get-identity`, when present. */
  readonly identityNonce?: string | undefined;
  /** When Access issued the token (`iat`), when present. */
  readonly issuedAt?: Date | undefined;
  /** When the token expires (`exp`). */
  readonly expiresAt: Date;
  /** Every verified claim. */
  readonly claims: Types.JsonObject;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/**
 * Verifies Cloudflare Access application tokens against the team's key set.
 *
 * Holds the key cache, so build the layer once per process (a Worker
 * isolate), not once per request.
 *
 * @since 0.6.0
 * @category services
 */
export class CloudflareAccessVerifier extends Context.Service<
  CloudflareAccessVerifier,
  {
    /** Verify one application token and return its identity. */
    readonly verify: (
      token: string,
    ) => Effect.Effect<CloudflareAccessIdentity, CloudflareAccessError>;
    /**
     * Read the token from a request (see `sources`) and verify it.
     * `Option.none()` when the request carries no token; a token that fails
     * verification fails, it is never read as anonymous.
     */
    readonly verifyRequest: (
      source: CredentialSource,
    ) => Effect.Effect<Option.Option<CloudflareAccessIdentity>, CloudflareAccessError>;
  }
>()("@effect-auth/CloudflareAccessVerifier") {
  /**
   * A layer over {@link make}. Fails with a `"config"` {@link CloudflareAccessError}
   * when the team domain or audience is unusable. The key set is fetched
   * through the `HttpClient` the application provides (`FetchHttpClient.layer`).
   */
  static readonly layer = (config: CloudflareAccessConfig) =>
    Layer.effect(CloudflareAccessVerifier, make(config));
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

const fail = (reason: CloudflareAccessFailure, message: string, cause?: unknown) =>
  new CloudflareAccessError({ reason, message, ...(cause !== undefined && { cause }) });

/** `https://<host>` from a team domain given with or without its scheme. */
const issuerOf = (teamDomain: string): string | undefined => {
  const host = teamDomain
    .trim()
    .replace(/^https:\/\//i, "")
    .replace(/\/+$/, "")
    .toLowerCase();
  return /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(host)
    ? `https://${host}`
    : undefined;
};

const decodeSegmentJson = Schema.decodeSync(Schema.fromJsonString(Schema.JsonObject));
const decodeBase64UrlText = Schema.decodeSync(Schema.StringFromBase64Url);
const decodeBase64UrlBytes = Schema.decodeSync(Schema.Uint8ArrayFromBase64Url);
const decodeSegment = (segment: string): Types.JsonObject =>
  decodeSegmentJson(decodeBase64UrlText(segment));

const Jwks = Schema.Struct({ keys: Schema.Array(Schema.JsonObject) });
const decodeJwks = Schema.decodeUnknownEffect(Jwks);

interface KeyCache {
  readonly keys: ReadonlyArray<Types.JsonObject>;
  /** When the keys were last fetched successfully. */
  readonly fetchedAt: number;
  /** When a fetch was last attempted, whatever its outcome. */
  readonly attemptedAt: number;
}

/** A JWT `NumericDate` (seconds) as a `Date`. */
const dateOf = (seconds: number): Date => DateTime.toDateUtc(DateTime.makeUnsafe(seconds * 1000));

const findKey = (keys: ReadonlyArray<Types.JsonObject>, kid: string) =>
  keys.find((key) => key["kid"] === kid);

const missingKey = () => fail("key", "No Cloudflare Access key matches the token's kid");

const nonEmpty = (value: string | null | undefined): value is string =>
  P.isString(value) && value.trim() !== "";

/** Read one token source from a request. */
const readSource = (source: CredentialSource) => (from: CloudflareAccessSource) =>
  from === "header" ? source.header(ACCESS_JWT_HEADER) : source.cookie(ACCESS_JWT_COOKIE);

const optionalString = (claims: Types.JsonObject, name: string): string | undefined => {
  const value = claims[name];
  return P.isString(value) && value !== "" ? value : undefined;
};

/** The identity in a verified payload, or `undefined` when it names neither a user nor a service token. */
const identityOf = (
  claims: Types.JsonObject,
  exp: number,
): CloudflareAccessIdentity | undefined => {
  const email = optionalString(claims, "email");
  const commonName = optionalString(claims, "common_name");
  const sub = optionalString(claims, "sub");
  const iat = claims["iat"];
  const common = {
    country: optionalString(claims, "country"),
    identityNonce: optionalString(claims, "identity_nonce"),
    issuedAt: P.isNumber(iat) ? dateOf(iat) : undefined,
    expiresAt: dateOf(exp),
    claims,
  };
  if (email !== undefined && sub !== undefined) {
    return { kind: "user", subject: sub, email, ...common };
  }
  if (email === undefined && commonName !== undefined) {
    return { kind: "service-token", subject: commonName, commonName, ...common };
  }
  return undefined;
};

/** The first claim check (`iss`, `aud`, `exp`, `nbf`) the payload fails, if any. */
const claimFailure = (
  payload: Types.JsonObject,
  issuer: string,
  audiences: ReadonlyArray<string>,
  now: number,
  toleranceMs: number,
): CloudflareAccessError | undefined => {
  if (payload["iss"] !== issuer) return fail("issuer", "Access token issuer mismatch");
  const aud = payload["aud"];
  const tokenAudiences = P.isString(aud) ? [aud] : Array.isArray(aud) ? aud : [];
  if (!tokenAudiences.some((a) => P.isString(a) && audiences.includes(a))) {
    return fail("audience", "Access token audience mismatch");
  }
  const exp = payload["exp"];
  if (!P.isNumber(exp)) return fail("claims", "Access token has no exp");
  if (now - toleranceMs >= exp * 1000) return fail("expired", "Access token expired");
  const nbf = payload["nbf"];
  if (nbf !== undefined && (!P.isNumber(nbf) || now + toleranceMs < nbf * 1000)) {
    return fail("not-yet-valid", "Access token is not valid yet");
  }
  return undefined;
};

/**
 * Build a {@link CloudflareAccessVerifier}. The key set is fetched lazily, on
 * the first token.
 *
 * @since 0.6.0
 * @category constructors
 */
export const make = (
  config: CloudflareAccessConfig,
): Effect.Effect<
  typeof CloudflareAccessVerifier.Service,
  CloudflareAccessError,
  HttpClient.HttpClient
> =>
  Effect.gen(function* () {
    const issuer = issuerOf(config.teamDomain);
    if (issuer === undefined) {
      return yield* fail(
        "config",
        `Invalid Cloudflare Access team domain: ${Formatter.format(config.teamDomain)}`,
      );
    }
    const audiences: ReadonlyArray<string> = P.isString(config.audience)
      ? [config.audience]
      : config.audience;
    if (!Arr.isReadonlyArrayNonEmpty(audiences) || audiences.some((a) => a.trim() === "")) {
      return yield* fail("config", "Cloudflare Access audience must be one or more AUD tags");
    }
    const sources = config.sources ?? ["header"];
    if (!Arr.isReadonlyArrayNonEmpty(sources)) {
      return yield* fail("config", "Cloudflare Access sources must name at least one source");
    }
    const certsUrl = config.certsUrl ?? `${issuer}/cdn-cgi/access/certs`;
    const toleranceMs = config.clockToleranceMs ?? 60_000;
    const keysTtlMs = config.keysTtlMs ?? 3_600_000;
    const minRefreshIntervalMs = config.minRefreshIntervalMs ?? 30_000;
    const fetchTimeoutMs = config.fetchTimeoutMs ?? 5_000;

    const cache = yield* SynchronizedRef.make<KeyCache>({
      keys: [],
      fetchedAt: Number.NEGATIVE_INFINITY,
      attemptedAt: Number.NEGATIVE_INFINITY,
    });

    const outbound = yield* OutboundHttp.resolve();
    const fetchKeys = OutboundHttp.send(outbound.client, OutboundHttp.getJson(certsUrl), {
      ...outbound.limits,
      timeoutMs: fetchTimeoutMs,
    }).pipe(
      Effect.mapError((cause) =>
        fail(
          "jwks",
          cause.reason === "timeout"
            ? "Timed out fetching the Cloudflare Access keys"
            : "Failed to fetch the Cloudflare Access keys",
          cause,
        ),
      ),
      Effect.flatMap((response) =>
        OutboundHttp.isOk(response)
          ? OutboundHttp.parseJson(response.body).pipe(
              Effect.flatMap((body) => decodeJwks(body)),
              Effect.mapError((cause) => fail("jwks", "Invalid Cloudflare Access key set", cause)),
            )
          : OutboundHttp.logUpstreamFailure(
              "Cloudflare Access key set request failed",
              response,
            ).pipe(
              Effect.andThen(
                Effect.fail(
                  fail(
                    "jwks",
                    `Cloudflare Access key set request failed with status ${response.status}`,
                  ),
                ),
              ),
            ),
      ),
      Effect.map((jwks) => jwks.keys),
    );

    const keyFor = (kid: string): Effect.Effect<Types.JsonObject, CloudflareAccessError> =>
      Effect.gen(function* () {
        const now = yield* Clock.currentTimeMillis;
        const current = yield* SynchronizedRef.get(cache);
        const cached = findKey(current.keys, kid);
        if (cached !== undefined && now - current.fetchedAt < keysTtlMs) return cached;

        return yield* SynchronizedRef.modifyEffect(cache, (state) =>
          Effect.gen(function* () {
            const known = findKey(state.keys, kid);
            // Another fiber may have refreshed while this one waited.
            if (known !== undefined && now - state.fetchedAt < keysTtlMs) {
              return [known, state] as const;
            }
            if (now - state.attemptedAt < minRefreshIntervalMs) {
              if (known !== undefined) return [known, state] as const;
              return yield* missingKey();
            }
            const fetched = yield* Effect.result(fetchKeys);
            if (Result.isFailure(fetched)) {
              // Keep serving a key Cloudflare published before; a fetch fault
              // must not sign everybody out.
              const next = { ...state, attemptedAt: now };
              if (known !== undefined) return [known, next] as const;
              return yield* fetched.failure;
            }
            const next = { keys: fetched.success, fetchedAt: now, attemptedAt: now };
            const key = findKey(next.keys, kid);
            if (key === undefined) {
              // Record the fetch even though it failed this token.
              return [undefined, next] as const;
            }
            return [key, next] as const;
          }),
        ).pipe(Effect.filterOrFail(P.isNotUndefined, missingKey));
      });

    const verify = Effect.fn("CloudflareAccessVerifier.verify")(function* (token: string) {
      const [headerSeg, payloadSeg, signatureSeg, ...rest] = token.split(".");
      if (
        headerSeg === undefined ||
        payloadSeg === undefined ||
        signatureSeg === undefined ||
        Arr.isReadonlyArrayNonEmpty(rest)
      ) {
        return yield* fail("malformed", "Malformed Access token");
      }
      const { header, payload } = yield* Effect.try({
        try: () => {
          // A signature segment that is not base64url is malformed, not a bad signature.
          decodeBase64UrlBytes(signatureSeg);
          return { header: decodeSegment(headerSeg), payload: decodeSegment(payloadSeg) };
        },
        catch: (cause) => fail("malformed", "Malformed Access token", cause),
      });
      if (header["alg"] !== "RS256") {
        return yield* fail(
          "algorithm",
          `Unsupported Access token algorithm: ${Formatter.format(header["alg"])}`,
        );
      }
      const kid = header["kid"];
      if (!P.isString(kid) || kid === "") {
        return yield* fail("key", "Access token has no kid");
      }
      const jwk = yield* keyFor(kid);
      const verified = yield* verifiesWithJwk(token, jwk, "RS256").pipe(
        Effect.mapError((cause) =>
          fail("signature", "Access token signature verification failed", cause),
        ),
      );
      if (!verified) return yield* fail("signature", "Invalid Access token signature");

      const failure = claimFailure(
        payload,
        issuer,
        audiences,
        yield* Clock.currentTimeMillis,
        toleranceMs,
      );
      if (failure !== undefined) return yield* failure;

      // `claimFailure` has checked that `exp` is a number.
      const exp = payload["exp"];
      const identity = P.isNumber(exp) ? identityOf(payload, exp) : undefined;
      if (identity === undefined) {
        return yield* fail("claims", "Access token names neither a user nor a service token");
      }
      return identity;
    });

    const tokenIn = (source: CredentialSource): string | undefined =>
      Option.getOrUndefined(Arr.findFirst(Arr.map(sources, readSource(source)), nonEmpty))?.trim();

    return {
      verify,
      verifyRequest: (source) => {
        const token = tokenIn(source);
        return token === undefined ? Effect.succeedNone : Effect.asSome(verify(token));
      },
    };
  });

// ---------------------------------------------------------------------------
// Mapping to effect-auth users
// ---------------------------------------------------------------------------

/**
 * The effect-auth user an Access identity belongs to: the owner of a
 * **verified** email identifier equal to the identity's email (lower-cased).
 *
 * `Option.none()` for a service token, for an email no user holds, for an
 * address held only unverified (Access proves the address, but this function
 * never promotes or clears an account; a first-proof flow does that), and for
 * a user who is banned or SCIM-deactivated. Users are never created here.
 *
 * @since 0.6.0
 * @category users
 */
export const findUser = (
  identity: CloudflareAccessIdentity,
): Effect.Effect<Option.Option<Types.User>, AuthError, IdentifierStore | UserStore> =>
  Effect.gen(function* () {
    if (identity.kind !== "user" || identity.email === undefined) return Option.none();
    const identifiers = yield* IdentifierStore;
    const users = yield* UserStore;
    const identifier = yield* lookupIdentifier(
      identifiers,
      "email",
      identity.email.trim().toLowerCase(),
    );
    if (identifier === null || !identifier.verified) return Option.none();
    const user = yield* users.get(identifier.userId);
    if (user === null || !(yield* isInGoodStanding(user))) return Option.none();
    return Option.some(user);
  });

/**
 * The credential class an Access identity authenticates as: a service token
 * is `"machine"`, a person `"interactive"`.
 *
 * @since 0.6.0
 * @category users
 */
export const credentialClassOf = (identity: CloudflareAccessIdentity): CredentialClass =>
  identity.kind === "service-token" ? "machine" : "interactive";

/**
 * Provide `CurrentUser`, `CurrentPrincipal` and `CurrentCredential` for a user
 * {@link findUser} resolved from an Access identity, through
 * `SessionContext.userLayer`. Access issued no effect-auth session, so
 * `CurrentSession` and `MaybeCurrentSession` are not provided.
 *
 * @since 0.6.0
 * @category users
 */
export const userContextLayer = (
  identity: CloudflareAccessIdentity,
  user: Types.User,
): Layer.Layer<CurrentUser | CurrentPrincipal | CurrentCredential> =>
  userLayer(user, { credentialClass: credentialClassOf(identity) });
