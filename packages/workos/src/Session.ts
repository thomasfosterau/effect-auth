/**
 * Sessions over WorkOS: a stateless sealed cookie. It holds the refresh token,
 * the claims of the last access token (verified against the environment's key
 * set when it arrived), the user and the sign-in's attributes, sealed with
 * AES-256-GCM. A request whose access token is still fresh costs no API call;
 * an expired one is refreshed once (`grant_type=refresh_token`), and the new
 * cookie goes back through `validateSession`'s `reissued`.
 *
 * @since 0.1.0
 */
import { Clock, Context, Effect, Layer, Redacted } from "effect";
import * as Arr from "effect/Array";
import * as MutableHashMap from "effect/MutableHashMap";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import type { HttpClient } from "effect/http";
import { KeyValueStore } from "effect/persistence";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Seal from "./Seal.ts";
import {
  AuthenticationResponse,
  Impersonator,
  instant,
  List,
  WireSession,
  WireUser,
} from "./Schemas.ts";
import { toUser } from "./Users.ts";
import { path, unsupported, WorkOSClient, toAuthError, type WorkOSError } from "./WorkOS.ts";

/**
 * The attribute keys this package writes on a `Session`, under `workos.`.
 *
 * @since 0.1.0
 * @category constants
 */
export const SessionAttribute = {
  organizationId: "workos.organizationId",
  role: "workos.role",
  roles: "workos.roles",
  permissions: "workos.permissions",
  authenticationMethod: "workos.authenticationMethod",
  impersonator: "workos.impersonator",
} as const;

/**
 * The verified claims of a WorkOS user access token this package reads.
 *
 * @since 0.1.0
 * @category schemas
 */
export const AccessTokenClaims = Schema.Struct({
  sub: Schema.String,
  sid: Schema.String,
  iss: Schema.String,
  exp: Schema.Number,
  iat: Schema.Number,
  auth_time: Schema.optional(Schema.Number),
  org_id: Schema.optional(Schema.String),
  role: Schema.optional(Schema.String),
  roles: Schema.optional(Schema.Array(Schema.String)),
  permissions: Schema.optional(Schema.Array(Schema.String)),
  sub_profile: Schema.optional(Schema.String),
  sub_type: Schema.optional(Schema.String),
});

/** @since 0.1.0 */
export type AccessTokenClaims = typeof AccessTokenClaims.Type;

/** What the cookie seals. */
const Sealed = Schema.Struct({
  v: Schema.Literal(1),
  refreshToken: Schema.String,
  claims: AccessTokenClaims,
  user: WireUser,
  startedAt: Schema.Number,
  authenticationMethod: Schema.optional(Schema.String),
  impersonator: Schema.optional(Impersonator),
  attributes: Auth.Attributes,
});
type Sealed = typeof Sealed.Type;

const SealedJson = Schema.fromJsonString(Sealed);
const encodeSealed = Schema.encodeSync(SealedJson);
const decodeSealed = Schema.decodeUnknownOption(SealedJson);
const decodeClaims = Schema.decodeUnknownEffect(AccessTokenClaims);

/**
 * Sessions WorkOS has revoked, so a cookie whose access token is still fresh
 * stops working before it expires. The `session.revoked` webhook and sign-out
 * write it; `validateSession` reads it. Without it a revoked session lasts until
 * its access token expires (minutes).
 *
 * @since 0.1.0
 * @category services
 */
export class RevokedSessions extends Context.Service<
  RevokedSessions,
  {
    /** Record `sessionId` as revoked for `ttlMs`, at least the access-token lifetime. */
    readonly revoke: (sessionId: string, ttlMs: number) => Effect.Effect<void, Auth.AuthError>;
    readonly isRevoked: (sessionId: string) => Effect.Effect<boolean, Auth.AuthError>;
  }
>()("@effect-auth/workos/RevokedSessions") {
  /** Over the `KeyValueStore` in context, under `workos-revoked:`; entries expire by their stored deadline. */
  static readonly layerKeyValueStore: Layer.Layer<
    RevokedSessions,
    never,
    KeyValueStore.KeyValueStore
  > = Layer.effect(
    RevokedSessions,
    Effect.gen(function* () {
      const store = KeyValueStore.prefix(yield* KeyValueStore.KeyValueStore, "workos-revoked:");
      const fault = (cause: unknown) =>
        new Auth.AuthError({ message: "The revoked-session store failed", cause });
      return {
        revoke: (sessionId, ttlMs) =>
          Effect.flatMap(Clock.currentTimeMillis, (now) =>
            store.set(sessionId, `${now + ttlMs}`),
          ).pipe(Effect.mapError(fault)),
        isRevoked: Effect.fn("WorkOS.RevokedSessions.isRevoked")(function* (sessionId: string) {
          const until = yield* store.get(sessionId);
          if (until === undefined) return false;
          const now = yield* Clock.currentTimeMillis;
          if (Number(until) > now) return true;
          yield* store.remove(sessionId);
          return false;
        }, Effect.mapError(fault)),
      };
    }),
  );

  /** In memory, per process: for one instance, or tests. */
  static readonly layerMemory: Layer.Layer<RevokedSessions> =
    RevokedSessions.layerKeyValueStore.pipe(Layer.provide(KeyValueStore.layerMemory));
}

/** How long a revocation is remembered: past any access token's lifetime. */
const REVOCATION_TTL_MS = 60 * 60 * 1000;

/** How long one refresh's answer is shared with concurrent requests holding the same refresh token. */
const REFRESH_SHARE_MS = 30_000;

/**
 * A session just issued from a WorkOS authentication, with its user.
 *
 * @since 0.1.0
 * @category models
 */
export interface WorkOSIssued extends Auth.IssuedSession {
  readonly user: Auth.User;
}

/**
 * The sealed-cookie session machinery the flows and the `SessionService`
 * share.
 *
 * @since 0.1.0
 * @category services
 */
export class WorkOSSessions extends Context.Service<
  WorkOSSessions,
  {
    /**
     * Turn a WorkOS authentication into a session: verify its access token,
     * run `beforeCreateSession` / `afterCreateSession`, and seal the cookie.
     */
    readonly issue: (
      auth: AuthenticationResponse,
      attributes?: Auth.Attributes,
    ) => Effect.Effect<WorkOSIssued, Auth.AuthError | Auth.HookError>;
    /**
     * Switch the session a cookie names to another organization the user
     * belongs to (a refresh with `organization_id`), answering the new cookie.
     */
    readonly switchOrganization: (
      token: string,
      organizationId: string,
    ) => Effect.Effect<
      WorkOSIssued,
      Auth.SessionNotFoundError | Auth.SessionExpiredError | Auth.AuthError | Auth.HookError
    >;
    /** The WorkOS session id (`sid`) a cookie names, when it opens. */
    readonly sessionIdOf: (token: string) => Effect.Effect<Option.Option<string>>;
    /**
     * The hosted AuthKit logout URL for a session: it ends the WorkOS session
     * and its AuthKit cookie, then sends the browser to `returnTo`.
     */
    readonly logoutUrl: (options: {
      readonly sessionId: string;
      readonly returnTo?: string;
    }) => string;
  }
>()("@effect-auth/workos/WorkOSSessions") {}

const sessionAttributes = (sealed: Sealed): Auth.Attributes => {
  const { claims } = sealed;
  return {
    ...sealed.attributes,
    ...(claims.org_id !== undefined && { [SessionAttribute.organizationId]: claims.org_id }),
    ...(claims.role !== undefined && { [SessionAttribute.role]: claims.role }),
    ...(claims.roles !== undefined && { [SessionAttribute.roles]: [...claims.roles] }),
    ...(claims.permissions !== undefined && {
      [SessionAttribute.permissions]: [...claims.permissions],
    }),
    ...(sealed.authenticationMethod !== undefined && {
      [SessionAttribute.authenticationMethod]: sealed.authenticationMethod,
    }),
    ...(sealed.impersonator !== undefined && {
      [SessionAttribute.impersonator]: {
        email: sealed.impersonator.email,
        reason: sealed.impersonator.reason ?? null,
      },
      // The core's impersonation flag, so lockout, Guard and the audit log
      // treat the session as someone else's, as they do the core's own.
      impersonatedBy: sealed.impersonator.email,
    }),
  };
};

const toSession = (sealed: Sealed, sessionMaxAge: number): Auth.Session => ({
  id: sealed.claims.sid,
  userId: sealed.claims.sub,
  createdAt: instant(sealed.startedAt),
  lastActivityAt: instant(sealed.claims.iat * 1000),
  expiresAt: instant(sealed.startedAt + sessionMaxAge),
  attributes: sessionAttributes(sealed),
});

/** Whether a refusal means the session is over, rather than a fault to retry. */
const sessionOver = (error: WorkOSError): boolean =>
  error.status >= 400 && error.status < 500 && error.status !== 429;

/** The WorkOS session machinery and the `SessionService` over it. */
export const make = Effect.fn("WorkOS.Session.make")(function* () {
  const workos = yield* WorkOSClient;
  const { config } = workos;
  const hooks = yield* Auth.Hooks;
  const sealer = yield* Seal.make(config.cookiePasswords).pipe(
    Effect.provide(Auth.PlatformCrypto.layer),
    Effect.orDie,
  );
  const verifier = yield* Auth.remoteJwksVerifier({
    jwksUri: `${config.baseUrl}${path`/sso/jwks/${config.clientId}`}`,
    issuer: config.issuer,
    // WorkOS access tokens carry no `typ`; the issuer, signature, `exp` and the
    // user-token claims below are what tell them apart.
    tokenType: null,
    clockSkewLeeway: config.clockSkewLeeway,
  }).pipe(Effect.provide(Auth.PlatformCrypto.layer), Effect.orDie);
  const revoked = Option.getOrUndefined(yield* Effect.serviceOption(RevokedSessions));

  /** Verify an access token as a WorkOS *user* access token, as the WorkOS SDK does. */
  const verifyAccessToken = (token: string) =>
    verifier.verify(token).pipe(
      Effect.flatMap(decodeClaims),
      Effect.filterOrFail(
        (claims) =>
          (claims.sub_profile === undefined || claims.sub_profile === "user") &&
          claims.sub_type === undefined,
        () => new Auth.AuthError({ message: "Not a WorkOS user access token" }),
      ),
      Effect.mapError((cause) =>
        P.isTagged(cause, "AuthError")
          ? cause
          : new Auth.AuthError({ message: "WorkOS access token did not verify", cause }),
      ),
    );

  const seal = (sealed: Sealed) => sealer.seal(encodeSealed(sealed));
  const open = (token: string) => Effect.map(sealer.open(token), Option.flatMap(decodeSealed));

  const authenticate = (body: Readonly<Record<string, string>>) =>
    workos.request({
      method: "POST",
      path: "/user_management/authenticate",
      route: "/user_management/authenticate",
      body: {
        client_id: config.clientId,
        client_secret: Redacted.value(config.apiKey),
        ...body,
      },
      schema: AuthenticationResponse,
    });

  const refresh = (refreshToken: string, organizationId: string | undefined) =>
    authenticate({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      ...(organizationId !== undefined && { organization_id: organizationId }),
    });

  // Concurrent requests holding one cookie would each spend its single-use
  // refresh token, and all but the first would fail. Share one refresh per
  // token for a short window, per process.
  const refreshes = MutableHashMap.empty<
    string,
    { readonly at: number; readonly answer: Effect.Effect<AuthenticationResponse, WorkOSError> }
  >();
  const refreshShared = (refreshToken: string, organizationId: string | undefined) =>
    Effect.gen(function* () {
      const now = yield* Clock.currentTimeMillis;
      MutableHashMap.forEach(refreshes, (entry, key) => {
        if (now - entry.at > REFRESH_SHARE_MS) MutableHashMap.remove(refreshes, key);
      });
      const key = `${organizationId ?? ""}\u0000${refreshToken}`;
      const shared = MutableHashMap.get(refreshes, key);
      if (Option.isSome(shared)) return yield* shared.value.answer;
      const answer = yield* Effect.cached(refresh(refreshToken, organizationId));
      MutableHashMap.set(refreshes, key, { at: now, answer });
      return yield* answer;
    });

  const sealedFrom = (
    auth: AuthenticationResponse,
    claims: AccessTokenClaims,
    previous: Pick<Sealed, "startedAt" | "attributes"> | undefined,
    now: number,
  ): Sealed => ({
    v: 1,
    refreshToken: auth.refresh_token,
    claims,
    user: auth.user,
    startedAt: previous?.startedAt ?? (claims.auth_time ?? Math.floor(now / 1000)) * 1000,
    attributes: previous?.attributes ?? {},
    ...(auth.authentication_method != null && {
      authenticationMethod: auth.authentication_method,
    }),
    ...(auth.impersonator != null && { impersonator: auth.impersonator }),
  });

  const issue = (auth: AuthenticationResponse, attributes: Auth.Attributes = {}) =>
    Effect.gen(function* () {
      const claims = yield* verifyAccessToken(auth.access_token);
      if (claims.sub !== auth.user.id) {
        return yield* new Auth.AuthError({ message: "WorkOS access token names another user" });
      }
      const args = yield* hooks.beforeCreateSession({ userId: auth.user.id, attributes });
      const now = yield* Clock.currentTimeMillis;
      const base = sealedFrom(auth, claims, undefined, now);
      const sealed: Sealed = { ...base, attributes: args.attributes ?? {} };
      const token = yield* seal(sealed);
      const session = yield* hooks.afterCreateSession(toSession(sealed, config.sessionMaxAge));
      return { session, token, user: toUser(sealed.user) };
    });

  /** Refresh a sealed session into a new cookie. */
  const refreshSealed = (sealed: Sealed, organizationId: string | undefined) =>
    Effect.gen(function* () {
      const auth = yield* refreshShared(sealed.refreshToken, organizationId).pipe(
        Effect.catchTag(
          "WorkOSError",
          (error): Effect.Effect<never, Auth.SessionExpiredError | Auth.AuthError> =>
            sessionOver(error)
              ? Effect.fail(
                  new Auth.SessionExpiredError({
                    message: "The WorkOS session has ended",
                    sessionId: sealed.claims.sid,
                  }),
                )
              : Effect.fail(toAuthError(error)),
        ),
      );
      const claims = yield* verifyAccessToken(auth.access_token);
      if (claims.sub !== sealed.claims.sub) {
        return yield* new Auth.AuthError({ message: "WorkOS refreshed another user's session" });
      }
      const now = yield* Clock.currentTimeMillis;
      const next = sealedFrom(auth, claims, sealed, now);
      return { sealed: next, token: yield* seal(next) };
    });

  const notFound = (sessionId = "") =>
    new Auth.SessionNotFoundError({ message: "Session not found", sessionId });

  const revokeAtWorkOS = (sessionId: string) =>
    workos
      .request({
        method: "POST",
        path: "/user_management/sessions/revoke",
        route: "/user_management/sessions/revoke",
        body: { session_id: sessionId },
      })
      .pipe(
        // An unknown or already-ended session is revoked as far as anyone can tell.
        Effect.catchTag("WorkOSError", (error) =>
          error.status === 404 ? Effect.void : Effect.fail(toAuthError(error)),
        ),
        Effect.andThen(
          revoked === undefined ? Effect.void : revoked.revoke(sessionId, REVOCATION_TTL_MS),
        ),
      );

  const listWorkOSSessions = (userId: string) =>
    workos
      .request({
        method: "GET",
        path: path`/user_management/users/${userId}/sessions`,
        route: "/user_management/users/{id}/sessions",
        query: { limit: "100" },
        schema: List(WireSession),
      })
      .pipe(
        Effect.map((page) => page.data.filter((s) => s.status === "active")),
        Effect.mapError(toAuthError),
      );

  const fromWireSession = (s: WireSession): Auth.Session => ({
    id: s.id,
    userId: s.user_id,
    createdAt: instant(s.created_at),
    lastActivityAt: instant(s.updated_at),
    expiresAt: instant(s.expires_at),
    attributes: {
      ...(s.organization_id != null && { [SessionAttribute.organizationId]: s.organization_id }),
      ...(s.auth_method != null && { [SessionAttribute.authenticationMethod]: s.auth_method }),
      ...(s.impersonator != null && {
        [SessionAttribute.impersonator]: {
          email: s.impersonator.email,
          reason: s.impersonator.reason ?? null,
        },
        impersonatedBy: s.impersonator.email,
      }),
      ...(s.ip_address != null && { ipAddress: s.ip_address }),
      ...(s.user_agent != null && { userAgent: s.user_agent }),
    },
  });

  const validateSession = Effect.fn("WorkOS.validateSession")(function* (token: string) {
    const opened = yield* open(token);
    if (Option.isNone(opened)) return yield* notFound();
    const sealed = opened.value;
    const sessionId = sealed.claims.sid;
    yield* hooks.beforeValidateSession({ sessionId });
    if (revoked !== undefined && (yield* revoked.isRevoked(sessionId))) {
      return yield* notFound(sessionId);
    }
    const now = yield* Clock.currentTimeMillis;
    if (now >= sealed.startedAt + config.sessionMaxAge) {
      return yield* new Auth.SessionExpiredError({
        message: "Session exceeded maximum lifetime",
        sessionId,
      });
    }
    const fresh = sealed.claims.exp * 1000 - config.clockSkewLeeway > now;
    const current = fresh
      ? { sealed, token: undefined }
      : yield* refreshSealed(sealed, sealed.claims.org_id);
    const session = toSession(current.sealed, config.sessionMaxAge);
    const validated = yield* hooks.afterValidateSession({
      session,
      user: toUser(current.sealed.user),
    });
    return current.token === undefined
      ? validated
      : { ...validated, reissued: { session: validated.session, token: current.token } };
  });

  const sessions = WorkOSSessions.of({
    issue,
    switchOrganization: (token, organizationId) =>
      Effect.gen(function* () {
        const opened = yield* open(token);
        if (Option.isNone(opened)) return yield* notFound();
        const next = yield* refreshSealed(opened.value, organizationId);
        const session = yield* hooks.afterCreateSession(
          toSession(next.sealed, config.sessionMaxAge),
        );
        return { session, token: next.token, user: toUser(next.sealed.user) };
      }),
    sessionIdOf: (token) =>
      Effect.map(
        open(token),
        Option.map((s) => s.claims.sid),
      ),
    logoutUrl: ({ sessionId, returnTo }) => {
      const url = new URL("/user_management/sessions/logout", config.baseUrl);
      url.searchParams.set("session_id", sessionId);
      if (returnTo !== undefined) url.searchParams.set("return_to", returnTo);
      return url.toString();
    },
  });

  const service = Auth.SessionService.of({
    createSession: () =>
      Effect.fail(
        unsupported("SessionService.createSession (a WorkOS session comes from authenticating)"),
      ),
    validateSession,
    invalidateSession: Effect.fn("WorkOS.invalidateSession")(function* (token: string) {
      const opened = yield* open(token);
      // A cookie that does not open names no session to end.
      if (Option.isNone(opened)) return;
      const sessionId = opened.value.claims.sid;
      yield* hooks.beforeSignOut({ sessionId });
      yield* revokeAtWorkOS(sessionId);
      yield* hooks.afterSignOut({ sessionId });
    }),
    invalidateUserSessions: (userId) =>
      Effect.flatMap(listWorkOSSessions(userId), (list) =>
        Effect.forEach(list, (s) => revokeAtWorkOS(s.id), { concurrency: 1, discard: true }),
      ),
    listSessions: (userId) => Effect.map(listWorkOSSessions(userId), Arr.map(fromWireSession)),
    revokeSessionById: (userId, sessionId) =>
      Effect.gen(function* () {
        const list = yield* listWorkOSSessions(userId);
        if (!list.some((s) => s.id === sessionId)) return false;
        yield* revokeAtWorkOS(sessionId);
        return true;
      }),
    revokeOtherSessions: (userId, keepSessionId) =>
      Effect.flatMap(listWorkOSSessions(userId), (list) =>
        Effect.forEach(
          list.filter((s) => s.id !== keepSessionId),
          (s) => revokeAtWorkOS(s.id),
          { concurrency: 1, discard: true },
        ),
      ),
    setSessionAttributes: () =>
      Effect.fail(
        unsupported(
          "SessionService.setSessionAttributes (the cookie is the record; use WorkOSSessions.switchOrganization)",
        ),
      ),
  });

  return { sessions, service, authenticate, revokeAtWorkOS };
});

/** The pieces `make` builds, for the flows of this package. */
export class WorkOSAuthenticate extends Context.Service<
  WorkOSAuthenticate,
  {
    /** `POST /user_management/authenticate` with the client credentials added. */
    readonly authenticate: (
      body: Readonly<Record<string, string>>,
    ) => Effect.Effect<AuthenticationResponse, WorkOSError>;
    /** Revoke a WorkOS session (and record it in `RevokedSessions`, when present). */
    readonly revoke: (sessionId: string) => Effect.Effect<void, Auth.AuthError>;
  }
>()("@effect-auth/workos/WorkOSAuthenticate") {}

/**
 * `SessionService`, {@link WorkOSSessions} and {@link WorkOSAuthenticate} over
 * the {@link WorkOSClient}. Reads `RevokedSessions` when it is provided.
 *
 * @since 0.1.0
 * @category layers
 */
export const layer: Layer.Layer<
  Auth.SessionService | WorkOSSessions | WorkOSAuthenticate,
  never,
  WorkOSClient | Auth.Hooks | HttpClient.HttpClient
> = Layer.effectContext(
  Effect.map(make(), ({ sessions, service, authenticate, revokeAtWorkOS }) =>
    Context.make(Auth.SessionService, service).pipe(
      Context.add(WorkOSSessions, sessions),
      Context.add(WorkOSAuthenticate, { authenticate, revoke: revokeAtWorkOS }),
    ),
  ),
);
