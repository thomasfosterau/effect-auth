/**
 * Sessions over BetterAuth: the request lookup the SvelteKit `handle` and
 * `SessionResolution` take, and the core's `SessionService` over BetterAuth's
 * internal adapter.
 *
 * @since 0.1.0
 */
import { Clock, Context, Effect, Layer, Result } from "effect";
import * as Arr from "effect/Array";
import * as HashSet from "effect/HashSet";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import * as Auth from "@thomasfosterau/effect-auth";
import {
  adapterCall,
  columnsOf,
  type BetterAuthContext,
  BetterAuthInstance,
  type BetterAuthSession,
} from "./BetterAuth.ts";
import { requireGoodStanding, toSession, toUser } from "./Convert.ts";

/**
 * A lookup's answer: the session, if any, and BetterAuth's `Set-Cookie` lines
 * (a slid session expiry, a refreshed or cleared cache cookie) for the
 * response. Structurally the SvelteKit `handle`'s `SessionLookup`.
 *
 * @since 0.1.0
 * @category models
 */
export interface SessionLookup {
  readonly session: Option.Option<Auth.SessionWithUser>;
  readonly setCookie: ReadonlyArray<string>;
}

/**
 * The credential naming of BetterAuth's session cookie, for
 * `SessionResolution.detectCredential` and the SvelteKit `handle`'s `cookies`
 * option. The name is read from the instance (`better-auth.session_token`, or
 * `__Secure-…` when the cookie is secure, under `advanced.cookiePrefix`),
 * never hard-coded, with `hostPrefix: false` since BetterAuth sets none.
 *
 * Only the session cookie is detected: BetterAuth's cache cookie is
 * `…session_data`, which the core's `${name}_data` cannot name, and it is
 * never sent without the session cookie, so the cookieless skip stays correct.
 *
 * @since 0.1.0
 * @category constructors
 */
export const credentialConfig = (
  context: BetterAuthContext,
): Auth.SessionResolution.CredentialConfig => {
  const { name, attributes } = context.authCookies.sessionToken;
  return {
    name,
    secure: attributes.secure === true,
    ...(attributes.path !== undefined && { path: attributes.path }),
    hostPrefix: false,
  };
};

/**
 * The session a request carries, through BetterAuth's own `getSession`.
 *
 * @since 0.1.0
 * @category services
 */
export class BetterAuthSessions extends Context.Service<
  BetterAuthSessions,
  {
    /**
     * Look the request's session up with `auth.api.getSession`, which checks
     * the cookie's signature, honours the cookie cache and answers `null` for
     * anonymous or expired. A banned user reads as anonymous. A bearer caller
     * (BetterAuth's `bearer()` plugin) is marked `credentialClass: "machine"`.
     * Any failure of the call is a fault (`AuthError`), never anonymous.
     */
    readonly lookup: (request: Request) => Effect.Effect<SessionLookup, Auth.AuthError>;
    /** The cookie naming for `SessionResolution` and the SvelteKit `handle`. */
    readonly credentialConfig: Auth.SessionResolution.CredentialConfig;
  }
>()("@effect-auth/better-auth/BetterAuthSessions") {
  static readonly layer: Layer.Layer<BetterAuthSessions, never, BetterAuthInstance> = Layer.effect(
    BetterAuthSessions,
    Effect.gen(function* () {
      const { api, context } = yield* BetterAuthInstance;
      const config = credentialConfig(context);
      return {
        credentialConfig: config,
        lookup: Effect.fn("BetterAuthSessions.lookup")(function* (request: Request) {
          const { headers, response } = yield* adapterCall("getSession", () =>
            api.getSession({ headers: request.headers, returnHeaders: true }),
          );
          const setCookie = headers.getSetCookie();
          if (response === null) return { session: Option.none(), setCookie };
          const user = toUser(response.user);
          const standing = yield* Effect.result(requireGoodStanding(user));
          if (Result.isFailure(standing)) return { session: Option.none(), setCookie };
          const presence = Auth.SessionResolution.detectCredential(
            Auth.SessionResolution.fromRequest(request),
            config,
          );
          const session = toSession(response.session);
          const machine = presence.hasBearer && !presence.hasSessionCookie;
          return {
            session: Option.some({
              user,
              session: machine
                ? {
                    ...session,
                    attributes: {
                      ...session.attributes,
                      [Auth.CREDENTIAL_CLASS_ATTRIBUTE]: "machine",
                    },
                  }
                : session,
            }),
            setCookie,
          };
        }),
      };
    }),
  );
}

/**
 * Session columns `setSessionAttributes` refuses: the record's own fields,
 * the client's address and agent (BetterAuth records them) and the admin
 * plugin's impersonation marker.
 */
const PROTECTED_SESSION_COLUMNS = HashSet.make(
  "id",
  "token",
  "userId",
  "expiresAt",
  "createdAt",
  "updatedAt",
  "ipAddress",
  "userAgent",
  "impersonatedBy",
);

const unsupported = (method: string, reason: string) =>
  new Auth.AuthError({
    message: `SessionService.${method} is not supported over BetterAuth: ${reason}`,
  });

/**
 * The core's `SessionService` over BetterAuth's internal adapter, for code
 * that holds a raw token or a user id rather than a request. Sessions are
 * named by BetterAuth's stored `session.id`; the raw token is what
 * `validateSession` and `invalidateSession` take.
 *
 * - `createSession` fails with `AuthError`: BetterAuth's routes issue sessions
 *   and their signed cookie.
 * - No effect-auth hook runs (BetterAuth's `databaseHooks` still do).
 * - `setSessionAttributes` writes only columns BetterAuth declares
 *   (`activeOrganizationId`, `activeTeamId`, `additionalFields`); any other
 *   key fails with `AuthError`.
 *
 * @since 0.1.0
 * @category layers
 */
export const sessionServiceLayer: Layer.Layer<Auth.SessionService, never, BetterAuthInstance> =
  Layer.effect(
    Auth.SessionService,
    Effect.gen(function* () {
      const { context } = yield* BetterAuthInstance;
      const internal = context.internalAdapter;
      const writable = HashSet.fromIterable(
        Arr.filter(
          columnsOf(context, "session"),
          (key) => !HashSet.has(PROTECTED_SESSION_COLUMNS, key),
        ),
      );

      const liveSessions = Effect.fn("SessionService.listSessions")(function* (userId: string) {
        const sessions = yield* adapterCall("listSessions", () => internal.listSessions(userId));
        const now = yield* Clock.currentTimeMillis;
        return Arr.filter(sessions, (session) => session.expiresAt.getTime() > now);
      });

      return {
        createSession: () =>
          Effect.fail(unsupported("createSession", "BetterAuth's routes issue sessions")),

        validateSession: Effect.fn("SessionService.validateSession")(function* (token: string) {
          const found = yield* adapterCall("findSession", () => internal.findSession(token));
          if (found === null) {
            return yield* new Auth.SessionNotFoundError({
              message: "Session not found",
              sessionId: "",
            });
          }
          const session = toSession(found.session);
          if (session.expiresAt.getTime() <= (yield* Clock.currentTimeMillis)) {
            return yield* new Auth.SessionExpiredError({
              message: "Session expired",
              sessionId: session.id,
            });
          }
          const user = toUser(found.user);
          yield* requireGoodStanding(user);
          return { session, user };
        }),

        invalidateSession: (token: string) =>
          Effect.asVoid(adapterCall("deleteSession", () => internal.deleteSession(token))),

        invalidateUserSessions: (userId: string) =>
          Effect.asVoid(
            adapterCall("deleteUserSessions", () => internal.deleteUserSessions(userId)),
          ),

        listSessions: (userId: string) => Effect.map(liveSessions(userId), Arr.map(toSession)),

        revokeSessionById: Effect.fn("SessionService.revokeSessionById")(function* (
          userId: string,
          storedSessionId: string,
        ) {
          const sessions = yield* adapterCall("listSessions", () => internal.listSessions(userId));
          const match = Arr.findFirst(sessions, (session) => session.id === storedSessionId);
          if (Option.isNone(match)) return false;
          yield* adapterCall("deleteSession", () => internal.deleteSession(match.value.token));
          return true;
        }),

        revokeOtherSessions: Effect.fn("SessionService.revokeOtherSessions")(function* (
          userId: string,
          keepSessionId: string,
        ) {
          const sessions = yield* adapterCall("listSessions", () => internal.listSessions(userId));
          const others = Arr.filterMap(sessions, (session) =>
            session.id === keepSessionId ? Result.failVoid : Result.succeed(session.token),
          );
          if (Arr.isArrayNonEmpty(others)) {
            yield* adapterCall("deleteSessions", () => internal.deleteSessions(others));
          }
        }),

        setSessionAttributes: Effect.fn("SessionService.setSessionAttributes")(function* (
          storedSessionId: string,
          attributes: Auth.Attributes,
        ) {
          const refused = Arr.findFirst(R.keys(attributes), (key) => !HashSet.has(writable, key));
          if (Option.isSome(refused)) {
            return yield* new Auth.AuthError({
              message: `"${refused.value}" is not a session column BetterAuth declares, or is one it owns`,
            });
          }
          const stored = yield* adapterCall("findOne(session)", () =>
            context.adapter.findOne<BetterAuthSession>({
              model: "session",
              where: [{ field: "id", value: storedSessionId }],
            }),
          );
          if (stored === null) {
            return yield* new Auth.SessionNotFoundError({
              message: "Session not found",
              sessionId: storedSessionId,
            });
          }
          const updated = yield* adapterCall("updateSession", () =>
            internal.updateSession(stored.token, { ...attributes }),
          );
          if (updated === null) {
            return yield* new Auth.SessionNotFoundError({
              message: "Session not found",
              sessionId: storedSessionId,
            });
          }
          return toSession(updated);
        }),
      };
    }),
  );
