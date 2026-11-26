/**
 * An in-memory WorkOS User Management API for the suites: the endpoints this
 * package calls, RS256 access tokens signed with a test key and its JWKS, and
 * single-use refresh tokens. Its wire shapes follow the WorkOS Node SDK's
 * (de)serializers, which is what "the published package's source" means for
 * the details the suites pin.
 */
import { Clock, Data, DateTime, Effect, Layer, Redacted } from "effect";
import * as Arr from "effect/Array";
import * as MutableHashMap from "effect/MutableHashMap";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import { HttpClient, HttpClientResponse } from "effect/http";
import { Base64Url } from "effect/encoding";
import type { WorkOSConfig } from "./WorkOS.ts";
import type { WireSession, WireUser } from "./Schemas.ts";

export const BASE_URL = "https://workos.test";
export const CLIENT_ID = "client_test";
export const API_KEY = "sk_test_secret";
export const ISSUER = `${BASE_URL}/user_management/${CLIENT_ID}`;
const COOKIE_PASSWORD = "a-cookie-password-of-at-least-32-bytes!";

export const testConfig = (overrides: Partial<WorkOSConfig> = {}): WorkOSConfig => ({
  apiKey: Redacted.make(API_KEY),
  clientId: CLIENT_ID,
  cookiePassword: Redacted.make(COOKIE_PASSWORD),
  baseUrl: BASE_URL,
  redirectUri: "https://app.test/callback",
  ...overrides,
});

interface FakeUser {
  wire: WireUser;
  password: string | undefined;
}

interface FakeSession {
  readonly id: string;
  readonly userId: string;
  organizationId: string | undefined;
  status: "active" | "inactive";
  readonly authMethod: string;
  readonly impersonator: { readonly email: string; readonly reason: string | null } | undefined;
  readonly createdAt: number;
}

export interface FakeOptions {
  /** Answer `email_verification_required` to a password grant for an unverified user. */
  readonly requireEmailVerification?: boolean;
  /** Access-token lifetime in seconds (default 300). */
  readonly accessTokenTtl?: number;
  /** Roles and permissions put in every access token. */
  readonly role?: string;
  readonly roles?: ReadonlyArray<string>;
  readonly permissions?: ReadonlyArray<string>;
}

/** Every request body field the package sends, all optional. */
const Body = Schema.Struct({
  client_id: Schema.optional(Schema.String),
  client_secret: Schema.optional(Schema.String),
  grant_type: Schema.optional(Schema.String),
  email: Schema.optional(Schema.String),
  password: Schema.optional(Schema.String),
  refresh_token: Schema.optional(Schema.String),
  organization_id: Schema.optional(Schema.String),
  code: Schema.optional(Schema.String),
  code_verifier: Schema.optional(Schema.String),
  first_name: Schema.optional(Schema.String),
  last_name: Schema.optional(Schema.String),
  email_verified: Schema.optional(Schema.Boolean),
  metadata: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  session_id: Schema.optional(Schema.String),
  token: Schema.optional(Schema.String),
  new_password: Schema.optional(Schema.String),
});
type Body = typeof Body.Type;
const decodeBody = Schema.decodeUnknownOption(Schema.fromJsonString(Body));

interface RecordedCall {
  readonly method: string;
  readonly path: string;
  readonly body: Body | undefined;
  readonly authorization: string | undefined;
}

const encoder = new TextEncoder();
const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));
const b64 = (value: Schema.Json) => Base64Url.encode(encoder.encode(encodeJson(value)));
const iso = (ms: number) => DateTime.formatIso(DateTime.makeUnsafe(ms));
class SubtleCryptoError extends Data.TaggedError("SubtleCryptoError")<{
  readonly cause: unknown;
}> {}
const subtle = <A>(run: () => Promise<A>) =>
  Effect.tryPromise({ try: run, catch: (cause) => new SubtleCryptoError({ cause }) }).pipe(
    Effect.orDie,
  );

/** An answer: its body is any JSON-serializable value (wire shapes included). */
type Answer = { readonly status: number; readonly body: object | undefined };
const ok = (body: object): Answer => ({ status: 200, body });
const created = (body: object): Answer => ({ status: 201, body });
const fail = (
  status: number,
  code: string,
  extra: Readonly<Record<string, string>> = {},
): Answer => ({
  status,
  body: { code, message: code, ...extra },
});
const page = (data: ReadonlyArray<object>): Answer =>
  ok({ data: [...data], list_metadata: { before: null, after: null } });

/** The fake. Build it once per test: its state is its own. */
export const make = Effect.fn("FakeWorkOS.make")(function* (options: FakeOptions = {}) {
  const keys = yield* subtle(() =>
    crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    ),
  );
  const publicJwk = yield* subtle(() => crypto.subtle.exportKey("jwk", keys.publicKey));
  const jwks = {
    keys: [
      {
        kty: publicJwk.kty ?? "RSA",
        n: publicJwk.n ?? "",
        e: publicJwk.e ?? "",
        kid: "fake-1",
        alg: "RS256",
        use: "sig",
      },
    ],
  };

  const users = MutableHashMap.empty<string, FakeUser>();
  const sessions = MutableHashMap.empty<string, FakeSession>();
  const refreshTokens = MutableHashMap.empty<string, string>();
  const magicCodes = MutableHashMap.empty<string, string>();
  const verificationCodes = MutableHashMap.empty<string, string>();
  const resetTokens = MutableHashMap.empty<string, string>();
  const authorizationCodes = MutableHashMap.empty<string, { userId: string; challenge: string }>();
  const calls: Array<RecordedCall> = [];
  let counter = 0;
  let impersonateNext: { email: string; reason: string | null } | undefined;
  const nextId = (prefix: string) => {
    counter += 1;
    return `${prefix}_${counter.toString().padStart(6, "0")}`;
  };
  /** Take `key`'s value out of `map`: a single-use read. */
  const take = <V>(map: MutableHashMap.MutableHashMap<string, V>, key: string | undefined) => {
    if (key === undefined) return Option.none<V>();
    const value = MutableHashMap.get(map, key);
    MutableHashMap.remove(map, key);
    return value;
  };

  const sign = (claims: Schema.JsonObject) =>
    Effect.gen(function* () {
      const input = `${b64({ alg: "RS256", kid: "fake-1" })}.${b64(claims)}`;
      const signature = yield* subtle(() =>
        crypto.subtle.sign("RSASSA-PKCS1-v1_5", keys.privateKey, encoder.encode(input)),
      );
      return `${input}.${Base64Url.encode(new Uint8Array(signature))}`;
    });

  const addUser = (
    email: string,
    password: string | undefined,
    fields: Partial<WireUser> = {},
  ): Effect.Effect<WireUser> =>
    Effect.map(Clock.currentTimeMillis, (now) => {
      const wire: WireUser = {
        id: nextId("user"),
        email,
        email_verified: true,
        first_name: null,
        last_name: null,
        name: null,
        profile_picture_url: null,
        last_sign_in_at: null,
        external_id: null,
        metadata: {},
        created_at: iso(now),
        updated_at: iso(now),
        ...fields,
      };
      MutableHashMap.set(users, wire.id, { wire, password });
      return wire;
    });

  const userByEmail = (email: string | undefined) =>
    Arr.findFirst(MutableHashMap.values(users), (u) => u.wire.email === email);

  const authenticated = (user: FakeUser, session: FakeSession) =>
    Effect.gen(function* () {
      const now = yield* Clock.currentTimeMillis;
      const iat = Math.floor(now / 1000);
      const accessToken = yield* sign({
        iss: ISSUER,
        sub: user.wire.id,
        sid: session.id,
        iat,
        exp: iat + (options.accessTokenTtl ?? 300),
        auth_time: Math.floor(session.createdAt / 1000),
        ...(session.organizationId !== undefined && { org_id: session.organizationId }),
        ...(options.role !== undefined && { role: options.role }),
        ...(options.roles !== undefined && { roles: [...options.roles] }),
        ...(options.permissions !== undefined && { permissions: [...options.permissions] }),
      });
      const refreshToken = nextId("refresh");
      MutableHashMap.set(refreshTokens, refreshToken, session.id);
      return ok({
        user: user.wire,
        organization_id: session.organizationId ?? null,
        access_token: accessToken,
        refresh_token: refreshToken,
        authentication_method: session.authMethod,
        impersonator: session.impersonator ?? null,
      });
    });

  const newSession = (user: FakeUser, authMethod: string) =>
    Effect.flatMap(Clock.currentTimeMillis, (now) => {
      const session: FakeSession = {
        id: nextId("session"),
        userId: user.wire.id,
        organizationId: undefined,
        status: "active",
        authMethod,
        impersonator: impersonateNext,
        createdAt: now,
      };
      impersonateNext = undefined;
      MutableHashMap.set(sessions, session.id, session);
      return authenticated(user, session);
    });

  const wireSession = (s: FakeSession): WireSession => ({
    id: s.id,
    user_id: s.userId,
    organization_id: s.organizationId ?? null,
    status: s.status,
    auth_method: s.authMethod,
    ip_address: null,
    user_agent: null,
    impersonator: s.impersonator ?? null,
    expires_at: iso(s.createdAt + 30 * 24 * 3600 * 1000),
    ended_at: null,
    created_at: iso(s.createdAt),
    updated_at: iso(s.createdAt),
  });

  const s256 = (verifier: string) =>
    Effect.map(
      subtle(() => crypto.subtle.digest("SHA-256", encoder.encode(verifier))),
      (digest) => Base64Url.encode(new Uint8Array(digest)),
    );

  const passwordGrant = (body: Body) => {
    const user = Option.getOrUndefined(userByEmail(body.email));
    if (user?.password === undefined || user.password !== body.password) {
      return Effect.succeed(fail(400, "invalid_credentials"));
    }
    if (options.requireEmailVerification === true && !user.wire.email_verified) {
      return Effect.succeed(
        fail(403, "email_verification_required", {
          pending_authentication_token: "pending_1",
          email: user.wire.email,
        }),
      );
    }
    return newSession(user, "Password");
  };

  const refreshGrant = (body: Body) => {
    const session = Option.flatMap(take(refreshTokens, body.refresh_token), (sid) =>
      MutableHashMap.get(sessions, sid),
    );
    const user = Option.flatMap(session, (s) => MutableHashMap.get(users, s.userId));
    if (Option.isNone(session) || Option.isNone(user) || session.value.status !== "active") {
      return Effect.succeed(fail(400, "invalid_grant"));
    }
    if (body.organization_id !== undefined) session.value.organizationId = body.organization_id;
    return authenticated(user.value, session.value);
  };

  const codeGrant = (body: Body) =>
    Effect.gen(function* () {
      const entry = take(authorizationCodes, body.code);
      const user = Option.flatMap(entry, (e) => MutableHashMap.get(users, e.userId));
      if (Option.isNone(entry) || Option.isNone(user)) return fail(400, "invalid_grant");
      if ((yield* s256(body.code_verifier ?? "")) !== entry.value.challenge) {
        return fail(400, "invalid_grant");
      }
      return yield* newSession(user.value, "OAuth");
    });

  const magicGrant = (body: Body) =>
    Effect.gen(function* () {
      const email = body.email ?? "";
      const code = MutableHashMap.get(magicCodes, email);
      if (Option.isNone(code) || code.value !== body.code) {
        return fail(400, "invalid_one_time_code");
      }
      MutableHashMap.remove(magicCodes, email);
      const existing = userByEmail(email);
      const user = Option.isSome(existing)
        ? existing.value
        : { wire: yield* addUser(email, undefined), password: undefined };
      return yield* newSession(user, "MagicAuth");
    });

  const authenticate = (body: Body): Effect.Effect<Answer> => {
    if (body.client_id !== CLIENT_ID || body.client_secret !== API_KEY) {
      return Effect.succeed(fail(401, "invalid_client"));
    }
    if (body.grant_type === "password") return passwordGrant(body);
    if (body.grant_type === "refresh_token") return refreshGrant(body);
    if (body.grant_type === "authorization_code") return codeGrant(body);
    if (body.grant_type === "urn:workos:oauth:grant-type:magic-auth:code") return magicGrant(body);
    return Effect.succeed(fail(400, "unsupported_grant_type"));
  };

  const createUser = (body: Body) =>
    Effect.gen(function* () {
      if (Option.isSome(userByEmail(body.email))) return fail(422, "email_not_available");
      const wire = yield* addUser(body.email ?? "", body.password, {
        email_verified: options.requireEmailVerification !== true,
        first_name: body.first_name ?? null,
        last_name: body.last_name ?? null,
      });
      if (options.requireEmailVerification === true) {
        MutableHashMap.set(verificationCodes, wire.id, "123456");
      }
      return created(wire);
    });

  const updateUser = (user: FakeUser, body: Body, now: number) => {
    if (body.password !== undefined) user.password = body.password;
    user.wire = {
      ...user.wire,
      ...(body.email !== undefined && { email: body.email }),
      ...(body.email_verified !== undefined && { email_verified: body.email_verified }),
      ...(body.first_name !== undefined && { first_name: body.first_name }),
      ...(body.last_name !== undefined && { last_name: body.last_name }),
      ...(body.metadata !== undefined && { metadata: body.metadata }),
      updated_at: iso(now),
    };
    return ok(user.wire);
  };

  const userRoute = (
    method: string,
    user: FakeUser,
    sub: string | undefined,
    action: string | undefined,
    body: Body,
    now: number,
  ): Answer => {
    if (sub === undefined && method === "GET") return ok(user.wire);
    if (sub === undefined && method === "PUT") return updateUser(user, body, now);
    if (sub === undefined && method === "DELETE") {
      MutableHashMap.remove(users, user.wire.id);
      return { status: 202, body: undefined };
    }
    if (sub === "sessions" && method === "GET") {
      return page(
        Arr.filter(MutableHashMap.values(sessions), (s) => s.userId === user.wire.id).map(
          wireSession,
        ),
      );
    }
    if (sub === "email_verification" && action === "send") {
      MutableHashMap.set(verificationCodes, user.wire.id, "123456");
      return ok({ user: user.wire });
    }
    if (sub === "email_verification" && action === "confirm") {
      const code = MutableHashMap.get(verificationCodes, user.wire.id);
      if (Option.isNone(code) || code.value !== body.code) return fail(400, "invalid_code");
      MutableHashMap.remove(verificationCodes, user.wire.id);
      user.wire = { ...user.wire, email_verified: true };
      return ok({ user: user.wire });
    }
    return fail(404, "not_found");
  };

  const magicAuth = (body: Body, now: number) =>
    Effect.gen(function* () {
      const email = body.email ?? "";
      const code = `${100000 + counter}`;
      counter += 1;
      MutableHashMap.set(magicCodes, email, code);
      const existing = userByEmail(email);
      const userId = Option.isSome(existing)
        ? existing.value.wire.id
        : (yield* addUser(email, undefined)).id;
      return created({
        id: nextId("magic_auth"),
        user_id: userId,
        email,
        expires_at: iso(now + 600_000),
        code,
        created_at: iso(now),
        updated_at: iso(now),
      });
    });

  const passwordReset = (body: Body, now: number): Answer => {
    const user = userByEmail(body.email);
    if (Option.isNone(user)) return fail(404, "entity_not_found");
    const token = nextId("reset_token");
    MutableHashMap.set(resetTokens, token, user.value.wire.id);
    return created({
      id: nextId("password_reset"),
      user_id: user.value.wire.id,
      email: user.value.wire.email,
      password_reset_token: token,
      password_reset_url: `https://reset.test/?token=${token}`,
      expires_at: iso(now + 600_000),
      created_at: iso(now),
    });
  };

  const confirmReset = (body: Body): Answer => {
    const user = Option.flatMap(take(resetTokens, body.token), (id) =>
      MutableHashMap.get(users, id),
    );
    if (Option.isNone(user)) return fail(400, "password_reset_token_invalid");
    user.value.password = body.new_password;
    return ok({ user: user.value.wire });
  };

  const listUsers = (query: URLSearchParams) => {
    const email = query.get("email");
    return page(
      Arr.filter(MutableHashMap.values(users), (u) => email === null || u.wire.email === email).map(
        (u) => u.wire,
      ),
    );
  };

  const revokeSession = (body: Body): Answer => {
    const session = Option.flatMap(Option.fromUndefinedOr(body.session_id), (sid) =>
      MutableHashMap.get(sessions, sid),
    );
    if (Option.isNone(session)) return fail(404, "entity_not_found");
    session.value.status = "inactive";
    return ok({});
  };

  const usersRoute = (
    method: string,
    [id, sub, action]: ReadonlyArray<string | undefined>,
    body: Body,
    query: URLSearchParams,
    now: number,
  ): Effect.Effect<Answer> => {
    if (id === undefined)
      return method === "POST" ? createUser(body) : Effect.succeed(listUsers(query));
    const user = MutableHashMap.get(users, id);
    return Option.isNone(user)
      ? Effect.succeed(fail(404, "entity_not_found"))
      : Effect.succeed(userRoute(method, user.value, sub, action, body, now));
  };

  const endpoints = (body: Body, now: number): Record<string, () => Effect.Effect<Answer>> => ({
    "POST authenticate": () => authenticate(body),
    "POST sessions/revoke": () => Effect.succeed(revokeSession(body)),
    "POST magic_auth": () => magicAuth(body, now),
    "POST password_reset": () => Effect.succeed(passwordReset(body, now)),
    "POST password_reset/confirm": () => Effect.succeed(confirmReset(body)),
  });

  const route = (
    method: string,
    path: string,
    body: Body,
    query: URLSearchParams,
  ): Effect.Effect<Answer> =>
    Effect.gen(function* () {
      const now = yield* Clock.currentTimeMillis;
      if (method === "GET" && path === `/sso/jwks/${CLIENT_ID}`) return ok(jwks);
      const [root, resource, ...rest] = path
        .split("/")
        .filter((part) => part !== "")
        .map(decodeURIComponent);
      if (root !== "user_management") return fail(404, "not_found");
      if (resource === "users") return yield* usersRoute(method, rest, body, query, now);
      const handler = R.get(
        endpoints(body, now),
        `${method} ${resource}${rest[0] === undefined ? "" : `/${rest[0]}`}`,
      );
      return Option.isNone(handler) ? fail(404, "not_found") : yield* handler.value();
    });

  const client = HttpClient.make((request, url) =>
    Effect.gen(function* () {
      const body =
        request.body._tag === "Uint8Array"
          ? Option.getOrUndefined(decodeBody(new TextDecoder().decode(request.body.body)))
          : undefined;
      calls.push({
        method: request.method,
        path: url.pathname,
        body,
        authorization: request.headers["authorization"],
      });
      const answer = yield* route(request.method, url.pathname, body ?? {}, url.searchParams);
      const headers = { "x-request-id": "req_fake" };
      return HttpClientResponse.fromWeb(
        request,
        answer.body === undefined
          ? new Response(null, { status: answer.status, headers })
          : Response.json(answer.body, { status: answer.status, headers }),
      );
    }),
  );

  const sessionStatus = (id: string | undefined) =>
    Option.getOrUndefined(
      Option.map(
        Option.flatMap(Option.fromUndefinedOr(id), (sid) => MutableHashMap.get(sessions, sid)),
        (s) => s.status,
      ),
    );

  return {
    layer: Layer.succeed(HttpClient.HttpClient, client),
    calls,
    addUser,
    sign,
    /** `active`, `inactive`, or `undefined` for a session WorkOS never made. */
    sessionStatus,
    activeSessionIds: () =>
      Arr.filter(MutableHashMap.values(sessions), (s) => s.status === "active").map((s) => s.id),
    /** The Magic Auth code WorkOS "emailed" to `email`. */
    magicCode: (email: string) => Option.getOrUndefined(MutableHashMap.get(magicCodes, email)),
    /** The password-reset tokens WorkOS "emailed", oldest first. */
    resetTokens: () => [...MutableHashMap.keys(resetTokens)],
    /** A code `/authenticate` exchanges for `userId`, bound to the authorize URL's PKCE challenge. */
    authorizationCode: (userId: string, challenge: string) => {
      const code = nextId("code");
      MutableHashMap.set(authorizationCodes, code, { userId, challenge });
      return code;
    },
    /** Make the next session an impersonation. */
    impersonateNext: (email: string, reason: string | null) => {
      impersonateNext = { email, reason };
    },
  };
});

export type FakeWorkOS = Effect.Success<ReturnType<typeof make>>;
