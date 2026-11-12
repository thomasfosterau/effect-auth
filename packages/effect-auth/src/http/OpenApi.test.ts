import { assert, describe, it, expect, onTestFinished } from "vite-plus/test";
import { HashSet, Layer, Order, Struct } from "effect";
import * as Arr from "effect/Array";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import type { OpenApi } from "effect/http-api";
import { getOpenApiSpec } from "./HttpApi.ts";
import { type AuthServices } from "./HttpServer.ts";
import * as HttpServer from "./HttpServer.ts";
import { SessionService } from "../SessionService.ts";
import { AuthLifecycleService } from "../AuthLifecycle.ts";
import { IdentifierStore } from "../Identifier.ts";
import { PasswordHasher } from "../password/Password.ts";
import { EmailPasswordService } from "../email/EmailPassword.ts";
import { EmailVerificationService, EmailVerificationStore } from "../email/EmailVerification.ts";
import {
  PasswordResetService,
  PasswordResetStore,
  PasswordResetUserStore,
} from "../password/PasswordReset.ts";
import { UserService, UserServiceStore } from "../User.ts";
import { Hooks } from "../Hooks.ts";

/**
 * SAFETY: the docs routes are intercepted before the API router runs, so the
 * handlers' services are never exercised here — `undefined` stubs satisfy the types.
 */
const stubServices = (): Layer.Layer<AuthServices> =>
  Layer.mergeAll(
    Layer.succeed(AuthLifecycleService)(undefined as never),
    Layer.succeed(SessionService)(undefined as never),
    Layer.succeed(EmailPasswordService)(undefined as never),
    Layer.succeed(IdentifierStore)(undefined as never),
    Layer.succeed(PasswordHasher)(undefined as never),
    Layer.succeed(EmailVerificationService)(undefined as never),
    Layer.succeed(EmailVerificationStore)(undefined as never),
    Layer.succeed(PasswordResetService)(undefined as never),
    Layer.succeed(PasswordResetStore)(undefined as never),
    Layer.succeed(PasswordResetUserStore)(undefined as never),
    Layer.succeed(UserService)(undefined as never),
    Layer.succeed(UserServiceStore)(undefined as never),
    Hooks.Default,
  );

/** Every path the auth contract exposes (kept in sync with `HttpApi.ts`). */
const EXPECTED_PATHS = [
  "/sessions",
  "/sessions/{id}",
  "/identifiers",
  "/identifiers/{id}",
  "/users",
  "/users/{id}",
  "/users/me/password",
  "/email-changes",
  "/email-changes/redemptions",
  "/account-deletions",
  "/account-deletions/redemptions",
  "/multi-factor-enrollments",
  "/multi-factor-enrollments/current",
  "/backup-code-sets",
  "/second-factor-challenges/verifications",
  "/otp-challenges",
  "/email-verifications",
  "/email-verifications/redemptions",
  "/password-resets",
  "/password-resets/redemptions",
  "/google-one-tap-nonces",
  "/device-sessions",
  "/device-sessions/active",
  "/device-sessions/{id}",
  "/device/code",
  "/device/token",
  "/device-authorizations/decisions",
  "/organizations",
  "/organizations/active",
  "/organizations/{id}",
  "/organizations/{id}/members",
  "/organizations/{id}/invitations",
  "/organization-members/{id}",
  "/invitations/{id}",
  "/invitations/{id}/deliveries",
  "/organizations/{id}/domains",
  "/organizations/{id}/roles",
  "/organizations/{id}/teams",
  "/organization-members/{id}/teams",
  "/organization-domains/{id}",
  "/organization-domains/{id}/verifications",
  "/admin/organization-domains",
  "/admin/organization-domains/{id}",
  "/organization-roles/{id}",
  "/teams/{id}",
  "/teams/{id}/members",
  "/team-members/{id}",
  "/admin/users",
  "/admin/users/{id}",
  "/admin/users/{id}/sessions",
  "/user-bans",
  "/user-bans/{id}",
  "/impersonations",
  "/impersonations/{id}",
  "/api-keys",
  "/api-keys/{id}",
  "/sso-providers",
  "/sso-authorizations",
  "/sso/callback",
  "/sso/saml/acs/{providerId}",
  "/sso/saml/metadata/{providerId}",
  "/jwks",
  "/tokens",
  "/oauth-clients",
  "/oauth-clients/{id}",
  "/oauth2/authorize",
  "/oauth2/consent",
  "/oauth2/token",
  "/oauth2/userinfo",
  "/register",
  "/register/{clientId}",
  "/.well-known/openid-configuration",
  "/.well-known/oauth-authorization-server",
  "/.well-known/jwks.json",
  // SCIM 2.0 provisioning (its own group, mounted under /scim/v2).
  "/scim/v2/Users",
  "/scim/v2/Users/{id}",
  "/scim/v2/Groups",
  "/scim/v2/Groups/{id}",
  "/scim/v2/ServiceProviderConfig",
  "/scim/v2/ResourceTypes",
  "/scim/v2/Schemas",
];

const JSON_API = "application/vnd.api+json";

/**
 * The endpoints whose wire format another specification fixes (the `auth` and
 * `scim` groups): RFC 8628, the SSO bindings, RFC 7517, OAuth 2.0 / OIDC,
 * RFC 7591 / 7592, RFC 8414 and SCIM 2.0.
 */
const RFC_TIER_PATHS = [
  "/device/code",
  "/device/token",
  "/sso/callback",
  "/sso/saml/acs/{providerId}",
  "/sso/saml/metadata/{providerId}",
  "/jwks",
  "/oauth2/authorize",
  "/oauth2/consent",
  "/oauth2/token",
  "/oauth2/userinfo",
  "/register",
  "/register/{clientId}",
  "/.well-known/openid-configuration",
  "/.well-known/oauth-authorization-server",
  "/.well-known/jwks.json",
  "/scim/v2/Users",
  "/scim/v2/Users/{id}",
  "/scim/v2/Groups",
  "/scim/v2/Groups/{id}",
  "/scim/v2/ServiceProviderConfig",
  "/scim/v2/ResourceTypes",
  "/scim/v2/Schemas",
];

/** The groups that make up the RFC tier. */
const RFC_TIER_TAGS = HashSet.make("auth", "scim");

/** Whether an operation belongs to the RFC tier. */
const isRfc = (operation: OpenApi.OpenAPISpecOperation) =>
  operation.tags.some((tag) => HashSet.has(RFC_TIER_TAGS, tag));

const METHODS = ["get", "put", "post", "delete", "patch"] as const;

/** One media type an operation declares, for a request body or a response. */
interface DeclaredMediaType {
  readonly path: string;
  readonly method: string;
  readonly mediaType: string;
}

/** Every media type an operation declares, request bodies and responses alike. */
const declaredMediaTypes = (
  path: string,
  method: string,
  operation: OpenApi.OpenAPISpecOperation,
): ReadonlyArray<DeclaredMediaType> =>
  [
    ...Struct.keys(operation.requestBody?.content ?? {}),
    ...R.values(operation.responses).flatMap((response) => Struct.keys(response.content ?? {})),
  ].map((mediaType) => ({ path, method, mediaType }));

/** The declared media types of the document, split into the RFC tier and the rest. */
const mediaTypesByTier = (spec: OpenApi.OpenAPISpec) => {
  const operations = R.toEntries(spec.paths).flatMap(([path, item]) =>
    METHODS.flatMap((method) => {
      const operation = item[method];
      return operation === undefined ? [] : [{ path, method, operation }];
    }),
  );
  const flatten = (rfc: boolean) =>
    operations
      .filter(({ operation }) => isRfc(operation) === rfc)
      .flatMap(({ path, method, operation }) => declaredMediaTypes(path, method, operation));
  return { jsonApi: flatten(false), rfc: flatten(true) };
};

describe("getOpenApiSpec", () => {
  it("is a valid OpenAPI 3.1 document with metadata", () => {
    const spec = getOpenApiSpec();
    expect(spec.openapi).toBe("3.1.0");
    expect(spec.info.title).toBe("effect-auth");
    expect(spec.info.version).toBe("1.0.0");
  });

  it("contains every endpoint path", () => {
    const spec = getOpenApiSpec();
    const paths = Struct.keys(spec.paths);
    Arr.forEach(EXPECTED_PATHS, (p) => {
      expect(paths).toContain(p);
    });
    // No endpoint should be missing from the document.
    expect(paths.length).toBe(EXPECTED_PATHS.length);
  });

  it("documents each error schema under its HTTP status code", () => {
    const spec = getOpenApiSpec();

    // Sign-up and sign-in answer `201` with a session or `202` without one,
    // and JSON:API's negotiation errors (406 / 415) besides their own.
    const signUp = spec.paths["/users"]?.post?.responses ?? {};
    expect(Arr.sort(Struct.keys(signUp), Order.String)).toEqual([
      "201",
      "202",
      "400",
      "403",
      "406",
      "409",
      "415",
      "429",
      "500",
    ]);

    const signIn = spec.paths["/sessions"]?.post?.responses ?? {};
    expect(Arr.sort(Struct.keys(signIn), Order.String)).toEqual([
      "201",
      "202",
      "400",
      "401",
      "403",
      "404",
      "406",
      "415",
      "429",
      "500",
    ]);

    // A JSON:API resource endpoint documents its own errors and the
    // protocol's (400 for a malformed query, 406 / 415 for negotiation).
    const session = spec.paths["/sessions/{id}"]?.get?.responses ?? {};
    expect(Arr.sort(Struct.keys(session), Order.String)).toEqual([
      "200",
      "400",
      "401",
      "404",
      "406",
      "415",
      "500",
    ]);
  });

  it("documents minting a JWT and a key as creates, never as reads", () => {
    const { paths } = getOpenApiSpec();
    expect(paths["/tokens"]?.get).toBeUndefined();
    expect(Struct.keys(paths["/tokens"]?.post?.responses ?? {})).toContain("201");
    expect(Struct.keys(paths["/api-keys"]?.post?.responses ?? {})).toContain("201");
    // Device approval carries the user code in the body: no path names it.
    expect(Struct.keys(paths).filter((path) => path.startsWith("/device-authorizations"))).toEqual([
      "/device-authorizations/decisions",
    ]);
  });

  it("declares JSON:API on every resource group and never on the RFC tier (#205)", () => {
    const tiers = mediaTypesByTier(getOpenApiSpec());
    // The RFC tier is exactly the endpoints another specification fixes.
    expect(Arr.sort(Arr.dedupe(tiers.rfc.map(({ path }) => path)), Order.String)).toEqual(
      Arr.sort(RFC_TIER_PATHS, Order.String),
    );
    // Every body a resource group takes or answers is a JSON:API document.
    const notJsonApi = tiers.jsonApi.filter(({ mediaType }) => mediaType !== JSON_API);
    expect(notJsonApi).toEqual([]);
    expect(tiers.jsonApi.length).toBeGreaterThan(0);
    // And no RFC endpoint declares one, in a request or a response.
    expect(tiers.rfc.filter(({ mediaType }) => mediaType === JSON_API)).toEqual([]);
    const rfcTypes = Arr.dedupe(tiers.rfc.map(({ mediaType }) => mediaType));
    expect(Arr.sort(rfcTypes, Order.String)).toEqual([
      "application/json",
      "application/samlmetadata+xml",
      "application/scim+json",
      "application/x-www-form-urlencoded",
    ]);
    // SCIM speaks `application/scim+json` throughout.
    const scim = tiers.rfc.filter(({ path }) => path.startsWith("/scim/v2/"));
    expect(Arr.dedupe(scim.map(({ mediaType }) => mediaType))).toEqual(["application/scim+json"]);
  });

  it("documents a 409 only where a create can conflict", () => {
    const { paths } = getOpenApiSpec();
    // Defining a role an organization already defines is a conflict; creating
    // a team never is.
    const roles = paths["/organizations/{id}/roles"]?.post?.responses;
    const teams = paths["/organizations/{id}/teams"]?.post?.responses;
    assert.isDefined(roles);
    assert.isDefined(teams);
    expect(Struct.keys(roles)).toContain("409");
    expect(Struct.keys(teams)).not.toContain("409");
  });
});

/** The parts of the served `openapi.json` the docs-route tests read. */
const OpenApiDocument = Schema.Struct({
  openapi: Schema.String,
  paths: Schema.Record(Schema.String, Schema.Json),
});

describe("HttpServer.make docs routes", () => {
  it("serves openapi.json and the reference UI when docs are enabled", async () => {
    const { handler, dispose } = HttpServer.make({
      services: stubServices(),
      prefix: "/api/auth",
      docs: true,
      ipRateLimit: false,
    });
    onTestFinished(dispose);
    const jsonRes = await handler(new Request("http://test/api/auth/openapi.json"));
    expect(jsonRes.status).toBe(200);
    expect(jsonRes.headers.get("content-type")).toContain("application/json");
    const doc = Schema.decodeUnknownSync(OpenApiDocument)(await jsonRes.json());
    expect(doc.openapi).toBe("3.1.0");
    expect(Struct.keys(doc.paths)).toContain("/sessions");

    const refRes = await handler(new Request("http://test/api/auth/reference"));
    expect(refRes.status).toBe(200);
    expect(refRes.headers.get("content-type")).toContain("text/html");
    const html = await refRes.text();
    expect(html).toContain("api-reference");
    expect(html).toContain("openapi.json");
  });

  it("serves docs at the root when no prefix is configured", async () => {
    const { handler, dispose } = HttpServer.make({
      services: stubServices(),
      docs: true,
      ipRateLimit: false,
    });
    onTestFinished(dispose);
    const res = await handler(new Request("http://test/openapi.json"));
    expect(res.status).toBe(200);
  });

  it("does not expose docs routes when docs are disabled", async () => {
    const { handler, dispose } = HttpServer.make({
      services: stubServices(),
      prefix: "/api/auth",
      ipRateLimit: false,
    });
    onTestFinished(dispose);
    const jsonRes = await handler(new Request("http://test/api/auth/openapi.json"));
    expect(jsonRes.status).toBe(404);
    const refRes = await handler(new Request("http://test/api/auth/reference"));
    expect(refRes.status).toBe(404);
  });
});
