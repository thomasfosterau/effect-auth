import { describe, it, expect, onTestFinished } from "vite-plus/test";
import { Array as Arr, Layer, Order, Schema } from "effect";
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
  "/multi-session/list",
  "/multi-session/set-active",
  "/multi-session/revoke",
  "/device/code",
  "/device/token",
  "/device/approve",
  "/device/deny",
  "/organization/create",
  "/organizations",
  "/organization/{organizationId}",
  "/organization/set-active",
  "/organization/{organizationId}/invitations",
  "/invitations/{invitationId}/accept",
  "/invitations/{invitationId}/reject",
  "/invitations/{invitationId}/cancel",
  "/invitations/{invitationId}/resend",
  "/organization/{organizationId}/members",
  "/organization/{organizationId}/members/{userId}",
  "/organization/{organizationId}/members/{userId}/deactivate",
  "/organization/{organizationId}/members/{userId}/reactivate",
  "/organization/{organizationId}/default-role",
  "/organization/{organizationId}/domains",
  "/organization/{organizationId}/domains/{domainId}",
  "/organization/{organizationId}/domains/{domainId}/verify",
  "/organization/{organizationId}/roles",
  "/organization/{organizationId}/roles/{role}",
  "/organization/{organizationId}/teams",
  "/organization/{organizationId}/members/{userId}/teams",
  "/teams/{teamId}",
  "/teams/{teamId}/members",
  "/teams/{teamId}/members/{userId}",
  "/admin/users/list",
  "/admin/users/set-role",
  "/admin/users/ban",
  "/admin/users/unban",
  "/admin/users/remove",
  "/admin/users/revoke-sessions",
  "/admin/impersonate",
  "/admin/stop-impersonating",
  "/api-keys",
  "/api-keys/{keyId}",
  "/sso/register",
  "/sign-in/sso",
  "/sso/callback",
  "/sso/saml/acs/{providerId}",
  "/sso/saml/metadata/{providerId}",
  "/token",
  "/jwks",
  "/oauth2/register",
  "/oauth2/clients",
  "/oauth2/clients/{clientId}",
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

describe("getOpenApiSpec", () => {
  it("is a valid OpenAPI 3.1 document with metadata", () => {
    const spec = getOpenApiSpec();
    expect(spec.openapi).toBe("3.1.0");
    expect(spec.info.title).toBe("effect-auth");
    expect(spec.info.version).toBe("1.0.0");
  });

  it("contains every endpoint path", () => {
    const spec = getOpenApiSpec();
    const paths = Object.keys(spec.paths);
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
    expect(Arr.sort(Object.keys(signUp), Order.String)).toEqual([
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
    expect(Arr.sort(Object.keys(signIn), Order.String)).toEqual([
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
    expect(Arr.sort(Object.keys(session), Order.String)).toEqual([
      "200",
      "400",
      "401",
      "404",
      "406",
      "415",
      "500",
    ]);
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
    });
    onTestFinished(dispose);
    const jsonRes = await handler(new Request("http://test/api/auth/openapi.json"));
    expect(jsonRes.status).toBe(200);
    expect(jsonRes.headers.get("content-type")).toContain("application/json");
    const doc = Schema.decodeUnknownSync(OpenApiDocument)(await jsonRes.json());
    expect(doc.openapi).toBe("3.1.0");
    expect(Object.keys(doc.paths)).toContain("/sessions");

    const refRes = await handler(new Request("http://test/api/auth/reference"));
    expect(refRes.status).toBe(200);
    expect(refRes.headers.get("content-type")).toContain("text/html");
    const html = await refRes.text();
    expect(html).toContain("api-reference");
    expect(html).toContain("openapi.json");
  });

  it("serves docs at the root when no prefix is configured", async () => {
    const { handler, dispose } = HttpServer.make({ services: stubServices(), docs: true });
    onTestFinished(dispose);
    const res = await handler(new Request("http://test/openapi.json"));
    expect(res.status).toBe(200);
  });

  it("does not expose docs routes when docs are disabled", async () => {
    const { handler, dispose } = HttpServer.make({
      services: stubServices(),
      prefix: "/api/auth",
    });
    onTestFinished(dispose);
    const jsonRes = await handler(new Request("http://test/api/auth/openapi.json"));
    expect(jsonRes.status).toBe(404);
    const refRes = await handler(new Request("http://test/api/auth/reference"));
    expect(refRes.status).toBe(404);
  });
});
