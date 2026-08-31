import { describe, it, expect } from "vite-plus/test";
import { Layer } from "effect";
import { getOpenApiSpec } from "./HttpApi.ts";
import { type AuthServices } from "./HttpServer.ts";
import * as HTTPServer from "./HttpServer.ts";
import { SessionService } from "../SessionService.ts";
import { AuthLifecycleService } from "../AuthLifecycle.ts";
import { IdentifierStore } from "../Identifier.ts";
import { PasswordHasher } from "../password/Password.ts";
import { EmailVerificationService, EmailVerificationStore } from "../email/EmailVerification.ts";
import {
  PasswordResetService,
  PasswordResetStore,
  PasswordResetUserStore,
} from "../password/PasswordReset.ts";
import { UserService, UserServiceStore } from "../User.ts";
import { Hooks } from "../Hooks.ts";

/**
 * The docs routes are intercepted before the API router runs, so the handlers'
 * services are never exercised here — no-op stubs satisfy the types.
 */
const stubServices = (): Layer.Layer<AuthServices> =>
  Layer.mergeAll(
    Layer.succeed(AuthLifecycleService)(undefined as never),
    Layer.succeed(SessionService)(undefined as never),
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
  "/sign-up",
  "/sign-in",
  "/sign-out",
  "/session",
  "/sessions",
  "/sessions/revoke-others",
  "/sessions/{sessionId}",
  "/identifiers",
  "/identifiers/{identifierId}",
  "/user",
  "/change-password",
  "/email-verification/send",
  "/email-verification/verify",
  "/password-reset/request",
  "/password-reset/reset",
  "/magic-link/send",
  "/magic-link/verify",
  "/change-email/request",
  "/change-email/confirm",
  "/delete-user/request",
  "/delete-user/confirm",
  "/email-otp/send",
  "/sign-in/email-otp",
  "/sign-in/anonymous",
  "/sign-in/username",
  "/multi-session/list",
  "/multi-session/set-active",
  "/multi-session/revoke",
  "/device/code",
  "/device/token",
  "/device/approve",
  "/device/deny",
  "/phone-otp/send",
  "/sign-in/phone-otp",
  "/multi-factor/enable",
  "/multi-factor/confirm",
  "/multi-factor/disable",
  "/multi-factor/verify-totp",
  "/multi-factor/verify-backup-code",
  "/multi-factor/regenerate-backup-codes",
  "/organization/create",
  "/organizations",
  "/organization/{organizationId}",
  "/organization/set-active",
  "/organization/{organizationId}/invitations",
  "/invitations/{invitationId}/accept",
  "/invitations/{invitationId}/reject",
  "/invitations/{invitationId}/cancel",
  "/organization/{organizationId}/members",
  "/organization/{organizationId}/members/{userId}",
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
  "/sign-in/google-one-tap/nonce",
  "/sign-in/google-one-tap",
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
    for (const p of EXPECTED_PATHS) {
      expect(paths).toContain(p);
    }
    // No endpoint should be missing from the document.
    expect(paths.length).toBe(EXPECTED_PATHS.length);
  });

  it("documents each error schema under its HTTP status code", () => {
    const spec = getOpenApiSpec();

    const signUp = spec.paths["/sign-up"]?.post?.responses ?? {};
    expect(Object.keys(signUp).sort()).toEqual(["200", "400", "403", "409", "429", "500"]);

    const signIn = spec.paths["/sign-in"]?.post?.responses ?? {};
    expect(Object.keys(signIn).sort()).toEqual(["200", "400", "401", "403", "429", "500"]);

    const session = spec.paths["/session"]?.get?.responses ?? {};
    expect(Object.keys(session).sort()).toEqual(["200", "401"]);
  });
});

describe("HTTPServer.make docs routes", () => {
  it("serves openapi.json and the reference UI when docs are enabled", async () => {
    const { handler, dispose } = HTTPServer.make({
      services: stubServices(),
      prefix: "/api/auth",
      docs: true,
    });
    try {
      const jsonRes = await handler(new Request("http://test/api/auth/openapi.json"));
      expect(jsonRes.status).toBe(200);
      expect(jsonRes.headers.get("content-type")).toContain("application/json");
      const doc = (await jsonRes.json()) as { openapi: string; paths: Record<string, unknown> };
      expect(doc.openapi).toBe("3.1.0");
      expect(Object.keys(doc.paths)).toContain("/sign-in");

      const refRes = await handler(new Request("http://test/api/auth/reference"));
      expect(refRes.status).toBe(200);
      expect(refRes.headers.get("content-type")).toContain("text/html");
      const html = await refRes.text();
      expect(html).toContain("api-reference");
      expect(html).toContain("openapi.json");
    } finally {
      await dispose();
    }
  });

  it("serves docs at the root when no prefix is configured", async () => {
    const { handler, dispose } = HTTPServer.make({ services: stubServices(), docs: true });
    try {
      const res = await handler(new Request("http://test/openapi.json"));
      expect(res.status).toBe(200);
    } finally {
      await dispose();
    }
  });

  it("does not expose docs routes when docs are disabled", async () => {
    const { handler, dispose } = HTTPServer.make({
      services: stubServices(),
      prefix: "/api/auth",
    });
    try {
      const jsonRes = await handler(new Request("http://test/api/auth/openapi.json"));
      expect(jsonRes.status).toBe(404);
      const refRes = await handler(new Request("http://test/api/auth/reference"));
      expect(refRes.status).toBe(404);
    } finally {
      await dispose();
    }
  });
});
