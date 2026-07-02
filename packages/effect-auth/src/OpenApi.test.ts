import { describe, it, expect } from "vite-plus/test";
import { Layer } from "effect";
import { getOpenApiSpec } from "./HttpApi.js";
import { makeAuthWebHandler, type AuthServices } from "./HttpServer.js";
import { SessionManagerTag } from "./Session.js";
import { AuthLifecycleServiceTag } from "./AuthLifecycle.js";
import { EmailPasswordStoreTag } from "./EmailPassword.js";
import { PasswordHasherTag } from "./Password.js";
import { EmailVerificationServiceTag, EmailVerificationStoreTag } from "./EmailVerification.js";
import {
  PasswordResetServiceTag,
  PasswordResetStoreTag,
  PasswordResetUserStoreTag,
} from "./PasswordReset.js";
import { UserServiceTag, UserServiceStoreTag } from "./User.js";
import { Hooks } from "./Hooks.js";

/**
 * The docs routes are intercepted before the API router runs, so the handlers'
 * services are never exercised here — no-op stubs satisfy the types.
 */
const stubServices = (): Layer.Layer<AuthServices> =>
  Layer.mergeAll(
    Layer.succeed(AuthLifecycleServiceTag)(undefined as never),
    Layer.succeed(SessionManagerTag)(undefined as never),
    Layer.succeed(EmailPasswordStoreTag)(undefined as never),
    Layer.succeed(PasswordHasherTag)(undefined as never),
    Layer.succeed(EmailVerificationServiceTag)(undefined as never),
    Layer.succeed(EmailVerificationStoreTag)(undefined as never),
    Layer.succeed(PasswordResetServiceTag)(undefined as never),
    Layer.succeed(PasswordResetStoreTag)(undefined as never),
    Layer.succeed(PasswordResetUserStoreTag)(undefined as never),
    Layer.succeed(UserServiceTag)(undefined as never),
    Layer.succeed(UserServiceStoreTag)(undefined as never),
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
  "/two-factor/enable",
  "/two-factor/confirm",
  "/two-factor/disable",
  "/two-factor/verify-totp",
  "/two-factor/verify-backup-code",
  "/two-factor/regenerate-backup-codes",
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
    expect(Object.keys(signUp).sort()).toEqual(["200", "400", "409", "500"]);

    const signIn = spec.paths["/sign-in"]?.post?.responses ?? {};
    expect(Object.keys(signIn).sort()).toEqual(["200", "401", "403", "500"]);

    const session = spec.paths["/session"]?.get?.responses ?? {};
    expect(Object.keys(session).sort()).toEqual(["200", "401"]);
  });
});

describe("makeAuthWebHandler docs routes", () => {
  it("serves openapi.json and the reference UI when docs are enabled", async () => {
    const { handler, dispose } = makeAuthWebHandler({
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
    const { handler, dispose } = makeAuthWebHandler({ services: stubServices(), docs: true });
    try {
      const res = await handler(new Request("http://test/openapi.json"));
      expect(res.status).toBe(200);
    } finally {
      await dispose();
    }
  });

  it("does not expose docs routes when docs are disabled", async () => {
    const { handler, dispose } = makeAuthWebHandler({
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
