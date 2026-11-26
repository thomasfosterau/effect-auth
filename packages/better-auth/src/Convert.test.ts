import { describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { at } from "./testing/Fixtures.ts";
import { fromApiError, toSession, toUser } from "./Convert.ts";

const apiError = (statusCode: number, code?: string) => ({
  statusCode,
  status: "X",
  body: code === undefined ? undefined : { code, message: "m" },
});

describe("fromApiError", () => {
  it("maps BetterAuth's codes, and keeps everything else as AuthError with its cause", () => {
    expect(fromApiError(apiError(401, "INVALID_EMAIL_OR_PASSWORD"))).toBeInstanceOf(
      Auth.Errors.InvalidCredentialsError,
    );
    expect(fromApiError(apiError(422, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"))).toBeInstanceOf(
      Auth.Errors.EmailInUseError,
    );
    expect(fromApiError(apiError(403, "EMAIL_NOT_VERIFIED"), "a@x.test")).toBeInstanceOf(
      Auth.Errors.EmailNotVerifiedError,
    );
    const limited = apiError(429);
    const mapped = fromApiError(limited);
    expect(mapped).toBeInstanceOf(Auth.Errors.AuthError);
    expect(mapped instanceof Auth.Errors.AuthError && mapped.cause).toBe(limited);
    // A 401 with another code is not a credentials verdict.
    expect(fromApiError(apiError(401, "INVALID_TOKEN"))).toBeInstanceOf(Auth.Errors.AuthError);
    const thrown = new TypeError("boom");
    expect(fromApiError(thrown)).toMatchObject({ _tag: "AuthError", cause: thrown });
  });
});

describe("toUser and toSession", () => {
  const epoch = at(0);

  it("keeps the token, email and identifier columns off the domain values", () => {
    const session = toSession({
      id: "s1",
      token: "secret-token",
      userId: "u1",
      expiresAt: epoch,
      createdAt: epoch,
      updatedAt: at(5),
      ipAddress: "203.0.113.1",
      userAgent: null,
      activeOrganizationId: "o1",
    });
    expect(session).toEqual({
      id: "s1",
      userId: "u1",
      expiresAt: epoch,
      createdAt: epoch,
      lastActivityAt: at(5),
      attributes: { ipAddress: "203.0.113.1", userAgent: null, activeOrganizationId: "o1" },
    });
    const user = toUser({
      id: "u1",
      name: "Ada",
      email: "ada@example.test",
      emailVerified: true,
      image: null,
      createdAt: epoch,
      updatedAt: epoch,
      username: "ada",
      role: "admin",
      banExpires: at(1234),
    });
    expect(user).toEqual({
      id: "u1",
      name: "Ada",
      createdAt: epoch,
      updatedAt: epoch,
      attributes: { role: "admin", banExpires: 1234 },
    });
  });
});
