import { describe, it, expect } from "vite-plus/test";
import { Config, ConfigProvider, Effect, Layer, Redacted, Result } from "effect";
import { AuthenticationException } from "@workos-inc/node";
import { makeClient, makeFromClient, WorkOS, type WorkOSClient } from "./WorkOS.js";
import { toWorkOSError, WorkOSError } from "./Errors.js";

/**
 * Build a real WorkOS SDK client (construction does no network I/O) so every
 * module is present, then override individual methods to exercise the wrapper
 * without making real API calls.
 */
const overrideMethod = (
  client: WorkOSClient,
  module: keyof WorkOSClient,
  method: string,
  impl: (...args: ReadonlyArray<unknown>) => unknown,
): void => {
  (client[module] as unknown as Record<string, unknown>)[method] = impl;
};

const testClient = (): WorkOSClient =>
  makeClient({ apiKey: "sk_test_123", clientId: "client_test" });

describe("makeFromClient / effectified modules", () => {
  it("wraps a synchronous method into a succeeding Effect", async () => {
    const client = testClient();
    overrideMethod(client, "sso", "getAuthorizationUrl", () => "https://auth.workos.com/url");
    const workos = makeFromClient(client);

    const url = await Effect.runPromise(
      workos.sso.getAuthorizationUrl({
        clientId: "client_test",
        redirectUri: "https://example.com/callback",
        provider: "GoogleOAuth",
      }),
    );
    expect(url).toBe("https://auth.workos.com/url");
  });

  it("wraps an async method that resolves", async () => {
    const client = testClient();
    overrideMethod(client, "organizations", "createOrganization", (opts) =>
      Promise.resolve({ id: "org_1", name: (opts as { name: string }).name }),
    );
    const workos = makeFromClient(client);

    const org = await Effect.runPromise(workos.organizations.createOrganization({ name: "Acme" }));
    expect(org).toEqual({ id: "org_1", name: "Acme" });
  });

  it("maps a rejected SDK exception into a WorkOSError with metadata", async () => {
    const client = testClient();
    overrideMethod(client, "userManagement", "authenticateWithPassword", () =>
      Promise.reject({
        name: "UnauthorizedException",
        status: 401,
        code: "invalid_credentials",
        requestID: "req_abc",
        message: "Invalid credentials",
      }),
    );
    const workos = makeFromClient(client);

    const result = await Effect.runPromise(
      Effect.result(
        workos.userManagement.authenticateWithPassword({
          clientId: "client_test",
          email: "a@b.com",
          password: "nope",
        }),
      ),
    );

    expect(Result.isFailure(result)).toBe(true);
    if (Result.isFailure(result)) {
      const error = result.failure;
      expect(WorkOSError.is(error)).toBe(true);
      expect(error.exception).toBe("UnauthorizedException");
      expect(error.status).toBe(401);
      expect(error.code).toBe("invalid_credentials");
      expect(error.requestID).toBe("req_abc");
      expect(error.operation).toBe("userManagement.authenticateWithPassword");
      expect(error.message).toBe("Invalid credentials");
    }
  });

  it("maps a synchronous throw into a WorkOSError", async () => {
    const client = testClient();
    overrideMethod(client, "sso", "getAuthorizationUrl", () => {
      throw new Error("boom");
    });
    const workos = makeFromClient(client);

    const result = await Effect.runPromise(
      Effect.result(
        workos.sso.getAuthorizationUrl({
          clientId: "client_test",
          redirectUri: "https://example.com/callback",
          provider: "GoogleOAuth",
        }),
      ),
    );
    expect(Result.isFailure(result) && result.failure.message).toBe("boom");
  });

  it("exposes the raw client and a `use` escape hatch", async () => {
    const client = testClient();
    const workos = makeFromClient(client);
    expect(workos.client).toBe(client);

    const value = await Effect.runPromise(workos.use(() => Promise.resolve(42)));
    expect(value).toBe(42);

    const failed = await Effect.runPromise(
      Effect.result(
        workos.use(() => {
          throw new Error("use failed");
        }),
      ),
    );
    expect(Result.isFailure(failed) && failed.failure.operation).toBe("use");
  });

  it("does not invoke the underlying method until the Effect is run", async () => {
    const client = testClient();
    let calls = 0;
    overrideMethod(client, "organizations", "listOrganizations", () => {
      calls += 1;
      return Promise.resolve({ data: [] });
    });
    const workos = makeFromClient(client);

    const effect = workos.organizations.listOrganizations();
    expect(calls).toBe(0);
    await Effect.runPromise(effect);
    expect(calls).toBe(1);
  });
});

describe("WorkOS layers", () => {
  it("layerClient provides the service from an existing client", async () => {
    const client = testClient();
    const program = Effect.gen(function* () {
      const workos = yield* WorkOS;
      return workos.client;
    });
    const resolved = await Effect.runPromise(
      program.pipe(Effect.provide(WorkOS.layerClient(client))),
    );
    expect(resolved).toBe(client);
  });

  it("layerOptions constructs a client from options", async () => {
    const program = Effect.gen(function* () {
      const workos = yield* WorkOS;
      return workos.client.clientId;
    });
    const clientId = await Effect.runPromise(
      program.pipe(
        Effect.provide(WorkOS.layerOptions({ apiKey: "sk_x", clientId: "client_opts" })),
      ),
    );
    expect(clientId).toBe("client_opts");
  });

  it("layer reads credentials from Config", async () => {
    const provider = ConfigProvider.layer(
      ConfigProvider.fromUnknown({
        WORKOS_API_KEY: "sk_from_env",
        WORKOS_CLIENT_ID: "client_env",
      }),
    );
    const program = Effect.gen(function* () {
      const workos = yield* WorkOS;
      return workos.client.clientId;
    });
    const clientId = await Effect.runPromise(
      program.pipe(Effect.provide(WorkOS.layer.pipe(Layer.provide(provider)))),
    );
    expect(clientId).toBe("client_env");
  });

  it("layer fails with a ConfigError when WORKOS_API_KEY is missing", async () => {
    const provider = ConfigProvider.layer(ConfigProvider.fromUnknown({}));
    const program = Effect.gen(function* () {
      yield* WorkOS;
    });
    const result = await Effect.runPromise(
      Effect.result(program.pipe(Effect.provide(WorkOS.layer.pipe(Layer.provide(provider))))),
    );
    expect(Result.isFailure(result)).toBe(true);
  });
});

describe("makeClient", () => {
  it("accepts a redacted API key", () => {
    const client = makeClient({ apiKey: Redacted.make("sk_redacted"), clientId: "client_r" });
    expect(client.clientId).toBe("client_r");
  });
});

describe("toWorkOSError", () => {
  it("extracts rate-limit retryAfter", () => {
    const error = toWorkOSError(
      { name: "RateLimitExceededException", status: 429, message: "slow down", retryAfter: 30 },
      "events.listEvents",
    );
    expect(error.status).toBe(429);
    expect(error.retryAfter).toBe(30);
    expect(error.operation).toBe("events.listEvents");
  });

  it("extracts AuthKit authentication metadata from the real SDK exception shape", () => {
    // AuthenticationException stores step-up data in rawData with snake_case keys;
    // toWorkOSError must read from there, not from invented top-level camelCase fields.
    const exc = new AuthenticationException(
      403,
      { message: "MFA required", code: "mfa_challenge", pending_authentication_token: "pat_123" },
      "req_xyz",
    );
    const error = toWorkOSError(exc);
    expect(error.authenticationCode).toBe("mfa_challenge");
    expect(error.pendingAuthenticationToken).toBe("pat_123");
  });

  it("handles plain Errors and strings", () => {
    expect(toWorkOSError(new Error("plain")).message).toBe("plain");
    expect(toWorkOSError("just a string").message).toBe("just a string");
    expect(toWorkOSError(undefined).message).toBe("WorkOS request failed");
  });
});

// Type-level smoke test: a Config-driven program type-checks against the service.
const _typeCheck: Effect.Effect<unknown, WorkOSError | Config.ConfigError, never> = Effect.gen(
  function* () {
    const workos = yield* WorkOS;
    return yield* workos.userManagement.listUsers();
  },
).pipe(Effect.provide(WorkOS.layer));
void _typeCheck;
