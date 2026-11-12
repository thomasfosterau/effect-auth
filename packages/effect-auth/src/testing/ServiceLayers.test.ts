import { describe, expect, it } from "vite-plus/test";
import { Effect } from "effect";
import { ApiKeyService, hashApiKey } from "../ApiKey.ts";
import { SessionService } from "../SessionService.ts";
import * as Testing from "./index.ts";

const ada = Testing.fixtureUser({ name: "Ada" });

describe("sessionServiceLayer", () => {
  it("round-trips create, validate and revoke", async () => {
    const program = Effect.fn("sessionRoundTrip")(function* () {
      const sessions = yield* SessionService;
      const created = yield* sessions.createSession(ada.id);
      expect((yield* sessions.validateSession(created.id)).user.id).toBe(ada.id);
      yield* sessions.invalidateSession(created.id);
      const failure = yield* Effect.flip(sessions.validateSession(created.id));
      expect(failure._tag).toBe("SessionNotFoundError");
    });
    await Effect.runPromise(
      program().pipe(Effect.provide(Testing.sessionServiceLayer({ users: [ada] }))),
    );
  });

  it("rejects a user that was not seeded and accepts a custom config", async () => {
    const program = Effect.fn("unseededUser")(function* () {
      const sessions = yield* SessionService;
      const created = yield* sessions.createSession("stranger");
      const failure = yield* Effect.flip(sessions.validateSession(created.id));
      expect(failure._tag).toBe("UserNotFoundError");
    });
    await Effect.runPromise(
      program().pipe(
        Effect.provide(
          Testing.sessionServiceLayer({
            users: [ada],
            config: { sessionExpiresIn: { activePeriod: 1000, idlePeriod: 500 } },
          }),
        ),
      ),
    );
  });

  it("starts each build empty", async () => {
    const layer = Testing.sessionServiceLayer({ users: [ada] });
    const create = Effect.flatMap(SessionService, (s) => s.createSession(ada.id));
    const list = Effect.flatMap(SessionService, (s) => s.listSessions(ada.id));
    const afterCreate = await Effect.runPromise(
      create.pipe(Effect.andThen(list), Effect.provide(layer)),
    );
    expect(afterCreate).toHaveLength(1);
    expect(await Effect.runPromise(list.pipe(Effect.provide(layer)))).toHaveLength(0);
  });
});

describe("apiKeyServiceLayer", () => {
  it("round-trips create, verify and revoke", async () => {
    const program = Effect.fn("apiKeyRoundTrip")(function* () {
      const apiKeys = yield* ApiKeyService;
      const created = yield* apiKeys.create("user-1", { name: "CI" });
      const ok = yield* apiKeys.verify(created.key);
      expect(ok.valid).toBe(true);
      expect(ok.apiKey?.userId).toBe("user-1");
      yield* apiKeys.delete("user-1", created.apiKey.id);
      expect((yield* apiKeys.verify(created.key)).valid).toBe(false);
    });
    await Effect.runPromise(program().pipe(Effect.provide(Testing.apiKeyServiceLayer())));
  });

  it("a disabled key fails verify", async () => {
    const program = Effect.fn("disabledKey")(function* () {
      const apiKeys = yield* ApiKeyService;
      const created = yield* apiKeys.create("user-1");
      yield* apiKeys.update("user-1", created.apiKey.id, { enabled: false });
      expect((yield* apiKeys.verify(created.key)).valid).toBe(false);
    });
    await Effect.runPromise(program().pipe(Effect.provide(Testing.apiKeyServiceLayer())));
  });

  it("seeds keys and applies config", async () => {
    const plaintext = "seeded_secret";
    const program = Effect.fn("seededKeys")(function* () {
      const apiKeys = yield* ApiKeyService;
      expect((yield* apiKeys.verify(plaintext)).valid).toBe(true);
      const created = yield* apiKeys.create("user-1");
      expect(created.key.startsWith("test_")).toBe(true);
    });
    await Effect.runPromise(
      program().pipe(
        Effect.provide(
          Testing.apiKeyServiceLayer({
            config: { defaultPrefix: "test_" },
            keys: [
              {
                id: "seed-1",
                start: "seeded",
                keyHash: hashApiKey(plaintext),
                userId: "user-1",
                enabled: true,
                metadata: {},
                createdAt: 0,
                updatedAt: 0,
              },
            ],
          }),
        ),
      ),
    );
  });

  it("provides a RateLimitStore for verifyWithRateLimit", async () => {
    const program = Effect.fn("rateLimited")(function* () {
      const apiKeys = yield* ApiKeyService;
      const created = yield* apiKeys.create("user-1", {});
      expect((yield* apiKeys.verifyWithRateLimit(created.key)).valid).toBe(true);
    });
    await Effect.runPromise(program().pipe(Effect.provide(Testing.apiKeyServiceLayer())));
  });
});
