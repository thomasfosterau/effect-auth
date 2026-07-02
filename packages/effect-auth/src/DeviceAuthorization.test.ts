import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Effect, Layer } from "effect";
import {
  DeviceAuthorizationServiceLayer,
  DeviceAuthorizationServiceTag,
  DeviceAuthorizationStoreTag,
  DevicePollError,
  DeviceCodeError,
  normalizeUserCode,
  type DeviceAuthorizationRecord,
  type DeviceAuthorizationService,
  type DeviceAuthorizationStore,
} from "./DeviceAuthorization.js";
import {
  SessionManagerLayer,
  SessionStoreTag,
  UserStoreTag,
  SessionManagerTag,
  type SessionStore,
  type UserStore,
} from "./Session.js";
import { Hooks } from "./Hooks.js";
import { SessionNotFoundError, UserNotFoundError } from "./Errors.js";
import type * as Types from "./Types.js";

const records = new Map<string, DeviceAuthorizationRecord>();
const sessions = new Map<string, Types.Session>();
const users = new Map<string, Types.User>();

const store: DeviceAuthorizationStore = {
  create: (record) =>
    Effect.sync(() => {
      records.set(record.deviceCode, record);
      return record;
    }),
  getByDeviceCode: (deviceCode) => Effect.sync(() => records.get(deviceCode) ?? null),
  getByUserCode: (userCode) =>
    Effect.sync(() => [...records.values()].find((r) => r.userCode === userCode) ?? null),
  update: (record) =>
    Effect.sync(() => {
      records.set(record.deviceCode, record);
      return record;
    }),
  delete: (deviceCode) => Effect.sync(() => void records.delete(deviceCode)),
};

const sessionStore: SessionStore = {
  create: (session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),
  get: (sessionId) =>
    Effect.suspend(() => {
      const session = sessions.get(sessionId);
      return session === undefined
        ? Effect.fail(new SessionNotFoundError({ message: "not found", sessionId }))
        : Effect.succeed(session);
    }),
  update: (session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),
  delete: (sessionId) => Effect.sync(() => void sessions.delete(sessionId)),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      for (const [id, s] of sessions) if (s.userId === userId) sessions.delete(id);
    }),
  listByUserId: (userId) =>
    Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
};

const userStore: UserStore = {
  get: (userId) =>
    Effect.suspend(() => {
      const user = users.get(userId);
      return user === undefined
        ? Effect.fail(new UserNotFoundError({ message: "not found", userId }))
        : Effect.succeed(user);
    }),
  getCredentials: (userId) => Effect.fail(new UserNotFoundError({ message: "no creds", userId })),
};

const sessionConfig: Types.SessionConfig = {
  sessionExpiresIn: { activePeriod: 1000 * 60 * 60, idlePeriod: 1000 * 60 * 60 },
};

const layer = Layer.mergeAll(
  DeviceAuthorizationServiceLayer({
    verificationUri: "https://example.com/device",
    interval: 5,
  }),
  Layer.succeed(DeviceAuthorizationStoreTag)(store),
  SessionManagerLayer(sessionConfig).pipe(
    Layer.provide(
      Layer.mergeAll(
        Layer.succeed(SessionStoreTag)(sessionStore),
        Layer.succeed(UserStoreTag)(userStore),
      ),
    ),
  ),
  Layer.succeed(UserStoreTag)(userStore),
  Hooks.Default,
);

const run = <A, E>(
  f: (
    svc: DeviceAuthorizationService,
  ) => Effect.Effect<A, E, DeviceAuthorizationStoreTag | SessionManagerTag | Hooks>,
) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* DeviceAuthorizationServiceTag;
      return yield* f(svc);
    }).pipe(Effect.provide(layer)),
  );

describe("DeviceAuthorizationService", () => {
  beforeEach(() => {
    records.clear();
    sessions.clear();
    users.clear();
    const now = new Date();
    users.set("user-1", {
      id: "user-1",
      email: "u@example.com",
      emailVerified: true,
      createdAt: now,
      updatedAt: now,
      attributes: {},
    });
  });

  it("begins a request with a device + user code", async () => {
    const result = await run((svc) => svc.begin({ clientId: "cli" }));
    expect(result.deviceCode).toBeTruthy();
    expect(result.userCode).toMatch(/^[A-Z0-9]+-[A-Z0-9]+$/);
    expect(result.verificationUri).toBe("https://example.com/device");
    expect(result.interval).toBe(5);
    const record = records.get(result.deviceCode);
    expect(record?.status).toBe("pending");
  });

  it("returns authorization_pending before approval", async () => {
    const begun = await run((svc) => svc.begin());
    const pending = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    expect(pending).toBeInstanceOf(DevicePollError);
    expect((pending as DevicePollError).error).toBe("authorization_pending");
  });

  it("returns a session after approval", async () => {
    // Fresh request so the success poll is the first poll (no slow_down).
    const begun = await run((svc) => svc.begin());
    await run((svc) => svc.approve(begun.userCode, "user-1"));
    const result = await run((svc) => svc.poll(begun.deviceCode));
    expect(result.user.id).toBe("user-1");
    expect(result.session.userId).toBe("user-1");
  });

  it("consumes the request on success (user code single use)", async () => {
    const begun = await run((svc) => svc.begin());
    await run((svc) => svc.approve(begun.userCode, "user-1"));
    await run((svc) => svc.poll(begun.deviceCode));

    const again = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    expect((again as DevicePollError).error).toBe("expired_token");
  });

  it("enforces slow_down when polled faster than the interval", async () => {
    const begun = await run((svc) => svc.begin());
    // First poll sets lastPolledAt.
    await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    const tooSoon = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    expect((tooSoon as DevicePollError).error).toBe("slow_down");
  });

  it("returns access_denied after deny", async () => {
    const begun = await run((svc) => svc.begin());
    await run((svc) => svc.deny(begun.userCode));
    const denied = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    expect((denied as DevicePollError).error).toBe("access_denied");
  });

  it("returns expired_token once the request has expired", async () => {
    const begun = await run((svc) => svc.begin());
    const record = records.get(begun.deviceCode)!;
    records.set(begun.deviceCode, { ...record, expiresAt: Date.now() - 1 });
    const expired = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    expect((expired as DevicePollError).error).toBe("expired_token");
  });

  it("rejects approving an unknown user code", async () => {
    const err = await run((svc) => Effect.flip(svc.approve("ZZZZ-ZZZZ", "user-1")));
    expect(err).toBeInstanceOf(DeviceCodeError);
  });

  it("normalizes user codes (case / separators)", () => {
    expect(normalizeUserCode("bdwm-hqpk")).toBe("BDWMHQPK");
  });
});
