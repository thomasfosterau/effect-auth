import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import { DateTime, Effect, Layer, MutableHashMap, Result } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import {
  DeviceAuthorizationService,
  DeviceAuthorizationStore,
  DevicePollError,
  DeviceCodeError,
  normalizeUserCode,
  type DeviceAuthorizationRecord,
} from "./DeviceAuthorization.ts";
import { hashToken } from "./TokenHash.ts";
import { SessionStore } from "./SessionStore.ts";
import { UserStore } from "./UserStore.ts";
import { SessionService } from "./SessionService.ts";
import { Hooks } from "./Hooks.ts";
import type * as Types from "./Types.ts";

const records = MutableHashMap.empty<string, DeviceAuthorizationRecord>();
const sessions = MutableHashMap.empty<string, Types.Session>();
const users = MutableHashMap.empty<string, Types.User>();

const store: typeof DeviceAuthorizationStore.Service = {
  create: (record) =>
    Effect.sync(() => {
      // record.deviceCode and record.userCode are already hashed by the service.
      MutableHashMap.set(records, record.deviceCode, record);
      return record;
    }),
  getByDeviceCode: (deviceCode) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(records, deviceCode))),
  getByUserCode: (userCode) =>
    Effect.sync(
      () =>
        Arr.fromIterable(MutableHashMap.values(records)).find((r) => r.userCode === userCode) ??
        null,
    ),
  update: (record) =>
    Effect.sync(() => {
      MutableHashMap.set(records, record.deviceCode, record);
      return record;
    }),
  delete: (deviceCode) => Effect.sync(() => void MutableHashMap.remove(records, deviceCode)),
  claimApproval: (deviceCode) =>
    Effect.sync(() => {
      const record = Option.getOrUndefined(MutableHashMap.get(records, deviceCode));
      if (record === undefined || record.status !== "approved") return null;
      // Read and delete in one synchronous step — atomic on a single JS thread.
      MutableHashMap.remove(records, deviceCode);
      return record;
    }),
};

const sessionStore: typeof SessionStore.Service = {
  create: (session) =>
    Effect.sync(() => {
      MutableHashMap.set(sessions, session.id, session);
      return session;
    }),
  get: (sessionId) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(sessions, sessionId))),
  update: (session) =>
    Effect.sync(() => {
      MutableHashMap.set(sessions, session.id, session);
      return session;
    }),
  delete: (sessionId) => Effect.sync(() => void MutableHashMap.remove(sessions, sessionId)),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      MutableHashMap.forEach(sessions, (s, id) => {
        if (s.userId === userId) MutableHashMap.remove(sessions, id);
      });
    }),
  listByUserId: (userId) =>
    Effect.sync(() =>
      Arr.fromIterable(MutableHashMap.values(sessions)).filter((s) => s.userId === userId),
    ),
};

const userStore: typeof UserStore.Service = {
  get: (userId) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(users, userId))),
};

const sessionConfig: Types.SessionConfig = {
  sessionExpiresIn: { activePeriod: 1000 * 60 * 60, idlePeriod: 1000 * 60 * 60 },
};

const storeLayer = Layer.mergeAll(
  Layer.succeed(DeviceAuthorizationStore)(store),
  Layer.succeed(SessionStore)(sessionStore),
  Layer.succeed(UserStore)(userStore),
  Hooks.Default,
);

const sessionServiceLayer = SessionService.layer(sessionConfig).pipe(Layer.provide(storeLayer));

const deviceAuthorizationServiceLayer = DeviceAuthorizationService.layer({
  verificationUri: "https://example.com/device",
  interval: 5,
}).pipe(Layer.provide(Layer.mergeAll(storeLayer, sessionServiceLayer)));

const layer = Layer.mergeAll(storeLayer, sessionServiceLayer, deviceAuthorizationServiceLayer);

const run = <A, E>(
  f: (
    svc: typeof DeviceAuthorizationService.Service,
  ) => Effect.Effect<A, E, DeviceAuthorizationStore | SessionService | Hooks>,
) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* DeviceAuthorizationService;
      return yield* f(svc);
    }).pipe(Effect.provide(layer)),
  );

describe("DeviceAuthorizationService", () => {
  beforeEach(() => {
    MutableHashMap.clear(records);
    MutableHashMap.clear(sessions);
    MutableHashMap.clear(users);
    const now = DateTime.toDateUtc(DateTime.nowUnsafe());
    MutableHashMap.set(users, "user-1", {
      id: "user-1",
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
    // The store is keyed by hash; the returned deviceCode is the raw value.
    const record = Option.getOrUndefined(MutableHashMap.get(records, hashToken(result.deviceCode)));
    expect(record?.status).toBe("pending");
  });

  it("returns authorization_pending before approval", async () => {
    const begun = await run((svc) => svc.begin());
    const pending = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    assert.instanceOf(pending, DevicePollError);
    expect(pending.error).toBe("authorization_pending");
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
    assert.instanceOf(again, DevicePollError);
    expect(again.error).toBe("expired_token");
  });

  it("enforces slow_down when polled faster than the interval", async () => {
    const begun = await run((svc) => svc.begin());
    // First poll sets lastPolledAt.
    await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    const tooSoon = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    assert.instanceOf(tooSoon, DevicePollError);
    expect(tooSoon.error).toBe("slow_down");
  });

  it("returns access_denied after deny", async () => {
    const begun = await run((svc) => svc.begin());
    await run((svc) => svc.deny(begun.userCode));
    const denied = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    assert.instanceOf(denied, DevicePollError);
    expect(denied.error).toBe("access_denied");
  });

  it("returns expired_token once the request has expired", async () => {
    const begun = await run((svc) => svc.begin());
    const deviceHash = hashToken(begun.deviceCode);
    const record = Option.getOrUndefined(MutableHashMap.get(records, deviceHash));
    assert(record !== undefined, "begin stored the request");
    MutableHashMap.set(records, deviceHash, {
      ...record,
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) - 1,
    });
    const expired = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    assert.instanceOf(expired, DevicePollError);
    expect(expired.error).toBe("expired_token");
  });

  it("rejects approving an unknown user code", async () => {
    const err = await run((svc) => Effect.flip(svc.approve("ZZZZ-ZZZZ", "user-1")));
    expect(err).toBeInstanceOf(DeviceCodeError);
  });

  it("normalizes user codes (case / separators)", () => {
    expect(normalizeUserCode("bdwm-hqpk")).toBe("BDWMHQPK");
  });

  it("concurrent polls only mint one session (atomic consumption)", async () => {
    const begun = await run((svc) => svc.begin());
    await run((svc) => svc.approve(begun.userCode, "user-1"));

    // Run two polls "concurrently". With sync stores they serialise on the JS
    // event loop, but claimApproval is a conditional-delete so exactly one wins.
    const results = await Promise.all(
      [0, 1].map(() =>
        Effect.runPromise(
          Effect.gen(function* () {
            const svc = yield* DeviceAuthorizationService;
            return yield* Effect.result(svc.poll(begun.deviceCode));
          }).pipe(Effect.provide(layer)),
        ),
      ),
    );

    const successes = results.filter(Result.isSuccess);
    const expired = results.filter(
      (r) =>
        Result.isFailure(r) &&
        r.failure instanceof DevicePollError &&
        r.failure.error === "expired_token",
    );
    expect(successes).toHaveLength(1);
    expect(expired).toHaveLength(1);
    // Exactly one session was created — no duplicate mint.
    expect(MutableHashMap.size(sessions)).toBe(1);
  });

  it("slow_down does not reset the polling window and escalates the interval", async () => {
    const begun = await run((svc) => svc.begin());
    const hash = hashToken(begun.deviceCode);

    // Seed lastPolledAt to 1 second ago — within the 5 s interval.
    const record = Option.getOrUndefined(MutableHashMap.get(records, hash));
    assert(record !== undefined, "begin stored the request");
    const lastPolled = DateTime.toEpochMillis(DateTime.nowUnsafe()) - 1000;
    MutableHashMap.set(records, hash, { ...record, lastPolledAt: lastPolled });

    const err = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    assert.instanceOf(err, DevicePollError);
    expect(err.error).toBe("slow_down");

    const updated = Option.getOrUndefined(MutableHashMap.get(records, hash));
    assert(updated !== undefined, "the request is still stored");

    // lastPolledAt must NOT advance — the rejected poll must not reset the window.
    expect(updated.lastPolledAt).toBe(lastPolled);
    // Interval escalates by 5 s per RFC 8628 §3.5.
    expect(updated.interval).toBe(record.interval + 5);
  });
});
