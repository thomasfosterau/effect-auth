import { sha256Hex } from "./testing/Sha256.ts";
import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as MutableHashMap from "effect/MutableHashMap";
import * as Result from "effect/Result";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import {
  DeviceAuthorizationService,
  DeviceAuthorizationStore,
  DevicePollError,
  DeviceCodeError,
  DeviceClientError,
  deviceGrantOf,
  normalizeUserCode,
  type DeviceAuthorizationRecord,
} from "./DeviceAuthorization.ts";
import { SessionStore } from "./SessionStore.ts";
import { UserStore } from "./UserStore.ts";
import { SessionService } from "./SessionService.ts";
import { Hooks } from "./Hooks.ts";
import type * as Types from "./Types.ts";
import { memoryDeviceAuthorizationStore, memorySessionStore } from "./testing/MemoryStores.ts";
import type { SessionTouch } from "./SessionStore.ts";

const records = MutableHashMap.empty<string, DeviceAuthorizationRecord>();
const sessions = MutableHashMap.empty<string, Types.Session>();
const users = MutableHashMap.empty<string, Types.User>();

const store = memoryDeviceAuthorizationStore(records);

const sessionStore: typeof SessionStore.Service = {
  create: (session) =>
    Effect.sync(() => {
      MutableHashMap.set(sessions, session.id, session);
      return session;
    }),
  get: (sessionId) => Effect.sync(() => MutableHashMap.get(sessions, sessionId)),
  update: (session) =>
    Effect.sync(() => {
      MutableHashMap.set(sessions, session.id, session);
      return session;
    }),
  touch: (sessionId: string, touch: SessionTouch) =>
    memorySessionStore(sessions).touch(sessionId, touch),
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
  get: (userId) => Effect.sync(() => MutableHashMap.get(users, userId)),
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
  clients: [{ id: "cli", name: "Example CLI", scopes: ["read", "write"] }],
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
    expect(result.verificationUriComplete).toBe(
      `https://example.com/device?user_code=${encodeURIComponent(result.userCode)}`,
    );
    expect(result.interval).toBe(5);
    // The store is keyed by hash; the returned deviceCode is the raw value.
    const record = Option.getOrUndefined(MutableHashMap.get(records, sha256Hex(result.deviceCode)));
    expect(record?.status).toBe("pending");
  });

  it("returns authorization_pending before approval", async () => {
    const begun = await run((svc) => svc.begin({ clientId: "cli" }));
    const pending = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    assert.instanceOf(pending, DevicePollError);
    expect(pending.error).toBe("authorization_pending");
  });

  it("refuses another client's poll with invalid_grant and leaves the request as it was", async () => {
    const begun = await run((svc) => svc.begin({ clientId: "cli" }));
    const before = Option.getOrUndefined(MutableHashMap.get(records, sha256Hex(begun.deviceCode)));
    const refused = await run((svc) => Effect.flip(svc.poll(begun.deviceCode, "other")));
    assert.instanceOf(refused, DevicePollError);
    expect(refused.error).toBe("invalid_grant");
    // Nothing was written: the owning client's next poll is not slowed.
    expect(MutableHashMap.get(records, sha256Hex(begun.deviceCode))).toEqual(Option.some(before));
    const pending = await run((svc) => Effect.flip(svc.poll(begun.deviceCode, "cli")));
    assert.instanceOf(pending, DevicePollError);
    expect(pending.error).toBe("authorization_pending");
  });

  it("returns a session after approval", async () => {
    // Fresh request so the success poll is the first poll (no slow_down).
    const begun = await run((svc) => svc.begin({ clientId: "cli" }));
    await run((svc) => svc.approve(begun.userCode, "user-1"));
    const result = await run((svc) => svc.poll(begun.deviceCode));
    expect(result.user.id).toBe("user-1");
    expect(result.session.userId).toBe("user-1");
  });

  it("consumes the request on success (user code single use)", async () => {
    const begun = await run((svc) => svc.begin({ clientId: "cli" }));
    await run((svc) => svc.approve(begun.userCode, "user-1"));
    await run((svc) => svc.poll(begun.deviceCode));

    const again = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    assert.instanceOf(again, DevicePollError);
    expect(again.error).toBe("expired_token");
  });

  it("enforces slow_down when polled faster than the interval", async () => {
    const begun = await run((svc) => svc.begin({ clientId: "cli" }));
    // First poll sets lastPolledAt.
    await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    const tooSoon = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    assert.instanceOf(tooSoon, DevicePollError);
    expect(tooSoon.error).toBe("slow_down");
  });

  it("returns access_denied after deny", async () => {
    const begun = await run((svc) => svc.begin({ clientId: "cli" }));
    await run((svc) => svc.deny(begun.userCode, "user-1"));
    const denied = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    assert.instanceOf(denied, DevicePollError);
    expect(denied.error).toBe("access_denied");
  });

  it("returns expired_token once the request has expired", async () => {
    const begun = await run((svc) => svc.begin({ clientId: "cli" }));
    const deviceHash = sha256Hex(begun.deviceCode);
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
    const begun = await run((svc) => svc.begin({ clientId: "cli" }));
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
    const begun = await run((svc) => svc.begin({ clientId: "cli" }));
    const hash = sha256Hex(begun.deviceCode);

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

  it("refuses a client that is not registered", async () => {
    const err = await run((svc) => Effect.flip(svc.begin({ clientId: "intruder" })));
    assert.instanceOf(err, DeviceClientError);
    expect(err.error).toBe("invalid_client");
    expect(MutableHashMap.size(records)).toBe(0);
  });

  it("refuses a scope the client is not registered for", async () => {
    const err = await run((svc) =>
      Effect.flip(svc.begin({ clientId: "cli", scopes: ["read", "admin"] })),
    );
    assert.instanceOf(err, DeviceClientError);
    expect(err.error).toBe("invalid_scope");
    expect(MutableHashMap.size(records)).toBe(0);
  });

  it("looks up the client and scopes a pending code asks for", async () => {
    const begun = await run((svc) => svc.begin({ clientId: "cli", scopes: ["read"] }));
    const request = await run((svc) => svc.lookup(begun.userCode.toLowerCase()));
    expect(request).toMatchObject({
      id: sha256Hex(begun.deviceCode),
      clientId: "cli",
      clientName: "Example CLI",
      scopes: ["read"],
      status: "pending",
    });
    // The id is the device code's digest, never the device code.
    expect(request.id).not.toBe(begun.deviceCode);
  });

  it("answers the decided request from approve and deny", async () => {
    const approved = await run((svc) => svc.begin({ clientId: "cli", scopes: ["write"] }));
    const answer = await run((svc) => svc.approve(approved.userCode, "user-1"));
    expect(answer).toMatchObject({
      clientName: "Example CLI",
      scopes: ["write"],
      status: "approved",
    });
    const denied = await run((svc) => svc.begin({ clientId: "cli" }));
    expect((await run((svc) => svc.deny(denied.userCode, "user-1"))).status).toBe("denied");
  });

  it("records the client and scopes on the session it mints", async () => {
    const begun = await run((svc) => svc.begin({ clientId: "cli", scopes: ["read", "read"] }));
    await run((svc) => svc.approve(begun.userCode, "user-1"));
    const result = await run((svc) => svc.poll(begun.deviceCode));
    const grant = { clientId: "cli", scopes: ["read"] };
    expect(result.grant).toEqual(grant);
    expect(deviceGrantOf(result.session)).toEqual(Option.some(grant));
    const stored = Option.getOrUndefined(MutableHashMap.get(sessions, result.session.id));
    assert(stored !== undefined, "the session is stored");
    expect(deviceGrantOf(stored)).toEqual(Option.some(grant));
  });

  it("refuses a second decision: a denial is never turned into an approval", async () => {
    const begun = await run((svc) => svc.begin({ clientId: "cli" }));
    await run((svc) => svc.deny(begun.userCode, "user-1"));
    const err = await run((svc) => Effect.flip(svc.approve(begun.userCode, "user-1")));
    assert.instanceOf(err, DeviceCodeError);
    const lookup = await run((svc) => Effect.flip(svc.lookup(begun.userCode)));
    assert.instanceOf(lookup, DeviceCodeError);
    const poll = await run((svc) => Effect.flip(svc.poll(begun.deviceCode)));
    assert.instanceOf(poll, DevicePollError);
    expect(poll.error).toBe("access_denied");
  });

  it("a poll racing a denial never writes the old status back", async () => {
    const begun = await run((svc) => svc.begin({ clientId: "cli" }));
    const hash = sha256Hex(begun.deviceCode);
    // A store whose poll-time write is preceded by the user's denial: the
    // poll read `pending`, then the denial lands, then the poll writes.
    const racing: typeof DeviceAuthorizationStore.Service = {
      ...store,
      touch: (deviceCode, touch) =>
        store
          .settle(
            sha256Hex(normalizeUserCode(begun.userCode)),
            {
              status: "denied",
              userId: "user-1",
            },
            0,
          )
          .pipe(Effect.andThen(store.touch(deviceCode, touch))),
    };
    const racingLayer = DeviceAuthorizationService.layer({
      verificationUri: "https://example.com/device",
      clients: [{ id: "cli", name: "Example CLI" }],
    }).pipe(
      Layer.provide(
        Layer.mergeAll(Layer.succeed(DeviceAuthorizationStore)(racing), sessionServiceLayer),
      ),
    );
    const poll = await Effect.runPromise(
      Effect.flip(
        Effect.flatMap(DeviceAuthorizationService, (svc) => svc.poll(begun.deviceCode)),
      ).pipe(Effect.provide(racingLayer)),
    );
    assert.instanceOf(poll, DevicePollError);
    expect(poll.error).toBe("access_denied");
    expect(MutableHashMap.has(records, hash)).toBe(false);
    expect(MutableHashMap.size(sessions)).toBe(0);
  });

  it("refuses a request whose client has since been removed", async () => {
    const begun = await run((svc) => svc.begin({ clientId: "cli" }));
    await run((svc) => svc.approve(begun.userCode, "user-1"));
    const withoutClient = DeviceAuthorizationService.layer({
      verificationUri: "https://example.com/device",
      clients: [],
    }).pipe(Layer.provide(Layer.mergeAll(storeLayer, sessionServiceLayer)));
    const poll = await Effect.runPromise(
      Effect.flip(
        Effect.flatMap(DeviceAuthorizationService, (svc) => svc.poll(begun.deviceCode)),
      ).pipe(Effect.provide(withoutClient)),
    );
    assert.instanceOf(poll, DevicePollError);
    expect(poll.error).toBe("expired_token");
    expect(MutableHashMap.size(sessions)).toBe(0);
  });
});
