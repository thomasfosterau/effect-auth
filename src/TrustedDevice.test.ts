import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Effect, Redacted } from "effect";
import { AuthError } from "./Errors.js";
import { Hooks } from "./Hooks.js";
import {
  makeTrustedDeviceService,
  makeTrustedDeviceGateShape,
  TrustedDeviceCookieRef,
  TrustedDeviceStore,
  type TrustedDeviceRecord,
} from "./TrustedDevice.js";
import type { User } from "./Types.js";

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

const deviceRecords = new Map<string, TrustedDeviceRecord>(); // key: tokenHash

const deviceStore = {
  upsert: (record: TrustedDeviceRecord) =>
    Effect.sync(() => {
      deviceRecords.set(record.tokenHash, record);
      return record;
    }),

  getByTokenHash: (tokenHash: string) => Effect.sync(() => deviceRecords.get(tokenHash) ?? null),

  delete: (tokenHash: string) =>
    Effect.sync(() => {
      deviceRecords.delete(tokenHash);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      for (const [hash, record] of deviceRecords.entries()) {
        if (record.userId === userId) {
          deviceRecords.delete(hash);
        }
      }
    }),
};

const storeCtx = Context.make(TrustedDeviceStore, deviceStore);

const testConfig = { secret: Redacted.make("test-hmac-secret-32bytes-exactly!!") };

const testUser: User = {
  id: "user-td-1",
  email: "alice@example.com",
  emailVerified: true,
  createdAt: new Date(),
  updatedAt: new Date(),
  attributes: {},
};

beforeEach(() => {
  deviceRecords.clear();
});

// ---------------------------------------------------------------------------
// TrustedDeviceService
// ---------------------------------------------------------------------------

describe("TrustedDeviceService", () => {
  it("issues a cookie and verifies it successfully", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeTrustedDeviceService(testConfig);
      const { cookieValue, expiresAt } = yield* service.issue(testUser.id);
      const verifiedId = yield* service.verify(cookieValue);
      return { cookieValue, expiresAt, verifiedId };
    }).pipe(Effect.provide(storeCtx));

    const { cookieValue, expiresAt, verifiedId } = await Effect.runPromise(
      Effect.provide(program, Hooks.Default),
    );

    expect(cookieValue).toContain(".");
    expect(expiresAt).toBeGreaterThan(Date.now());
    expect(verifiedId).toBe(testUser.id);
    expect(deviceRecords.size).toBe(1);
  });

  it("stores only the hash, not the raw token", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeTrustedDeviceService(testConfig);
      const { cookieValue } = yield* service.issue(testUser.id);
      return cookieValue;
    }).pipe(Effect.provide(storeCtx));

    const cookieValue = await Effect.runPromise(Effect.provide(program, Hooks.Default));
    const rawToken = cookieValue.split(".").slice(0, -1).join(".");

    // The raw token must never appear in the stored record
    for (const record of deviceRecords.values()) {
      expect(record.tokenHash).not.toBe(rawToken);
    }
    expect(deviceRecords.size).toBe(1);
  });

  it("returns null for a tampered HMAC", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeTrustedDeviceService(testConfig);
      const { cookieValue } = yield* service.issue(testUser.id);
      // Flip a character in the HMAC (last segment), ensuring it actually changes
      const parts = cookieValue.split(".");
      const lastIdx = parts.length - 1;
      const lastChar = parts[lastIdx]!.slice(-1);
      const newChar = lastChar === "0" ? "1" : "0";
      parts[lastIdx] = parts[lastIdx]!.slice(0, -1) + newChar;
      const tampered = parts.join(".");
      return yield* service.verify(tampered);
    }).pipe(Effect.provide(storeCtx));

    const result = await Effect.runPromise(Effect.provide(program, Hooks.Default));
    expect(result).toBeNull();
  });

  it("returns null for an expired token", async () => {
    const program = Effect.gen(function* () {
      // maxAge = 1 ms → already expired
      const service = yield* makeTrustedDeviceService({ ...testConfig, maxAge: 1 });
      const { cookieValue } = yield* service.issue(testUser.id);
      // Small wait to ensure expiry
      yield* Effect.sleep("5 millis");
      return yield* service.verify(cookieValue);
    }).pipe(Effect.provide(storeCtx));

    const result = await Effect.runPromise(Effect.provide(program, Hooks.Default));
    expect(result).toBeNull();
    // Expired record must be eagerly deleted
    expect(deviceRecords.size).toBe(0);
  });

  it("revoke removes a specific token", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeTrustedDeviceService(testConfig);
      const { cookieValue } = yield* service.issue(testUser.id);
      yield* service.revoke(cookieValue);
      return yield* service.verify(cookieValue);
    }).pipe(Effect.provide(storeCtx));

    const result = await Effect.runPromise(Effect.provide(program, Hooks.Default));
    expect(result).toBeNull();
    expect(deviceRecords.size).toBe(0);
  });

  it("revokeAll removes every token for a user", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeTrustedDeviceService(testConfig);
      const { cookieValue: c1 } = yield* service.issue(testUser.id);
      const { cookieValue: c2 } = yield* service.issue(testUser.id);
      // Different user's token should survive
      const { cookieValue: c3 } = yield* service.issue("other-user");
      yield* service.revokeAll(testUser.id);
      return {
        v1: yield* service.verify(c1),
        v2: yield* service.verify(c2),
        v3: yield* service.verify(c3),
      };
    }).pipe(Effect.provide(storeCtx));

    const { v1, v2, v3 } = await Effect.runPromise(Effect.provide(program, Hooks.Default));
    expect(v1).toBeNull();
    expect(v2).toBeNull();
    expect(v3).toBe("other-user");
  });

  it("ignores an unrecognised cookie format gracefully", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeTrustedDeviceService(testConfig);
      return {
        empty: yield* service.verify(""),
        noSeparator: yield* service.verify("noseparatorhere"),
        revoke: yield* service.revoke("invalid-cookie"),
      };
    }).pipe(Effect.provide(storeCtx));

    const result = await Effect.runPromise(Effect.provide(program, Hooks.Default));
    expect(result.empty).toBeNull();
    expect(result.noSeparator).toBeNull();
    // revoke with bad cookie should not throw
  });
});

// ---------------------------------------------------------------------------
// makeTrustedDeviceGateShape
// ---------------------------------------------------------------------------

describe("makeTrustedDeviceGateShape", () => {
  const innerRequired = {
    required: (_user: User) => Effect.succeed(true),
    begin: (_user: User) => Effect.fail(new AuthError({ message: "not exercised" })),
  } as any;

  it("required returns false when a valid device token is in TrustedDeviceCookieRef", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeTrustedDeviceService(testConfig);
      const { cookieValue } = yield* service.issue(testUser.id);

      const gate = makeTrustedDeviceGateShape(service, storeCtx, innerRequired);

      return yield* gate
        .required(testUser)
        .pipe(Effect.provide(Context.make(TrustedDeviceCookieRef, cookieValue)));
    }).pipe(Effect.provide(storeCtx));

    const result = await Effect.runPromise(Effect.provide(program, Hooks.Default));
    expect(result).toBe(false);
  });

  it("required delegates to inner gate when TrustedDeviceCookieRef is empty", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeTrustedDeviceService(testConfig);
      const gate = makeTrustedDeviceGateShape(service, storeCtx, innerRequired);

      // Default FiberRef value is undefined — no cookie
      return yield* gate.required(testUser);
    }).pipe(Effect.provide(storeCtx));

    const result = await Effect.runPromise(Effect.provide(program, Hooks.Default));
    // inner gate returns true
    expect(result).toBe(true);
  });

  it("required delegates to inner gate when device token is expired", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeTrustedDeviceService({ ...testConfig, maxAge: 1 });
      const { cookieValue } = yield* service.issue(testUser.id);
      yield* Effect.sleep("5 millis");

      const gate = makeTrustedDeviceGateShape(service, storeCtx, innerRequired);
      return yield* gate
        .required(testUser)
        .pipe(Effect.provide(Context.make(TrustedDeviceCookieRef, cookieValue)));
    }).pipe(Effect.provide(storeCtx));

    const result = await Effect.runPromise(Effect.provide(program, Hooks.Default));
    expect(result).toBe(true);
  });

  it("required delegates to inner gate when device token is revoked", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeTrustedDeviceService(testConfig);
      const { cookieValue } = yield* service.issue(testUser.id);
      yield* service.revokeAll(testUser.id);

      const gate = makeTrustedDeviceGateShape(service, storeCtx, innerRequired);
      return yield* gate
        .required(testUser)
        .pipe(Effect.provide(Context.make(TrustedDeviceCookieRef, cookieValue)));
    }).pipe(Effect.provide(storeCtx));

    const result = await Effect.runPromise(Effect.provide(program, Hooks.Default));
    expect(result).toBe(true);
  });

  it("required delegates when the token belongs to a different user", async () => {
    const program = Effect.gen(function* () {
      const service = yield* makeTrustedDeviceService(testConfig);
      // Issue for a different user
      const { cookieValue } = yield* service.issue("other-user-id");

      const gate = makeTrustedDeviceGateShape(service, storeCtx, innerRequired);
      // testUser.id !== "other-user-id"
      return yield* gate
        .required(testUser)
        .pipe(Effect.provide(Context.make(TrustedDeviceCookieRef, cookieValue)));
    }).pipe(Effect.provide(storeCtx));

    const result = await Effect.runPromise(Effect.provide(program, Hooks.Default));
    expect(result).toBe(true);
  });
});
