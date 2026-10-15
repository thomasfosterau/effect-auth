import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { KeyValueStore } from "effect/persistence";
import {
  IdentifierStore,
  type Identifier,
  makeIdentifier,
  memoryIdentifierStore,
  primaryEmail,
  primaryEmailValue,
  replaceIdentifier,
} from "./Identifier.ts";
import { IdentifierStoreKV } from "./KeyValueStores.ts";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const testLayer = () => IdentifierStoreKV.pipe(Layer.provide(KeyValueStore.layerMemory));

const run = <A, E>(effect: Effect.Effect<A, E, IdentifierStore>): Promise<A> =>
  Effect.runPromise(effect.pipe(Effect.provide(testLayer())) as Effect.Effect<A, E>);

const now = new Date("2026-07-04T00:00:00.000Z");

const mkIdentifier = (overrides: Partial<Identifier> = {}): Identifier => ({
  id: "id-1",
  userId: "user-1",
  type: "email",
  value: "alice@example.com",
  verified: false,
  createdAt: now,
  ...overrides,
});

// ---------------------------------------------------------------------------
// IdentifierStoreKV — create / getByValue / listByUser
// ---------------------------------------------------------------------------

describe("IdentifierStoreKV", () => {
  it("create and getByValue roundtrip", async () => {
    const identifier = mkIdentifier();
    const result = await run(
      Effect.gen(function* () {
        const store = yield* IdentifierStore;
        yield* store.create(identifier);
        return yield* store.getByValue("email", "alice@example.com");
      }),
    );
    expect(result).not.toBeNull();
    expect(result?.id).toBe("id-1");
    expect(result?.userId).toBe("user-1");
    expect(result?.type).toBe("email");
    expect(result?.value).toBe("alice@example.com");
    expect(result?.verified).toBe(false);
    expect(result?.createdAt).toEqual(now);
  });

  it("getByValue returns null for unknown (type, value)", async () => {
    const result = await run(
      Effect.gen(function* () {
        const store = yield* IdentifierStore;
        return yield* store.getByValue("email", "unknown@example.com");
      }),
    );
    expect(result).toBeNull();
  });

  it("listByUser returns empty array for unknown user", async () => {
    const result = await run(
      Effect.gen(function* () {
        const store = yield* IdentifierStore;
        return yield* store.listByUser("no-such-user");
      }),
    );
    expect(result).toEqual([]);
  });

  it("listByUser returns all identifiers for a user sorted by createdAt", async () => {
    const a = mkIdentifier({
      id: "id-email",
      type: "email",
      value: "alice@example.com",
      createdAt: new Date("2026-07-04T01:00:00.000Z"),
    });
    const b = mkIdentifier({
      id: "id-username",
      type: "username",
      value: "alice",
      createdAt: new Date("2026-07-04T02:00:00.000Z"),
    });
    const c = mkIdentifier({
      id: "id-phone",
      type: "phone",
      value: "+61400000000",
      createdAt: new Date("2026-07-04T00:30:00.000Z"),
    });
    const result = await run(
      Effect.gen(function* () {
        const store = yield* IdentifierStore;
        yield* store.create(a);
        yield* store.create(b);
        yield* store.create(c);
        return yield* store.listByUser("user-1");
      }),
    );
    expect(result).toHaveLength(3);
    // ordered by createdAt ascending
    expect(result[0]?.id).toBe("id-phone");
    expect(result[1]?.id).toBe("id-email");
    expect(result[2]?.id).toBe("id-username");
  });

  it("listByUser only returns identifiers for the requested user", async () => {
    const a = mkIdentifier({ id: "id-u1", userId: "user-1", value: "a@example.com" });
    const b = mkIdentifier({ id: "id-u2", userId: "user-2", value: "b@example.com" });
    const result = await run(
      Effect.gen(function* () {
        const store = yield* IdentifierStore;
        yield* store.create(a);
        yield* store.create(b);
        return yield* store.listByUser("user-1");
      }),
    );
    expect(result).toHaveLength(1);
    expect(result[0]?.id).toBe("id-u1");
  });

  // -------------------------------------------------------------------------
  // setVerified
  // -------------------------------------------------------------------------

  it("setVerified marks an identifier as verified and records verifiedAt", async () => {
    const identifier = mkIdentifier();
    const verifiedAt = new Date("2026-07-04T12:00:00.000Z");
    const result = await run(
      Effect.gen(function* () {
        const store = yield* IdentifierStore;
        yield* store.create(identifier);
        return yield* store.setVerified("id-1", verifiedAt);
      }),
    );
    expect(result).not.toBeNull();
    expect(result?.verified).toBe(true);
    expect(result?.verifiedAt).toEqual(verifiedAt);
  });

  it("setVerified returns null for unknown id", async () => {
    const result = await run(
      Effect.gen(function* () {
        const store = yield* IdentifierStore;
        return yield* store.setVerified("no-such-id", new Date());
      }),
    );
    expect(result).toBeNull();
  });

  it("setVerified preserves the updated record in getByValue", async () => {
    const identifier = mkIdentifier();
    const verifiedAt = new Date("2026-07-04T12:00:00.000Z");
    const fetched = await run(
      Effect.gen(function* () {
        const store = yield* IdentifierStore;
        yield* store.create(identifier);
        yield* store.setVerified("id-1", verifiedAt);
        return yield* store.getByValue("email", "alice@example.com");
      }),
    );
    expect(fetched?.verified).toBe(true);
    expect(fetched?.verifiedAt).toEqual(verifiedAt);
  });

  // -------------------------------------------------------------------------
  // delete
  // -------------------------------------------------------------------------

  it("delete removes a single identifier and clears indexes", async () => {
    const identifier = mkIdentifier();
    const result = await run(
      Effect.gen(function* () {
        const store = yield* IdentifierStore;
        yield* store.create(identifier);
        yield* store.delete("id-1");
        const byValue = yield* store.getByValue("email", "alice@example.com");
        const byUser = yield* store.listByUser("user-1");
        return { byValue, byUser };
      }),
    );
    expect(result.byValue).toBeNull();
    expect(result.byUser).toHaveLength(0);
  });

  it("delete is a no-op for unknown id", async () => {
    await expect(
      run(
        Effect.gen(function* () {
          const store = yield* IdentifierStore;
          return yield* store.delete("no-such-id");
        }),
      ),
    ).resolves.toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // deleteByUser
  // -------------------------------------------------------------------------

  it("deleteByUser removes all identifiers for a user", async () => {
    const a = mkIdentifier({ id: "id-1", value: "a@example.com" });
    const b = mkIdentifier({ id: "id-2", type: "username", value: "alice" });
    const result = await run(
      Effect.gen(function* () {
        const store = yield* IdentifierStore;
        yield* store.create(a);
        yield* store.create(b);
        yield* store.deleteByUser("user-1");
        const byUser = yield* store.listByUser("user-1");
        const byEmail = yield* store.getByValue("email", "a@example.com");
        const byUsername = yield* store.getByValue("username", "alice");
        return { byUser, byEmail, byUsername };
      }),
    );
    expect(result.byUser).toHaveLength(0);
    expect(result.byEmail).toBeNull();
    expect(result.byUsername).toBeNull();
  });

  it("deleteByUser does not affect other users", async () => {
    const a = mkIdentifier({ id: "id-u1", userId: "user-1", value: "a@example.com" });
    const b = mkIdentifier({ id: "id-u2", userId: "user-2", value: "b@example.com" });
    const result = await run(
      Effect.gen(function* () {
        const store = yield* IdentifierStore;
        yield* store.create(a);
        yield* store.create(b);
        yield* store.deleteByUser("user-1");
        return yield* store.listByUser("user-2");
      }),
    );
    expect(result).toHaveLength(1);
    expect(result[0]?.id).toBe("id-u2");
  });

  it("deleteByUser is a no-op for unknown user", async () => {
    await expect(
      run(
        Effect.gen(function* () {
          const store = yield* IdentifierStore;
          return yield* store.deleteByUser("no-such-user");
        }),
      ),
    ).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// replace — the same contract over the in-memory and KeyValueStore stores
// ---------------------------------------------------------------------------

const replaceStores: ReadonlyArray<readonly [string, () => Layer.Layer<IdentifierStore>]> = [
  ["memoryIdentifierStore", () => Layer.succeed(IdentifierStore)(memoryIdentifierStore())],
  ["IdentifierStoreKV", testLayer],
];

for (const [label, makeLayer] of replaceStores) {
  const runOn = <A, E>(effect: Effect.Effect<A, E, IdentifierStore>): Promise<A> =>
    Effect.runPromise(effect.pipe(Effect.provide(makeLayer())) as Effect.Effect<A, E>);
  const email = (userId: string, value: string, verified = false) =>
    makeIdentifier({ userId, type: "email", value, verified });

  describe(`${label}: replace`, () => {
    it("swaps the user's identifier for the new one and releases the old value", async () => {
      const result = await runOn(
        Effect.gen(function* () {
          const store = yield* IdentifierStore;
          const alice = yield* store.create(email("user-1", "alice@example.com"));
          const replaced = yield* store.replace(
            alice,
            email("user-1", "alice-new@example.com", true),
          );
          return {
            replaced,
            listed: yield* store.listByUser("user-1"),
            old: yield* store.getByValue("email", "alice@example.com"),
          };
        }),
      );
      expect(result.replaced?.value).toBe("alice-new@example.com");
      expect(result.listed.map((i) => [i.value, i.verified])).toEqual([
        ["alice-new@example.com", true],
      ]);
      expect(result.old).toBeNull();
    });

    it("refuses a value another user holds with AuthError (IdentifierTakenError through replaceIdentifier) and keeps the old one", async () => {
      const result = await runOn(
        Effect.gen(function* () {
          const store = yield* IdentifierStore;
          const alice = yield* store.create(email("user-1", "alice@example.com", true));
          yield* store.create(email("user-2", "bob@example.com"));
          return {
            refused: yield* Effect.flip(store.replace(alice, email("user-1", "bob@example.com"))),
            taken: yield* Effect.flip(
              replaceIdentifier(store, alice, email("user-1", "bob@example.com")),
            ),
            listed: yield* store.listByUser("user-1"),
            bob: yield* store.getByValue("email", "bob@example.com"),
          };
        }),
      );
      expect(result.refused._tag).toBe("AuthError");
      expect(result.taken._tag).toBe("IdentifierTakenError");
      expect(result.listed.map((i) => [i.value, i.verified])).toEqual([
        ["alice@example.com", true],
      ]);
      expect(result.bob?.userId).toBe("user-2");
    });

    it("resolves to null for an identifier the user no longer holds (IdentifierNotFoundError through replaceIdentifier), writing nothing", async () => {
      const result = await runOn(
        Effect.gen(function* () {
          const store = yield* IdentifierStore;
          const alice = yield* store.create(email("user-1", "alice@example.com"));
          const stale = { ...alice, value: "alice-old@example.com" };
          return {
            replaced: yield* store.replace(stale, email("user-1", "alice-new@example.com")),
            notFound: yield* Effect.flip(
              replaceIdentifier(store, stale, email("user-1", "alice-new@example.com")),
            ),
            listed: yield* store.listByUser("user-1"),
          };
        }),
      );
      expect(result.replaced).toBeNull();
      expect(result.notFound._tag).toBe("IdentifierNotFoundError");
      expect(result.listed.map((i) => i.value)).toEqual(["alice@example.com"]);
    });

    it("refuses a replacement for another user, of another type, with the same id, or of the same value", async () => {
      const result = await runOn(
        Effect.gen(function* () {
          const store = yield* IdentifierStore;
          const alice = yield* store.create(email("user-1", "alice@example.com"));
          return {
            otherUser: yield* Effect.flip(store.replace(alice, email("user-2", "x@example.com"))),
            otherType: yield* Effect.flip(
              store.replace(
                alice,
                makeIdentifier({ userId: "user-1", type: "username", value: "alice" }),
              ),
            ),
            // Reusing `from`'s id would make the claim overwrite `from`, so the
            // release would take the replacement with it.
            sameId: yield* Effect.flip(
              store.replace(alice, { ...email("user-1", "alice-new@example.com"), id: alice.id }),
            ),
            sameValue: yield* Effect.flip(
              store.replace(alice, email("user-1", "alice@example.com", true)),
            ),
            listed: yield* store.listByUser("user-1"),
          };
        }),
      );
      expect(result.otherUser._tag).toBe("AuthError");
      expect(result.otherType._tag).toBe("AuthError");
      expect(result.sameId._tag).toBe("AuthError");
      expect(result.sameValue._tag).toBe("AuthError");
      expect(result.listed.map((i) => [i.value, i.verified])).toEqual([
        ["alice@example.com", false],
      ]);
    });
  });
}

// ---------------------------------------------------------------------------
// primaryEmail helper
// ---------------------------------------------------------------------------

describe("primaryEmail", () => {
  it("returns null for an empty list", () => {
    expect(primaryEmail([])).toBeNull();
  });

  it("returns null when no email identifiers exist", () => {
    const phone = mkIdentifier({ type: "phone", value: "+61400000000", verified: true });
    expect(primaryEmail([phone])).toBeNull();
  });

  it("returns null when email exists but is unverified", () => {
    const email = mkIdentifier({ type: "email", verified: false });
    expect(primaryEmail([email])).toBeNull();
  });

  it("returns the verified email", () => {
    const email = mkIdentifier({ type: "email", verified: true });
    expect(primaryEmail([email])).toEqual(email);
  });

  it("returns the earliest verified email when multiple exist", () => {
    const older = mkIdentifier({
      id: "id-old",
      type: "email",
      value: "old@example.com",
      verified: true,
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    });
    const newer = mkIdentifier({
      id: "id-new",
      type: "email",
      value: "new@example.com",
      verified: true,
      createdAt: new Date("2026-06-01T00:00:00.000Z"),
    });
    expect(primaryEmail([newer, older])?.id).toBe("id-old");
  });

  it("ignores unverified emails when selecting primary", () => {
    const unverified = mkIdentifier({
      id: "id-unverified",
      type: "email",
      value: "early@example.com",
      verified: false,
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    });
    const verified = mkIdentifier({
      id: "id-verified",
      type: "email",
      value: "later@example.com",
      verified: true,
      createdAt: new Date("2026-06-01T00:00:00.000Z"),
    });
    expect(primaryEmail([unverified, verified])?.id).toBe("id-verified");
  });
});

// ---------------------------------------------------------------------------
// primaryEmailValue helper
// ---------------------------------------------------------------------------

describe("primaryEmailValue", () => {
  it("returns null for empty list", () => {
    expect(primaryEmailValue([])).toBeNull();
  });

  it("returns the email value string for a verified email", () => {
    const email = mkIdentifier({ type: "email", value: "alice@example.com", verified: true });
    expect(primaryEmailValue([email])).toBe("alice@example.com");
  });
});
