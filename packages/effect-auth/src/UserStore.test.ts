import { describe, it, expect } from "vite-plus/test";
import { Effect } from "effect";
import { AuthError } from "./Errors.ts";
import {
  type Identifier,
  IdentifierTakenError,
  makeIdentifier,
  memoryIdentifierStore,
} from "./Identifier.ts";
import { createUserWithIdentifier, type NewUserIdentifier } from "./UserStore.ts";
import type { User } from "./Types.ts";

const now = new Date("2026-10-15T00:00:00.000Z");

const makeUser = (id: string): User => ({ id, createdAt: now, updatedAt: now, attributes: {} });

const email: NewUserIdentifier = { type: "email", value: "ada@example.com", verified: false };

/**
 * A user writer that keeps the address on the user row, as a single-table
 * store does: the identifier it was given is held from the insert on, with the
 * user's id as its id. A unique index on the address rejects a held one.
 */
const rowWriter = (records: Map<string, Identifier>, id: string, written?: Partial<Identifier>) => {
  const inputs: Array<NewUserIdentifier | undefined> = [];
  const create = (identifier: NewUserIdentifier) =>
    Effect.suspend(() => {
      inputs.push(identifier);
      for (const held of records.values()) {
        if (held.type === identifier.type && held.value === identifier.value) {
          return Effect.fail(new AuthError({ message: "unique index on users.email" }));
        }
      }
      records.set(id, {
        id,
        userId: id,
        type: identifier.type,
        value: identifier.value,
        verified: identifier.verified,
        ...(identifier.verifiedAt !== undefined && { verifiedAt: identifier.verifiedAt }),
        createdAt: now,
        ...written,
      });
      return Effect.succeed(makeUser(id));
    });
  return { create, inputs };
};

/** A user writer that keeps identifiers elsewhere, and so ignores the field. */
const tableWriter = (id: string) => {
  const inputs: Array<NewUserIdentifier | undefined> = [];
  const create = (identifier: NewUserIdentifier) =>
    Effect.sync(() => {
      inputs.push(identifier);
      return makeUser(id);
    });
  return { create, inputs };
};

describe("createUserWithIdentifier", () => {
  it("passes the identifier to create, and claims it in a store that keeps identifiers apart", async () => {
    const records = new Map<string, Identifier>();
    const writer = tableWriter("u-1");

    const result = await Effect.runPromise(
      createUserWithIdentifier(memoryIdentifierStore(records), email, writer.create),
    );

    expect(writer.inputs).toEqual([email]);
    expect(result.user.id).toBe("u-1");
    expect(result.identifier).toMatchObject({
      userId: "u-1",
      type: "email",
      value: "ada@example.com",
      verified: false,
    });
    expect([...records.values()]).toEqual([result.identifier]);
  });

  it("finds the address already held when the store wrote it into the user row", async () => {
    const records = new Map<string, Identifier>();
    const writer = rowWriter(records, "u-1");

    const result = await Effect.runPromise(
      createUserWithIdentifier(memoryIdentifierStore(records), email, writer.create),
    );

    expect(writer.inputs).toEqual([email]);
    // The row's record, not a second claim: one identifier, keyed by the user.
    expect(result.identifier).toEqual(records.get("u-1"));
    expect(records.size).toBe(1);
  });

  it("marks the held address verified when the flow asked for a verified one", async () => {
    const records = new Map<string, Identifier>();
    const verifiedAt = new Date("2026-10-15T01:00:00.000Z");
    // A writer that stores the address but not its verification.
    const writer = rowWriter(records, "u-1", { verified: false });

    const result = await Effect.runPromise(
      createUserWithIdentifier(
        memoryIdentifierStore(records),
        { ...email, verified: true, verifiedAt },
        writer.create,
      ),
    );

    expect(result.identifier).toMatchObject({ id: "u-1", verified: true, verifiedAt });
    expect(records.get("u-1")).toMatchObject({ verified: true, verifiedAt });
  });

  it("fails with IdentifierTakenError when another user holds the address before the claim", async () => {
    const records = new Map<string, Identifier>();
    const other = makeIdentifier({ userId: "u-0", type: "email", value: email.value });
    records.set(other.id, other);
    const writer = tableWriter("u-1");

    const error = await Effect.runPromise(
      Effect.flip(createUserWithIdentifier(memoryIdentifierStore(records), email, writer.create)),
    );

    expect(error).toBeInstanceOf(IdentifierTakenError);
    expect([...records.values()]).toEqual([other]);
  });

  it("fails with IdentifierTakenError when the row's unique index rejects the insert", async () => {
    const records = new Map<string, Identifier>();
    const other = makeIdentifier({ userId: "u-0", type: "email", value: email.value });
    records.set(other.id, other);
    const writer = rowWriter(records, "u-1");

    const error = await Effect.runPromise(
      Effect.flip(createUserWithIdentifier(memoryIdentifierStore(records), email, writer.create)),
    );

    expect(error).toBeInstanceOf(IdentifierTakenError);
    expect(writer.inputs).toEqual([email]);
    expect(records.has("u-1")).toBe(false);
  });

  it("passes any other failure of create through", async () => {
    const records = new Map<string, Identifier>();
    const failure = new AuthError({ message: "database unavailable" });

    const error = await Effect.runPromise(
      Effect.flip(
        createUserWithIdentifier(memoryIdentifierStore(records), email, () => Effect.fail(failure)),
      ),
    );

    expect(error).toBe(failure);
  });
});
