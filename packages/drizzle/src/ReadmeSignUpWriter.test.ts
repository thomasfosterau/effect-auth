/**
 * The README's sign-up writer examples (#406), compiled and run.
 *
 * The writers live in `testing/readme/`, between `README:begin` and
 * `README:end` markers, so the type check covers them; the first test checks the
 * README shows each one verbatim. The rest run them on PGlite against a NOT NULL
 * users table and a nullable one, both mapping `email_verified_at`.
 */

import type { PGlite } from "@electric-sql/pglite";
import { count, eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/pglite";
import { Effect, Layer } from "effect";
import { readFile } from "node:fs/promises";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer } from "./Database.ts";
import { defineUsers, layer } from "./SingleTableIdentifierStore.ts";
import { migratedPglite, truncate } from "./testing/PgliteTemplate.ts";
import { createUser as notNullWriter } from "./testing/readme/NotNullWriter.ts";
import { createUser as nullableWriter } from "./testing/readme/NullableWriter.ts";
import { notNullUsers, nullableUsers, readmeTablesSql, setDb } from "./testing/readme/tables.ts";

let client: PGlite;

beforeAll(async () => {
  client = await migratedPglite();
  await client.exec(readmeTablesSql);
  setDb(drizzle(client));
});

afterAll(async () => {
  await client?.close();
});

beforeEach(async () => {
  await truncate(client, ["app_users_readme_strict", "app_users_readme"]);
});

const verifiedAt = new Date(Date.UTC(2026, 9, 15));
const ada: Auth.NewUserIdentifier = {
  type: "email",
  value: "ada@example.com",
  verified: true,
  verifiedAt,
};

const region = async (file: string): Promise<string> => {
  const source = await readFile(new URL(file, import.meta.url), "utf8");
  const match = /\/\/ README:begin\n([\s\S]*?)\/\/ README:end\n/.exec(source);
  if (match?.[1] === undefined) throw new Error(`${file} has no README region`);
  return match[1];
};

describe("README: sign-up writer examples", () => {
  it("the README shows each compiled writer verbatim", async () => {
    const readme = await readFile(new URL("../README.md", import.meta.url), "utf8");
    for (const file of [
      "./testing/readme/NotNullWriter.ts",
      "./testing/readme/NullableWriter.ts",
    ]) {
      expect(readme).toContain("```ts\n" + (await region(file)) + "```");
    }
  });

  it("NOT NULL: inserts the row with the address and its verification, and reports created", async () => {
    const result = await Effect.runPromise(notNullWriter({ name: "Ada", identifier: ada }));

    expect(result.created).toBe(true);
    const rows = await drizzle(client)
      .select()
      .from(notNullUsers)
      .where(eq(notNullUsers.userId, result.user.id));
    expect(rows).toMatchObject([
      { name: "Ada", email: ada.value, emailVerified: true, emailVerifiedAt: verifiedAt },
    ]);
  });

  it("NOT NULL: fails with AuthError when there is no email address, and inserts nothing", async () => {
    const error = await Effect.runPromise(Effect.flip(notNullWriter({ name: "Nobody" })));

    expect(error).toBeInstanceOf(Auth.AuthError);
    const [row] = await drizzle(client).select({ n: count() }).from(notNullUsers);
    expect(row?.n).toBe(0);
  });

  it("nullable: inserts NULL when there is no address, and the address when there is one", async () => {
    const without = await Effect.runPromise(nullableWriter({}));
    const withAddress = await Effect.runPromise(nullableWriter({ identifier: ada }));

    expect([without.created, withAddress.created]).toEqual([true, true]);
    const read = async (id: string) =>
      (
        await drizzle(client)
          .select({
            email: nullableUsers.email,
            emailVerified: nullableUsers.emailVerified,
            emailVerifiedAt: nullableUsers.emailVerifiedAt,
          })
          .from(nullableUsers)
          .where(eq(nullableUsers.userId, id))
      )[0];
    expect(await read(without.user.id)).toEqual({
      email: null,
      emailVerified: false,
      emailVerifiedAt: null,
    });
    expect(await read(withAddress.user.id)).toEqual({
      email: ada.value,
      emailVerified: true,
      emailVerifiedAt: verifiedAt,
    });
  });

  it("NOT NULL: core's claim finds the address the writer put on the row", async () => {
    const users = defineUsers({
      table: notNullUsers,
      columns: {
        id: "userId",
        email: "email",
        emailVerified: "emailVerified",
        emailVerifiedAt: "emailVerifiedAt",
        createdAt: "createdAt",
      },
    });

    const created = await Effect.runPromise(
      Effect.gen(function* () {
        const identifiers = yield* Auth.IdentifierStore;
        return yield* Auth.createUserWithIdentifier(identifiers, ada, (identifier) =>
          notNullWriter({ identifier }),
        );
      }).pipe(Effect.provide(layer(users).pipe(Layer.provide(databaseLayer(drizzle(client)))))),
    );

    expect(created.identifier).toMatchObject({
      id: created.user.id,
      userId: created.user.id,
      value: ada.value,
      verified: true,
      verifiedAt,
    });
  });
});
