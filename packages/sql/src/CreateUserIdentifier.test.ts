/**
 * effect-auth-sql keeps identifiers in `auth_identifiers`, apart from the user
 * row, so it ignores the `identifier` core passes to `createUser` (#380): every
 * `createUser` seam inserts the user with no identifier, and the claim that
 * follows records the address, as it does without the field.
 */

import type { PGlite } from "@electric-sql/pglite";
import * as PgliteClient from "@effect/sql-pglite/PgliteClient";
import { Effect, Layer } from "effect";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { layer } from "./Stores.ts";
import { migratedPglite } from "./testing/PgliteTemplate.ts";

let database: PGlite;

beforeAll(async () => {
  database = await migratedPglite();
});

afterAll(async () => {
  await database?.close();
});

type Stores = Layer.Success<typeof layer>;

const run = <A, E>(program: Effect.Effect<A, E, Stores>): Promise<A> =>
  Effect.runPromise(
    program.pipe(
      Effect.provide(layer.pipe(Layer.provide(PgliteClient.layer({ liveClient: database })))),
    ) as Effect.Effect<A, E>,
  );

const identifierFor = (value: string): Auth.NewUserIdentifier => ({
  type: "email",
  value,
  verified: true,
  verifiedAt: new Date(Date.UTC(2026, 9, 15)),
});

describe("effect-auth-sql: createUser ignores the identifier", () => {
  it("every createUser seam inserts the user without an identifier", async () => {
    const result = await run(
      Effect.gen(function* () {
        const identifiers = yield* Auth.IdentifierStore;
        const created = [
          yield* (yield* Auth.Email.EmailPasswordStore).createUser({
            identifier: identifierFor("password@example.com"),
          }),
          yield* (yield* Auth.OAuth.OAuthUserStore).createUser({
            identifier: identifierFor("oauth@example.com"),
          }),
          yield* (yield* Auth.MagicLinkUserStore).createUser({
            identifier: identifierFor("link@example.com"),
          }),
          yield* (yield* Auth.Email.EmailOtpUserStore).createUser({
            identifier: identifierFor("otp@example.com"),
          }),
          yield* (yield* Auth.AdminUserStore).createUser({
            identifier: identifierFor("admin@example.com"),
          }),
        ];
        const held = [];
        for (const user of created) held.push(...(yield* identifiers.listByUser(user.id)));
        return { created, held };
      }),
    );

    expect(result.created).toHaveLength(5);
    expect(result.held).toEqual([]);
  });

  it("the claim that follows records the address in auth_identifiers", async () => {
    const result = await run(
      Effect.gen(function* () {
        const identifiers = yield* Auth.IdentifierStore;
        const store = yield* Auth.Email.EmailPasswordStore;
        const created = yield* Auth.createUserWithIdentifier(
          identifiers,
          identifierFor("ada@example.com"),
          (identifier) => store.createUser({ identifier }),
        );
        return { created, listed: yield* identifiers.listByUser(created.user.id) };
      }),
    );

    expect(result.listed).toEqual([result.created.identifier]);
    expect(result.created.identifier).toMatchObject({
      userId: result.created.user.id,
      type: "email",
      value: "ada@example.com",
      verified: true,
    });
  });
});
