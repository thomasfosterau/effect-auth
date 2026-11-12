/**
 * Drizzle-backed implementation of effect-auth's `UserServiceStore` — the
 * store `UserService`, `AccountManagementService` and `AdminService` read,
 * update and delete users through (#728).
 *
 * {@link make} is an `Effect` that reads {@link DrizzleDatabase} out of context
 * and returns a plain store object; {@link layer} lifts it into a `Layer` keyed
 * by `Auth.UserServiceStore`. Both take an optional schema — any dialect's
 * {@link Tables} under any names, or an {@link AuthSchema} mapped onto the
 * application's own table — exactly as `UserStore` does.
 *
 * ### Contract notes
 *
 * - `get` reads through `UserStore`'s projection, so it returns the same user
 *   (promoted columns included, `password_hash` never), and `null` on a miss.
 * - `update` is one `UPDATE` of the user's row that writes `name`, `image`
 *   (`NULL` when absent), `updatedAt` and the attributes, then returns the user
 *   it was given, as core's `/sql` store does. The user is written whole: on a
 *   `defineSchema` mapping each attribute declared under `promoted` goes to its
 *   own column (`NULL` when the user no longer has it, which reads back absent),
 *   and every other attribute replaces the bag. Attributes for a users table
 *   with no mapped bag fail with `Auth.AuthError` rather than being dropped —
 *   the rule `EmailPasswordStore.createUser` applies. An update of a missing
 *   user writes nothing and still succeeds.
 * - `delete` removes the user's row only (sessions and identifiers are the
 *   services' to clean up); a delete of a missing user is a no-op.
 * - Every driver failure surfaces as `Auth.AuthError` with the original error
 *   preserved as `cause`.
 */

import { eq } from "drizzle-orm";
import { Effect, Layer } from "effect";
import * as R from "effect/Record";
import * as Auth from "@thomasfosterau/effect-auth";
import { resolveSchema, type SchemaInput, type UserSchema, writeValues } from "./Columns.ts";
import { DrizzleDatabase } from "./Database.ts";
import { promotedKeys, splitAttributes } from "./EmailPasswordStore.ts";
import { makeQuery, selectOne } from "./internal.ts";
import { tables as defaultTables } from "./PgSchema.ts";
import { makeToUser, selection } from "./UserStore.ts";

/** Build a `UserServiceStore` over the ambient {@link DrizzleDatabase}. */
export const make = (
  schema: SchemaInput = defaultTables,
): Effect.Effect<typeof Auth.UserServiceStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const query = makeQuery(yield* DrizzleDatabase);
    const users: UserSchema = resolveSchema(schema).users;
    const column = users.columns;
    const projection = selection(users);
    const toUser = makeToUser(users);
    const keys = promotedKeys(users);
    // Every promoted column, cleared: what a user without that attribute writes.
    const cleared = R.fromEntries(R.values(keys).map((key) => [key, null] as const));

    const update: (typeof Auth.UserServiceStore.Service)["update"] = (user) =>
      Effect.gen(function* () {
        const { columns, bag } = yield* splitAttributes(
          users,
          keys,
          user.attributes,
          "userService.update",
        );
        yield* query("userService.update", (db) =>
          db
            .update(users.table)
            .set({
              ...writeValues(users, {
                name: user.name ?? null,
                image: user.image ?? null,
                attributes: bag,
                updatedAt: user.updatedAt,
              }),
              ...cleared,
              ...columns,
            })
            .where(eq(column.id, user.id))
            .execute(),
        );
        return user;
      });

    return {
      get: (userId) =>
        selectOne(query, "userService.get", projection, users.table, eq(column.id, userId)).pipe(
          Effect.map((row) => (row === null ? null : toUser(row))),
        ),
      update,
      delete: (userId) =>
        query("userService.delete", (db) =>
          db.delete(users.table).where(eq(column.id, userId)).execute(),
        ).pipe(Effect.asVoid),
    } satisfies typeof Auth.UserServiceStore.Service;
  });

/** `UserServiceStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const layer = (
  schema: SchemaInput = defaultTables,
): Layer.Layer<Auth.UserServiceStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.UserServiceStore, make(schema));
