/**
 * Drizzle `UserServiceStore`, for `UserService`, `AccountManagementService` and
 * `AdminService`: `get` is `UserStore`'s projection, `update` writes the user
 * whole in one `UPDATE`, and `delete` removes the row only. It takes `Tables`
 * or a `defineSchema` mapping, as `UserStore` does.
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
