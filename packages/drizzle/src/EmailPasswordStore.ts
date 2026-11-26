/**
 * Drizzle `EmailPasswordStore` and `PasswordResetUserStore`, the only stores
 * that read or write `password_hash`. `createUser` inserts the user row alone;
 * promoted attributes go to their columns, and attributes with no mapped bag
 * fail with `AuthError`. A mapping without `passwordHash` cannot build the
 * layer.
 */

import { eq, getTableColumns, type Column } from "drizzle-orm";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import * as Auth from "@thomasfosterau/effect-auth";
import {
  type NullableColumn,
  resolveSchema,
  type SchemaInput,
  type UserSchema,
  writeValues,
} from "./Columns.ts";
import { DrizzleDatabase } from "./Database.ts";
import { queryRunner, type Query, selectOne } from "./internal.ts";
import { tables as defaultTables } from "./PgSchema.ts";
import { userFromRow, selection } from "./UserStore.ts";

/**
 * Each promoted attribute's column, by the key it has on the table object
 * (what an insert's or update's values are keyed by).
 *
 * @internal Also used by `UserServiceStore.update`.
 */
export const promotedKeys = (users: UserSchema): Readonly<Record<string, string>> => {
  const tableColumns = R.toEntries(getTableColumns(users.table));
  const keyOf = (column: Column): string | undefined =>
    Option.getOrUndefined(
      Option.map(
        Arr.findFirst(tableColumns, ([, candidate]) => candidate === column),
        ([key]) => key,
      ),
    );
  return R.filter(R.map(users.promoted, keyOf), (key): key is string => key !== undefined);
};

/**
 * Split a user's attributes into the promoted columns' write values and the
 * bag, failing when the bag is unmapped but needed. `label` names the store
 * call in the error.
 *
 * @internal Also used by `UserServiceStore.update`.
 */
export const splitAttributes = (
  users: UserSchema,
  keys: Readonly<Record<string, string>>,
  attributes: Auth.Attributes,
  label: string,
) => {
  const bag = R.filter(attributes, (_value, name) => !R.has(keys, name));
  const columns = R.mapKeys(
    R.filter(attributes, (_value, name) => R.has(keys, name)),
    (name) => keys[name] ?? name,
  );
  return users.columns.attributes === undefined && !R.isEmptyRecord(bag)
    ? Effect.fail(
        new Auth.AuthError({
          message: `drizzle ${label} failed: the users table has no attribute bag for ${R.keys(bag).join(", ")}`,
        }),
      )
    : Effect.succeed({ columns, bag });
};

/** The users table's password column, or a defect naming what is missing. */
const passwordColumn = (users: UserSchema): Effect.Effect<NullableColumn<string>> =>
  users.columns.passwordHash === undefined
    ? Effect.die(
        new Auth.AuthError({
          message:
            "EmailPasswordStore needs the users table's password hash: map `passwordHash` in defineSchema",
        }),
      )
    : Effect.succeed(users.columns.passwordHash);

/** Write `hash` (or `NULL`) as the user's password. */
const writePassword = (
  query: Query,
  users: UserSchema,
  label: string,
  userId: string,
  hash: string | null,
) =>
  query(label, (db) =>
    db
      .update(users.table)
      .set(writeValues(users, { passwordHash: hash }))
      .where(eq(users.columns.id, userId))
      .execute(),
  ).pipe(Effect.asVoid);

/** Build an `EmailPasswordStore` over the ambient {@link DrizzleDatabase}. */
export const make = (
  schema: SchemaInput = defaultTables,
): Effect.Effect<typeof Auth.Email.EmailPasswordStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const query = queryRunner(yield* DrizzleDatabase);
    const users = resolveSchema(schema).users;
    const password = yield* passwordColumn(users);
    const column = users.columns;
    const projection = selection(users);
    const toUser = userFromRow(users);
    const keys = promotedKeys(users);

    const readUser = (userId: string) =>
      selectOne(
        query,
        "emailPassword.createUser.read",
        projection,
        users.table,
        eq(column.id, userId),
      ).pipe(Effect.map(Option.map(toUser)));

    const createUser: (typeof Auth.Email.EmailPasswordStore.Service)["createUser"] = (input) =>
      Effect.gen(function* () {
        const { columns, bag } = yield* splitAttributes(
          users,
          keys,
          input.attributes ?? {},
          "emailPassword.createUser",
        );
        const id = globalThis.crypto.randomUUID();
        const now = yield* DateTime.nowAsDate;
        yield* query("emailPassword.createUser", (db) =>
          db
            .insert(users.table)
            .values({
              ...writeValues(users, {
                id,
                name: input.name ?? null,
                image: input.image ?? null,
                attributes: bag,
                createdAt: now,
                updatedAt: now,
              }),
              ...columns,
            })
            .execute(),
        );
        const user = yield* readUser(id);
        if (Option.isNone(user)) {
          return yield* new Auth.AuthError({
            message: "drizzle emailPassword.createUser failed: the inserted user was not found",
          });
        }
        return { user: user.value, created: true };
      });

    return {
      createUser,
      getPasswordHash: (userId) =>
        selectOne(
          query,
          "emailPassword.getPasswordHash",
          { hash: password },
          users.table,
          eq(column.id, userId),
        ).pipe(Effect.map(Option.flatMap((row) => Option.fromNullishOr(row.hash)))),
      setPasswordHash: (userId, hash) =>
        writePassword(query, users, "emailPassword.setPasswordHash", userId, hash),
      clearPasswordHash: (userId) =>
        writePassword(query, users, "emailPassword.clearPasswordHash", userId, null),
    } satisfies typeof Auth.Email.EmailPasswordStore.Service;
  });

/** `EmailPasswordStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const layer = (
  schema: SchemaInput = defaultTables,
): Layer.Layer<Auth.Email.EmailPasswordStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.Email.EmailPasswordStore, make(schema));

/**
 * `PasswordResetUserStore` backed by drizzle: the same `setPasswordHash` as
 * {@link layer}'s store, for `PasswordResetService`.
 */
export const passwordResetUserLayer = (
  schema: SchemaInput = defaultTables,
): Layer.Layer<Auth.Password.PasswordResetUserStore, never, DrizzleDatabase> =>
  Layer.effect(
    Auth.Password.PasswordResetUserStore,
    Effect.map(make(schema), (store) => ({ setPasswordHash: store.setPasswordHash })),
  );
