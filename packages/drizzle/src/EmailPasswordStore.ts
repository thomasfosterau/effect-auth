/**
 * Drizzle-backed implementation of effect-auth's `EmailPasswordStore` — the
 * store `EmailPasswordService` creates users and reads and writes password
 * hashes through — and of `PasswordResetUserStore`, the one setter
 * `PasswordResetService` writes a new hash with.
 *
 * Both live on the users table: the password hash is its `password_hash`
 * column (`passwordHash` in a `defineSchema` mapping). This is the only store
 * in the package that reads or writes that column; `UserStore` never selects
 * it.
 *
 * ### Contract notes
 *
 * - `createUser` is a plain `INSERT` with a fresh random UUID, so every success
 *   is a new user (`created: true`) and an existing row is never touched. It
 *   inserts the user row only: core claims the login address in the
 *   identifiers table afterwards (`Auth.createUserWithIdentifier`). The user it
 *   returns is read back through the same projection as `UserStore.get`, so a
 *   column default the database applied (a promoted `role`) is in it.
 * - On a `defineSchema` mapping, an attribute declared under `promoted` is
 *   written to its own column, and every other attribute to the bag. A sign-up
 *   carrying attributes for a users table with no mapped bag fails with
 *   `Auth.AuthError` rather than dropping them.
 * - `getPasswordHash` is `null` for a user with no password and for a missing
 *   user; `setPasswordHash` / `clearPasswordHash` of a missing user are no-ops.
 * - A users table whose mapping leaves `passwordHash` out cannot serve this
 *   store: building the layer dies with a defect naming the missing column.
 * - Every driver failure surfaces as `Auth.AuthError` with the original error
 *   preserved as `cause`.
 */

import { eq, getTableColumns, type Column } from "drizzle-orm";
import { DateTime, Effect, Layer } from "effect";
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
import { makeQuery, type Query, selectOne } from "./internal.ts";
import { tables as defaultTables } from "./PgSchema.ts";
import { makeToUser, selection } from "./UserStore.ts";

/**
 * Each promoted attribute's column, by the key it has on the table object
 * (what an insert's values are keyed by).
 */
const promotedKeys = (users: UserSchema): Readonly<Record<string, string>> => {
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
 * Split a new user's attributes into the promoted columns' insert values and
 * the bag, failing when the bag is unmapped but needed.
 */
const splitAttributes = (
  users: UserSchema,
  keys: Readonly<Record<string, string>>,
  attributes: Auth.Attributes,
) => {
  const bag = R.filter(attributes, (_value, name) => !R.has(keys, name));
  const columns = R.mapKeys(
    R.filter(attributes, (_value, name) => R.has(keys, name)),
    (name) => keys[name] ?? name,
  );
  return users.columns.attributes === undefined && !R.isEmptyRecord(bag)
    ? Effect.fail(
        new Auth.AuthError({
          message: `drizzle emailPassword.createUser failed: the users table has no attribute bag for ${R.keys(bag).join(", ")}`,
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
    const query = makeQuery(yield* DrizzleDatabase);
    const users = resolveSchema(schema).users;
    const password = yield* passwordColumn(users);
    const column = users.columns;
    const projection = selection(users);
    const toUser = makeToUser(users);
    const keys = promotedKeys(users);

    const readUser = (userId: string) =>
      selectOne(
        query,
        "emailPassword.createUser.read",
        projection,
        users.table,
        eq(column.id, userId),
      ).pipe(Effect.map((row) => (row === null ? null : toUser(row))));

    const createUser: (typeof Auth.Email.EmailPasswordStore.Service)["createUser"] = (input) =>
      Effect.gen(function* () {
        const { columns, bag } = yield* splitAttributes(users, keys, input.attributes ?? {});
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
        if (user === null) {
          return yield* new Auth.AuthError({
            message: "drizzle emailPassword.createUser failed: the inserted user was not found",
          });
        }
        return { user, created: true };
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
        ).pipe(Effect.map((row) => row?.hash ?? null)),
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
