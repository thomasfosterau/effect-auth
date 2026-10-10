/**
 * A single-table `IdentifierStore`: the `email` identifier is the application's
 * own `users` row.
 *
 * {@link IdentifierStore} keeps identifiers in a table of their own, so a user
 * may hold several emails, a username and a phone number. An application whose
 * `users` table already carries the login address — `email` and
 * `email_verified` columns on the row — has no such table to hand over, and
 * migrating its entity graph onto one is the cost this module avoids. It is
 * opt-in: {@link layer} is a separate layer, and the default store stays the
 * multi-identifier one.
 *
 * ### The trade-off
 *
 * A user has at most **one** identifier, and it is always of type `email`. The
 * store cannot hold a second address, a username or a phone number, and says so
 * with an `AuthError` rather than silently dropping the write. Core flows that
 * need several identifiers at once (for example SCIM's add-then-remove when a
 * `userName` changes) fail on this store; flows that replace an address by
 * removing the old one first (`AccountManagement`) work.
 *
 * ### How each field is read and written
 *
 * | `Identifier` field | Lives in                                             |
 * | ------------------ | ---------------------------------------------------- |
 * | `id`               | `users.id` — an email identifier's id is its user's id |
 * | `userId`           | `users.id`                                           |
 * | `type`             | always `"email"`; no column                          |
 * | `value`            | `users.email`                                        |
 * | `verified`         | `users.email_verified`                               |
 * | `verifiedAt`       | not stored; never reported                           |
 * | `createdAt`        | `users.created_at`                                   |
 *
 * An identifier exists while `users.email` is non-null. A user whose email is
 * `NULL` holds no identifier.
 *
 * ### Per-method behaviour
 *
 * - `getByValue("email", value)` is a lookup on `users.email`. Any other type
 *   resolves to `null`: the table holds no such identifiers.
 * - `listByUser` returns the user's email identifier, or `[]`.
 * - `create` refuses any type but `email` (`AuthError`), refuses a user with no
 *   row or one that already holds an email (`AuthError`), and otherwise writes
 *   `users.email` and `users.email_verified` on that row. The uniqueness of
 *   `users.email` is what rejects an address claimed by another user; the driver
 *   error surfaces as `AuthError`, which `Auth.claimIdentifier` re-reads into an
 *   `IdentifierTakenError`. The store's own duplicate check does not exist here:
 *   the index must carry it (see the requirements below).
 * - `setVerified` sets `users.email_verified`, returns the identifier, or `null`
 *   when the id names no user holding an email. The `verifiedAt` argument has no
 *   column to go to and is dropped.
 * - `delete` and `deleteByUser` set `users.email` and `users.email_verified` back
 *   to `NULL` and `false`, and leave the user row alone. Deleting a missing
 *   identifier is a no-op. This needs `users.email` to be nullable: on a
 *   `NOT NULL` column the database rejects the write and it surfaces as
 *   `AuthError`.
 *
 * ### What the application's table must satisfy
 *
 * - `users.email` is **nullable** and carries a **unique index**. The index is
 *   the only thing that stops two users holding one address; the store does not
 *   check it.
 * - `users.email_verified` is a non-null boolean.
 * - The user row exists before its email is claimed. The store never inserts a
 *   user; the application's own user writer does.
 * - Addresses are normalised by the application, as for every identifier store.
 *
 * The store writes nothing else on the row: `updated_at` and every other column
 * belong to the application.
 *
 * @example
 * ```ts
 * import { Layer } from "effect";
 * import * as Drizzle from "@thomasfosterau/effect-auth-drizzle";
 *
 * // `appUsers` is the application's own table: `email` nullable and unique.
 * const users = Drizzle.SingleTableIdentifierStore.defineUsers({
 *   table: appUsers,
 *   columns: {
 *     id: "userId",
 *     email: "email",
 *     emailVerified: "emailVerified",
 *     createdAt: "createdAt",
 *   },
 * });
 *
 * const identifiers = Drizzle.SingleTableIdentifierStore.layer(users).pipe(
 *   Layer.provide(Drizzle.databaseLayer(db)),
 * );
 * ```
 */

import { and, eq, isNotNull, isNull } from "drizzle-orm";
import type { Table } from "drizzle-orm";
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import {
  type ColumnKey,
  type NullableColumn,
  resolveTable,
  type StoreColumn,
  type TableSchema,
  type TableSpec,
  writeValues,
} from "./Columns.ts";
import { type DrizzleSelected, DrizzleDatabase } from "./Database.ts";
import { makeQuery } from "./internal.ts";

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

/** Which of `TTable`'s columns hold each field the single-table store reads and writes. */
export interface SingleTableUserColumnNames<TTable extends Table> {
  /** The user's primary key; also the id of the email identifier. */
  readonly id: ColumnKey<TTable, string>;
  /** The login address. Nullable, unique — see the module docs. */
  readonly email: ColumnKey<TTable, string | null>;
  /** Whether {@link email} has been verified. */
  readonly emailVerified: ColumnKey<TTable, boolean>;
  /** The user's creation time, which the email identifier reports as its own. */
  readonly createdAt: ColumnKey<TTable, Date>;
}

/** The resolved column objects the single-table store queries with. */
export type SingleTableUserColumns = {
  readonly id: StoreColumn<string>;
  readonly email: NullableColumn<string>;
  readonly emailVerified: StoreColumn<boolean>;
  readonly createdAt: StoreColumn<Date>;
};

/** A users table and where the login address lives in it. */
export type SingleTableUsers = TableSchema<SingleTableUserColumns>;

/**
 * Map an application's `users` table onto the single-table store.
 *
 * Each column is named by its key on the table object, as in `defineSchema`, not
 * by its database name. The column types are checked at this call site: `email`
 * must read back as a string or `null`, `emailVerified` as a boolean, `createdAt`
 * as a `Date`.
 */
export const defineUsers = <TUsers extends Table>(
  spec: TableSpec<TUsers, SingleTableUserColumnNames<TUsers>>,
): SingleTableUsers => resolveTable<SingleTableUserColumns>(spec);

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

type UserRow = DrizzleSelected<SingleTableUserColumns>;

/** The identifier a user row holds, or `null` when the row holds no email. */
const toIdentifier = (row: UserRow): Auth.Identifier | null =>
  row.email === null
    ? null
    : {
        id: row.id,
        userId: row.id,
        type: "email",
        value: row.email,
        verified: row.emailVerified,
        createdAt: row.createdAt,
      };

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/** Build a single-table `IdentifierStore` over the ambient {@link DrizzleDatabase}. */
export const make = (
  users: SingleTableUsers,
): Effect.Effect<typeof Auth.IdentifierStore.Service, never, DrizzleDatabase> =>
  Effect.gen(function* () {
    const query = makeQuery(yield* DrizzleDatabase);
    const column = users.columns;
    const table = users.table;
    const selection = {
      id: column.id,
      email: column.email,
      emailVerified: column.emailVerified,
      createdAt: column.createdAt,
    };

    /** `users.email IS NOT NULL`: the row holds an identifier. */
    const holdsEmail = () => isNotNull(column.email);

    const readUser = (userId: string, label: string) =>
      query(label, (db) =>
        db.select(selection).from(table).where(eq(column.id, userId)).limit(1).execute(),
      ).pipe(Effect.map((rows) => rows[0] ?? null));

    /** Set the email columns back to "no address", leaving the user row in place. */
    const clearEmail = (userId: string, label: string) =>
      query(label, (db) =>
        db
          .update(table)
          .set(writeValues(users, { email: null, emailVerified: false }))
          .where(eq(column.id, userId))
          .execute(),
      ).pipe(Effect.asVoid);

    return {
      getByValue: (type, value) => {
        // The table holds only email identifiers; another type has no record here.
        if (type !== "email") return Effect.succeed(null);
        return query("identifier.getByValue", (db) =>
          db.select(selection).from(table).where(eq(column.email, value)).limit(1).execute(),
        ).pipe(
          Effect.map((rows) => {
            const row = rows[0];
            return row === undefined ? null : toIdentifier(row);
          }),
        );
      },

      listByUser: (userId) =>
        query("identifier.listByUser", (db) =>
          db
            .select(selection)
            .from(table)
            .where(and(eq(column.id, userId), holdsEmail()))
            .execute(),
        ).pipe(
          Effect.map((rows) =>
            rows.flatMap((row) => {
              const identifier = toIdentifier(row);
              return identifier === null ? [] : [identifier];
            }),
          ),
        ),

      create: (identifier) => {
        if (identifier.type !== "email") {
          return Effect.fail(
            new Auth.AuthError({
              message: `the single-table IdentifierStore holds email identifiers only; a ${identifier.type} identifier needs the multi-identifier store`,
            }),
          );
        }
        return Effect.gen(function* () {
          const current = yield* readUser(identifier.userId, "identifier.create.read");
          if (current === null) {
            return yield* new Auth.AuthError({
              message: "the single-table IdentifierStore has no user row to hold the email",
            });
          }
          if (current.email !== null) {
            return yield* new Auth.AuthError({
              message:
                "the single-table IdentifierStore allows one email identifier per user, and this user already has one",
            });
          }

          // The unique index on `email` rejects an address another user holds;
          // `IS NULL` keeps a concurrent claim by this user from being overwritten.
          yield* query("identifier.create", (db) =>
            db
              .update(table)
              .set(
                writeValues(users, {
                  email: identifier.value,
                  emailVerified: identifier.verified,
                }),
              )
              .where(and(eq(column.id, identifier.userId), isNull(column.email)))
              .execute(),
          );

          const stored = yield* readUser(identifier.userId, "identifier.create.read");
          const claimed = stored === null ? null : toIdentifier(stored);
          if (claimed === null || claimed.value !== identifier.value) {
            return yield* new Auth.AuthError({
              message: "the user's email changed while it was being claimed",
            });
          }
          return claimed;
        });
      },

      // The identifier's id is the user's id, so `setVerified` takes it there.
      // `verifiedAt` has no column and is not stored.
      setVerified: (id) =>
        Effect.gen(function* () {
          yield* query("identifier.setVerified", (db) =>
            db
              .update(table)
              .set(writeValues(users, { emailVerified: true }))
              .where(and(eq(column.id, id), holdsEmail()))
              .execute(),
          );

          const rows = yield* query("identifier.setVerified.read", (db) =>
            db
              .select(selection)
              .from(table)
              .where(and(eq(column.id, id), holdsEmail()))
              .limit(1)
              .execute(),
          );

          const row = rows[0];
          return row === undefined ? null : toIdentifier(row);
        }),

      // An email identifier's id is its user's id, so deleting one and deleting
      // all of a user's identifiers are the same write.
      delete: (id) => clearEmail(id, "identifier.delete"),
      deleteByUser: (userId) => clearEmail(userId, "identifier.deleteByUser"),
    } satisfies typeof Auth.IdentifierStore.Service;
  });

/** `IdentifierStore` over a `users` table that holds the email itself. */
export const layer = (
  users: SingleTableUsers,
): Layer.Layer<Auth.IdentifierStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.IdentifierStore, make(users));
