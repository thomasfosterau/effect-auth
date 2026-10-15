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
 * need several identifiers at once fail on this store. SCIM's add-then-remove
 * when a `userName` changes is one. Email change is another: it claims the new
 * address before it releases the old one, and the store refuses a second address
 * while the user holds one, on a nullable column and a NOT NULL one alike. The
 * change fails with an `AuthError` and the previous address stays. It becomes
 * supported once `IdentifierStore.replace` lands (#381).
 *
 * ### How each field is read and written
 *
 * | `Identifier` field | Lives in                                               |
 * | ------------------ | ------------------------------------------------------ |
 * | `id`               | `users.id` — an email identifier's id is its user's id |
 * | `userId`           | `users.id`                                             |
 * | `type`             | always `"email"`; no column                            |
 * | `value`            | `users.email`                                          |
 * | `verified`         | `users.email_verified`                                 |
 * | `verifiedAt`       | `users.email_verified_at`, when that column is mapped; otherwise not stored and never reported |
 * | `createdAt`        | `users.created_at`                                     |
 *
 * An identifier exists while `users.email` is non-null. A user whose email is
 * `NULL` holds no identifier.
 *
 * ### Nullable or NOT NULL `email`
 *
 * Whether `users.email` is nullable is read from the drizzle column at
 * {@link defineUsers} time, so the same store serves both:
 *
 * - **Nullable** (the usual case). Deleting an address writes `NULL` to
 *   `email`, and the row stays. Account deletion clears the address and then
 *   deletes the row.
 * - **NOT NULL.** The store never writes `NULL`. Deleting a user's address by
 *   identifier (`delete`) is refused with an `AuthError` while the row holds
 *   it, so a targeted delete leaves the address in place. `deleteByUser` does
 *   nothing: the user row is about to be deleted (account deletion does this
 *   right after it), and deleting the row takes the address with it. This
 *   departs from the {@link IdentifierStore} contract, which says `deleteByUser`
 *   deletes all of a user's identifiers: here the application's user writer must
 *   hard-delete the row. A soft-delete writer leaves the address claimed.
 *   Account deletion therefore works. Email change does not, on either shape: it
 *   claims the new address while the old one is still held, and the store
 *   refuses that claim.
 *
 * ### Per-method behaviour
 *
 * - `getByValue("email", value)` is a lookup on `users.email`. Any other type
 *   resolves to `null`: the table holds no such identifiers.
 * - `listByUser` returns the user's email identifier, or `[]`.
 * - `create` refuses any type but `email` (`AuthError`), refuses a user with no
 *   row or one that already holds an email (`AuthError`), and otherwise writes
 *   `users.email`, `users.email_verified` and, when mapped,
 *   `users.email_verified_at` on that row. The uniqueness of `users.email` is
 *   what rejects an address claimed by another user; the driver error surfaces
 *   as `AuthError`, which `Auth.claimIdentifier` re-reads into an
 *   `IdentifierTakenError`. The store's own duplicate check does not exist here:
 *   the index must carry it (see the requirements below).
 * - `setVerified` sets `users.email_verified`, and `users.email_verified_at` when
 *   mapped, then returns the identifier, or `null` when the id names no user
 *   holding an email. Without the `emailVerifiedAt` mapping the `verifiedAt`
 *   argument has no column to go to and is dropped.
 * - `delete` and `deleteByUser` on a nullable column set `users.email`,
 *   `users.email_verified` and, when mapped, `users.email_verified_at` back to
 *   `NULL`, `false` and `NULL`, and leave the user row alone. Deleting a missing
 *   identifier is a no-op. On a NOT NULL column see the section above.
 *
 * ### What the application's table must satisfy
 *
 * - `users.email` carries a **unique index**. The index is the only thing that
 *   stops two users holding one address; the store does not check it. It may be
 *   nullable or NOT NULL (see above).
 * - `users.email_verified` is a non-null boolean.
 * - `users.email_verified_at`, if mapped, is a nullable timestamp.
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
 * // `appUsers` is the application's own table: `email` unique, nullable or
 * // NOT NULL, with `email_verified_at` mapped if the application keeps one.
 * const users = Drizzle.SingleTableIdentifierStore.defineUsers({
 *   table: appUsers,
 *   columns: {
 *     id: "userId",
 *     email: "email",
 *     emailVerified: "emailVerified",
 *     emailVerifiedAt: "emailVerifiedAt",
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
  /**
   * The login address. Unique. Nullable or NOT NULL: the store detects which from
   * the column, and see the module docs for what each one means.
   */
  readonly email: ColumnKey<TTable, string | null>;
  /** Whether {@link email} has been verified. */
  readonly emailVerified: ColumnKey<TTable, boolean>;
  /**
   * When the address was verified, as a nullable timestamp. Optional: when
   * mapped, {@link Auth.Identifier.verifiedAt} is stored and reported; when not
   * mapped it is neither stored nor reported.
   */
  readonly emailVerifiedAt?: ColumnKey<TTable, Date | null> | undefined;
  /** The user's creation time, which the email identifier reports as its own. */
  readonly createdAt: ColumnKey<TTable, Date>;
}

/** The resolved column objects the single-table store queries with. */
export type SingleTableUserColumns = {
  readonly id: StoreColumn<string>;
  readonly email: NullableColumn<string>;
  readonly emailVerified: StoreColumn<boolean>;
  readonly emailVerifiedAt?: NullableColumn<Date>;
  readonly createdAt: StoreColumn<Date>;
};

/**
 * A users table and where the login address lives in it.
 *
 * {@link emailNullable} is read from the drizzle `email` column by
 * {@link defineUsers}: `true` when the column allows `NULL`.
 */
export type SingleTableUsers = TableSchema<SingleTableUserColumns> & {
  readonly emailNullable: boolean;
};

/**
 * Map an application's `users` table onto the single-table store.
 *
 * Each column is named by its key on the table object, as in `defineSchema`, not
 * by its database name. The column types are checked at this call site: `email`
 * must read back as a string or `null`, `emailVerified` as a boolean,
 * `emailVerifiedAt` as a `Date` or `null`, `createdAt` as a `Date`.
 *
 * Whether `email` is nullable is taken from the column's own `NOT NULL` setting,
 * so a `NOT NULL` column is supported without any extra option.
 */
export const defineUsers = <TUsers extends Table>(
  spec: TableSpec<TUsers, SingleTableUserColumnNames<TUsers>>,
): SingleTableUsers => {
  const users = resolveTable<SingleTableUserColumns>(spec);
  return { ...users, emailNullable: !users.columns.email.notNull };
};

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

type UserRow = DrizzleSelected<SingleTableUserColumns>;

/** The row's verification time: `null` when the column is unmapped, or holds no time. */
const verifiedAtOf = (row: UserRow): Date | null => {
  const value = row.emailVerifiedAt;
  return value instanceof Date ? value : null;
};

/**
 * The identifier a user row holds, or `null` when the row holds no email.
 *
 * `verifiedAt` is reported only when the `emailVerifiedAt` column is mapped (the
 * projection then includes it) and holds a value.
 */
const toIdentifier = (row: UserRow): Auth.Identifier | null => {
  if (row.email === null) return null;
  const verifiedAt = verifiedAtOf(row);
  return {
    id: row.id,
    userId: row.id,
    type: "email",
    value: row.email,
    verified: row.emailVerified,
    createdAt: row.createdAt,
    ...(verifiedAt === null ? {} : { verifiedAt }),
  };
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
    const nullable = users.emailNullable;
    const verifiedAtColumn = column.emailVerifiedAt;
    const selection = {
      id: column.id,
      email: column.email,
      emailVerified: column.emailVerified,
      createdAt: column.createdAt,
      ...(verifiedAtColumn !== undefined && { emailVerifiedAt: verifiedAtColumn }),
    };

    /**
     * The `emailVerifiedAt` part of a write: the value when the column is
     * mapped, nothing when it is not (so nothing is written to a column that
     * does not exist).
     */
    const verifiedAtWrite = (value: Date | null) =>
      verifiedAtColumn === undefined ? {} : { emailVerifiedAt: value };

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
          .set(
            writeValues(users, {
              email: null,
              emailVerified: false,
              ...verifiedAtWrite(null),
            }),
          )
          .where(eq(column.id, userId))
          .execute(),
      ).pipe(Effect.asVoid);

    /**
     * A NOT NULL `email` cannot be cleared. A targeted delete of a user's address
     * refuses while the row holds one; a missing row holds nothing to delete.
     */
    const refuseClear = (userId: string) =>
      readUser(userId, "identifier.delete.read").pipe(
        Effect.flatMap((row) =>
          row === null
            ? Effect.void
            : Effect.fail(
                new Auth.AuthError({
                  message:
                    "the single-table IdentifierStore cannot remove the email of a user whose users.email is NOT NULL: the address would be left NULL. Deleting the user row removes it.",
                }),
              ),
        ),
      );

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
                  ...verifiedAtWrite(identifier.verifiedAt ?? null),
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
      setVerified: (id, verifiedAt) =>
        Effect.gen(function* () {
          yield* query("identifier.setVerified", (db) =>
            db
              .update(table)
              .set(writeValues(users, { emailVerified: true, ...verifiedAtWrite(verifiedAt) }))
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
      // all of a user's identifiers address the same row.
      delete: (id) => (nullable ? clearEmail(id, "identifier.delete") : refuseClear(id)),

      // On a NOT NULL column this does nothing. Account deletion deletes the user
      // row straight after this call, and the row's address goes with it; clearing
      // the column here would be refused. A NOT NULL caller that keeps the row
      // keeps the address.
      deleteByUser: (userId) =>
        nullable ? clearEmail(userId, "identifier.deleteByUser") : Effect.void,
    } satisfies typeof Auth.IdentifierStore.Service;
  });

/** `IdentifierStore` over a `users` table that holds the email itself. */
export const layer = (
  users: SingleTableUsers,
): Layer.Layer<Auth.IdentifierStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.IdentifierStore, make(users));
