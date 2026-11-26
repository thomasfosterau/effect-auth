/**
 * A single-table `IdentifierStore`: a user's one `email` identifier lives on
 * the application's own `users` row (`email`, `email_verified`, optionally
 * `email_verified_at`). It is opt-in through {@link layer}, and refuses
 * anything but one email with `IdentifierRefusedError`. The Drizzle guide
 * lists what the table must satisfy.
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
import * as Option from "effect/Option";
import * as Arr from "effect/Array";
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
import { makeQuery, selectOne } from "./internal.ts";

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

/** Which of `TTable`'s columns hold each field the single-table store reads and writes. */
export interface SingleTableUserColumnNames<TTable extends Table> {
  /** The user's primary key; also the id of the email identifier. */
  readonly id: ColumnKey<TTable, string>;
  /**
   * The login address. Unique. Nullable or NOT NULL: the store detects which from
   * the column; on a NOT NULL column the store never clears the address.
   */
  readonly email: ColumnKey<TTable, string | null>;
  /** Whether {@link email} has been verified. */
  readonly emailVerified: ColumnKey<TTable, boolean>;
  /**
   * When the address was verified, as a nullable timestamp. Optional: when
   * mapped, {@link Auth.Identifier.verifiedAt} is stored and reported; when not
   * mapped it is neither stored nor reported.
   */
  readonly emailVerifiedAt?: ColumnKey<TTable, Date | null>;
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
 * The identifier a user row holds, or `None` when the row holds no email.
 *
 * `verifiedAt` is reported only when the `emailVerifiedAt` column is mapped (the
 * projection then includes it) and holds a value.
 */
const toIdentifier = (row: UserRow): Option.Option<Auth.Identifier> => {
  if (row.email === null) return Option.none();
  const verifiedAt = verifiedAtOf(row);
  return Option.some({
    id: row.id,
    userId: row.id,
    type: "email",
    value: row.email,
    verified: row.emailVerified,
    createdAt: row.createdAt,
    ...(verifiedAt === null ? {} : { verifiedAt }),
  });
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
      selectOne(query, label, selection, table, eq(column.id, userId));

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
          Option.isNone(row)
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
        if (type !== "email") return Effect.succeedNone;
        return query("identifier.getByValue", (db) =>
          db.select(selection).from(table).where(eq(column.email, value)).limit(1).execute(),
        ).pipe(Effect.map((rows) => Option.flatMap(Arr.head(rows), toIdentifier)));
      },

      listByUser: (userId) =>
        query("identifier.listByUser", (db) =>
          db
            .select(selection)
            .from(table)
            .where(and(eq(column.id, userId), holdsEmail()))
            .execute(),
        ).pipe(Effect.map((rows) => Arr.getSomes(rows.map(toIdentifier)))),

      create: (identifier) => {
        if (identifier.type !== "email") {
          return Effect.fail(
            new Auth.IdentifierRefusedError({
              message: `the single-table IdentifierStore holds email identifiers only; a ${identifier.type} identifier needs the multi-identifier store`,
              identifierType: identifier.type,
            }),
          );
        }
        return Effect.gen(function* () {
          const current = yield* readUser(identifier.userId, "identifier.create.read");
          if (Option.isNone(current)) {
            return yield* new Auth.AuthError({
              message: "the single-table IdentifierStore has no user row to hold the email",
            });
          }
          if (current.value.email !== null) {
            return yield* new Auth.IdentifierRefusedError({
              message:
                "the single-table IdentifierStore allows one email identifier per user, and this user already has one",
              identifierType: "email",
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
          const claimed = Option.flatMap(stored, toIdentifier);
          if (Option.isNone(claimed) || claimed.value.value !== identifier.value) {
            return yield* new Auth.AuthError({
              message: "the user's email changed while it was being claimed",
            });
          }
          return claimed.value;
        });
      },

      // One guarded UPDATE: the row moves from `from`'s address to `to`'s, or
      // stays as it is. Never NULL, so a NOT NULL column takes it too.
      replace: (from, to) => {
        const invalid = Auth.replaceInputError(from, to);
        if (Option.isSome(invalid)) return Effect.fail(invalid.value);
        if (from.type !== "email") {
          return Effect.fail(
            new Auth.AuthError({
              message: `the single-table IdentifierStore holds email identifiers only; a ${from.type} identifier needs the multi-identifier store`,
            }),
          );
        }
        // An email identifier's id is its user's id; any other id is not one this
        // store holds.
        if (from.id !== from.userId) return Effect.succeedNone;
        return Effect.gen(function* () {
          yield* query("identifier.replace", (db) =>
            db
              .update(table)
              .set(
                writeValues(users, {
                  email: to.value,
                  emailVerified: to.verified,
                  ...verifiedAtWrite(to.verifiedAt ?? null),
                }),
              )
              .where(and(eq(column.id, from.userId), eq(column.email, from.value)))
              .execute(),
          );

          const stored = yield* readUser(from.userId, "identifier.replace.read");
          return Option.filter(
            Option.flatMap(stored, toIdentifier),
            (replaced) => replaced.value === to.value,
          );
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

          return Option.flatMap(Arr.head(rows), toIdentifier);
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
