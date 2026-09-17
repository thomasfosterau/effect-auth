/**
 * Pointing the stores at tables this package did not define.
 *
 * `Pg.defineTables()` and its SQLite/MySQL siblings build the three auth tables
 * under names of your choosing, but with column names and column types this
 * package picks. That is the right default, and most applications should stay on
 * it. It is the wrong answer for an application adopting effect-auth **in
 * place** — one whose entire entity graph already has foreign keys into
 * `users.id`, whose primary keys are `uuid` rather than `text`, and whose
 * migrations it owns. For those, adoption has to meet the existing schema rather
 * than the reverse.
 *
 * This module is how. An {@link AuthSchema} pairs each of the three tables with
 * a mapping from the fields the stores need to the columns *that* table actually
 * has. Everything below `AuthSchema` is the same store code, running the same
 * queries; only the projection changes.
 *
 * ### What is checked, and where
 *
 * The mapping is type-level: {@link ColumnKey} picks out exactly those keys of a
 * table whose selected value is assignable to the type the store needs, so
 * naming a `text` column for `expiresAt`, or a nullable one for `id`, is a
 * compile error at the call site — not a runtime surprise.
 *
 * Column *names* are free because the mapping supplies them, and column *types*
 * are free as long as they read back as the value the domain uses. A `uuid`
 * primary key reads back as `string`, so it needs nothing but the mapping; a
 * `bigint` one does not, and is out of scope.
 *
 * ### What a caller-supplied table still has to satisfy
 *
 * - **Attribute bags** must read back as an object. A drizzle `jsonb()` column
 *   with no `$type` reads back as `unknown`, which no mapping will accept; write
 *   `jsonb().$type<Record<string, unknown>>()`.
 * - **Extra required columns** — a `role text NOT NULL` the stores know nothing
 *   about — must have a database-level default, since the stores insert only the
 *   columns they were given. Promoting an attribute to a real typed column the
 *   stores write is separate work (#182).
 * - **Uniqueness on `(type, value)`** in the identifiers table is still what
 *   makes `Auth.claimIdentifier` correct. The mapping cannot check that; the
 *   application's migration has to carry it.
 *
 * @example
 * ```ts
 * // An application's own `users` table: uuid keys, its own column names,
 * // columns the stores know nothing about.
 * const appUsers = pgTable("users", {
 *   userId: uuid("id").primaryKey(),
 *   displayName: text("display_name"),
 *   avatarUrl: text("avatar_url"),
 *   meta: jsonb("meta").$type<Record<string, unknown>>().notNull().default({}),
 *   role: text("role").notNull().default("user"),
 *   created: timestamp("created_at", { withTimezone: true }).notNull(),
 *   updated: timestamp("updated_at", { withTimezone: true }).notNull(),
 * });
 *
 * const schema = defineSchema({
 *   sessions: { table: appSessions, columns: { ... } },
 *   users: {
 *     table: appUsers,
 *     columns: {
 *       id: "userId",
 *       name: "displayName",
 *       image: "avatarUrl",
 *       attributes: "meta",
 *       createdAt: "created",
 *       updatedAt: "updated",
 *     },
 *   },
 *   identifiers: { table: appIdentifiers, columns: { ... } },
 * });
 *
 * const stores = layer(schema).pipe(Layer.provide(databaseLayer(db)));
 * ```
 */

import type { AnyColumn, Column, GetColumnData, Table } from "drizzle-orm";
import type * as Auth from "@thomasfosterau/effect-auth";
import type { Tables } from "./Schema.ts";

// ---------------------------------------------------------------------------
// Picking a column by the value it reads back as
// ---------------------------------------------------------------------------

/**
 * The keys of `TTable` naming a column a `SELECT` reads back as `TValue`.
 *
 * This is the whole type-level mechanism: `$inferSelect` is drizzle's own
 * record of what each column yields — nullability, `$type` overrides and all —
 * so filtering its keys by assignability to `TValue` is exactly "which of this
 * table's columns can stand in for the one the store needs". A table with no
 * such column resolves to `never`, and the mapping will not type-check.
 */
export type ColumnKey<TTable extends Table, TValue> = {
  [K in keyof TTable["$inferSelect"]]-?: TTable["$inferSelect"][K] extends TValue ? K : never;
}[keyof TTable["$inferSelect"]] &
  keyof TTable["$inferInsert"] &
  keyof TTable &
  string;

/**
 * A resolved column, tagged with the value the store reads out of it.
 *
 * `AnyColumn` is drizzle's own way of describing a column by part of its config
 * and leaving the rest open, which is what lets one store serve `text`, `uuid`
 * and `varchar` keys alike: they differ in `columnType`, and agree on `data`.
 */
type StoreColumn<TValue> = AnyColumn<{ data: TValue; notNull: true }>;

/** A resolved column the store tolerates `NULL` in. */
type NullableColumn<TValue> = AnyColumn<{ data: TValue; notNull: false }>;

// ---------------------------------------------------------------------------
// Per-store column sets
// ---------------------------------------------------------------------------

/** Which of `TTable`'s columns hold each field of a session. */
export interface SessionColumnNames<TTable extends Table> {
  /** SHA-256 hex digest of the bearer token — never the raw token itself. */
  readonly id: ColumnKey<TTable, string>;
  readonly userId: ColumnKey<TTable, string>;
  readonly expiresAt: ColumnKey<TTable, Date>;
  readonly createdAt: ColumnKey<TTable, Date>;
  readonly lastActivityAt: ColumnKey<TTable, Date>;
  readonly attributes: ColumnKey<TTable, Record<string, unknown> | null>;
}

/** Which of `TTable`'s columns hold each field of a user. */
export interface UserColumnNames<TTable extends Table> {
  readonly id: ColumnKey<TTable, string>;
  readonly name: ColumnKey<TTable, string | null>;
  readonly image: ColumnKey<TTable, string | null>;
  readonly attributes: ColumnKey<TTable, Record<string, unknown> | null>;
  readonly createdAt: ColumnKey<TTable, Date>;
  readonly updatedAt: ColumnKey<TTable, Date>;
}

/** Which of `TTable`'s columns hold each field of an identifier. */
export interface IdentifierColumnNames<TTable extends Table> {
  readonly id: ColumnKey<TTable, string>;
  readonly userId: ColumnKey<TTable, string>;
  /**
   * `$type<Auth.IdentifierType>()` is welcome but not required: a plain `text`
   * column maps fine. See {@link IdentifierColumns.type} for what the store
   * assumes about its contents.
   */
  readonly type: ColumnKey<TTable, string>;
  readonly value: ColumnKey<TTable, string>;
  readonly verified: ColumnKey<TTable, boolean>;
  readonly verifiedAt: ColumnKey<TTable, Date | null>;
  readonly createdAt: ColumnKey<TTable, Date>;
}

/** The session columns, resolved to drizzle column objects. */
export type SessionColumns = {
  readonly id: StoreColumn<string>;
  readonly userId: StoreColumn<string>;
  readonly expiresAt: StoreColumn<Date>;
  readonly createdAt: StoreColumn<Date>;
  readonly lastActivityAt: StoreColumn<Date>;
  readonly attributes: NullableColumn<Record<string, unknown>>;
};

/** The user columns, resolved to drizzle column objects. */
export type UserColumns = {
  readonly id: StoreColumn<string>;
  readonly name: NullableColumn<string>;
  readonly image: NullableColumn<string>;
  readonly attributes: NullableColumn<Record<string, unknown>>;
  readonly createdAt: StoreColumn<Date>;
  readonly updatedAt: StoreColumn<Date>;
};

/** The identifier columns, resolved to drizzle column objects. */
export type IdentifierColumns = {
  readonly id: StoreColumn<string>;
  readonly userId: StoreColumn<string>;
  /**
   * Read back as an `Auth.IdentifierType`. The mapping only requires a `string`
   * column, because an application's `type` column is usually plain `text`; this
   * package never writes a value outside the three, and a row that holds one
   * (put there by something else) is passed through as it was found rather than
   * rejected — the same behaviour the fixed-shape tables have always had.
   */
  readonly type: StoreColumn<Auth.IdentifierType>;
  readonly value: StoreColumn<string>;
  readonly verified: StoreColumn<boolean>;
  readonly verifiedAt: NullableColumn<Date>;
  readonly createdAt: StoreColumn<Date>;
};

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

/** One table, and where each field the store needs lives in it. */
export interface TableSchema<TColumns> {
  readonly table: Table;
  readonly columns: TColumns;
  /** The mapping that produced {@link columns}, kept for building writes. */
  readonly names: Readonly<Record<keyof TColumns & string, string>>;
}

/** Everything the session store addresses. */
export type SessionSchema = TableSchema<SessionColumns>;
/** Everything the user store addresses. */
export type UserSchema = TableSchema<UserColumns>;
/** Everything the identifier store addresses. */
export type IdentifierSchema = TableSchema<IdentifierColumns>;

/**
 * The three tables and their column mappings — what every store factory in this
 * package ultimately runs against.
 *
 * Build one with {@link defineSchema} for an application's own tables, or with
 * {@link fromTables} for the tables this package defines.
 */
export interface AuthSchema {
  readonly _tag: "AuthSchema";
  readonly sessions: SessionSchema;
  readonly users: UserSchema;
  readonly identifiers: IdentifierSchema;
}

/** What a store factory accepts: this package's tables, or a full mapping. */
export type SchemaInput = Tables | AuthSchema;

/** One table plus its mapping, before resolution. */
export interface TableSpec<TTable extends Table, TColumns> {
  readonly table: TTable;
  readonly columns: TColumns;
}

/** The argument {@link defineSchema} takes. */
export interface AuthSchemaSpec<
  TSessions extends Table,
  TUsers extends Table,
  TIdentifiers extends Table,
> {
  readonly sessions: TableSpec<TSessions, SessionColumnNames<TSessions>>;
  readonly users: TableSpec<TUsers, UserColumnNames<TUsers>>;
  readonly identifiers: TableSpec<TIdentifiers, IdentifierColumnNames<TIdentifiers>>;
}

/**
 * Resolve one table's mapping into the column objects the store queries with.
 *
 * The cast is where the two type systems meet. `ColumnKey` has already checked,
 * at the caller's own call site, that every named column reads back as the value
 * the store needs; what it cannot do is carry that fact through a lookup on a
 * table whose shape is still generic. `TColumns` restates it, once, here.
 */
const resolveTable = <TColumns>(spec: TableSpec<Table, object>): TableSchema<TColumns> => {
  const source = spec.table as unknown as Readonly<Record<string, Column>>;
  const names = spec.columns as Readonly<Record<string, string>>;
  const columns: Record<string, Column> = {};
  for (const [field, key] of Object.entries(names)) {
    columns[field] = source[key] as Column;
  }
  return {
    table: spec.table,
    columns: columns as TColumns,
    names: names as Readonly<Record<keyof TColumns & string, string>>,
  };
};

/**
 * Point the stores at tables this package did not define.
 *
 * Each entry names a table and says which of its columns holds each field the
 * corresponding store reads and writes. See the module docs for what a table
 * still has to satisfy beyond the mapping.
 */
export const defineSchema = <
  TSessions extends Table,
  TUsers extends Table,
  TIdentifiers extends Table,
>(
  spec: AuthSchemaSpec<TSessions, TUsers, TIdentifiers>,
): AuthSchema => ({
  _tag: "AuthSchema",
  sessions: resolveTable<SessionColumns>(spec.sessions),
  users: resolveTable<UserColumns>(spec.users),
  identifiers: resolveTable<IdentifierColumns>(spec.identifiers),
});

/**
 * The identity mapping over this package's own tables: every field lives in the
 * column of the same name.
 *
 * This is what a store factory builds when it is handed a {@link Tables} set,
 * which is why the fixed-shape path and the mapped path are one code path.
 */
export const fromTables = (tables: Tables): AuthSchema =>
  defineSchema({
    sessions: {
      table: tables.sessions,
      columns: {
        id: "id",
        userId: "userId",
        expiresAt: "expiresAt",
        createdAt: "createdAt",
        lastActivityAt: "lastActivityAt",
        attributes: "attributes",
      },
    },
    users: {
      table: tables.users,
      columns: {
        id: "id",
        name: "name",
        image: "image",
        attributes: "attributes",
        createdAt: "createdAt",
        updatedAt: "updatedAt",
      },
    },
    identifiers: {
      table: tables.identifiers,
      columns: {
        id: "id",
        userId: "userId",
        type: "type",
        value: "value",
        verified: "verified",
        verifiedAt: "verifiedAt",
        createdAt: "createdAt",
      },
    },
  });

/** Accept either shape a store factory is given. @internal */
export const resolveSchema = (input: SchemaInput): AuthSchema =>
  "_tag" in input ? input : fromTables(input);

/**
 * Re-key a logical row into the column names the target table uses, so a write
 * built from domain fields lands in the caller's columns.
 *
 * The values are checked against the resolved columns on the way through —
 * `GetColumnData` in `query` mode is what each column reads and writes,
 * nullability included — so a store cannot put a `Date` where its mapping named
 * a text column.
 *
 * @internal
 */
export const writeValues = <TColumns extends Readonly<Record<string, Column>>>(
  schema: TableSchema<TColumns>,
  values: Partial<{ readonly [K in keyof TColumns]: GetColumnData<TColumns[K], "query"> }>,
): Record<string, unknown> => {
  const row: Record<string, unknown> = {};
  for (const [field, value] of Object.entries(values)) {
    row[schema.names[field as keyof TColumns & string]] = value;
  }
  return row;
};
