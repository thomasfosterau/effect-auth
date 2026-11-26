/**
 * Pointing the stores at tables this package did not define: an {@link
 * AuthSchema} maps each field a store needs to a column of the application's
 * table, checked at compile time by {@link ColumnKey}. See {@link defineSchema}
 * for what such a table must satisfy.
 *
 * @example
 * ```ts
 * // An application's own `users` table: uuid keys, its own column names,
 * // columns the stores know nothing about.
 * const appUsers = pgTable("users", {
 *   userId: uuid("id").primaryKey(),
 *   displayName: text("display_name"),
 *   avatarUrl: text("avatar_url"),
 *   meta: jsonb("meta").$type<Auth.JsonObject>().notNull().default({}),
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

import * as Schema from "effect/Schema";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import {
  getTableColumns,
  type AnyColumn,
  type Column,
  type GetColumnData,
  type InferInsertModel,
  type InferSelectModel,
  type Table,
} from "drizzle-orm";
import type { SQL } from "drizzle-orm";
import type * as Auth from "@thomasfosterau/effect-auth";
import type { ApiKeyPermissions, Tables, TokenPurpose } from "./Schema.ts";

// ---------------------------------------------------------------------------
// Picking a column by the value it reads back as
// ---------------------------------------------------------------------------

/**
 * The keys of `TTable` naming a column a `SELECT` reads back as `TValue`.
 *
 * This is the whole type-level mechanism: `InferSelectModel` is drizzle's own
 * record of what each column yields — nullability, `$type` overrides and all —
 * so filtering its keys by assignability to `TValue` is exactly "which of this
 * table's columns can stand in for the one the store needs". A table with no
 * such column resolves to `never`, and the mapping will not type-check.
 */
export type ColumnKey<TTable extends Table, TValue> = {
  [K in keyof InferSelectModel<TTable>]-?: InferSelectModel<TTable>[K] extends TValue ? K : never;
}[keyof InferSelectModel<TTable>] &
  keyof InferInsertModel<TTable> &
  keyof TTable &
  string;

/**
 * A resolved column, tagged with the value the store reads out of it.
 *
 * `AnyColumn` is drizzle's own way of describing a column by part of its config
 * and leaving the rest open, which is what lets one store serve `text`, `uuid`
 * and `varchar` keys alike: they differ in `columnType`, and agree on `data`.
 *
 * @internal
 */
export type StoreColumn<TValue> = AnyColumn<{ data: TValue; notNull: true }>;

/**
 * A resolved column the store tolerates `NULL` in.
 *
 * @internal
 */
export type NullableColumn<TValue> = AnyColumn<{ data: TValue; notNull: false }>;

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
  readonly attributes: ColumnKey<TTable, Auth.JsonObject | null>;
}

/** Which of `TTable`'s columns hold each field of a user. */
export interface UserColumnNames<TTable extends Table> {
  readonly id: ColumnKey<TTable, string>;
  readonly name: ColumnKey<TTable, string | null>;
  readonly image: ColumnKey<TTable, string | null>;
  /**
   * The `jsonb` attribute bag. Optional: a table that keeps every attribute it
   * has as a promoted column needs none.
   */
  readonly attributes?: ColumnKey<TTable, Auth.JsonObject | null>;
  readonly createdAt: ColumnKey<TTable, Date>;
  readonly updatedAt: ColumnKey<TTable, Date>;
  /**
   * The password hash, a nullable text column. Optional: only
   * `EmailPasswordStore` reads or writes it (`UserStore` never selects it), and
   * that store's layer requires it.
   */
  readonly passwordHash?: ColumnKey<TTable, string | null>;
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
  readonly attributes: NullableColumn<Auth.JsonObject>;
};

/** The user columns, resolved to drizzle column objects. */
export type UserColumns = {
  readonly id: StoreColumn<string>;
  readonly name: NullableColumn<string>;
  readonly image: NullableColumn<string>;
  readonly attributes?: NullableColumn<Auth.JsonObject>;
  readonly createdAt: StoreColumn<Date>;
  readonly updatedAt: StoreColumn<Date>;
  readonly passwordHash?: NullableColumn<string>;
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
/** A value a promoted attribute column may read back as. */
export type PromotedValue = string | number | boolean | null;

/** Everything the user store addresses. */
export type UserSchema = TableSchema<UserColumns> & {
  /** Attribute name → the real column that holds it, the only authority for that key. */
  readonly promoted: Readonly<Record<string, Column>>;
};
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
  readonly users: TableSpec<TUsers, UserColumnNames<TUsers>> & {
    /**
     * Attributes kept as real columns, keyed by attribute name: `{ role: "role" }`.
     * Each column must read back as a string, number, boolean or `null`.
     */
    readonly promoted?: Readonly<Record<string, ColumnKey<TUsers, PromotedValue>>>;
  };
  readonly identifiers: TableSpec<TIdentifiers, IdentifierColumnNames<TIdentifiers>>;
}

/**
 * Resolve one table's mapping into the column objects the store queries with.
 *
 * The cast is where the two type systems meet. `ColumnKey` has already checked,
 * at the caller's own call site, that every named column reads back as the value
 * the store needs; what it cannot do is carry that fact through a lookup on a
 * table whose shape is still generic. `TColumns` restates it, once, here.
 *
 * @internal
 */
export const resolveTable = <TColumns>(spec: TableSpec<Table, object>): TableSchema<TColumns> => {
  const source: Readonly<Record<string, Column>> = getTableColumns(spec.table);
  // SAFETY: `TableSpec` types `columns` as a mapping whose every value is a
  // `ColumnKey`, a string key of `spec.table` (or absent, for an optional field).
  const names = spec.columns as Readonly<Record<string, string>>;
  // An optional field left unmapped (`users.attributes`) is simply absent.
  const columns = R.map(
    R.filter(names, (key) => key !== undefined),
    (key) => source[key],
  );
  return {
    table: spec.table,
    // SAFETY: each column was named through a `ColumnKey`, which checked at the
    // caller's call site that it reads back as `TColumns` needs (see above).
    columns: columns as TColumns,
    names,
  };
};

/**
 * A `defineSchema` mapping the stores cannot use: a promoted attribute mapped
 * onto a column the stores already write as a fixed field (`id`, `name`,
 * `image`, `attributes`, `createdAt`, `updatedAt`, `passwordHash`).
 */
export class SchemaMappingError extends Schema.TaggedError<
  SchemaMappingError,
  { readonly brand: unique symbol }
>()("SchemaMappingError", {
  message: Schema.String,
}) {}

/**
 * Point the stores at tables this package did not define.
 *
 * Each entry names a table and says which of its columns holds each field the
 * corresponding store reads and writes. A column's type must read back as the
 * value the store needs (a `uuid` key reads as `string`; a `bigint` one is not
 * supported). Beyond the mapping, a table still needs:
 *
 * - attribute bags that read back as an object
 *   (`jsonb().$type<Auth.JsonObject>()`, not a bare `jsonb()`);
 * - a database default for every required column the stores do not know;
 * - a unique index on the identifiers table's `(type, value)`, which makes
 *   `Auth.claimIdentifier` correct.
 *
 * An attribute under `users.promoted` is a real column, presented in
 * `user.attributes` under its name; the column is the only authority for that
 * key, and a `NULL` leaves it absent.
 *
 * Throws {@link SchemaMappingError} when `users.promoted` maps an attribute
 * onto a column already mapped to a fixed field.
 */
export const defineSchema = <
  TSessions extends Table,
  TUsers extends Table,
  TIdentifiers extends Table,
>(
  spec: AuthSchemaSpec<TSessions, TUsers, TIdentifiers>,
): AuthSchema => {
  const users = spec.users.columns;
  const fixed: Readonly<Record<string, string | undefined>> = {
    id: users.id,
    name: users.name,
    image: users.image,
    attributes: users.attributes,
    createdAt: users.createdAt,
    updatedAt: users.updatedAt,
    passwordHash: users.passwordHash,
  };
  const clashes = R.collect(spec.users.promoted ?? {}, (attribute, key) =>
    R.findFirst(fixed, (mapped) => mapped === key).pipe(
      Option.map(([field]) => `"${attribute}" onto "${key}", the ${field} column`),
    ),
  ).filter(Option.isSome);
  if (Arr.isReadonlyArrayNonEmpty(clashes)) {
    throw new SchemaMappingError({
      message:
        `defineSchema: users.promoted maps ${clashes.map((clash) => clash.value).join(", ")}. ` +
        "The stores write those columns as fixed fields, so a promoted attribute would overwrite them. " +
        "Map each promoted attribute to a column of its own.",
    });
  }
  const userColumns: Readonly<Record<string, Column>> = getTableColumns(spec.users.table);
  return {
    _tag: "AuthSchema",
    sessions: resolveTable<SessionColumns>(spec.sessions),
    users: {
      ...resolveTable<UserColumns>(spec.users),
      promoted: R.map(spec.users.promoted ?? {}, (key) => userColumns[key]),
    },
    identifiers: resolveTable<IdentifierColumns>(spec.identifiers),
  };
};

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
        passwordHash: "passwordHash",
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
 * built from domain fields lands in the caller's columns. A field whose
 * optional column the mapping left out (`users.passwordHash`) is dropped, so
 * nothing is written to a column the table does not have.
 *
 * The values are checked against the resolved columns on the way through —
 * `GetColumnData` in `query` mode is what each column reads and writes,
 * nullability included — so a store cannot put a `Date` where its mapping named
 * a text column. A value may also be a `SQL` expression over the row
 * (`remaining - 1`), which every dialect's `set` accepts.
 *
 * @internal
 */
export const writeValues = <TColumns extends Readonly<Record<string, Column>>>(
  schema: TableSchema<TColumns>,
  values: Partial<{ readonly [K in keyof TColumns]: GetColumnData<TColumns[K]> | SQL }>,
): InferInsertModel<Table> => {
  const names: Readonly<Record<string, string | undefined>> = schema.names;
  return R.mapKeys(
    R.filter(values, (_value, field) => names[field] !== undefined),
    (field) => names[field] ?? field,
  );
};

// ---------------------------------------------------------------------------
// The stores beyond sign-in: API keys, one-time tokens, rate limits
// ---------------------------------------------------------------------------

/** Which of `TTable`'s columns hold each field of an API key. */
export interface ApiKeyColumnNames<TTable extends Table> {
  readonly id: ColumnKey<TTable, string>;
  /** The owner: the column an application points its foreign key at `users.id` from. */
  readonly userId: ColumnKey<TTable, string>;
  readonly name: ColumnKey<TTable, string | null>;
  readonly prefix: ColumnKey<TTable, string | null>;
  readonly start: ColumnKey<TTable, string>;
  /** SHA-256 hex digest of the full key, never the key; give it a unique index. */
  readonly keyHash: ColumnKey<TTable, string>;
  readonly enabled: ColumnKey<TTable, boolean>;
  readonly expiresAt: ColumnKey<TTable, Date | null>;
  readonly lastUsedAt: ColumnKey<TTable, Date | null>;
  readonly permissions: ColumnKey<TTable, ApiKeyPermissions | null>;
  readonly metadata: ColumnKey<TTable, Auth.JsonObject | null>;
  readonly remaining: ColumnKey<TTable, number | null>;
  readonly refillAmount: ColumnKey<TTable, number | null>;
  readonly refillInterval: ColumnKey<TTable, number | null>;
  readonly refillMax: ColumnKey<TTable, number | null>;
  readonly lastRefillAt: ColumnKey<TTable, Date | null>;
  readonly rateLimitMaxRequests: ColumnKey<TTable, number | null>;
  readonly rateLimitWindowMs: ColumnKey<TTable, number | null>;
  readonly createdAt: ColumnKey<TTable, Date>;
  readonly updatedAt: ColumnKey<TTable, Date>;
}

/** Which of `TTable`'s columns hold each field of a pending one-time token. */
export interface TokenColumnNames<TTable extends Table> {
  /** SHA-256 hex digest of the token, never the token; the primary key. */
  readonly token: ColumnKey<TTable, string>;
  /**
   * `"email-verification"` or `"password-reset"`: one table serves both
   * stores. A plain `text` column maps fine.
   */
  readonly purpose: ColumnKey<TTable, string>;
  /** The owner: the column an application points its foreign key at `users.id` from. */
  readonly userId: ColumnKey<TTable, string>;
  readonly email: ColumnKey<TTable, string>;
  readonly createdAt: ColumnKey<TTable, Date>;
  readonly expiresAt: ColumnKey<TTable, Date>;
}

/** Which of `TTable`'s columns hold each field of a rate-limit counter. */
export interface RateLimitColumnNames<TTable extends Table> {
  /** The rate-limit key; the primary key (the upsert conflicts on it). */
  readonly key: ColumnKey<TTable, string>;
  readonly count: ColumnKey<TTable, number>;
  readonly resetAt: ColumnKey<TTable, Date>;
  readonly blockedUntil: ColumnKey<TTable, Date | null>;
}

/** The API key columns, resolved to drizzle column objects. */
export type ApiKeyColumns = {
  readonly id: StoreColumn<string>;
  readonly userId: StoreColumn<string>;
  readonly name: NullableColumn<string>;
  readonly prefix: NullableColumn<string>;
  readonly start: StoreColumn<string>;
  readonly keyHash: StoreColumn<string>;
  readonly enabled: StoreColumn<boolean>;
  readonly expiresAt: NullableColumn<Date>;
  readonly lastUsedAt: NullableColumn<Date>;
  readonly permissions: NullableColumn<ApiKeyPermissions>;
  readonly metadata: NullableColumn<Auth.JsonObject>;
  readonly remaining: NullableColumn<number>;
  readonly refillAmount: NullableColumn<number>;
  readonly refillInterval: NullableColumn<number>;
  readonly refillMax: NullableColumn<number>;
  readonly lastRefillAt: NullableColumn<Date>;
  readonly rateLimitMaxRequests: NullableColumn<number>;
  readonly rateLimitWindowMs: NullableColumn<number>;
  readonly createdAt: StoreColumn<Date>;
  readonly updatedAt: StoreColumn<Date>;
};

/** The token columns, resolved to drizzle column objects. */
export type TokenColumns = {
  readonly token: StoreColumn<string>;
  /** Read back as a `TokenPurpose`; the stores write no other value. */
  readonly purpose: StoreColumn<TokenPurpose>;
  readonly userId: StoreColumn<string>;
  readonly email: StoreColumn<string>;
  readonly createdAt: StoreColumn<Date>;
  readonly expiresAt: StoreColumn<Date>;
};

/** The rate-limit columns, resolved to drizzle column objects. */
export type RateLimitColumns = {
  readonly key: StoreColumn<string>;
  readonly count: StoreColumn<number>;
  readonly resetAt: StoreColumn<Date>;
  readonly blockedUntil: NullableColumn<Date>;
};

/** What `ApiKeyStore` addresses: one table and its mapping. */
export type ApiKeySchema = TableSchema<ApiKeyColumns> & { readonly _tag: "ApiKeySchema" };
/** What the token stores address: one table and its mapping. */
export type TokenSchema = TableSchema<TokenColumns> & { readonly _tag: "TokenSchema" };
/** What `RateLimitStore` addresses: one table and its mapping. */
export type RateLimitSchema = TableSchema<RateLimitColumns> & { readonly _tag: "RateLimitSchema" };

/**
 * Point `ApiKeyStore` at an application's own API keys table, so the
 * application owns its migration and its `user_id` foreign key (with
 * `ON DELETE CASCADE`, deleting a user revokes their keys in the database as
 * well as through core's account deletion).
 *
 * Every field is mapped, since the store writes every one. The `keyHash`
 * column needs a unique index; an extra required column the store knows
 * nothing about needs a database default.
 *
 * @example
 * ```ts
 * const appApiKeys = pgTable("api_keys", {
 *   id: text("id").primaryKey(),
 *   owner: uuid("owner_id").notNull().references(() => appUsers.userId, { onDelete: "cascade" }),
 *   // ... the other columns, under the application's own names
 * });
 *
 * const apiKeys = defineApiKeyTable({
 *   table: appApiKeys,
 *   columns: { id: "id", userId: "owner", keyHash: "digest", ... },
 * });
 *
 * const store = ApiKeyStore.layer(apiKeys).pipe(Layer.provide(databaseLayer(db)));
 * ```
 */
export const defineApiKeyTable = <TTable extends Table>(
  spec: TableSpec<TTable, ApiKeyColumnNames<TTable>>,
): ApiKeySchema => ({ _tag: "ApiKeySchema", ...resolveTable<ApiKeyColumns>(spec) });

/**
 * Point `TokenStore`'s email-verification and password-reset stores at an
 * application's own tokens table, so the application owns its `user_id`
 * foreign key: with `ON DELETE CASCADE`, deleting a user drops their pending
 * tokens in the database too.
 *
 * The table holds both purposes, told apart by the mapped `purpose` column,
 * with `token` as its primary key; an index on `(purpose, user_id)` serves the
 * per-user reads and deletes.
 */
export const defineTokenTable = <TTable extends Table>(
  spec: TableSpec<TTable, TokenColumnNames<TTable>>,
): TokenSchema => ({ _tag: "TokenSchema", ...resolveTable<TokenColumns>(spec) });

/**
 * Point `RateLimitStore` (and its `purgeExpired`) at an application's own
 * rate-limit table. `key` must be the primary key or carry a unique index:
 * `increment` and `set` are upserts that conflict on it.
 */
export const defineRateLimitTable = <TTable extends Table>(
  spec: TableSpec<TTable, RateLimitColumnNames<TTable>>,
): RateLimitSchema => ({ _tag: "RateLimitSchema", ...resolveTable<RateLimitColumns>(spec) });

/** What `ApiKeyStore` accepts: a dialect's tables, or a mapped API keys table. */
export type ApiKeyTableInput = Tables | ApiKeySchema;
/** What the token stores accept: a dialect's tables, or a mapped tokens table. */
export type TokenTableInput = Tables | TokenSchema;
/** What `RateLimitStore` accepts: a dialect's tables, or a mapped rate-limit table. */
export type RateLimitTableInput = Tables | RateLimitSchema;

/** The identity mapping over a dialect's API keys table. @internal */
export const resolveApiKeyTable = (input: ApiKeyTableInput): ApiKeySchema =>
  "_tag" in input
    ? input
    : defineApiKeyTable({
        table: input.apiKeys,
        columns: {
          id: "id",
          userId: "userId",
          name: "name",
          prefix: "prefix",
          start: "start",
          keyHash: "keyHash",
          enabled: "enabled",
          expiresAt: "expiresAt",
          lastUsedAt: "lastUsedAt",
          permissions: "permissions",
          metadata: "metadata",
          remaining: "remaining",
          refillAmount: "refillAmount",
          refillInterval: "refillInterval",
          refillMax: "refillMax",
          lastRefillAt: "lastRefillAt",
          rateLimitMaxRequests: "rateLimitMaxRequests",
          rateLimitWindowMs: "rateLimitWindowMs",
          createdAt: "createdAt",
          updatedAt: "updatedAt",
        },
      });

/** The identity mapping over a dialect's tokens table. @internal */
export const resolveTokenTable = (input: TokenTableInput): TokenSchema =>
  "_tag" in input
    ? input
    : defineTokenTable({
        table: input.tokens,
        columns: {
          token: "token",
          purpose: "purpose",
          userId: "userId",
          email: "email",
          createdAt: "createdAt",
          expiresAt: "expiresAt",
        },
      });

/** The identity mapping over a dialect's rate-limit table. @internal */
export const resolveRateLimitTable = (input: RateLimitTableInput): RateLimitSchema =>
  "_tag" in input
    ? input
    : defineRateLimitTable({
        table: input.rateLimits,
        columns: { key: "key", count: "count", resetAt: "resetAt", blockedUntil: "blockedUntil" },
      });
