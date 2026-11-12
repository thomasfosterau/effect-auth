/**
 * The DDL behind every dialect's `migrationStatements`, generated from one
 * column spec per table and a per-dialect type map, so the three dialects
 * cannot drift apart in which columns, keys and indexes they create.
 *
 * Each column names a semantic {@link ColumnType}; a {@link DdlDialect} says
 * what that type is called on its engine, how a primary key and a default are
 * spelled, and whether indexes are separate statements (PostgreSQL, SQLite:
 * `CREATE INDEX IF NOT EXISTS`) or declared inside the `CREATE TABLE` (MySQL,
 * which has no `IF NOT EXISTS` for an index).
 *
 * The drizzle tables themselves stay per dialect, because each dialect's
 * builders are their own types; `*Schema.test.ts` checks that both agree.
 *
 * @internal
 */

import { resolveTableNames } from "./internal.ts";
import type { TableNames } from "./Schema.ts";

/** What a column holds, before a dialect names its type. */
export type ColumnType =
  | "key"
  | "image"
  | "password"
  | "tag"
  | "short"
  | "identifierValue"
  | "instant"
  | "json"
  | "boolean"
  | "integer"
  | "bigint";

/** A column default every dialect spells its own way. */
type DefaultValue = "emptyObject" | "true" | "false";

interface ColumnSpec {
  readonly name: string;
  readonly type: ColumnType;
  readonly notNull?: true;
  readonly primaryKey?: true;
  readonly default?: DefaultValue;
}

interface IndexSpec {
  /** Appended to the table name: `<table>_<suffix>`. */
  readonly suffix: string;
  readonly columns: ReadonlyArray<string>;
  readonly unique?: true;
}

interface TableSpec {
  readonly table: keyof TableNames;
  readonly columns: ReadonlyArray<ColumnSpec>;
  readonly indexes: ReadonlyArray<IndexSpec>;
}

/** How one engine spells the spec. */
export interface DdlDialect {
  readonly types: Readonly<Record<ColumnType, string>>;
  /** What follows a primary-key column's type. */
  readonly primaryKey: string;
  /** `DEFAULT <value>`'s value, or `undefined` where the engine takes none. */
  readonly defaults: Readonly<Record<DefaultValue, string | undefined>>;
  /** Quote a column name the engine reserves. */
  readonly quote: (name: string) => string;
  /** Declare indexes inside `CREATE TABLE` rather than as statements of their own. */
  readonly inlineIndexes: boolean;
}

const pk = (name: string): ColumnSpec => ({ name, type: "key", primaryKey: true });
const required = (name: string, type: ColumnType): ColumnSpec => ({ name, type, notNull: true });
const optional = (name: string, type: ColumnType): ColumnSpec => ({ name, type });
const bag = (name: string): ColumnSpec => ({
  name,
  type: "json",
  notNull: true,
  default: "emptyObject",
});
const flag = (name: string, value: "true" | "false"): ColumnSpec => ({
  name,
  type: "boolean",
  notNull: true,
  default: value,
});
const byUser: IndexSpec = { suffix: "user_id_idx", columns: ["user_id"] };

/** Every table, in dependency order. */
const spec: ReadonlyArray<TableSpec> = [
  {
    table: "users",
    columns: [
      pk("id"),
      optional("name", "key"),
      optional("image", "image"),
      optional("password_hash", "password"),
      bag("attributes"),
      required("created_at", "instant"),
      required("updated_at", "instant"),
    ],
    indexes: [],
  },
  {
    table: "sessions",
    columns: [
      pk("id"),
      required("user_id", "key"),
      required("expires_at", "instant"),
      required("created_at", "instant"),
      required("last_activity_at", "instant"),
      bag("attributes"),
    ],
    indexes: [byUser],
  },
  {
    table: "identifiers",
    columns: [
      pk("id"),
      required("user_id", "key"),
      required("type", "tag"),
      required("value", "identifierValue"),
      flag("verified", "false"),
      optional("verified_at", "instant"),
      required("created_at", "instant"),
    ],
    indexes: [{ suffix: "type_value_key", columns: ["type", "value"], unique: true }, byUser],
  },
  {
    table: "apiKeys",
    columns: [
      pk("id"),
      required("user_id", "key"),
      optional("name", "key"),
      optional("prefix", "short"),
      required("start", "short"),
      required("key_hash", "key"),
      flag("enabled", "true"),
      optional("expires_at", "instant"),
      optional("last_used_at", "instant"),
      optional("permissions", "json"),
      bag("metadata"),
      optional("remaining", "integer"),
      optional("refill_amount", "integer"),
      optional("refill_interval", "bigint"),
      optional("refill_max", "integer"),
      optional("last_refill_at", "instant"),
      optional("rate_limit_max_requests", "integer"),
      optional("rate_limit_window_ms", "bigint"),
      required("created_at", "instant"),
      required("updated_at", "instant"),
    ],
    indexes: [{ suffix: "key_hash_key", columns: ["key_hash"], unique: true }, byUser],
  },
  {
    table: "rateLimits",
    columns: [
      pk("key"),
      required("count", "integer"),
      required("reset_at", "instant"),
      optional("blocked_until", "instant"),
    ],
    indexes: [],
  },
  {
    table: "tokens",
    columns: [
      pk("token"),
      required("purpose", "tag"),
      required("user_id", "key"),
      required("email", "key"),
      required("created_at", "instant"),
      required("expires_at", "instant"),
    ],
    indexes: [{ suffix: "purpose_user_id_idx", columns: ["purpose", "user_id"] }],
  },
];

/** PostgreSQL: text keys, `timestamptz`, `jsonb`, separate index statements. */
export const pgDialect: DdlDialect = {
  types: {
    key: "TEXT",
    image: "TEXT",
    password: "TEXT",
    tag: "TEXT",
    short: "TEXT",
    identifierValue: "TEXT",
    instant: "TIMESTAMPTZ",
    json: "JSONB",
    boolean: "BOOLEAN",
    integer: "INTEGER",
    bigint: "BIGINT",
  },
  primaryKey: " PRIMARY KEY",
  defaults: { emptyObject: "'{}'::jsonb", true: "TRUE", false: "FALSE" },
  quote: (name) => name,
  inlineIndexes: false,
};

/**
 * SQLite: PostgreSQL's layout with SQLite's storage classes (epoch-millisecond
 * `INTEGER` instants, JSON as `TEXT`, 0/1 flags).
 */
export const sqliteDialect: DdlDialect = {
  ...pgDialect,
  types: {
    ...pgDialect.types,
    instant: "INTEGER",
    json: "TEXT",
    boolean: "INTEGER",
    bigint: "INTEGER",
  },
  defaults: { emptyObject: "'{}'", true: "1", false: "0" },
};

const columnLine = (dialect: DdlDialect, column: ColumnSpec): string => {
  const constraint =
    column.primaryKey === true ? dialect.primaryKey : column.notNull === true ? " NOT NULL" : "";
  const value = column.default === undefined ? undefined : dialect.defaults[column.default];
  const fallback = value === undefined ? "" : ` DEFAULT ${value}`;
  return `  ${dialect.quote(column.name)} ${dialect.types[column.type]}${constraint}${fallback}`;
};

const indexName = (table: string, index: IndexSpec): string => `${table}_${index.suffix}`;

const inlineIndex = (table: string, index: IndexSpec): string =>
  `  ${index.unique === true ? "UNIQUE KEY" : "KEY"} ${indexName(table, index)} (${index.columns.join(", ")})`;

const indexStatement = (table: string, index: IndexSpec): string =>
  `CREATE ${index.unique === true ? "UNIQUE INDEX" : "INDEX"} IF NOT EXISTS ${indexName(table, index)} ON ${table} (${index.columns.join(", ")})`;

const tableStatements = (dialect: DdlDialect, table: string, shape: TableSpec): Array<string> => {
  const inline = dialect.inlineIndexes
    ? shape.indexes.map((index) => inlineIndex(table, index))
    : [];
  const lines = [...shape.columns.map((column) => columnLine(dialect, column)), ...inline];
  const create = `CREATE TABLE IF NOT EXISTS ${table} (\n${lines.join(",\n")}\n)`;
  const separate = dialect.inlineIndexes
    ? []
    : shape.indexes.map((index) => indexStatement(table, index));
  return [create, ...separate];
};

/** Every table's DDL on `dialect`, under the given names, in dependency order. */
export const renderDdl = (
  dialect: DdlDialect,
  names?: Partial<TableNames>,
): ReadonlyArray<string> => {
  const resolved = resolveTableNames(names);
  return spec.flatMap((table) => tableStatements(dialect, resolved[table.table], table));
};

/** {@link renderDdl} joined into a single runnable SQL script. */
export const renderScript = (statements: ReadonlyArray<string>): string =>
  `${statements.join(";\n\n")};\n`;
