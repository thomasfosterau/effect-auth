/**
 * Drizzle `EmailVerificationStore` and `PasswordResetStore` over one tokens
 * table, told apart by `purpose` (a dialect's {@link Tables}, or a table mapped
 * with `defineTokenTable`). Each store reads and deletes only its own purpose.
 * Tokens are the digests core computes, and `consume` hands a row to one
 * consumer only.
 */

import { and, desc, eq } from "drizzle-orm";
import { DateTime, Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import {
  resolveTokenTable,
  type TokenColumns,
  type TokenTableInput,
  writeValues,
} from "./Columns.ts";
import { type DrizzleSelected, DrizzleDatabase } from "./Database.ts";
import { affectedRows, makeQuery } from "./internal.ts";
import { tables as defaultTables } from "./PgSchema.ts";
import type { TokenPurpose } from "./Schema.ts";

/** What a token read projects, under the store's own field names. */
type TokenRow = DrizzleSelected<TokenColumns>;

/** The record both token contracts store. */
interface TokenRecord {
  readonly token: string;
  readonly userId: string;
  readonly email: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/**
 * The operations of both token contracts: the four they share, and
 * `getLatestByUserId`, which `EmailVerificationStore` adds for its resend
 * cooldown.
 */
interface TokenStoreShape<A extends TokenRecord> {
  readonly create: (record: A) => Effect.Effect<A, Auth.AuthError>;
  readonly get: (token: string) => Effect.Effect<A | null, Auth.AuthError>;
  readonly consume: (token: string) => Effect.Effect<A | null, Auth.AuthError>;
  readonly delete: (token: string) => Effect.Effect<void, Auth.AuthError>;
  readonly deleteByUserId: (userId: string) => Effect.Effect<void, Auth.AuthError>;
  readonly getLatestByUserId: (userId: string) => Effect.Effect<A | null, Auth.AuthError>;
}

const instant = (millis: number): Date => DateTime.toDateUtc(DateTime.makeUnsafe(millis));

const toRecord = (row: TokenRow): TokenRecord => ({
  token: row.token,
  userId: row.userId,
  email: row.email,
  createdAt: row.createdAt.getTime(),
  expiresAt: row.expiresAt.getTime(),
});

/** One purpose's view of the tokens table. */
const makeFor = (
  purpose: TokenPurpose,
  tables: TokenTableInput,
): Effect.Effect<TokenStoreShape<TokenRecord>, never, DrizzleDatabase> =>
  Effect.map(DrizzleDatabase, (handle) => {
    const query = makeQuery(handle);
    const schema = resolveTokenTable(tables);
    const table = schema.table;
    const column = schema.columns;
    const byToken = (token: string) => and(eq(column.token, token), eq(column.purpose, purpose));
    const byUser = (userId: string) => and(eq(column.userId, userId), eq(column.purpose, purpose));

    return {
      create: (record) =>
        query(`${purpose}.create`, (db) =>
          db
            .insert(table)
            .values(
              writeValues(schema, {
                token: record.token,
                purpose,
                userId: record.userId,
                email: record.email,
                createdAt: instant(record.createdAt),
                expiresAt: instant(record.expiresAt),
              }),
            )
            .execute(),
        ).pipe(Effect.as(record)),

      get: (token) =>
        query(`${purpose}.get`, (db) =>
          db.select(column).from(table).where(byToken(token)).limit(1).execute(),
        ).pipe(Effect.map((rows) => (rows[0] === undefined ? null : toRecord(rows[0])))),

      consume: (token) =>
        Effect.gen(function* () {
          const rows = yield* query(`${purpose}.consume.read`, (db) =>
            db.select(column).from(table).where(byToken(token)).limit(1).execute(),
          );
          const row = rows[0];
          if (row === undefined) return null;
          const deleted = yield* affectedRows(
            `${purpose}.consume`,
            query(`${purpose}.consume`, (db) => db.delete(table).where(byToken(token)).execute()),
          );
          return deleted > 0 ? toRecord(row) : null;
        }),

      delete: (token) =>
        query(`${purpose}.delete`, (db) => db.delete(table).where(byToken(token)).execute()).pipe(
          Effect.asVoid,
        ),

      deleteByUserId: (userId) =>
        query(`${purpose}.deleteByUserId`, (db) =>
          db.delete(table).where(byUser(userId)).execute(),
        ).pipe(Effect.asVoid),

      // The fragment every dialect spells alike has no `limit` after
      // `orderBy`; a user holds only the few rows each resend leaves.
      getLatestByUserId: (userId) =>
        query(`${purpose}.getLatestByUserId`, (db) =>
          db
            .select(column)
            .from(table)
            .where(byUser(userId))
            .orderBy(desc(column.createdAt))
            .execute(),
        ).pipe(Effect.map((rows) => (rows[0] === undefined ? null : toRecord(rows[0])))),
    };
  });

/** Build an `EmailVerificationStore` over the ambient {@link DrizzleDatabase}. */
export const makeEmailVerificationStore = (
  tables: TokenTableInput = defaultTables,
): Effect.Effect<typeof Auth.Email.EmailVerificationStore.Service, never, DrizzleDatabase> =>
  makeFor("email-verification", tables);

/** Build a `PasswordResetStore` over the ambient {@link DrizzleDatabase}. */
export const makePasswordResetStore = (
  tables: TokenTableInput = defaultTables,
): Effect.Effect<typeof Auth.Password.PasswordResetStore.Service, never, DrizzleDatabase> =>
  makeFor("password-reset", tables);

/** `EmailVerificationStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const emailVerificationLayer = (
  tables: TokenTableInput = defaultTables,
): Layer.Layer<Auth.Email.EmailVerificationStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.Email.EmailVerificationStore, makeEmailVerificationStore(tables));

/** `PasswordResetStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const passwordResetLayer = (
  tables: TokenTableInput = defaultTables,
): Layer.Layer<Auth.Password.PasswordResetStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.Password.PasswordResetStore, makePasswordResetStore(tables));

/** Both token stores, over one `tokens` table. */
export const layer = (
  tables: TokenTableInput = defaultTables,
): Layer.Layer<
  Auth.Email.EmailVerificationStore | Auth.Password.PasswordResetStore,
  never,
  DrizzleDatabase
> => Layer.merge(emailVerificationLayer(tables), passwordResetLayer(tables));
