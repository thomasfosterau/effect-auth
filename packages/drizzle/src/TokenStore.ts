/**
 * Drizzle-backed implementations of the two stores that keep pending one-time
 * tokens for a user's address: `Auth.Email.EmailVerificationStore` (email
 * verification links) and `Auth.Password.PasswordResetStore` (password reset
 * links).
 *
 * The two contracts have the same shape (`create`, `get`, `delete`,
 * `deleteByUserId` over `{ token, userId, email, createdAt, expiresAt }`;
 * `EmailVerificationStore` adds `getLatestByUserId`, served for both), so
 * one `tokens` table holds both, told apart by its `purpose` column. Every
 * read and delete is scoped to the store's own purpose: a password-reset
 * request, which first clears the user's pending resets, never clears a
 * pending email verification.
 *
 * ### Contract notes
 *
 * - `token` is the SHA-256 hex digest the core services compute
 *   (`Auth.hashToken`); the raw token goes to the user and never reaches the
 *   store.
 * - `get` returns `null` on a miss; deletes of missing rows are no-ops.
 * - Expiry is the services' to check: an expired row is returned as found.
 * - Every driver failure surfaces as `Auth.AuthError` with the original error
 *   preserved as `cause`.
 */

import { and, desc, eq } from "drizzle-orm";
import { DateTime, Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import { DrizzleDatabase } from "./Database.ts";
import { makeQuery } from "./internal.ts";
import { tables as defaultTables } from "./PgSchema.ts";
import type { Tables, TokenPurpose, TokenRow } from "./Schema.ts";

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
 * cooldown (#682).
 */
interface TokenStoreShape<A extends TokenRecord> {
  readonly create: (record: A) => Effect.Effect<A, Auth.AuthError>;
  readonly get: (token: string) => Effect.Effect<A | null, Auth.AuthError>;
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
  tables: Tables,
): Effect.Effect<TokenStoreShape<TokenRecord>, never, DrizzleDatabase> =>
  Effect.map(DrizzleDatabase, (handle) => {
    const query = makeQuery(handle);
    const table = tables.tokens;
    const byToken = (token: string) => and(eq(table.token, token), eq(table.purpose, purpose));
    const byUser = (userId: string) => and(eq(table.userId, userId), eq(table.purpose, purpose));

    return {
      create: (record) =>
        query(`${purpose}.create`, (db) =>
          db
            .insert(table)
            .values({
              token: record.token,
              purpose,
              userId: record.userId,
              email: record.email,
              createdAt: instant(record.createdAt),
              expiresAt: instant(record.expiresAt),
            })
            .execute(),
        ).pipe(Effect.as(record)),

      get: (token) =>
        query(`${purpose}.get`, (db) =>
          db.select().from(table).where(byToken(token)).limit(1).execute(),
        ).pipe(Effect.map((rows) => (rows[0] === undefined ? null : toRecord(rows[0])))),

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
          db.select().from(table).where(byUser(userId)).orderBy(desc(table.createdAt)).execute(),
        ).pipe(Effect.map((rows) => (rows[0] === undefined ? null : toRecord(rows[0])))),
    };
  });

/** Build an `EmailVerificationStore` over the ambient {@link DrizzleDatabase}. */
export const makeEmailVerificationStore = (
  tables: Tables = defaultTables,
): Effect.Effect<typeof Auth.Email.EmailVerificationStore.Service, never, DrizzleDatabase> =>
  makeFor("email-verification", tables);

/** Build a `PasswordResetStore` over the ambient {@link DrizzleDatabase}. */
export const makePasswordResetStore = (
  tables: Tables = defaultTables,
): Effect.Effect<typeof Auth.Password.PasswordResetStore.Service, never, DrizzleDatabase> =>
  makeFor("password-reset", tables);

/** `EmailVerificationStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const emailVerificationLayer = (
  tables: Tables = defaultTables,
): Layer.Layer<Auth.Email.EmailVerificationStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.Email.EmailVerificationStore, makeEmailVerificationStore(tables));

/** `PasswordResetStore` backed by drizzle, on top of {@link DrizzleDatabase}. */
export const passwordResetLayer = (
  tables: Tables = defaultTables,
): Layer.Layer<Auth.Password.PasswordResetStore, never, DrizzleDatabase> =>
  Layer.effect(Auth.Password.PasswordResetStore, makePasswordResetStore(tables));

/** Both token stores, over one `tokens` table. */
export const layer = (
  tables: Tables = defaultTables,
): Layer.Layer<
  Auth.Email.EmailVerificationStore | Auth.Password.PasswordResetStore,
  never,
  DrizzleDatabase
> => Layer.merge(emailVerificationLayer(tables), passwordResetLayer(tables));
