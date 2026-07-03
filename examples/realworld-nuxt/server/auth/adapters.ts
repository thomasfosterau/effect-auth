import * as Auth from "effect-auth";
import { Effect } from "effect";
import { eq } from "drizzle-orm";
import { db, schema } from "../db/client";

const rowToSession = (row: typeof schema.sessions.$inferSelect): Auth.Session => ({
  id: row.id,
  userId: row.userId,
  expiresAt: row.expiresAt,
  createdAt: row.createdAt,
  lastActivityAt: row.lastActivityAt,
  attributes: (row.attributes ?? {}) as Record<string, unknown>,
});

export const sessionStore: Auth.SessionStore = {
  create: (session) =>
    Effect.sync(() => {
      db.insert(schema.sessions)
        .values({
          id: session.id,
          userId: session.userId,
          expiresAt: session.expiresAt,
          createdAt: session.createdAt,
          lastActivityAt: session.lastActivityAt,
          attributes: (session.attributes ?? null) as never,
        })
        .run();
      return session;
    }),
  get: (sessionId) =>
    Effect.sync(() => {
      const row = db.select().from(schema.sessions).where(eq(schema.sessions.id, sessionId)).get();
      return row ? rowToSession(row) : null;
    }),
  update: (session) =>
    Effect.sync(() => {
      db.update(schema.sessions)
        .set({
          expiresAt: session.expiresAt,
          lastActivityAt: session.lastActivityAt,
          attributes: (session.attributes ?? null) as never,
        })
        .where(eq(schema.sessions.id, session.id))
        .run();
      return session;
    }),
  delete: (sessionId) =>
    Effect.sync(() => {
      db.delete(schema.sessions).where(eq(schema.sessions.id, sessionId)).run();
    }),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      db.delete(schema.sessions).where(eq(schema.sessions.userId, userId)).run();
    }),
  listByUserId: (userId) =>
    Effect.sync(() =>
      db
        .select()
        .from(schema.sessions)
        .where(eq(schema.sessions.userId, userId))
        .all()
        .map(rowToSession),
    ),
};

export const userStore: Auth.UserStore = {
  get: (userId) =>
    Effect.sync(() => {
      const row = db.select().from(schema.users).where(eq(schema.users.id, userId)).get();
      if (!row) return null;
      return {
        id: row.id,
        email: row.email,
        emailVerified: false,
        ...(row.image !== null && { image: row.image }),
        createdAt: row.createdAt,
        updatedAt: row.createdAt,
        attributes: { username: row.username, bio: row.bio, image: row.image },
      } satisfies Auth.User;
    }),
  getCredentials: (userId) =>
    Effect.sync(() => {
      const row = db
        .select({ passwordHash: schema.users.passwordHash })
        .from(schema.users)
        .where(eq(schema.users.id, userId))
        .get();
      return row?.passwordHash ?? null;
    }),
};
