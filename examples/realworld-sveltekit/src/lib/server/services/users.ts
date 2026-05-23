import { randomUUID } from "node:crypto";
import { eq, or } from "drizzle-orm";
import { db, schema } from "../db/client.js";
import type { ConduitProfile } from "../types.js";
import { hashPassword, verifyPassword } from "../auth/passwords.js";
import { createSession } from "../auth/sessions.js";

export class ConduitAuthError extends Error {
  constructor(
    message: string,
    readonly status = 422,
  ) {
    super(message);
    this.name = "ConduitAuthError";
  }
}

export async function registerUser(input: { email: string; username: string; password: string }) {
  if (!input.email || !input.username || !input.password) {
    throw new ConduitAuthError("email, username, and password are required");
  }
  if (input.password.length < 8) {
    throw new ConduitAuthError("password must be at least 8 characters");
  }

  const existing = db
    .select({ id: schema.users.id })
    .from(schema.users)
    .where(or(eq(schema.users.email, input.email), eq(schema.users.username, input.username)))
    .get();
  if (existing) {
    throw new ConduitAuthError("user with that email or username already exists");
  }

  const passwordHash = await hashPassword(input.password);
  const id = randomUUID();
  db.insert(schema.users)
    .values({ id, email: input.email, username: input.username, passwordHash })
    .run();

  const session = await createSession(id, { ip: null, userAgent: null });
  return {
    profile: toProfile({
      id,
      email: input.email,
      username: input.username,
      bio: null,
      image: null,
    }),
    sessionId: session.id,
    expiresAt: session.expiresAt,
  };
}

export async function loginUser(input: { email: string; password: string }) {
  const row = db.select().from(schema.users).where(eq(schema.users.email, input.email)).get();
  if (!row) throw new ConduitAuthError("invalid email or password", 401);
  const ok = await verifyPassword(input.password, row.passwordHash);
  if (!ok) throw new ConduitAuthError("invalid email or password", 401);
  const session = await createSession(row.id);
  return {
    profile: toProfile(row),
    sessionId: session.id,
    expiresAt: session.expiresAt,
  };
}

export function getUserByUsername(username: string): ConduitProfile | null {
  const row = db.select().from(schema.users).where(eq(schema.users.username, username)).get();
  return row ? toProfile(row) : null;
}

export function getUserById(id: string): ConduitProfile | null {
  const row = db.select().from(schema.users).where(eq(schema.users.id, id)).get();
  return row ? toProfile(row) : null;
}

export async function updateUser(
  userId: string,
  patch: {
    email?: string;
    username?: string;
    bio?: string | null;
    image?: string | null;
    password?: string;
  },
): Promise<ConduitProfile> {
  const updates: Partial<typeof schema.users.$inferInsert> = {};
  if (patch.email !== undefined) updates.email = patch.email;
  if (patch.username !== undefined) updates.username = patch.username;
  if (patch.bio !== undefined) updates.bio = patch.bio;
  if (patch.image !== undefined) updates.image = patch.image;
  if (patch.password) {
    if (patch.password.length < 8)
      throw new ConduitAuthError("password must be at least 8 characters");
    updates.passwordHash = await hashPassword(patch.password);
  }
  if (Object.keys(updates).length > 0) {
    db.update(schema.users).set(updates).where(eq(schema.users.id, userId)).run();
  }
  const row = db.select().from(schema.users).where(eq(schema.users.id, userId)).get();
  if (!row) throw new ConduitAuthError("user disappeared", 500);
  return toProfile(row);
}

function toProfile(row: {
  id: string;
  email: string;
  username: string;
  bio: string | null;
  image: string | null;
}): ConduitProfile {
  return {
    id: row.id,
    email: row.email,
    username: row.username,
    bio: row.bio,
    image: row.image,
  };
}
