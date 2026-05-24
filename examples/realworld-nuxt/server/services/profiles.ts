import { and, eq } from "drizzle-orm";
import { db, schema } from "../db/client";
import { getUserByUsername } from "./users";
import type { ConduitProfile } from "../types";

export function getProfile(username: string, viewerId: string | null): ConduitProfile | null {
  const target = getUserByUsername(username);
  if (!target) return null;
  return { ...target, following: viewerId ? isFollowing(viewerId, target.id) : false };
}

export function isFollowing(followerId: string, followingId: string): boolean {
  const row = db
    .select({ x: schema.follows.followerId })
    .from(schema.follows)
    .where(
      and(eq(schema.follows.followerId, followerId), eq(schema.follows.followingId, followingId)),
    )
    .get();
  return Boolean(row);
}

export function follow(followerId: string, username: string): ConduitProfile {
  const target = getUserByUsername(username);
  if (!target) throw Object.assign(new Error("profile not found"), { status: 404 });
  if (followerId === target.id)
    throw Object.assign(new Error("cannot follow yourself"), { status: 422 });
  db.insert(schema.follows)
    .values({ followerId, followingId: target.id })
    .onConflictDoNothing()
    .run();
  return { ...target, following: true };
}

export function unfollow(followerId: string, username: string): ConduitProfile {
  const target = getUserByUsername(username);
  if (!target) throw Object.assign(new Error("profile not found"), { status: 404 });
  db.delete(schema.follows)
    .where(
      and(eq(schema.follows.followerId, followerId), eq(schema.follows.followingId, target.id)),
    )
    .run();
  return { ...target, following: false };
}
