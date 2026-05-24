import { and, asc, eq, inArray } from "drizzle-orm";
import { db, schema } from "../db/client";
import { isFollowing } from "./profiles";
import type { ConduitComment } from "../types";

export class ConduitCommentError extends Error {
  constructor(
    message: string,
    readonly status = 422,
  ) {
    super(message);
    this.name = "ConduitCommentError";
  }
}

type CommentRow = typeof schema.comments.$inferSelect;
type UserRow = typeof schema.users.$inferSelect;

function rowToComment(row: CommentRow, author: UserRow, following: boolean): ConduitComment {
  return {
    id: row.id,
    body: row.body,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    author: {
      username: author.username,
      bio: author.bio,
      image: author.image,
      following,
    },
  };
}

export function listComments(slug: string, viewerId: string | null): ConduitComment[] {
  const article = db
    .select({ id: schema.articles.id })
    .from(schema.articles)
    .where(eq(schema.articles.slug, slug))
    .get();
  if (!article) return [];

  const rows = db
    .select()
    .from(schema.comments)
    .where(eq(schema.comments.articleId, article.id))
    .orderBy(asc(schema.comments.createdAt))
    .all();
  if (rows.length === 0) return [];

  const authorIds = [...new Set(rows.map((r) => r.authorId))];
  const authors = db.select().from(schema.users).where(inArray(schema.users.id, authorIds)).all();
  const authorById = new Map(authors.map((a) => [a.id, a] as const));

  return rows.map((r) =>
    rowToComment(
      r,
      authorById.get(r.authorId)!,
      viewerId ? isFollowing(viewerId, r.authorId) : false,
    ),
  );
}

export function addComment(slug: string, authorId: string, body: string): ConduitComment {
  if (!body?.trim()) throw new ConduitCommentError("body is required");
  const article = db
    .select({ id: schema.articles.id })
    .from(schema.articles)
    .where(eq(schema.articles.slug, slug))
    .get();
  if (!article) throw new ConduitCommentError("article not found", 404);

  const inserted = db
    .insert(schema.comments)
    .values({ articleId: article.id, authorId, body })
    .returning()
    .get();
  const author = db.select().from(schema.users).where(eq(schema.users.id, authorId)).get();
  return rowToComment(inserted, author!, false);
}

export function deleteComment(slug: string, commentId: number, requesterId: string): void {
  const article = db
    .select({ id: schema.articles.id })
    .from(schema.articles)
    .where(eq(schema.articles.slug, slug))
    .get();
  if (!article) throw new ConduitCommentError("article not found", 404);
  const row = db.select().from(schema.comments).where(eq(schema.comments.id, commentId)).get();
  if (!row || row.articleId !== article.id) throw new ConduitCommentError("comment not found", 404);
  if (row.authorId !== requesterId) throw new ConduitCommentError("forbidden", 403);
  db.delete(schema.comments)
    .where(and(eq(schema.comments.id, commentId), eq(schema.comments.articleId, article.id)))
    .run();
}
