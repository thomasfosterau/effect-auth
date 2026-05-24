import { randomUUID } from "node:crypto";
import { and, count, desc, eq, exists, inArray, sql } from "drizzle-orm";
import { db, schema } from "../db/client.js";
import { isFollowing } from "./profiles.js";
import type { ConduitArticle } from "../types.js";

export class ConduitArticleError extends Error {
  constructor(
    message: string,
    readonly status = 422,
  ) {
    super(message);
    this.name = "ConduitArticleError";
  }
}

function slugify(title: string): string {
  const base =
    title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 80) || "article";
  const suffix = randomUUID().slice(0, 6);
  return `${base}-${suffix}`;
}

type ArticleRow = typeof schema.articles.$inferSelect;
type UserRow = typeof schema.users.$inferSelect;

function rowToArticle(
  article: ArticleRow,
  author: Pick<UserRow, "username" | "bio" | "image" | "id">,
  tagList: string[],
  favorited: boolean,
  favoritesCount: number,
  following: boolean,
): ConduitArticle {
  return {
    slug: article.slug,
    title: article.title,
    description: article.description,
    body: article.body,
    tagList,
    createdAt: article.createdAt.toISOString(),
    updatedAt: article.updatedAt.toISOString(),
    favorited,
    favoritesCount,
    author: {
      username: author.username,
      bio: author.bio,
      image: author.image,
      following,
    },
  };
}

function hydrate(rows: ArticleRow[], viewerId: string | null): ConduitArticle[] {
  if (rows.length === 0) return [];
  const ids = rows.map((r) => r.id);
  const authorIds = [...new Set(rows.map((r) => r.authorId))];

  const authors = db.select().from(schema.users).where(inArray(schema.users.id, authorIds)).all();
  const authorById = new Map(authors.map((a) => [a.id, a] as const));

  const tagRows = db
    .select()
    .from(schema.articleTags)
    .where(inArray(schema.articleTags.articleId, ids))
    .all();
  const tagsByArticle = new Map<string, string[]>();
  for (const t of tagRows) {
    const list = tagsByArticle.get(t.articleId) ?? [];
    list.push(t.tag);
    tagsByArticle.set(t.articleId, list);
  }

  const favCounts = db
    .select({ articleId: schema.favorites.articleId, c: count() })
    .from(schema.favorites)
    .where(inArray(schema.favorites.articleId, ids))
    .groupBy(schema.favorites.articleId)
    .all();
  const favCountByArticle = new Map(favCounts.map((f) => [f.articleId, Number(f.c)] as const));

  const favorited = new Set<string>();
  if (viewerId) {
    const myFavs = db
      .select({ articleId: schema.favorites.articleId })
      .from(schema.favorites)
      .where(and(eq(schema.favorites.userId, viewerId), inArray(schema.favorites.articleId, ids)))
      .all();
    for (const f of myFavs) favorited.add(f.articleId);
  }

  const following = new Set<string>();
  if (viewerId) {
    const rels = db
      .select({ followingId: schema.follows.followingId })
      .from(schema.follows)
      .where(
        and(
          eq(schema.follows.followerId, viewerId),
          inArray(schema.follows.followingId, authorIds),
        ),
      )
      .all();
    for (const r of rels) following.add(r.followingId);
  }

  return rows.map((r) => {
    const author = authorById.get(r.authorId)!;
    return rowToArticle(
      r,
      author,
      (tagsByArticle.get(r.id) ?? []).sort(),
      favorited.has(r.id),
      favCountByArticle.get(r.id) ?? 0,
      following.has(r.authorId),
    );
  });
}

export type ListOpts = {
  tag?: string;
  author?: string;
  favorited?: string;
  limit?: number;
  offset?: number;
};

export function listArticles(
  opts: ListOpts,
  viewerId: string | null,
): { articles: ConduitArticle[]; articlesCount: number } {
  const limit = Math.min(Math.max(opts.limit ?? 20, 1), 100);
  const offset = Math.max(opts.offset ?? 0, 0);

  const whereClauses = [] as ReturnType<typeof eq>[];

  if (opts.author) {
    const author = db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.username, opts.author))
      .get();
    if (!author) return { articles: [], articlesCount: 0 };
    whereClauses.push(eq(schema.articles.authorId, author.id));
  }

  if (opts.favorited) {
    const user = db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.username, opts.favorited))
      .get();
    if (!user) return { articles: [], articlesCount: 0 };
    const favIds = db
      .select({ id: schema.favorites.articleId })
      .from(schema.favorites)
      .where(eq(schema.favorites.userId, user.id))
      .all()
      .map((r) => r.id);
    if (favIds.length === 0) return { articles: [], articlesCount: 0 };
    whereClauses.push(inArray(schema.articles.id, favIds));
  }

  if (opts.tag) {
    whereClauses.push(
      exists(
        db
          .select({ x: sql`1` })
          .from(schema.articleTags)
          .where(
            and(
              eq(schema.articleTags.articleId, schema.articles.id),
              eq(schema.articleTags.tag, opts.tag),
            ),
          ),
      ) as never,
    );
  }

  const where = whereClauses.length > 0 ? and(...whereClauses) : undefined;

  const rows = (
    where ? db.select().from(schema.articles).where(where) : db.select().from(schema.articles)
  )
    .orderBy(desc(schema.articles.createdAt))
    .limit(limit)
    .offset(offset)
    .all();

  const totalRow = where
    ? db.select({ c: count() }).from(schema.articles).where(where).get()
    : db.select({ c: count() }).from(schema.articles).get();
  const total = Number(totalRow?.c ?? 0);

  return { articles: hydrate(rows, viewerId), articlesCount: total };
}

export function feedArticles(
  viewerId: string,
  limit = 20,
  offset = 0,
): { articles: ConduitArticle[]; articlesCount: number } {
  const followingIds = db
    .select({ id: schema.follows.followingId })
    .from(schema.follows)
    .where(eq(schema.follows.followerId, viewerId))
    .all()
    .map((r) => r.id);
  if (followingIds.length === 0) return { articles: [], articlesCount: 0 };

  const where = inArray(schema.articles.authorId, followingIds);
  const rows = db
    .select()
    .from(schema.articles)
    .where(where)
    .orderBy(desc(schema.articles.createdAt))
    .limit(limit)
    .offset(offset)
    .all();
  const totalRow = db.select({ c: count() }).from(schema.articles).where(where).get();
  return { articles: hydrate(rows, viewerId), articlesCount: Number(totalRow?.c ?? 0) };
}

export function getArticleBySlug(slug: string, viewerId: string | null): ConduitArticle | null {
  const row = db.select().from(schema.articles).where(eq(schema.articles.slug, slug)).get();
  if (!row) return null;
  return hydrate([row], viewerId)[0]!;
}

export function createArticle(
  authorId: string,
  input: { title: string; description: string; body: string; tagList?: string[] },
): ConduitArticle {
  if (!input.title?.trim()) throw new ConduitArticleError("title is required");
  if (!input.description?.trim()) throw new ConduitArticleError("description is required");
  if (!input.body?.trim()) throw new ConduitArticleError("body is required");

  const id = randomUUID();
  const slug = slugify(input.title);
  const now = new Date();
  db.insert(schema.articles)
    .values({
      id,
      slug,
      title: input.title.trim(),
      description: input.description.trim(),
      body: input.body,
      authorId,
      createdAt: now,
      updatedAt: now,
    })
    .run();

  const tagList = (input.tagList ?? []).map((t) => t.trim()).filter(Boolean);
  if (tagList.length > 0) {
    db.insert(schema.tags)
      .values(tagList.map((name) => ({ name })))
      .onConflictDoNothing()
      .run();
    db.insert(schema.articleTags)
      .values(tagList.map((tag) => ({ articleId: id, tag })))
      .onConflictDoNothing()
      .run();
  }

  return getArticleBySlug(slug, authorId)!;
}

export function updateArticle(
  authorId: string,
  slug: string,
  patch: { title?: string; description?: string; body?: string },
): ConduitArticle {
  const article = db.select().from(schema.articles).where(eq(schema.articles.slug, slug)).get();
  if (!article) throw new ConduitArticleError("article not found", 404);
  if (article.authorId !== authorId) throw new ConduitArticleError("forbidden", 403);

  const updates: Partial<typeof schema.articles.$inferInsert> = { updatedAt: new Date() };
  let newSlug = article.slug;
  if (patch.title !== undefined && patch.title !== article.title) {
    updates.title = patch.title;
    updates.slug = slugify(patch.title);
    newSlug = updates.slug;
  }
  if (patch.description !== undefined) updates.description = patch.description;
  if (patch.body !== undefined) updates.body = patch.body;
  db.update(schema.articles).set(updates).where(eq(schema.articles.id, article.id)).run();

  return getArticleBySlug(newSlug, authorId)!;
}

export function deleteArticle(authorId: string, slug: string): void {
  const article = db.select().from(schema.articles).where(eq(schema.articles.slug, slug)).get();
  if (!article) throw new ConduitArticleError("article not found", 404);
  if (article.authorId !== authorId) throw new ConduitArticleError("forbidden", 403);
  db.delete(schema.articles).where(eq(schema.articles.id, article.id)).run();
}

export function favorite(userId: string, slug: string): ConduitArticle {
  const article = db.select().from(schema.articles).where(eq(schema.articles.slug, slug)).get();
  if (!article) throw new ConduitArticleError("article not found", 404);
  db.insert(schema.favorites).values({ userId, articleId: article.id }).onConflictDoNothing().run();
  return getArticleBySlug(slug, userId)!;
}

export function unfavorite(userId: string, slug: string): ConduitArticle {
  const article = db.select().from(schema.articles).where(eq(schema.articles.slug, slug)).get();
  if (!article) throw new ConduitArticleError("article not found", 404);
  db.delete(schema.favorites)
    .where(and(eq(schema.favorites.userId, userId), eq(schema.favorites.articleId, article.id)))
    .run();
  return getArticleBySlug(slug, userId)!;
}

// re-export so callers can use `isFollowing` without a separate import
export { isFollowing };
