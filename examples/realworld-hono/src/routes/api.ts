import { Hono } from "hono";
import { setSessionCookieValue } from "../auth/session";
import { invalidateSession } from "../auth/runtime";
import { ConduitAuthError, loginUser, registerUser, updateUser } from "../services/users";
import {
  ConduitArticleError,
  createArticle,
  deleteArticle,
  favorite,
  feedArticles,
  getArticleBySlug,
  listArticles,
  unfavorite,
  updateArticle,
} from "../services/articles";
import { ConduitCommentError, addComment, deleteComment, listComments } from "../services/comments";
import { follow, getProfile, unfollow } from "../services/profiles";
import { listTags } from "../services/tags";

export const apiRouter = new Hono();

apiRouter.post("/users", async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as {
    user?: { email: string; username: string; password: string };
  };
  if (!body.user) return c.json({ errors: { body: ["user is required"] } }, 422);
  try {
    const r = await registerUser(body.user);
    setSessionCookieValue(c, r.sessionId, r.expiresAt);
    return c.json({
      user: {
        email: r.profile.email,
        username: r.profile.username,
        bio: r.profile.bio,
        image: r.profile.image,
        token: r.sessionId,
      },
    });
  } catch (e) {
    if (e instanceof ConduitAuthError)
      return c.json({ errors: { body: [e.message] } }, e.status as never);
    throw e;
  }
});

apiRouter.post("/users/login", async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as {
    user?: { email: string; password: string };
  };
  if (!body.user) return c.json({ errors: { body: ["user is required"] } }, 422);
  try {
    const r = await loginUser(body.user);
    setSessionCookieValue(c, r.sessionId, r.expiresAt);
    return c.json({
      user: {
        email: r.profile.email,
        username: r.profile.username,
        bio: r.profile.bio,
        image: r.profile.image,
        token: r.sessionId,
      },
    });
  } catch (e) {
    if (e instanceof ConduitAuthError)
      return c.json({ errors: { "email or password": ["is invalid"] } }, e.status as never);
    throw e;
  }
});

apiRouter.post("/users/logout", async (c) => {
  const sid = c.get("sessionId");
  if (sid) await invalidateSession(sid);
  return c.json({ ok: true });
});

apiRouter.get("/user", async (c) => {
  const user = c.get("user");
  if (!user) return c.json({ errors: { body: ["unauthorized"] } }, 401);
  return c.json({
    user: {
      email: user.email,
      username: user.username,
      bio: user.bio,
      image: user.image,
      token: c.get("sessionId") ?? "",
    },
  });
});

apiRouter.put("/user", async (c) => {
  const user = c.get("user");
  if (!user) return c.json({ errors: { body: ["unauthorized"] } }, 401);
  const body = (await c.req.json().catch(() => ({}))) as { user?: Record<string, unknown> };
  if (!body.user) return c.json({ errors: { body: ["user is required"] } }, 422);
  try {
    const updated = await updateUser(user.id, body.user as never);
    return c.json({
      user: {
        email: updated.email,
        username: updated.username,
        bio: updated.bio,
        image: updated.image,
        token: c.get("sessionId") ?? "",
      },
    });
  } catch (e) {
    if (e instanceof ConduitAuthError)
      return c.json({ errors: { body: [e.message] } }, e.status as never);
    throw e;
  }
});

apiRouter.get("/profiles/:username", (c) => {
  const user = c.get("user");
  const profile = getProfile(c.req.param("username"), user?.id ?? null);
  if (!profile) return c.json({ errors: { body: ["profile not found"] } }, 404);
  return c.json({
    profile: {
      username: profile.username,
      bio: profile.bio,
      image: profile.image,
      following: profile.following ?? false,
    },
  });
});

apiRouter.post("/profiles/:username/follow", (c) => {
  const user = c.get("user");
  if (!user) return c.json({ errors: { body: ["unauthorized"] } }, 401);
  try {
    const profile = follow(user.id, c.req.param("username"));
    return c.json({
      profile: {
        username: profile.username,
        bio: profile.bio,
        image: profile.image,
        following: true,
      },
    });
  } catch (e) {
    const status = (e as { status?: number }).status ?? 500;
    return c.json({ errors: { body: [(e as Error).message] } }, status as never);
  }
});

apiRouter.delete("/profiles/:username/follow", (c) => {
  const user = c.get("user");
  if (!user) return c.json({ errors: { body: ["unauthorized"] } }, 401);
  try {
    const profile = unfollow(user.id, c.req.param("username"));
    return c.json({
      profile: {
        username: profile.username,
        bio: profile.bio,
        image: profile.image,
        following: false,
      },
    });
  } catch (e) {
    const status = (e as { status?: number }).status ?? 500;
    return c.json({ errors: { body: [(e as Error).message] } }, status as never);
  }
});

apiRouter.get("/articles", (c) => {
  const user = c.get("user");
  const q = c.req.query();
  return c.json(
    listArticles(
      {
        tag: q.tag,
        author: q.author,
        favorited: q.favorited,
        limit: q.limit ? Number(q.limit) : undefined,
        offset: q.offset ? Number(q.offset) : undefined,
      },
      user?.id ?? null,
    ),
  );
});

apiRouter.post("/articles", async (c) => {
  const user = c.get("user");
  if (!user) return c.json({ errors: { body: ["unauthorized"] } }, 401);
  const body = (await c.req.json().catch(() => ({}))) as {
    article?: { title: string; description: string; body: string; tagList?: string[] };
  };
  if (!body.article) return c.json({ errors: { body: ["article is required"] } }, 422);
  try {
    return c.json({ article: createArticle(user.id, body.article) });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return c.json({ errors: { body: [e.message] } }, e.status as never);
    throw e;
  }
});

apiRouter.get("/articles/feed", (c) => {
  const user = c.get("user");
  if (!user) return c.json({ errors: { body: ["unauthorized"] } }, 401);
  const q = c.req.query();
  return c.json(
    feedArticles(user.id, q.limit ? Number(q.limit) : 20, q.offset ? Number(q.offset) : 0),
  );
});

apiRouter.get("/articles/:slug", (c) => {
  const user = c.get("user");
  const article = getArticleBySlug(c.req.param("slug"), user?.id ?? null);
  if (!article) return c.json({ errors: { body: ["article not found"] } }, 404);
  return c.json({ article });
});

apiRouter.put("/articles/:slug", async (c) => {
  const user = c.get("user");
  if (!user) return c.json({ errors: { body: ["unauthorized"] } }, 401);
  const body = (await c.req.json().catch(() => ({}))) as {
    article?: { title?: string; description?: string; body?: string };
  };
  if (!body.article) return c.json({ errors: { body: ["article is required"] } }, 422);
  try {
    return c.json({ article: updateArticle(user.id, c.req.param("slug"), body.article) });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return c.json({ errors: { body: [e.message] } }, e.status as never);
    throw e;
  }
});

apiRouter.delete("/articles/:slug", (c) => {
  const user = c.get("user");
  if (!user) return c.json({ errors: { body: ["unauthorized"] } }, 401);
  try {
    deleteArticle(user.id, c.req.param("slug"));
    return c.body(null, 204);
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return c.json({ errors: { body: [e.message] } }, e.status as never);
    throw e;
  }
});

apiRouter.post("/articles/:slug/favorite", (c) => {
  const user = c.get("user");
  if (!user) return c.json({ errors: { body: ["unauthorized"] } }, 401);
  try {
    return c.json({ article: favorite(user.id, c.req.param("slug")) });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return c.json({ errors: { body: [e.message] } }, e.status as never);
    throw e;
  }
});

apiRouter.delete("/articles/:slug/favorite", (c) => {
  const user = c.get("user");
  if (!user) return c.json({ errors: { body: ["unauthorized"] } }, 401);
  try {
    return c.json({ article: unfavorite(user.id, c.req.param("slug")) });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return c.json({ errors: { body: [e.message] } }, e.status as never);
    throw e;
  }
});

apiRouter.get("/articles/:slug/comments", (c) => {
  const user = c.get("user");
  return c.json({ comments: listComments(c.req.param("slug"), user?.id ?? null) });
});

apiRouter.post("/articles/:slug/comments", async (c) => {
  const user = c.get("user");
  if (!user) return c.json({ errors: { body: ["unauthorized"] } }, 401);
  const body = (await c.req.json().catch(() => ({}))) as { comment?: { body: string } };
  if (!body.comment) return c.json({ errors: { body: ["comment is required"] } }, 422);
  try {
    return c.json({ comment: addComment(c.req.param("slug"), user.id, body.comment.body) });
  } catch (e) {
    if (e instanceof ConduitCommentError)
      return c.json({ errors: { body: [e.message] } }, e.status as never);
    throw e;
  }
});

apiRouter.delete("/articles/:slug/comments/:id", (c) => {
  const user = c.get("user");
  if (!user) return c.json({ errors: { body: ["unauthorized"] } }, 401);
  try {
    deleteComment(c.req.param("slug"), Number(c.req.param("id")), user.id);
    return c.body(null, 204);
  } catch (e) {
    if (e instanceof ConduitCommentError)
      return c.json({ errors: { body: [e.message] } }, e.status as never);
    throw e;
  }
});

apiRouter.get("/tags", (c) => c.json({ tags: listTags() }));
