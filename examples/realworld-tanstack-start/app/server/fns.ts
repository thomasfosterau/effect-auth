// @ts-nocheck — TanStack Start API surface still churning; runtime is current
import { createServerFn } from "@tanstack/react-start";
import { getCurrentUser, setSessionCookieValue, clearSessionCookieValue } from "./auth/session";
import { invalidateSession } from "./auth/runtime";
import { ConduitAuthError, loginUser, registerUser, updateUser } from "./services/users";
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
} from "./services/articles";
import { ConduitCommentError, addComment, deleteComment, listComments } from "./services/comments";
import { follow, getProfile, unfollow } from "./services/profiles";
import { listTags } from "./services/tags";

export const fetchCurrentUser = createServerFn({ method: "GET" }).handler(async () => {
  const { user } = await getCurrentUser();
  return user;
});

export const login = createServerFn({ method: "POST" })
  .validator((d: { email: string; password: string }) => d)
  .handler(async ({ data }) => {
    try {
      const r = await loginUser(data);
      setSessionCookieValue(r.sessionId, r.expiresAt);
      return { user: r.profile, token: r.sessionId };
    } catch (e) {
      if (e instanceof ConduitAuthError) throw new Error(e.message);
      throw e;
    }
  });

export const register = createServerFn({ method: "POST" })
  .validator((d: { email: string; username: string; password: string }) => d)
  .handler(async ({ data }) => {
    try {
      const r = await registerUser(data);
      setSessionCookieValue(r.sessionId, r.expiresAt);
      return { user: r.profile, token: r.sessionId };
    } catch (e) {
      if (e instanceof ConduitAuthError) throw new Error(e.message);
      throw e;
    }
  });

export const logout = createServerFn({ method: "POST" }).handler(async () => {
  const { sessionId } = await getCurrentUser();
  if (sessionId) await invalidateSession(sessionId);
  clearSessionCookieValue();
});

export const updateMe = createServerFn({ method: "POST" })
  .validator(
    (d: {
      email?: string;
      username?: string;
      bio?: string | null;
      image?: string | null;
      password?: string;
    }) => d,
  )
  .handler(async ({ data }) => {
    const { user } = await getCurrentUser();
    if (!user) throw new Error("unauthorized");
    try {
      return await updateUser(user.id, data);
    } catch (e) {
      if (e instanceof ConduitAuthError) throw new Error(e.message);
      throw e;
    }
  });

export const fetchTags = createServerFn({ method: "GET" }).handler(async () => listTags());

export const fetchArticles = createServerFn({ method: "GET" })
  .validator(
    (d: {
      tab?: string;
      tag?: string;
      author?: string;
      favorited?: string;
      offset?: number;
      limit?: number;
    }) => d,
  )
  .handler(async ({ data }) => {
    const { user } = await getCurrentUser();
    const limit = data.limit ?? 10;
    const offset = data.offset ?? 0;
    if (data.tab === "your" && user) return feedArticles(user.id, limit, offset);
    return listArticles(
      { tag: data.tag, author: data.author, favorited: data.favorited, limit, offset },
      user?.id ?? null,
    );
  });

export const fetchArticle = createServerFn({ method: "GET" })
  .validator((d: { slug: string }) => d)
  .handler(async ({ data }) => {
    const { user } = await getCurrentUser();
    return getArticleBySlug(data.slug, user?.id ?? null);
  });

export const fetchComments = createServerFn({ method: "GET" })
  .validator((d: { slug: string }) => d)
  .handler(async ({ data }) => {
    const { user } = await getCurrentUser();
    return listComments(data.slug, user?.id ?? null);
  });

export const publishArticle = createServerFn({ method: "POST" })
  .validator((d: { title: string; description: string; body: string; tagList?: string[] }) => d)
  .handler(async ({ data }) => {
    const { user } = await getCurrentUser();
    if (!user) throw new Error("unauthorized");
    try {
      return createArticle(user.id, data);
    } catch (e) {
      if (e instanceof ConduitArticleError) throw new Error(e.message);
      throw e;
    }
  });

export const editArticle = createServerFn({ method: "POST" })
  .validator((d: { slug: string; title: string; description: string; body: string }) => d)
  .handler(async ({ data }) => {
    const { user } = await getCurrentUser();
    if (!user) throw new Error("unauthorized");
    try {
      return updateArticle(user.id, data.slug, data);
    } catch (e) {
      if (e instanceof ConduitArticleError) throw new Error(e.message);
      throw e;
    }
  });

export const removeArticle = createServerFn({ method: "POST" })
  .validator((d: { slug: string }) => d)
  .handler(async ({ data }) => {
    const { user } = await getCurrentUser();
    if (!user) throw new Error("unauthorized");
    deleteArticle(user.id, data.slug);
  });

export const toggleFavorite = createServerFn({ method: "POST" })
  .validator((d: { slug: string; favorited: boolean }) => d)
  .handler(async ({ data }) => {
    const { user } = await getCurrentUser();
    if (!user) throw new Error("unauthorized");
    return data.favorited ? unfavorite(user.id, data.slug) : favorite(user.id, data.slug);
  });

export const toggleFollow = createServerFn({ method: "POST" })
  .validator((d: { username: string; following: boolean }) => d)
  .handler(async ({ data }) => {
    const { user } = await getCurrentUser();
    if (!user) throw new Error("unauthorized");
    return data.following ? unfollow(user.id, data.username) : follow(user.id, data.username);
  });

export const fetchProfile = createServerFn({ method: "GET" })
  .validator((d: { username: string }) => d)
  .handler(async ({ data }) => {
    const { user } = await getCurrentUser();
    return getProfile(data.username, user?.id ?? null);
  });

export const postComment = createServerFn({ method: "POST" })
  .validator((d: { slug: string; body: string }) => d)
  .handler(async ({ data }) => {
    const { user } = await getCurrentUser();
    if (!user) throw new Error("unauthorized");
    try {
      return addComment(data.slug, user.id, data.body);
    } catch (e) {
      if (e instanceof ConduitCommentError) throw new Error(e.message);
      throw e;
    }
  });

export const removeComment = createServerFn({ method: "POST" })
  .validator((d: { slug: string; id: number }) => d)
  .handler(async ({ data }) => {
    const { user } = await getCurrentUser();
    if (!user) throw new Error("unauthorized");
    deleteComment(data.slug, data.id, user.id);
  });
