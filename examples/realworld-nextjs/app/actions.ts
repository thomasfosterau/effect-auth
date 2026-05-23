"use server";

import { redirect } from "next/navigation";
import { clearSessionCookie, getCurrentUser, setSessionCookie } from "@/lib/server/auth/session";
import { invalidateSession } from "@/lib/server/auth/runtime";
import { ConduitAuthError, loginUser, registerUser, updateUser } from "@/lib/server/services/users";
import {
  ConduitArticleError,
  createArticle,
  deleteArticle,
  favorite,
  unfavorite,
  updateArticle,
} from "@/lib/server/services/articles";
import { ConduitCommentError, addComment, deleteComment } from "@/lib/server/services/comments";
import { follow, unfollow } from "@/lib/server/services/profiles";

export type FormState = { errors?: string[]; values?: Record<string, string> } | null;

export async function loginAction(_prev: FormState, data: FormData): Promise<FormState> {
  const email = String(data.get("email") ?? "");
  const password = String(data.get("password") ?? "");
  try {
    const r = await loginUser({ email, password });
    await setSessionCookie(r.sessionId, r.expiresAt);
  } catch (e) {
    if (e instanceof ConduitAuthError) return { errors: [e.message], values: { email } };
    throw e;
  }
  redirect("/");
}

export async function registerAction(_prev: FormState, data: FormData): Promise<FormState> {
  const email = String(data.get("email") ?? "");
  const username = String(data.get("username") ?? "");
  const password = String(data.get("password") ?? "");
  try {
    const r = await registerUser({ email, username, password });
    await setSessionCookie(r.sessionId, r.expiresAt);
  } catch (e) {
    if (e instanceof ConduitAuthError) return { errors: [e.message], values: { email, username } };
    throw e;
  }
  redirect("/");
}

export async function logoutAction() {
  const { sessionId } = await getCurrentUser();
  if (sessionId) await invalidateSession(sessionId);
  await clearSessionCookie();
  redirect("/");
}

export async function updateUserAction(_prev: FormState, data: FormData): Promise<FormState> {
  const { user } = await getCurrentUser();
  if (!user) return { errors: ["unauthorized"] };
  try {
    await updateUser(user.id, {
      image: String(data.get("image") ?? "") || null,
      username: String(data.get("username") ?? "") || undefined,
      bio: String(data.get("bio") ?? "") || null,
      email: String(data.get("email") ?? "") || undefined,
      password: String(data.get("password") ?? "") || undefined,
    });
  } catch (e) {
    if (e instanceof ConduitAuthError) return { errors: [e.message] };
    throw e;
  }
  redirect(`/profile/${data.get("username")}`);
}

export async function publishArticleAction(_prev: FormState, data: FormData): Promise<FormState> {
  const { user } = await getCurrentUser();
  if (!user) return { errors: ["unauthorized"] };
  try {
    const article = createArticle(user.id, {
      title: String(data.get("title") ?? ""),
      description: String(data.get("description") ?? ""),
      body: String(data.get("body") ?? ""),
      tagList: String(data.get("tagList") ?? "")
        .split(/[ ,]+/)
        .filter(Boolean),
    });
    redirect(`/article/${article.slug}`);
  } catch (e) {
    if (e instanceof ConduitArticleError) {
      return {
        errors: [e.message],
        values: {
          title: String(data.get("title") ?? ""),
          description: String(data.get("description") ?? ""),
          body: String(data.get("body") ?? ""),
          tagList: String(data.get("tagList") ?? ""),
        },
      };
    }
    throw e;
  }
}

export async function editArticleAction(_prev: FormState, data: FormData): Promise<FormState> {
  const { user } = await getCurrentUser();
  if (!user) return { errors: ["unauthorized"] };
  const slug = String(data.get("slug") ?? "");
  try {
    const updated = updateArticle(user.id, slug, {
      title: String(data.get("title") ?? ""),
      description: String(data.get("description") ?? ""),
      body: String(data.get("body") ?? ""),
    });
    redirect(`/article/${updated.slug}`);
  } catch (e) {
    if (e instanceof ConduitArticleError) return { errors: [e.message] };
    throw e;
  }
}

export async function deleteArticleAction(slug: string) {
  const { user } = await getCurrentUser();
  if (!user) redirect("/login");
  try {
    deleteArticle(user.id, slug);
  } catch (e) {
    if (e instanceof ConduitArticleError) return;
    throw e;
  }
  redirect("/");
}

export async function favoriteAction(slug: string) {
  const { user } = await getCurrentUser();
  if (!user) redirect("/login");
  favorite(user.id, slug);
}

export async function unfavoriteAction(slug: string) {
  const { user } = await getCurrentUser();
  if (!user) redirect("/login");
  unfavorite(user.id, slug);
}

export async function followAction(username: string) {
  const { user } = await getCurrentUser();
  if (!user) redirect("/login");
  follow(user.id, username);
}

export async function unfollowAction(username: string) {
  const { user } = await getCurrentUser();
  if (!user) redirect("/login");
  unfollow(user.id, username);
}

export async function addCommentAction(slug: string, body: string): Promise<{ error?: string }> {
  const { user } = await getCurrentUser();
  if (!user) return { error: "unauthorized" };
  try {
    addComment(slug, user.id, body);
    return {};
  } catch (e) {
    if (e instanceof ConduitCommentError) return { error: e.message };
    throw e;
  }
}

export async function deleteCommentAction(slug: string, id: number) {
  const { user } = await getCurrentUser();
  if (!user) redirect("/login");
  try {
    deleteComment(slug, id, user.id);
  } catch (e) {
    if (e instanceof ConduitCommentError) return;
    throw e;
  }
}
