import { error, fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import {
  ConduitArticleError,
  deleteArticle,
  favorite,
  getArticleBySlug,
  unfavorite,
} from "$lib/server/services/articles";
import {
  ConduitCommentError,
  addComment,
  deleteComment,
  listComments,
} from "$lib/server/services/comments";
import { follow, unfollow } from "$lib/server/services/profiles";

export const load: PageServerLoad = ({ locals, params }) => {
  const viewerId = locals.user?.id ?? null;
  const article = getArticleBySlug(params.slug, viewerId);
  if (!article) throw error(404, { message: "article not found" });
  const comments = listComments(params.slug, viewerId);
  return { article, comments };
};

export const actions: Actions = {
  favorite: async ({ locals, params }) => {
    if (!locals.user) throw redirect(303, "/login");
    try {
      favorite(locals.user.id, params.slug);
    } catch (e) {
      if (e instanceof ConduitArticleError) return fail(e.status, { errors: [e.message] });
      throw e;
    }
    return { success: true };
  },
  unfavorite: async ({ locals, params }) => {
    if (!locals.user) throw redirect(303, "/login");
    unfavorite(locals.user.id, params.slug);
    return { success: true };
  },
  follow: async ({ locals, request }) => {
    if (!locals.user) throw redirect(303, "/login");
    const data = await request.formData();
    follow(locals.user.id, String(data.get("username") ?? ""));
    return { success: true };
  },
  unfollow: async ({ locals, request }) => {
    if (!locals.user) throw redirect(303, "/login");
    const data = await request.formData();
    unfollow(locals.user.id, String(data.get("username") ?? ""));
    return { success: true };
  },
  comment: async ({ locals, request, params }) => {
    if (!locals.user) throw redirect(303, "/login");
    const data = await request.formData();
    try {
      addComment(params.slug, locals.user.id, String(data.get("body") ?? ""));
    } catch (e) {
      if (e instanceof ConduitCommentError) return fail(e.status, { errors: [e.message] });
      throw e;
    }
    return { success: true };
  },
  deleteComment: async ({ locals, request, params }) => {
    if (!locals.user) throw redirect(303, "/login");
    const data = await request.formData();
    try {
      deleteComment(params.slug, Number(data.get("id")), locals.user.id);
    } catch (e) {
      if (e instanceof ConduitCommentError) return fail(e.status, { errors: [e.message] });
      throw e;
    }
    return { success: true };
  },
  delete: async ({ locals, params }) => {
    if (!locals.user) throw redirect(303, "/login");
    try {
      deleteArticle(locals.user.id, params.slug);
    } catch (e) {
      if (e instanceof ConduitArticleError) return fail(e.status, { errors: [e.message] });
      throw e;
    }
    throw redirect(303, "/");
  },
};
