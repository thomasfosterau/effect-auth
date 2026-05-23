import { error, fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import {
  ConduitArticleError,
  getArticleBySlug,
  updateArticle,
} from "$lib/server/services/articles";

export const load: PageServerLoad = ({ locals, params }) => {
  if (!locals.user) throw redirect(303, "/login");
  const article = getArticleBySlug(params.slug, locals.user.id);
  if (!article) throw error(404, { message: "article not found" });
  if (article.author.username !== locals.user.username) throw error(403, { message: "forbidden" });
  return { article };
};

export const actions: Actions = {
  default: async ({ request, locals, params }) => {
    if (!locals.user) return fail(401, { errors: ["unauthorized"] });
    const data = await request.formData();
    try {
      const updated = updateArticle(locals.user.id, params.slug, {
        title: String(data.get("title") ?? ""),
        description: String(data.get("description") ?? ""),
        body: String(data.get("body") ?? ""),
      });
      throw redirect(303, `/article/${updated.slug}`);
    } catch (e) {
      if (e instanceof ConduitArticleError) return fail(e.status, { errors: [e.message] });
      throw e;
    }
  },
};
