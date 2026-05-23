import { fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { ConduitArticleError, createArticle } from "$lib/server/services/articles";

export const load: PageServerLoad = ({ locals }) => {
  if (!locals.user) throw redirect(303, "/login");
  return {};
};

export const actions: Actions = {
  default: async ({ request, locals }) => {
    if (!locals.user) return fail(401, { errors: ["unauthorized"] });
    const data = await request.formData();
    const tagList = String(data.get("tagList") ?? "")
      .split(/[ ,]+/)
      .filter(Boolean);
    try {
      const article = createArticle(locals.user.id, {
        title: String(data.get("title") ?? ""),
        description: String(data.get("description") ?? ""),
        body: String(data.get("body") ?? ""),
        tagList,
      });
      throw redirect(303, `/article/${article.slug}`);
    } catch (e) {
      if (e instanceof ConduitArticleError) {
        return fail(e.status, {
          errors: [e.message],
          title: String(data.get("title") ?? ""),
          description: String(data.get("description") ?? ""),
          body: String(data.get("body") ?? ""),
          tagList: String(data.get("tagList") ?? ""),
        });
      }
      throw e;
    }
  },
};
