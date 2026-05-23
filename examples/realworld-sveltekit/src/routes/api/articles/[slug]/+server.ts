import { error, json, type RequestHandler } from "@sveltejs/kit";
import { requireApiUser, resolveApiUser } from "$lib/server/api/auth";
import {
  ConduitArticleError,
  deleteArticle,
  getArticleBySlug,
  updateArticle,
} from "$lib/server/services/articles";

export const GET: RequestHandler = async (event) => {
  const viewer = await resolveApiUser(event);
  const article = getArticleBySlug(event.params.slug!, viewer?.id ?? null);
  if (!article) throw error(404, { message: "article not found" });
  return json({ article });
};

export const PUT: RequestHandler = async (event) => {
  const me = await requireApiUser(event);
  const body = (await event.request.json().catch(() => ({}))) as {
    article?: { title?: string; description?: string; body?: string };
  };
  if (!body.article) return json({ errors: { body: ["article is required"] } }, { status: 422 });
  try {
    const article = updateArticle(me.id, event.params.slug!, body.article);
    return json({ article });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
};

export const DELETE: RequestHandler = async (event) => {
  const me = await requireApiUser(event);
  try {
    deleteArticle(me.id, event.params.slug!);
    return new Response(null, { status: 204 });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
};
