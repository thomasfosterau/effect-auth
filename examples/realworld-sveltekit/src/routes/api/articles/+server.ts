import { json, type RequestHandler } from "@sveltejs/kit";
import { requireApiUser, resolveApiUser } from "$lib/server/api/auth";
import { ConduitArticleError, createArticle, listArticles } from "$lib/server/services/articles";

export const GET: RequestHandler = async (event) => {
  const viewer = await resolveApiUser(event);
  const url = event.url;
  const result = listArticles(
    {
      tag: url.searchParams.get("tag") ?? undefined,
      author: url.searchParams.get("author") ?? undefined,
      favorited: url.searchParams.get("favorited") ?? undefined,
      limit: url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : undefined,
      offset: url.searchParams.has("offset") ? Number(url.searchParams.get("offset")) : undefined,
    },
    viewer?.id ?? null,
  );
  return json(result);
};

export const POST: RequestHandler = async (event) => {
  const me = await requireApiUser(event);
  const body = (await event.request.json().catch(() => ({}))) as {
    article?: { title: string; description: string; body: string; tagList?: string[] };
  };
  if (!body.article) return json({ errors: { body: ["article is required"] } }, { status: 422 });
  try {
    const article = createArticle(me.id, body.article);
    return json({ article });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
};
