import type { ActionFunctionArgs, LoaderFunctionArgs } from "react-router";
import { getCurrentUser } from "~/server/auth/session";
import { ConduitArticleError, createArticle, listArticles } from "~/server/services/articles";

export async function loader({ request }: LoaderFunctionArgs) {
  const { user } = await getCurrentUser(request);
  const url = new URL(request.url);
  return Response.json(
    listArticles(
      {
        tag: url.searchParams.get("tag") ?? undefined,
        author: url.searchParams.get("author") ?? undefined,
        favorited: url.searchParams.get("favorited") ?? undefined,
        limit: url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : undefined,
        offset: url.searchParams.has("offset") ? Number(url.searchParams.get("offset")) : undefined,
      },
      user?.id ?? null,
    ),
  );
}

export async function action({ request }: ActionFunctionArgs) {
  const { user } = await getCurrentUser(request);
  if (!user) return Response.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const body = (await request.json().catch(() => ({}))) as {
    article?: { title: string; description: string; body: string; tagList?: string[] };
  };
  if (!body.article)
    return Response.json({ errors: { body: ["article is required"] } }, { status: 422 });
  try {
    return Response.json({ article: createArticle(user.id, body.article) });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return Response.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
