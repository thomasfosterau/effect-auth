import type { ActionFunctionArgs, LoaderFunctionArgs } from "react-router";
import { getCurrentUser } from "~/server/auth/session";
import {
  ConduitArticleError,
  deleteArticle,
  getArticleBySlug,
  updateArticle,
} from "~/server/services/articles";

export async function loader({ request, params }: LoaderFunctionArgs) {
  const { user } = await getCurrentUser(request);
  const article = getArticleBySlug(params.slug!, user?.id ?? null);
  if (!article) return Response.json({ errors: { body: ["article not found"] } }, { status: 404 });
  return Response.json({ article });
}

export async function action({ request, params }: ActionFunctionArgs) {
  const { user } = await getCurrentUser(request);
  if (!user) return Response.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  try {
    if (request.method === "DELETE") {
      deleteArticle(user.id, params.slug!);
      return new Response(null, { status: 204 });
    }
    if (request.method === "PUT") {
      const body = (await request.json().catch(() => ({}))) as {
        article?: { title?: string; description?: string; body?: string };
      };
      if (!body.article)
        return Response.json({ errors: { body: ["article is required"] } }, { status: 422 });
      return Response.json({ article: updateArticle(user.id, params.slug!, body.article) });
    }
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return Response.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
  return Response.json({ errors: { body: ["method not allowed"] } }, { status: 405 });
}
