import type { ActionFunctionArgs } from "react-router";
import { getCurrentUser } from "~/server/auth/session";
import { ConduitArticleError, favorite, unfavorite } from "~/server/services/articles";

export async function action({ request, params }: ActionFunctionArgs) {
  const { user } = await getCurrentUser(request);
  if (!user) return Response.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  try {
    const fn = request.method === "DELETE" ? unfavorite : favorite;
    return Response.json({ article: fn(user.id, params.slug!) });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return Response.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
