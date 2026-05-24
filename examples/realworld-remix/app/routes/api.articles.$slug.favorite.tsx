import { json, type ActionFunctionArgs } from "@remix-run/node";
import { getCurrentUser } from "~/server/auth/session";
import { ConduitArticleError, favorite, unfavorite } from "~/server/services/articles";

export async function action({ request, params }: ActionFunctionArgs) {
  const { user } = await getCurrentUser(request);
  if (!user) return json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  try {
    const fn = request.method === "DELETE" ? unfavorite : favorite;
    return json({ article: fn(user.id, params.slug!) });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
