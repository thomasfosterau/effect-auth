import { json, type RequestHandler } from "@sveltejs/kit";
import { requireApiUser } from "$lib/server/api/auth";
import { ConduitArticleError, favorite, unfavorite } from "$lib/server/services/articles";

export const POST: RequestHandler = async (event) => {
  const me = await requireApiUser(event);
  try {
    return json({ article: favorite(me.id, event.params.slug!) });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
};

export const DELETE: RequestHandler = async (event) => {
  const me = await requireApiUser(event);
  try {
    return json({ article: unfavorite(me.id, event.params.slug!) });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
};
