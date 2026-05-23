import { json, type RequestHandler } from "@sveltejs/kit";
import { requireApiUser } from "$lib/server/api/auth";
import { feedArticles } from "$lib/server/services/articles";

export const GET: RequestHandler = async (event) => {
  const me = await requireApiUser(event);
  const url = event.url;
  const limit = url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : 20;
  const offset = url.searchParams.has("offset") ? Number(url.searchParams.get("offset")) : 0;
  return json(feedArticles(me.id, limit, offset));
};
