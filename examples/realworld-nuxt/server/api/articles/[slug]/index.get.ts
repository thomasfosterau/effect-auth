import { createError, defineEventHandler, getRouterParam } from "h3";
import { resolveCurrentUser } from "../../../auth/session";
import { getArticleBySlug } from "../../../services/articles";

export default defineEventHandler(async (event) => {
  const { user } = await resolveCurrentUser(event);
  const slug = getRouterParam(event, "slug")!;
  const article = getArticleBySlug(slug, user?.id ?? null);
  if (!article) throw createError({ statusCode: 404, statusMessage: "article not found" });
  return { article };
});
