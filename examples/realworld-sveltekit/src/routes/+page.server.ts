import type { PageServerLoad } from "./$types";
import { feedArticles, listArticles } from "$lib/server/services/articles";
import { listTags } from "$lib/server/services/tags";

export const load: PageServerLoad = ({ locals, url }) => {
  const tab = url.searchParams.get("tab") ?? (locals.user ? "your" : "global");
  const tag = url.searchParams.get("tag") ?? undefined;
  const offset = Number(url.searchParams.get("offset") ?? 0);
  const limit = 10;

  const articles =
    tab === "your" && locals.user
      ? feedArticles(locals.user.id, limit, offset)
      : listArticles({ tag, limit, offset }, locals.user?.id ?? null);

  return {
    tab: tag ? "tag" : tab,
    tag,
    articles: articles.articles,
    articlesCount: articles.articlesCount,
    offset,
    limit,
    tags: listTags(),
  };
};
