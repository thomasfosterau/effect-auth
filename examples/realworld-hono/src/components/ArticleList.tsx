import type { FC } from "hono/jsx";
import type { ConduitArticle } from "../types";

export const ArticleList: FC<{
  articles: ConduitArticle[];
  articlesCount: number;
  offset: number;
  limit: number;
  baseHref: string;
}> = ({ articles, articlesCount, offset, limit, baseHref }) => {
  if (articles.length === 0) return <div class="article-preview">No articles are here... yet.</div>;
  const pages = Math.max(1, Math.ceil(articlesCount / limit));
  const current = Math.floor(offset / limit);
  const sep = baseHref.includes("?") ? "&" : "?";
  return (
    <>
      {articles.map((a) => (
        <div class="article-preview">
          <div class="article-meta">
            <a href={`/profile/${a.author.username}`}>
              {a.author.image && <img src={a.author.image} alt="" />}
            </a>
            <div class="info">
              <a href={`/profile/${a.author.username}`} class="author">
                {a.author.username}
              </a>
              <span class="date">{new Date(a.createdAt).toDateString()}</span>
            </div>
            <button
              class={`btn btn-sm pull-xs-right ${a.favorited ? "btn-primary" : "btn-outline-primary"}`}
            >
              <i class="ion-heart" /> {a.favoritesCount}
            </button>
          </div>
          <a href={`/article/${a.slug}`} class="preview-link">
            <h1>{a.title}</h1>
            <p>{a.description}</p>
            <span>Read more...</span>
            {a.tagList.length > 0 && (
              <ul class="tag-list">
                {a.tagList.map((t) => (
                  <li class="tag-default tag-pill tag-outline">{t}</li>
                ))}
              </ul>
            )}
          </a>
        </div>
      ))}
      {pages > 1 && (
        <ul class="pagination">
          {Array.from({ length: pages }).map((_, i) => (
            <li class={`page-item ${i === current ? "active" : ""}`}>
              <a class="page-link" href={`${baseHref}${sep}offset=${i * limit}`}>
                {i + 1}
              </a>
            </li>
          ))}
        </ul>
      )}
    </>
  );
};
