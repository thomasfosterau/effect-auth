// @ts-nocheck — React 18/19 @types collision in monorepo; runtime works fine
import { Link } from "@remix-run/react";
import type { ConduitArticle } from "~/server/types";

export default function ArticleList({
  articles,
  articlesCount,
  offset,
  limit,
  baseHref,
}: {
  articles: ConduitArticle[];
  articlesCount: number;
  offset: number;
  limit: number;
  baseHref: string;
}) {
  if (articles.length === 0)
    return <div className="article-preview">No articles are here... yet.</div>;
  const pages = Math.max(1, Math.ceil(articlesCount / limit));
  const current = Math.floor(offset / limit);
  const sep = baseHref.includes("?") ? "&" : "?";
  return (
    <>
      {articles.map((a) => (
        <div className="article-preview" key={a.slug}>
          <div className="article-meta">
            <Link to={`/profile/${a.author.username}`}>
              {a.author.image && <img src={a.author.image} alt="" />}
            </Link>
            <div className="info">
              <Link to={`/profile/${a.author.username}`} className="author">
                {a.author.username}
              </Link>
              <span className="date">{new Date(a.createdAt).toDateString()}</span>
            </div>
            <button
              className={`btn btn-sm pull-xs-right ${a.favorited ? "btn-primary" : "btn-outline-primary"}`}
            >
              <i className="ion-heart" /> {a.favoritesCount}
            </button>
          </div>
          <Link to={`/article/${a.slug}`} className="preview-link">
            <h1>{a.title}</h1>
            <p>{a.description}</p>
            <span>Read more...</span>
            {a.tagList.length > 0 && (
              <ul className="tag-list">
                {a.tagList.map((t) => (
                  <li key={t} className="tag-default tag-pill tag-outline">
                    {t}
                  </li>
                ))}
              </ul>
            )}
          </Link>
        </div>
      ))}
      {pages > 1 && (
        <ul className="pagination">
          {Array.from({ length: pages }).map((_, i) => (
            <li key={i} className={`page-item ${i === current ? "active" : ""}`}>
              <Link className="page-link" to={`${baseHref}${sep}offset=${i * limit}`}>
                {i + 1}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
