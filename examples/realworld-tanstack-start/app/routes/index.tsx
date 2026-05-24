// @ts-nocheck
import { createFileRoute, Link } from "@tanstack/react-router";
import { z } from "zod";
import { fetchArticles, fetchTags } from "~/server/fns";

const search = z.object({
  tab: z.enum(["your", "global", "tag"]).optional(),
  tag: z.string().optional(),
  offset: z.coerce.number().optional(),
});

export const Route = createFileRoute("/")({
  validateSearch: (s) => search.parse(s),
  loaderDeps: ({ search: s }) => ({ tab: s.tab, tag: s.tag, offset: s.offset }),
  loader: async ({ deps, context }) => {
    const tab = deps.tag ? "tag" : (deps.tab ?? (context.user ? "your" : "global"));
    const offset = deps.offset ?? 0;
    const limit = 10;
    const articles = await fetchArticles({ data: { tab, tag: deps.tag, offset, limit } });
    const tags = await fetchTags();
    return { tab, tag: deps.tag, offset, limit, articles, tags };
  },
  component: HomePage,
});

function HomePage() {
  const { tab, tag, offset, limit, articles, tags } = Route.useLoaderData();
  const { user } = Route.useRouteContext();
  return (
    <div className="home-page">
      <div className="banner">
        <div className="container">
          <h1 className="logo-font">conduit</h1>
          <p>A place to share your knowledge.</p>
        </div>
      </div>
      <div className="container page">
        <div className="row">
          <div className="col-md-9">
            <div className="feed-toggle">
              <ul className="nav nav-pills outline-active">
                {user && (
                  <li className="nav-item">
                    <Link
                      to="/"
                      search={{ tab: "your" }}
                      className={tab === "your" ? "nav-link active" : "nav-link"}
                    >
                      Your Feed
                    </Link>
                  </li>
                )}
                <li className="nav-item">
                  <Link
                    to="/"
                    search={{ tab: "global" }}
                    className={tab === "global" ? "nav-link active" : "nav-link"}
                  >
                    Global Feed
                  </Link>
                </li>
                {tag && (
                  <li className="nav-item">
                    <Link to="/" search={{ tag }} className="nav-link active">
                      #{tag}
                    </Link>
                  </li>
                )}
              </ul>
            </div>
            {articles.articles.length === 0 ? (
              <div className="article-preview">No articles are here... yet.</div>
            ) : (
              articles.articles.map((a) => (
                <div className="article-preview" key={a.slug}>
                  <div className="article-meta">
                    <Link to="/profile/$username" params={{ username: a.author.username }}>
                      {a.author.image && <img src={a.author.image} alt="" />}
                    </Link>
                    <div className="info">
                      <Link
                        to="/profile/$username"
                        params={{ username: a.author.username }}
                        className="author"
                      >
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
                  <Link to="/article/$slug" params={{ slug: a.slug }} className="preview-link">
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
              ))
            )}
          </div>
          <div className="col-md-3">
            <div className="sidebar">
              <p>Popular Tags</p>
              <div className="tag-list">
                {tags.map((t) => (
                  <Link key={t} to="/" search={{ tag: t }} className="tag-pill tag-default">
                    {t}
                  </Link>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
