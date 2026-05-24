import { Link, useLoaderData } from "react-router";
import type { LoaderFunctionArgs } from "react-router";
import ArticleList from "~/components/ArticleList";
import { getCurrentUser } from "~/server/auth/session";
import { feedArticles, listArticles } from "~/server/services/articles";
import { listTags } from "~/server/services/tags";

export async function loader({ request }: LoaderFunctionArgs) {
  const { user } = await getCurrentUser(request);
  const url = new URL(request.url);
  const tag = url.searchParams.get("tag") ?? undefined;
  const tab = tag ? "tag" : (url.searchParams.get("tab") ?? (user ? "your" : "global"));
  const offset = Number(url.searchParams.get("offset") ?? 0);
  const limit = 10;
  const data =
    tab === "your" && user
      ? feedArticles(user.id, limit, offset)
      : listArticles({ tag, limit, offset }, user?.id ?? null);
  return { user, tab, tag, offset, limit, data, tags: listTags() };
}

export default function Home() {
  const { user, tab, tag, offset, limit, data, tags } = useLoaderData<typeof loader>();
  const baseHref = tag
    ? `/?tag=${encodeURIComponent(tag)}`
    : tab === "your"
      ? "/?tab=your"
      : "/?tab=global";
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
                      className={tab === "your" ? "nav-link active" : "nav-link"}
                      to="/?tab=your"
                    >
                      Your Feed
                    </Link>
                  </li>
                )}
                <li className="nav-item">
                  <Link
                    className={tab === "global" ? "nav-link active" : "nav-link"}
                    to="/?tab=global"
                  >
                    Global Feed
                  </Link>
                </li>
                {tag && (
                  <li className="nav-item">
                    <Link className="nav-link active" to={`/?tag=${tag}`}>
                      #{tag}
                    </Link>
                  </li>
                )}
              </ul>
            </div>
            <ArticleList
              articles={data.articles}
              articlesCount={data.articlesCount}
              offset={offset}
              limit={limit}
              baseHref={baseHref}
            />
          </div>
          <div className="col-md-3">
            <div className="sidebar">
              <p>Popular Tags</p>
              <div className="tag-list">
                {tags.map((t) => (
                  <Link
                    key={t}
                    to={`/?tag=${encodeURIComponent(t)}`}
                    className="tag-pill tag-default"
                  >
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
