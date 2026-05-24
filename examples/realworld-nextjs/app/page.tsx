import Link from "next/link";
import ArticleList from "@/lib/components/ArticleList";
import { getCurrentUser } from "@/lib/server/auth/session";
import { feedArticles, listArticles } from "@/lib/server/services/articles";
import { listTags } from "@/lib/server/services/tags";

export const dynamic = "force-dynamic";

export default async function HomePage({
  searchParams,
}: {
  searchParams: Promise<{ tab?: string; tag?: string; offset?: string }>;
}) {
  const { user } = await getCurrentUser();
  const sp = await searchParams;
  const tab = sp.tag ? "tag" : (sp.tab ?? (user ? "your" : "global"));
  const offset = Number(sp.offset ?? 0);
  const limit = 10;

  const data =
    tab === "your" && user
      ? feedArticles(user.id, limit, offset)
      : listArticles({ tag: sp.tag, limit, offset }, user?.id ?? null);

  const baseHref = sp.tag
    ? `/?tag=${encodeURIComponent(sp.tag)}`
    : tab === "your"
      ? "/?tab=your"
      : "/?tab=global";
  const tags = listTags();

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
                      href="/?tab=your"
                    >
                      Your Feed
                    </Link>
                  </li>
                )}
                <li className="nav-item">
                  <Link
                    className={tab === "global" ? "nav-link active" : "nav-link"}
                    href="/?tab=global"
                  >
                    Global Feed
                  </Link>
                </li>
                {sp.tag && (
                  <li className="nav-item">
                    <Link className="nav-link active" href={`/?tag=${sp.tag}`}>
                      #{sp.tag}
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
                    href={`/?tag=${encodeURIComponent(t)}`}
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
