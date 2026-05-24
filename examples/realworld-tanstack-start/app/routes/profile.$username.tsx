// @ts-nocheck
import { createFileRoute, Link, notFound, useRouter } from "@tanstack/react-router";
import { z } from "zod";
import { fetchArticles, fetchProfile, toggleFollow } from "~/server/fns";

const search = z.object({ tab: z.enum(["my", "favorites"]).optional() });

export const Route = createFileRoute("/profile/$username")({
  validateSearch: (s) => search.parse(s),
  loaderDeps: ({ search: s }) => ({ tab: s.tab }),
  loader: async ({ params, deps }) => {
    const profile = await fetchProfile({ data: { username: params.username } });
    if (!profile) throw notFound();
    const tab = deps.tab === "favorites" ? "favorites" : "my";
    const articles = await fetchArticles({
      data:
        tab === "favorites"
          ? { favorited: profile.username, limit: 10 }
          : { author: profile.username, limit: 10 },
    });
    return { profile, tab, articles };
  },
  component: ProfilePage,
});

function ProfilePage() {
  const { profile, tab, articles } = Route.useLoaderData();
  const { user } = Route.useRouteContext();
  const router = useRouter();
  const isMe = user?.username === profile.username;

  return (
    <div className="profile-page">
      <div className="user-info">
        <div className="container">
          <div className="row">
            <div className="col-xs-12 col-md-10 offset-md-1">
              {profile.image && <img src={profile.image} className="user-img" alt="" />}
              <h4>{profile.username}</h4>
              {profile.bio && <p>{profile.bio}</p>}
              {isMe ? (
                <Link to="/settings" className="btn btn-sm btn-outline-secondary action-btn">
                  <i className="ion-gear-a" /> Edit Profile Settings
                </Link>
              ) : user ? (
                <button
                  className="btn btn-sm btn-outline-secondary action-btn"
                  onClick={async () => {
                    await toggleFollow({
                      data: { username: profile.username, following: profile.following ?? false },
                    });
                    await router.invalidate();
                  }}
                >
                  <i className="ion-plus-round" /> {profile.following ? "Unfollow" : "Follow"}{" "}
                  {profile.username}
                </button>
              ) : null}
            </div>
          </div>
        </div>
      </div>
      <div className="container">
        <div className="row">
          <div className="col-xs-12 col-md-10 offset-md-1">
            <div className="articles-toggle">
              <ul className="nav nav-pills outline-active">
                <li className="nav-item">
                  <Link
                    className={tab === "my" ? "nav-link active" : "nav-link"}
                    to="/profile/$username"
                    params={{ username: profile.username }}
                  >
                    My Articles
                  </Link>
                </li>
                <li className="nav-item">
                  <Link
                    className={tab === "favorites" ? "nav-link active" : "nav-link"}
                    to="/profile/$username"
                    params={{ username: profile.username }}
                    search={{ tab: "favorites" }}
                  >
                    Favorited Articles
                  </Link>
                </li>
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
                  </div>
                  <Link to="/article/$slug" params={{ slug: a.slug }} className="preview-link">
                    <h1>{a.title}</h1>
                    <p>{a.description}</p>
                    <span>Read more...</span>
                  </Link>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
