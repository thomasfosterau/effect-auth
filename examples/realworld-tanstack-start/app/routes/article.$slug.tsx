// @ts-nocheck
import { createFileRoute, Link, notFound, useRouter } from "@tanstack/react-router";
import { useState } from "react";
import {
  fetchArticle,
  fetchComments,
  postComment,
  removeArticle,
  removeComment,
  toggleFavorite,
  toggleFollow,
} from "~/server/fns";

export const Route = createFileRoute("/article/$slug")({
  loader: async ({ params }) => {
    const article = await fetchArticle({ data: { slug: params.slug } });
    if (!article) throw notFound();
    const comments = await fetchComments({ data: { slug: params.slug } });
    return { article, comments };
  },
  component: ArticlePage,
});

function ArticlePage() {
  const { article, comments } = Route.useLoaderData();
  const { user } = Route.useRouteContext();
  const router = useRouter();
  const [body, setBody] = useState("");
  const isAuthor = user?.username === article.author.username;

  async function refresh() {
    await router.invalidate();
  }

  return (
    <div className="article-page">
      <div className="banner">
        <div className="container">
          <h1>{article.title}</h1>
          <div className="article-meta">
            <Link to="/profile/$username" params={{ username: article.author.username }}>
              {article.author.image && <img src={article.author.image} alt="" />}
            </Link>
            <div className="info">
              <Link
                to="/profile/$username"
                params={{ username: article.author.username }}
                className="author"
              >
                {article.author.username}
              </Link>
              <span className="date">{new Date(article.createdAt).toDateString()}</span>
            </div>
            {isAuthor ? (
              <>
                <Link
                  to="/editor/$slug"
                  params={{ slug: article.slug }}
                  className="btn btn-sm btn-outline-secondary"
                >
                  <i className="ion-edit" /> Edit Article
                </Link>
                &nbsp;
                <button
                  className="btn btn-sm btn-outline-danger"
                  onClick={async () => {
                    await removeArticle({ data: { slug: article.slug } });
                    router.navigate({ to: "/" });
                  }}
                >
                  <i className="ion-trash-a" /> Delete Article
                </button>
              </>
            ) : user ? (
              <>
                <button
                  className="btn btn-sm btn-outline-secondary"
                  onClick={async () => {
                    await toggleFollow({
                      data: {
                        username: article.author.username,
                        following: article.author.following,
                      },
                    });
                    await refresh();
                  }}
                >
                  <i className="ion-plus-round" />{" "}
                  {article.author.following ? "Unfollow" : "Follow"} {article.author.username}
                </button>
                &nbsp;
                <button
                  className={`btn btn-sm ${article.favorited ? "btn-primary" : "btn-outline-primary"}`}
                  onClick={async () => {
                    await toggleFavorite({
                      data: { slug: article.slug, favorited: article.favorited },
                    });
                    await refresh();
                  }}
                >
                  <i className="ion-heart" /> {article.favorited ? "Unfavorite" : "Favorite"}{" "}
                  Article ({article.favoritesCount})
                </button>
              </>
            ) : null}
          </div>
        </div>
      </div>
      <div className="container page">
        <div className="row article-content">
          <div className="col-md-12">
            <p style={{ whiteSpace: "pre-wrap" }}>{article.body}</p>
            {article.tagList.length > 0 && (
              <ul className="tag-list">
                {article.tagList.map((t) => (
                  <li key={t} className="tag-default tag-pill tag-outline">
                    {t}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
        <hr />
        <div className="row">
          <div className="col-xs-12 col-md-8 offset-md-2">
            {user ? (
              <form
                className="card comment-form"
                onSubmit={async (e) => {
                  e.preventDefault();
                  await postComment({ data: { slug: article.slug, body } });
                  setBody("");
                  await refresh();
                }}
              >
                <div className="card-block">
                  <textarea
                    className="form-control"
                    placeholder="Write a comment..."
                    rows={3}
                    value={body}
                    onChange={(e) => setBody(e.target.value)}
                  />
                </div>
                <div className="card-footer">
                  {user.image && <img src={user.image} className="comment-author-img" alt="" />}
                  <button className="btn btn-sm btn-primary" type="submit">
                    Post Comment
                  </button>
                </div>
              </form>
            ) : (
              <p>
                <Link to="/login">Sign in</Link> or <Link to="/register">sign up</Link> to add
                comments on this article.
              </p>
            )}
            {comments.map((c) => (
              <div className="card" key={c.id}>
                <div className="card-block">
                  <p className="card-text">{c.body}</p>
                </div>
                <div className="card-footer">
                  <Link
                    to="/profile/$username"
                    params={{ username: c.author.username }}
                    className="comment-author"
                  >
                    {c.author.image && (
                      <img src={c.author.image} className="comment-author-img" alt="" />
                    )}
                  </Link>
                  &nbsp;
                  <Link
                    to="/profile/$username"
                    params={{ username: c.author.username }}
                    className="comment-author"
                  >
                    {c.author.username}
                  </Link>
                  <span className="date-posted">{new Date(c.createdAt).toDateString()}</span>
                  {user && user.username === c.author.username && (
                    <button
                      className="mod-options"
                      style={{ float: "right" }}
                      aria-label="Delete comment"
                      onClick={async () => {
                        await removeComment({ data: { slug: article.slug, id: c.id } });
                        await refresh();
                      }}
                    >
                      <i className="ion-trash-a" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
