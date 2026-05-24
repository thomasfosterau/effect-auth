import { Form, Link, redirect, useLoaderData } from "react-router";
import type { ActionFunctionArgs, LoaderFunctionArgs } from "react-router";
import { getCurrentUser, requireUser } from "~/server/auth/session";
import {
  ConduitArticleError,
  deleteArticle,
  favorite,
  getArticleBySlug,
  unfavorite,
} from "~/server/services/articles";
import {
  ConduitCommentError,
  addComment,
  deleteComment,
  listComments,
} from "~/server/services/comments";
import { follow, unfollow } from "~/server/services/profiles";

export async function loader({ request, params }: LoaderFunctionArgs) {
  const { user } = await getCurrentUser(request);
  const article = getArticleBySlug(params.slug!, user?.id ?? null);
  if (!article) throw new Response("not found", { status: 404 });
  const comments = listComments(params.slug!, user?.id ?? null);
  return { user, article, comments };
}

export async function action({ request, params }: ActionFunctionArgs) {
  const me = await requireUser(request);
  const data = await request.formData();
  const intent = String(data.get("_intent") ?? "");
  try {
    switch (intent) {
      case "favorite":
        favorite(me.id, params.slug!);
        break;
      case "unfavorite":
        unfavorite(me.id, params.slug!);
        break;
      case "follow":
        follow(me.id, String(data.get("username") ?? ""));
        break;
      case "unfollow":
        unfollow(me.id, String(data.get("username") ?? ""));
        break;
      case "comment":
        addComment(params.slug!, me.id, String(data.get("body") ?? ""));
        break;
      case "deleteComment":
        deleteComment(params.slug!, Number(data.get("id")), me.id);
        break;
      case "delete":
        deleteArticle(me.id, params.slug!);
        return redirect("/");
    }
  } catch (e) {
    if (e instanceof ConduitArticleError || e instanceof ConduitCommentError)
      return { errors: [e.message] };
    throw e;
  }
  return null;
}

export default function Article() {
  const { user, article: a, comments } = useLoaderData<typeof loader>();
  const isAuthor = user?.username === a.author.username;
  return (
    <div className="article-page">
      <div className="banner">
        <div className="container">
          <h1>{a.title}</h1>
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
            {isAuthor ? (
              <>
                <Link to={`/editor/${a.slug}`} className="btn btn-sm btn-outline-secondary">
                  <i className="ion-edit" /> Edit Article
                </Link>
                &nbsp;
                <Form method="post" style={{ display: "inline" }}>
                  <input type="hidden" name="_intent" value="delete" />
                  <button className="btn btn-sm btn-outline-danger" type="submit">
                    <i className="ion-trash-a" /> Delete Article
                  </button>
                </Form>
              </>
            ) : user ? (
              <>
                <Form method="post" style={{ display: "inline" }}>
                  <input
                    type="hidden"
                    name="_intent"
                    value={a.author.following ? "unfollow" : "follow"}
                  />
                  <input type="hidden" name="username" value={a.author.username} />
                  <button className="btn btn-sm btn-outline-secondary" type="submit">
                    <i className="ion-plus-round" /> {a.author.following ? "Unfollow" : "Follow"}{" "}
                    {a.author.username}
                  </button>
                </Form>
                &nbsp;
                <Form method="post" style={{ display: "inline" }}>
                  <input
                    type="hidden"
                    name="_intent"
                    value={a.favorited ? "unfavorite" : "favorite"}
                  />
                  <button
                    className={`btn btn-sm ${a.favorited ? "btn-primary" : "btn-outline-primary"}`}
                    type="submit"
                  >
                    <i className="ion-heart" /> {a.favorited ? "Unfavorite" : "Favorite"} Article (
                    {a.favoritesCount})
                  </button>
                </Form>
              </>
            ) : null}
          </div>
        </div>
      </div>
      <div className="container page">
        <div className="row article-content">
          <div className="col-md-12">
            <p style={{ whiteSpace: "pre-wrap" }}>{a.body}</p>
            {a.tagList.length > 0 && (
              <ul className="tag-list">
                {a.tagList.map((t) => (
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
              <Form className="card comment-form" method="post">
                <input type="hidden" name="_intent" value="comment" />
                <div className="card-block">
                  <textarea
                    className="form-control"
                    name="body"
                    placeholder="Write a comment..."
                    rows={3}
                  />
                </div>
                <div className="card-footer">
                  {user.image && <img src={user.image} className="comment-author-img" alt="" />}
                  <button className="btn btn-sm btn-primary" type="submit">
                    Post Comment
                  </button>
                </div>
              </Form>
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
                  <Link to={`/profile/${c.author.username}`} className="comment-author">
                    {c.author.image && (
                      <img src={c.author.image} className="comment-author-img" alt="" />
                    )}
                  </Link>
                  &nbsp;
                  <Link to={`/profile/${c.author.username}`} className="comment-author">
                    {c.author.username}
                  </Link>
                  <span className="date-posted">{new Date(c.createdAt).toDateString()}</span>
                  {user && user.username === c.author.username && (
                    <Form method="post" style={{ display: "inline", float: "right" }}>
                      <input type="hidden" name="_intent" value="deleteComment" />
                      <input type="hidden" name="id" value={c.id} />
                      <button className="mod-options" type="submit" aria-label="Delete comment">
                        <i className="ion-trash-a" />
                      </button>
                    </Form>
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
