import { Hono } from "hono";
import { Layout } from "../components/Layout";
import { ArticleList } from "../components/ArticleList";
import { clearSessionCookieValue, setSessionCookieValue } from "../auth/session";
import { invalidateSession } from "../auth/runtime";
import { ConduitAuthError, loginUser, registerUser, updateUser } from "../services/users";
import {
  ConduitArticleError,
  createArticle,
  deleteArticle,
  favorite,
  feedArticles,
  getArticleBySlug,
  listArticles,
  unfavorite,
  updateArticle,
} from "../services/articles";
import { ConduitCommentError, addComment, deleteComment, listComments } from "../services/comments";
import { follow, getProfile, unfollow } from "../services/profiles";
import { listTags } from "../services/tags";

export const uiRouter = new Hono();

// Home
uiRouter.get("/", (c) => {
  const user = c.get("user");
  const q = c.req.query();
  const tag = q.tag;
  const tab = tag ? "tag" : (q.tab ?? (user ? "your" : "global"));
  const offset = Number(q.offset ?? 0);
  const limit = 10;
  const data =
    tab === "your" && user
      ? feedArticles(user.id, limit, offset)
      : listArticles({ tag, limit, offset }, user?.id ?? null);
  const baseHref = tag
    ? `/?tag=${encodeURIComponent(tag)}`
    : tab === "your"
      ? "/?tab=your"
      : "/?tab=global";

  return c.html(
    <Layout user={user} active="/">
      <div class="home-page">
        <div class="banner">
          <div class="container">
            <h1 class="logo-font">conduit</h1>
            <p>A place to share your knowledge.</p>
          </div>
        </div>
        <div class="container page">
          <div class="row">
            <div class="col-md-9">
              <div class="feed-toggle">
                <ul class="nav nav-pills outline-active">
                  {user && (
                    <li class="nav-item">
                      <a class={tab === "your" ? "nav-link active" : "nav-link"} href="/?tab=your">
                        Your Feed
                      </a>
                    </li>
                  )}
                  <li class="nav-item">
                    <a
                      class={tab === "global" ? "nav-link active" : "nav-link"}
                      href="/?tab=global"
                    >
                      Global Feed
                    </a>
                  </li>
                  {tag && (
                    <li class="nav-item">
                      <a class="nav-link active" href={`/?tag=${tag}`}>
                        #{tag}
                      </a>
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
            <div class="col-md-3">
              <div class="sidebar">
                <p>Popular Tags</p>
                <div class="tag-list">
                  {listTags().map((t) => (
                    <a href={`/?tag=${encodeURIComponent(t)}`} class="tag-pill tag-default">
                      {t}
                    </a>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>,
  );
});

// Login GET / POST
uiRouter.get("/login", (c) => {
  if (c.get("user")) return c.redirect("/");
  return c.html(
    <Layout user={null} active="/login">
      <div class="auth-page">
        <div class="container page">
          <div class="row">
            <div class="col-md-6 offset-md-3 col-xs-12">
              <h1 class="text-xs-center">Sign in</h1>
              <p class="text-xs-center">
                <a href="/register">Need an account?</a>
              </p>
              <form method="post" action="/login">
                <fieldset class="form-group">
                  <input
                    class="form-control form-control-lg"
                    type="email"
                    name="email"
                    placeholder="Email"
                    required
                  />
                </fieldset>
                <fieldset class="form-group">
                  <input
                    class="form-control form-control-lg"
                    type="password"
                    name="password"
                    placeholder="Password"
                    required
                  />
                </fieldset>
                <button class="btn btn-lg btn-primary pull-xs-right" type="submit">
                  Sign in
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </Layout>,
  );
});

uiRouter.post("/login", async (c) => {
  const data = await c.req.parseBody();
  try {
    const r = await loginUser({ email: String(data.email), password: String(data.password) });
    setSessionCookieValue(c, r.sessionId, r.expiresAt);
    return c.redirect("/");
  } catch (e) {
    if (e instanceof ConduitAuthError) {
      return c.html(
        <Layout user={null} active="/login">
          <div class="auth-page">
            <div class="container page">
              <div class="row">
                <div class="col-md-6 offset-md-3 col-xs-12">
                  <h1 class="text-xs-center">Sign in</h1>
                  <ul class="error-messages">
                    <li>{e.message}</li>
                  </ul>
                  <form method="post" action="/login">
                    <fieldset class="form-group">
                      <input
                        class="form-control form-control-lg"
                        type="email"
                        name="email"
                        placeholder="Email"
                        value={String(data.email ?? "")}
                        required
                      />
                    </fieldset>
                    <fieldset class="form-group">
                      <input
                        class="form-control form-control-lg"
                        type="password"
                        name="password"
                        placeholder="Password"
                        required
                      />
                    </fieldset>
                    <button class="btn btn-lg btn-primary pull-xs-right" type="submit">
                      Sign in
                    </button>
                  </form>
                </div>
              </div>
            </div>
          </div>
        </Layout>,
      );
    }
    throw e;
  }
});

// Register
uiRouter.get("/register", (c) => {
  if (c.get("user")) return c.redirect("/");
  return c.html(
    <Layout user={null} active="/register">
      <div class="auth-page">
        <div class="container page">
          <div class="row">
            <div class="col-md-6 offset-md-3 col-xs-12">
              <h1 class="text-xs-center">Sign up</h1>
              <p class="text-xs-center">
                <a href="/login">Have an account?</a>
              </p>
              <form method="post" action="/register">
                <fieldset class="form-group">
                  <input
                    class="form-control form-control-lg"
                    type="text"
                    name="username"
                    placeholder="Username"
                    required
                  />
                </fieldset>
                <fieldset class="form-group">
                  <input
                    class="form-control form-control-lg"
                    type="email"
                    name="email"
                    placeholder="Email"
                    required
                  />
                </fieldset>
                <fieldset class="form-group">
                  <input
                    class="form-control form-control-lg"
                    type="password"
                    name="password"
                    placeholder="Password (8+ characters)"
                    minlength={8}
                    required
                  />
                </fieldset>
                <button class="btn btn-lg btn-primary pull-xs-right" type="submit">
                  Sign up
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </Layout>,
  );
});

uiRouter.post("/register", async (c) => {
  const data = await c.req.parseBody();
  try {
    const r = await registerUser({
      email: String(data.email),
      username: String(data.username),
      password: String(data.password),
    });
    setSessionCookieValue(c, r.sessionId, r.expiresAt);
    return c.redirect("/");
  } catch (e) {
    if (e instanceof ConduitAuthError) {
      return c.html(
        <Layout user={null} active="/register">
          <div class="auth-page">
            <div class="container page">
              <div class="row">
                <div class="col-md-6 offset-md-3 col-xs-12">
                  <h1 class="text-xs-center">Sign up</h1>
                  <ul class="error-messages">
                    <li>{e.message}</li>
                  </ul>
                  <form method="post" action="/register">
                    <fieldset class="form-group">
                      <input
                        class="form-control form-control-lg"
                        type="text"
                        name="username"
                        placeholder="Username"
                        value={String(data.username ?? "")}
                        required
                      />
                    </fieldset>
                    <fieldset class="form-group">
                      <input
                        class="form-control form-control-lg"
                        type="email"
                        name="email"
                        placeholder="Email"
                        value={String(data.email ?? "")}
                        required
                      />
                    </fieldset>
                    <fieldset class="form-group">
                      <input
                        class="form-control form-control-lg"
                        type="password"
                        name="password"
                        placeholder="Password (8+ characters)"
                        minlength={8}
                        required
                      />
                    </fieldset>
                    <button class="btn btn-lg btn-primary pull-xs-right" type="submit">
                      Sign up
                    </button>
                  </form>
                </div>
              </div>
            </div>
          </div>
        </Layout>,
      );
    }
    throw e;
  }
});

// Logout
uiRouter.post("/logout", async (c) => {
  const sid = c.get("sessionId");
  if (sid) await invalidateSession(sid);
  clearSessionCookieValue(c);
  return c.redirect("/");
});

// Settings
uiRouter.get("/settings", (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login");
  return c.html(
    <Layout user={user} active="/settings">
      <div class="settings-page">
        <div class="container page">
          <div class="row">
            <div class="col-md-6 offset-md-3 col-xs-12">
              <h1 class="text-xs-center">Your Settings</h1>
              <form method="post" action="/settings">
                <fieldset>
                  <fieldset class="form-group">
                    <input
                      class="form-control"
                      type="text"
                      name="image"
                      placeholder="URL of profile picture"
                      value={user.image ?? ""}
                    />
                  </fieldset>
                  <fieldset class="form-group">
                    <input
                      class="form-control form-control-lg"
                      type="text"
                      name="username"
                      placeholder="Your Name"
                      value={user.username}
                      required
                    />
                  </fieldset>
                  <fieldset class="form-group">
                    <textarea
                      class="form-control form-control-lg"
                      rows={8}
                      name="bio"
                      placeholder="Short bio about you"
                    >
                      {user.bio ?? ""}
                    </textarea>
                  </fieldset>
                  <fieldset class="form-group">
                    <input
                      class="form-control form-control-lg"
                      type="email"
                      name="email"
                      placeholder="Email"
                      value={user.email}
                      required
                    />
                  </fieldset>
                  <fieldset class="form-group">
                    <input
                      class="form-control form-control-lg"
                      type="password"
                      name="password"
                      placeholder="New Password (leave blank to keep)"
                    />
                  </fieldset>
                  <button class="btn btn-lg btn-primary pull-xs-right" type="submit">
                    Update Settings
                  </button>
                </fieldset>
              </form>
              <hr />
              <form method="post" action="/logout">
                <button class="btn btn-outline-danger" type="submit">
                  Or click here to logout.
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </Layout>,
  );
});

uiRouter.post("/settings", async (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login");
  const data = await c.req.parseBody();
  try {
    await updateUser(user.id, {
      image: String(data.image ?? "") || null,
      username: String(data.username ?? "") || undefined,
      bio: String(data.bio ?? "") || null,
      email: String(data.email ?? "") || undefined,
      password: String(data.password ?? "") || undefined,
    });
  } catch (e) {
    if (e instanceof ConduitAuthError) return c.text(e.message, e.status as never);
    throw e;
  }
  return c.redirect(`/profile/${data.username}`);
});

// Editor (new)
uiRouter.get("/editor", (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login");
  return c.html(
    <Layout user={user} active="/editor">
      <div class="editor-page">
        <div class="container page">
          <div class="row">
            <div class="col-md-10 offset-md-1 col-xs-12">
              <form method="post" action="/editor">
                <fieldset>
                  <fieldset class="form-group">
                    <input
                      type="text"
                      class="form-control form-control-lg"
                      name="title"
                      placeholder="Article Title"
                    />
                  </fieldset>
                  <fieldset class="form-group">
                    <input
                      type="text"
                      class="form-control"
                      name="description"
                      placeholder="What's this article about?"
                    />
                  </fieldset>
                  <fieldset class="form-group">
                    <textarea
                      class="form-control"
                      rows={8}
                      name="body"
                      placeholder="Write your article (in markdown)"
                    />
                  </fieldset>
                  <fieldset class="form-group">
                    <input
                      type="text"
                      class="form-control"
                      name="tagList"
                      placeholder="Enter tags (space or comma separated)"
                    />
                  </fieldset>
                  <button class="btn btn-lg pull-xs-right btn-primary" type="submit">
                    Publish Article
                  </button>
                </fieldset>
              </form>
            </div>
          </div>
        </div>
      </div>
    </Layout>,
  );
});

uiRouter.post("/editor", async (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login");
  const data = await c.req.parseBody();
  try {
    const article = createArticle(user.id, {
      title: String(data.title ?? ""),
      description: String(data.description ?? ""),
      body: String(data.body ?? ""),
      tagList: String(data.tagList ?? "")
        .split(/[ ,]+/)
        .filter(Boolean),
    });
    return c.redirect(`/article/${article.slug}`);
  } catch (e) {
    if (e instanceof ConduitArticleError) return c.text(e.message, e.status as never);
    throw e;
  }
});

// Editor (edit)
uiRouter.get("/editor/:slug", (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login");
  const article = getArticleBySlug(c.req.param("slug"), user.id);
  if (!article) return c.text("not found", 404);
  if (article.author.username !== user.username) return c.redirect("/");
  return c.html(
    <Layout user={user}>
      <div class="editor-page">
        <div class="container page">
          <div class="row">
            <div class="col-md-10 offset-md-1 col-xs-12">
              <form method="post" action={`/editor/${article.slug}`}>
                <fieldset>
                  <fieldset class="form-group">
                    <input
                      type="text"
                      class="form-control form-control-lg"
                      name="title"
                      value={article.title}
                    />
                  </fieldset>
                  <fieldset class="form-group">
                    <input
                      type="text"
                      class="form-control"
                      name="description"
                      value={article.description}
                    />
                  </fieldset>
                  <fieldset class="form-group">
                    <textarea class="form-control" rows={8} name="body">
                      {article.body}
                    </textarea>
                  </fieldset>
                  <button class="btn btn-lg pull-xs-right btn-primary" type="submit">
                    Update Article
                  </button>
                </fieldset>
              </form>
            </div>
          </div>
        </div>
      </div>
    </Layout>,
  );
});

uiRouter.post("/editor/:slug", async (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login");
  const data = await c.req.parseBody();
  try {
    const updated = updateArticle(user.id, c.req.param("slug"), {
      title: String(data.title ?? ""),
      description: String(data.description ?? ""),
      body: String(data.body ?? ""),
    });
    return c.redirect(`/article/${updated.slug}`);
  } catch (e) {
    if (e instanceof ConduitArticleError) return c.text(e.message, e.status as never);
    throw e;
  }
});

// Article view
uiRouter.get("/article/:slug", (c) => {
  const user = c.get("user");
  const slug = c.req.param("slug");
  const article = getArticleBySlug(slug, user?.id ?? null);
  if (!article) return c.text("not found", 404);
  const comments = listComments(slug, user?.id ?? null);
  const isAuthor = user?.username === article.author.username;
  return c.html(
    <Layout user={user}>
      <div class="article-page">
        <div class="banner">
          <div class="container">
            <h1>{article.title}</h1>
            <div class="article-meta">
              <a href={`/profile/${article.author.username}`}>
                {article.author.image && <img src={article.author.image} alt="" />}
              </a>
              <div class="info">
                <a href={`/profile/${article.author.username}`} class="author">
                  {article.author.username}
                </a>
                <span class="date">{new Date(article.createdAt).toDateString()}</span>
              </div>
              {isAuthor ? (
                <>
                  <a href={`/editor/${article.slug}`} class="btn btn-sm btn-outline-secondary">
                    <i class="ion-edit" /> Edit Article
                  </a>
                  &nbsp;
                  <form
                    method="post"
                    action={`/article/${article.slug}/delete`}
                    style="display:inline"
                  >
                    <button class="btn btn-sm btn-outline-danger" type="submit">
                      <i class="ion-trash-a" /> Delete Article
                    </button>
                  </form>
                </>
              ) : user ? (
                <>
                  <form
                    method="post"
                    action={`/profile/${article.author.username}/${article.author.following ? "unfollow" : "follow"}`}
                    style="display:inline"
                  >
                    <input type="hidden" name="redirect" value={`/article/${article.slug}`} />
                    <button class="btn btn-sm btn-outline-secondary" type="submit">
                      <i class="ion-plus-round" />{" "}
                      {article.author.following ? "Unfollow" : "Follow"} {article.author.username}
                    </button>
                  </form>
                  &nbsp;
                  <form
                    method="post"
                    action={`/article/${article.slug}/${article.favorited ? "unfavorite" : "favorite"}`}
                    style="display:inline"
                  >
                    <button
                      class={`btn btn-sm ${article.favorited ? "btn-primary" : "btn-outline-primary"}`}
                      type="submit"
                    >
                      <i class="ion-heart" /> {article.favorited ? "Unfavorite" : "Favorite"}{" "}
                      Article ({article.favoritesCount})
                    </button>
                  </form>
                </>
              ) : null}
            </div>
          </div>
        </div>
        <div class="container page">
          <div class="row article-content">
            <div class="col-md-12">
              <p style="white-space: pre-wrap">{article.body}</p>
              {article.tagList.length > 0 && (
                <ul class="tag-list">
                  {article.tagList.map((t) => (
                    <li class="tag-default tag-pill tag-outline">{t}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
          <hr />
          <div class="row">
            <div class="col-xs-12 col-md-8 offset-md-2">
              {user ? (
                <form
                  class="card comment-form"
                  method="post"
                  action={`/article/${article.slug}/comments`}
                >
                  <div class="card-block">
                    <textarea
                      class="form-control"
                      name="body"
                      placeholder="Write a comment..."
                      rows={3}
                    />
                  </div>
                  <div class="card-footer">
                    {user.image && <img src={user.image} class="comment-author-img" alt="" />}
                    <button class="btn btn-sm btn-primary" type="submit">
                      Post Comment
                    </button>
                  </div>
                </form>
              ) : (
                <p>
                  <a href="/login">Sign in</a> or <a href="/register">sign up</a> to add comments on
                  this article.
                </p>
              )}
              {comments.map((cmt) => (
                <div class="card">
                  <div class="card-block">
                    <p class="card-text">{cmt.body}</p>
                  </div>
                  <div class="card-footer">
                    <a href={`/profile/${cmt.author.username}`} class="comment-author">
                      {cmt.author.image && (
                        <img src={cmt.author.image} class="comment-author-img" alt="" />
                      )}
                    </a>
                    &nbsp;
                    <a href={`/profile/${cmt.author.username}`} class="comment-author">
                      {cmt.author.username}
                    </a>
                    <span class="date-posted">{new Date(cmt.createdAt).toDateString()}</span>
                    {user && user.username === cmt.author.username && (
                      <form
                        method="post"
                        action={`/article/${article.slug}/comments/${cmt.id}/delete`}
                        style="display:inline; float:right"
                      >
                        <button class="mod-options" type="submit" aria-label="Delete comment">
                          <i class="ion-trash-a" />
                        </button>
                      </form>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </Layout>,
  );
});

uiRouter.post("/article/:slug/favorite", (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login");
  favorite(user.id, c.req.param("slug"));
  return c.redirect(`/article/${c.req.param("slug")}`);
});

uiRouter.post("/article/:slug/unfavorite", (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login");
  unfavorite(user.id, c.req.param("slug"));
  return c.redirect(`/article/${c.req.param("slug")}`);
});

uiRouter.post("/article/:slug/delete", (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login");
  deleteArticle(user.id, c.req.param("slug"));
  return c.redirect("/");
});

uiRouter.post("/article/:slug/comments", async (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login");
  const data = await c.req.parseBody();
  try {
    addComment(c.req.param("slug"), user.id, String(data.body ?? ""));
  } catch (e) {
    if (e instanceof ConduitCommentError) return c.text(e.message, e.status as never);
    throw e;
  }
  return c.redirect(`/article/${c.req.param("slug")}`);
});

uiRouter.post("/article/:slug/comments/:id/delete", (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login");
  deleteComment(c.req.param("slug"), Number(c.req.param("id")), user.id);
  return c.redirect(`/article/${c.req.param("slug")}`);
});

// Profile + follow toggles
uiRouter.get("/profile/:username", (c) => {
  const me = c.get("user");
  const username = c.req.param("username");
  const profile = getProfile(username, me?.id ?? null);
  if (!profile) return c.text("not found", 404);
  const tab = c.req.query("tab") === "favorites" ? "favorites" : "my";
  const data =
    tab === "favorites"
      ? listArticles({ favorited: profile.username, limit: 10 }, me?.id ?? null)
      : listArticles({ author: profile.username, limit: 10 }, me?.id ?? null);
  const isMe = me?.username === profile.username;
  return c.html(
    <Layout user={me} active={`/profile/${username}`}>
      <div class="profile-page">
        <div class="user-info">
          <div class="container">
            <div class="row">
              <div class="col-xs-12 col-md-10 offset-md-1">
                {profile.image && <img src={profile.image} class="user-img" alt="" />}
                <h4>{profile.username}</h4>
                {profile.bio && <p>{profile.bio}</p>}
                {isMe ? (
                  <a href="/settings" class="btn btn-sm btn-outline-secondary action-btn">
                    <i class="ion-gear-a" /> Edit Profile Settings
                  </a>
                ) : me ? (
                  <form
                    method="post"
                    action={`/profile/${username}/${profile.following ? "unfollow" : "follow"}`}
                    style="display:inline"
                  >
                    <button class="btn btn-sm btn-outline-secondary action-btn" type="submit">
                      <i class="ion-plus-round" /> {profile.following ? "Unfollow" : "Follow"}{" "}
                      {profile.username}
                    </button>
                  </form>
                ) : null}
              </div>
            </div>
          </div>
        </div>
        <div class="container">
          <div class="row">
            <div class="col-xs-12 col-md-10 offset-md-1">
              <div class="articles-toggle">
                <ul class="nav nav-pills outline-active">
                  <li class="nav-item">
                    <a
                      class={tab === "my" ? "nav-link active" : "nav-link"}
                      href={`/profile/${username}`}
                    >
                      My Articles
                    </a>
                  </li>
                  <li class="nav-item">
                    <a
                      class={tab === "favorites" ? "nav-link active" : "nav-link"}
                      href={`/profile/${username}?tab=favorites`}
                    >
                      Favorited Articles
                    </a>
                  </li>
                </ul>
              </div>
              <ArticleList
                articles={data.articles}
                articlesCount={data.articlesCount}
                offset={0}
                limit={10}
                baseHref={`/profile/${username}${tab === "favorites" ? "?tab=favorites" : ""}`}
              />
            </div>
          </div>
        </div>
      </div>
    </Layout>,
  );
});

uiRouter.post("/profile/:username/follow", async (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login");
  follow(user.id, c.req.param("username"));
  const data = await c.req.parseBody();
  return c.redirect(String(data.redirect ?? `/profile/${c.req.param("username")}`));
});

uiRouter.post("/profile/:username/unfollow", async (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login");
  unfollow(user.id, c.req.param("username"));
  const data = await c.req.parseBody();
  return c.redirect(String(data.redirect ?? `/profile/${c.req.param("username")}`));
});
