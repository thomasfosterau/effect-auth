import { type RouteConfig, index, route } from "@react-router/dev/routes";

export default [
  index("routes/home.tsx"),
  route("login", "routes/login.tsx"),
  route("register", "routes/register.tsx"),
  route("logout", "routes/logout.tsx"),
  route("settings", "routes/settings.tsx"),
  route("editor", "routes/editor.tsx"),
  route("editor/:slug", "routes/editor.$slug.tsx"),
  route("article/:slug", "routes/article.$slug.tsx"),
  route("profile/:username", "routes/profile.$username.tsx"),

  route("api/users", "routes/api.users.tsx"),
  route("api/users/login", "routes/api.users.login.tsx"),
  route("api/user", "routes/api.user.tsx"),
  route("api/profiles/:username", "routes/api.profiles.$username.tsx"),
  route("api/profiles/:username/follow", "routes/api.profiles.$username.follow.tsx"),
  route("api/articles", "routes/api.articles.tsx"),
  route("api/articles/feed", "routes/api.articles.feed.tsx"),
  route("api/articles/:slug", "routes/api.articles.$slug.tsx"),
  route("api/articles/:slug/favorite", "routes/api.articles.$slug.favorite.tsx"),
  route("api/articles/:slug/comments", "routes/api.articles.$slug.comments.tsx"),
  route("api/articles/:slug/comments/:id", "routes/api.articles.$slug.comments.$id.tsx"),
  route("api/tags", "routes/api.tags.tsx"),
] satisfies RouteConfig;
