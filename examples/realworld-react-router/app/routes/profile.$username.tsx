import { Form, Link, useLoaderData } from "react-router";
import type { ActionFunctionArgs, LoaderFunctionArgs } from "react-router";
import ArticleList from "~/components/ArticleList";
import { getCurrentUser, requireUser } from "~/server/auth/session";
import { listArticles } from "~/server/services/articles";
import { follow, getProfile, unfollow } from "~/server/services/profiles";

export async function loader({ request, params }: LoaderFunctionArgs) {
  const { user } = await getCurrentUser(request);
  const profile = getProfile(params.username!, user?.id ?? null);
  if (!profile) throw new Response("not found", { status: 404 });
  const url = new URL(request.url);
  const tab = url.searchParams.get("tab") === "favorites" ? "favorites" : "my";
  const data =
    tab === "favorites"
      ? listArticles({ favorited: profile.username, limit: 10 }, user?.id ?? null)
      : listArticles({ author: profile.username, limit: 10 }, user?.id ?? null);
  return { user, profile, tab, data };
}

export async function action({ request, params }: ActionFunctionArgs) {
  const me = await requireUser(request);
  const data = await request.formData();
  if (data.get("_intent") === "follow") follow(me.id, params.username!);
  if (data.get("_intent") === "unfollow") unfollow(me.id, params.username!);
  return null;
}

export default function Profile() {
  const { user, profile, tab, data } = useLoaderData<typeof loader>();
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
                <Form method="post" style={{ display: "inline" }}>
                  <input
                    type="hidden"
                    name="_intent"
                    value={profile.following ? "unfollow" : "follow"}
                  />
                  <button className="btn btn-sm btn-outline-secondary action-btn" type="submit">
                    <i className="ion-plus-round" /> {profile.following ? "Unfollow" : "Follow"}{" "}
                    {profile.username}
                  </button>
                </Form>
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
                    to={`/profile/${profile.username}`}
                  >
                    My Articles
                  </Link>
                </li>
                <li className="nav-item">
                  <Link
                    className={tab === "favorites" ? "nav-link active" : "nav-link"}
                    to={`/profile/${profile.username}?tab=favorites`}
                  >
                    Favorited Articles
                  </Link>
                </li>
              </ul>
            </div>
            <ArticleList
              articles={data.articles}
              articlesCount={data.articlesCount}
              offset={0}
              limit={10}
              baseHref={`/profile/${profile.username}${tab === "favorites" ? "?tab=favorites" : ""}`}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
