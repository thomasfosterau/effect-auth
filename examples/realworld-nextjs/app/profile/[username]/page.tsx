import { notFound } from "next/navigation";
import Link from "next/link";
import ArticleList from "@/lib/components/ArticleList";
import { getCurrentUser } from "@/lib/server/auth/session";
import { listArticles } from "@/lib/server/services/articles";
import { getProfile } from "@/lib/server/services/profiles";
import FollowButton from "./FollowButton";

export const dynamic = "force-dynamic";

export default async function ProfilePage({
  params,
  searchParams,
}: {
  params: Promise<{ username: string }>;
  searchParams: Promise<{ tab?: string }>;
}) {
  const { user } = await getCurrentUser();
  const { username } = await params;
  const sp = await searchParams;
  const profile = getProfile(username, user?.id ?? null);
  if (!profile) notFound();
  const tab = sp.tab === "favorites" ? "favorites" : "my";
  const data =
    tab === "favorites"
      ? listArticles({ favorited: profile.username, limit: 10 }, user?.id ?? null)
      : listArticles({ author: profile.username, limit: 10 }, user?.id ?? null);
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
                <Link href="/settings" className="btn btn-sm btn-outline-secondary action-btn">
                  <i className="ion-gear-a" /> Edit Profile Settings
                </Link>
              ) : user ? (
                <FollowButton username={profile.username} following={profile.following ?? false} />
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
                    href={`/profile/${profile.username}`}
                  >
                    My Articles
                  </Link>
                </li>
                <li className="nav-item">
                  <Link
                    className={tab === "favorites" ? "nav-link active" : "nav-link"}
                    href={`/profile/${profile.username}?tab=favorites`}
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
