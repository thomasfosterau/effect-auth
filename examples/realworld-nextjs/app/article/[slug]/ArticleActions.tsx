"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTransition } from "react";
import type { ConduitArticle } from "@/lib/server/types";
import {
  deleteArticleAction,
  favoriteAction,
  followAction,
  unfavoriteAction,
  unfollowAction,
} from "../../actions";

export default function ArticleActions({
  article,
  isAuthor,
  viewerSignedIn,
}: {
  article: ConduitArticle;
  isAuthor: boolean;
  viewerSignedIn: boolean;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  function run(fn: () => Promise<unknown>) {
    startTransition(async () => {
      await fn();
      router.refresh();
    });
  }

  if (isAuthor) {
    return (
      <>
        <Link href={`/editor/${article.slug}`} className="btn btn-sm btn-outline-secondary">
          <i className="ion-edit" /> Edit Article
        </Link>
        &nbsp;
        <button
          className="btn btn-sm btn-outline-danger"
          disabled={pending}
          onClick={() => run(() => deleteArticleAction(article.slug))}
        >
          <i className="ion-trash-a" /> Delete Article
        </button>
      </>
    );
  }
  if (!viewerSignedIn) return null;

  return (
    <>
      <button
        className="btn btn-sm btn-outline-secondary"
        disabled={pending}
        onClick={() =>
          run(() =>
            article.author.following
              ? unfollowAction(article.author.username)
              : followAction(article.author.username),
          )
        }
      >
        <i className="ion-plus-round" /> {article.author.following ? "Unfollow" : "Follow"}{" "}
        {article.author.username}
      </button>
      &nbsp;
      <button
        className={`btn btn-sm ${article.favorited ? "btn-primary" : "btn-outline-primary"}`}
        disabled={pending}
        onClick={() =>
          run(() =>
            article.favorited ? unfavoriteAction(article.slug) : favoriteAction(article.slug),
          )
        }
      >
        <i className="ion-heart" /> {article.favorited ? "Unfavorite" : "Favorite"} Article (
        {article.favoritesCount})
      </button>
    </>
  );
}
