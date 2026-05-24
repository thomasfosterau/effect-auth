"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import type { ConduitComment, ConduitProfile } from "@/lib/server/types";
import { addCommentAction, deleteCommentAction } from "../../actions";

export default function CommentSection({
  slug,
  comments,
  viewer,
}: {
  slug: string;
  comments: ConduitComment[];
  viewer: ConduitProfile | null;
}) {
  const router = useRouter();
  const [body, setBody] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function submit(e: React.FormEvent) {
    e.preventDefault();
    startTransition(async () => {
      const res = await addCommentAction(slug, body);
      if (res.error) {
        setError(res.error);
      } else {
        setError(null);
        setBody("");
        router.refresh();
      }
    });
  }

  return (
    <div className="row">
      <div className="col-xs-12 col-md-8 offset-md-2">
        {viewer ? (
          <form className="card comment-form" onSubmit={submit}>
            <div className="card-block">
              <textarea
                className="form-control"
                placeholder="Write a comment..."
                rows={3}
                value={body}
                onChange={(e) => setBody(e.target.value)}
              />
              {error && <p className="error-messages">{error}</p>}
            </div>
            <div className="card-footer">
              {viewer.image && <img src={viewer.image} className="comment-author-img" alt="" />}
              <button className="btn btn-sm btn-primary" type="submit" disabled={pending}>
                Post Comment
              </button>
            </div>
          </form>
        ) : (
          <p>
            <Link href="/login">Sign in</Link> or <Link href="/register">sign up</Link> to add
            comments on this article.
          </p>
        )}

        {comments.map((c) => (
          <div className="card" key={c.id}>
            <div className="card-block">
              <p className="card-text">{c.body}</p>
            </div>
            <div className="card-footer">
              <Link href={`/profile/${c.author.username}`} className="comment-author">
                {c.author.image && (
                  <img src={c.author.image} className="comment-author-img" alt="" />
                )}
              </Link>
              &nbsp;
              <Link href={`/profile/${c.author.username}`} className="comment-author">
                {c.author.username}
              </Link>
              <span className="date-posted">{new Date(c.createdAt).toDateString()}</span>
              {viewer && viewer.username === c.author.username && (
                <button
                  className="mod-options"
                  style={{ float: "right" }}
                  aria-label="Delete comment"
                  onClick={() =>
                    startTransition(async () => {
                      await deleteCommentAction(slug, c.id);
                      router.refresh();
                    })
                  }
                >
                  <i className="ion-trash-a" />
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
