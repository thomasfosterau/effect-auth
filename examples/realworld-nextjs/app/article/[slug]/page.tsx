import Link from "next/link";
import { notFound } from "next/navigation";
import { getCurrentUser } from "@/lib/server/auth/session";
import { getArticleBySlug } from "@/lib/server/services/articles";
import { listComments } from "@/lib/server/services/comments";
import ArticleActions from "./ArticleActions";
import CommentSection from "./CommentSection";

export const dynamic = "force-dynamic";

export default async function ArticlePage({ params }: { params: Promise<{ slug: string }> }) {
  const { user } = await getCurrentUser();
  const { slug } = await params;
  const article = getArticleBySlug(slug, user?.id ?? null);
  if (!article) notFound();
  const comments = listComments(slug, user?.id ?? null);
  const isAuthor = user?.username === article.author.username;

  return (
    <div className="article-page">
      <div className="banner">
        <div className="container">
          <h1>{article.title}</h1>
          <div className="article-meta">
            <Link href={`/profile/${article.author.username}`}>
              {article.author.image && <img src={article.author.image} alt="" />}
            </Link>
            <div className="info">
              <Link href={`/profile/${article.author.username}`} className="author">
                {article.author.username}
              </Link>
              <span className="date">{new Date(article.createdAt).toDateString()}</span>
            </div>
            <ArticleActions article={article} isAuthor={isAuthor} viewerSignedIn={Boolean(user)} />
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
        <CommentSection slug={slug} comments={comments} viewer={user} />
      </div>
    </div>
  );
}
