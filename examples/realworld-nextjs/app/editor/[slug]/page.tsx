import { notFound, redirect } from "next/navigation";
import { getCurrentUser } from "@/lib/server/auth/session";
import { getArticleBySlug } from "@/lib/server/services/articles";
import EditForm from "./EditForm";

export const dynamic = "force-dynamic";

export default async function EditArticlePage({ params }: { params: Promise<{ slug: string }> }) {
  const { user } = await getCurrentUser();
  if (!user) redirect("/login");
  const { slug } = await params;
  const article = getArticleBySlug(slug, user.id);
  if (!article) notFound();
  if (article.author.username !== user.username) redirect("/");
  return <EditForm article={article} />;
}
