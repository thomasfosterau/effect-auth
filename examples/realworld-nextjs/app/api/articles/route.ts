import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/server/auth/session";
import { ConduitArticleError, createArticle, listArticles } from "@/lib/server/services/articles";

export async function GET(req: Request) {
  const { user } = await getCurrentUser(req);
  const url = new URL(req.url);
  const result = listArticles(
    {
      tag: url.searchParams.get("tag") ?? undefined,
      author: url.searchParams.get("author") ?? undefined,
      favorited: url.searchParams.get("favorited") ?? undefined,
      limit: url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : undefined,
      offset: url.searchParams.has("offset") ? Number(url.searchParams.get("offset")) : undefined,
    },
    user?.id ?? null,
  );
  return NextResponse.json(result);
}

export async function POST(req: Request) {
  const { user } = await getCurrentUser(req);
  if (!user) return NextResponse.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const body = (await req.json().catch(() => ({}))) as {
    article?: { title: string; description: string; body: string; tagList?: string[] };
  };
  if (!body.article)
    return NextResponse.json({ errors: { body: ["article is required"] } }, { status: 422 });
  try {
    return NextResponse.json({ article: createArticle(user.id, body.article) });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return NextResponse.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
