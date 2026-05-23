import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/server/auth/session";
import {
  ConduitArticleError,
  deleteArticle,
  getArticleBySlug,
  updateArticle,
} from "@/lib/server/services/articles";

export async function GET(req: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { user } = await getCurrentUser(req);
  const { slug } = await params;
  const article = getArticleBySlug(slug, user?.id ?? null);
  if (!article)
    return NextResponse.json({ errors: { body: ["article not found"] } }, { status: 404 });
  return NextResponse.json({ article });
}

export async function PUT(req: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { user } = await getCurrentUser(req);
  if (!user) return NextResponse.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const { slug } = await params;
  const body = (await req.json().catch(() => ({}))) as {
    article?: { title?: string; description?: string; body?: string };
  };
  if (!body.article)
    return NextResponse.json({ errors: { body: ["article is required"] } }, { status: 422 });
  try {
    return NextResponse.json({ article: updateArticle(user.id, slug, body.article) });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return NextResponse.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}

export async function DELETE(req: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { user } = await getCurrentUser(req);
  if (!user) return NextResponse.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const { slug } = await params;
  try {
    deleteArticle(user.id, slug);
    return new NextResponse(null, { status: 204 });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return NextResponse.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
