import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/server/auth/session";
import { ConduitArticleError, favorite, unfavorite } from "@/lib/server/services/articles";

export async function POST(req: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { user } = await getCurrentUser(req);
  if (!user) return NextResponse.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const { slug } = await params;
  try {
    return NextResponse.json({ article: favorite(user.id, slug) });
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
    return NextResponse.json({ article: unfavorite(user.id, slug) });
  } catch (e) {
    if (e instanceof ConduitArticleError)
      return NextResponse.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
