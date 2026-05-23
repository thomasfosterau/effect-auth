import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/server/auth/session";
import { ConduitCommentError, addComment, listComments } from "@/lib/server/services/comments";

export async function GET(req: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { user } = await getCurrentUser(req);
  const { slug } = await params;
  return NextResponse.json({ comments: listComments(slug, user?.id ?? null) });
}

export async function POST(req: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { user } = await getCurrentUser(req);
  if (!user) return NextResponse.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const { slug } = await params;
  const body = (await req.json().catch(() => ({}))) as { comment?: { body: string } };
  if (!body.comment)
    return NextResponse.json({ errors: { body: ["comment is required"] } }, { status: 422 });
  try {
    return NextResponse.json({ comment: addComment(slug, user.id, body.comment.body) });
  } catch (e) {
    if (e instanceof ConduitCommentError)
      return NextResponse.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
