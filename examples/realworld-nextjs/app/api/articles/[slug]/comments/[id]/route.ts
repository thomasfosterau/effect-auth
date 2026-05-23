import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/server/auth/session";
import { ConduitCommentError, deleteComment } from "@/lib/server/services/comments";

export async function DELETE(
  req: Request,
  { params }: { params: Promise<{ slug: string; id: string }> },
) {
  const { user } = await getCurrentUser(req);
  if (!user) return NextResponse.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const { slug, id } = await params;
  try {
    deleteComment(slug, Number(id), user.id);
    return new NextResponse(null, { status: 204 });
  } catch (e) {
    if (e instanceof ConduitCommentError)
      return NextResponse.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
