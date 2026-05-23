import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/server/auth/session";
import { ConduitAuthError, updateUser } from "@/lib/server/services/users";

export async function GET(req: Request) {
  const { user, sessionId } = await getCurrentUser(req);
  if (!user) return NextResponse.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  return NextResponse.json({
    user: {
      email: user.email,
      username: user.username,
      bio: user.bio,
      image: user.image,
      token: sessionId ?? "",
    },
  });
}

export async function PUT(req: Request) {
  const { user, sessionId } = await getCurrentUser(req);
  if (!user) return NextResponse.json({ errors: { body: ["unauthorized"] } }, { status: 401 });
  const body = (await req.json().catch(() => ({}))) as { user?: Record<string, unknown> };
  if (!body.user)
    return NextResponse.json({ errors: { body: ["user is required"] } }, { status: 422 });
  try {
    const updated = await updateUser(user.id, body.user as never);
    return NextResponse.json({
      user: {
        email: updated.email,
        username: updated.username,
        bio: updated.bio,
        image: updated.image,
        token: sessionId ?? "",
      },
    });
  } catch (e) {
    if (e instanceof ConduitAuthError)
      return NextResponse.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
