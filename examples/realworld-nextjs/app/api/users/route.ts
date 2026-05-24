import { NextResponse } from "next/server";
import { setSessionCookie } from "@/lib/server/auth/session";
import { ConduitAuthError, registerUser } from "@/lib/server/services/users";

export async function POST(req: Request) {
  const body = (await req.json().catch(() => ({}))) as {
    user?: { email: string; username: string; password: string };
  };
  if (!body.user)
    return NextResponse.json({ errors: { body: ["user is required"] } }, { status: 422 });
  try {
    const r = await registerUser(body.user);
    await setSessionCookie(r.sessionId, r.expiresAt);
    return NextResponse.json({
      user: {
        email: r.profile.email,
        username: r.profile.username,
        bio: r.profile.bio,
        image: r.profile.image,
        token: r.sessionId,
      },
    });
  } catch (e) {
    if (e instanceof ConduitAuthError)
      return NextResponse.json({ errors: { body: [e.message] } }, { status: e.status });
    throw e;
  }
}
