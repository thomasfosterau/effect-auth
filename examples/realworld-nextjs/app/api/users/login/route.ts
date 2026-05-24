import { NextResponse } from "next/server";
import { setSessionCookie } from "@/lib/server/auth/session";
import { ConduitAuthError, loginUser } from "@/lib/server/services/users";

export async function POST(req: Request) {
  const body = (await req.json().catch(() => ({}))) as {
    user?: { email: string; password: string };
  };
  if (!body.user)
    return NextResponse.json({ errors: { body: ["user is required"] } }, { status: 422 });
  try {
    const r = await loginUser(body.user);
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
      return NextResponse.json(
        { errors: { "email or password": ["is invalid"] } },
        { status: e.status },
      );
    throw e;
  }
}
