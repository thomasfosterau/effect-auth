import { cookies } from "next/headers";
import { validateSession } from "./runtime";
import { getUserById } from "../services/users";
import type { ConduitProfile } from "../types";

export const SESSION_COOKIE = "conduit_session";

export async function setSessionCookie(sessionId: string, expiresAt: Date) {
  const store = await cookies();
  store.set(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: expiresAt,
  });
}

export async function clearSessionCookie() {
  const store = await cookies();
  store.delete(SESSION_COOKIE);
}

export async function getSessionId(): Promise<string | null> {
  const store = await cookies();
  return store.get(SESSION_COOKIE)?.value ?? null;
}

/**
 * Resolve the current user from either the session cookie or the
 * `Authorization: Token <sid>` header on the given Request.
 */
export async function getCurrentUser(
  request?: Request,
): Promise<{ user: ConduitProfile | null; sessionId: string | null }> {
  let sid: string | null = null;
  if (request) {
    const header = request.headers.get("authorization");
    if (header) {
      const [scheme, value] = header.split(" ");
      if ((scheme === "Token" || scheme === "Bearer") && value) sid = value;
    }
  }
  if (!sid) sid = await getSessionId();
  if (!sid) return { user: null, sessionId: null };
  const r = await validateSession(sid);
  if (r._tag === "Left") return { user: null, sessionId: null };
  const user = getUserById(r.right.session.userId);
  return { user, sessionId: sid };
}
