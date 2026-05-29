import { getCookie, setCookie, deleteCookie, getHeader } from "vinxi/http";
import { validateSession } from "./runtime";
import { getUserById } from "../services/users";
import type { ConduitProfile } from "../types";

export const SESSION_COOKIE = "conduit_session";

export function setSessionCookieValue(sessionId: string, expiresAt: Date) {
  setCookie(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: expiresAt,
  });
}

export function clearSessionCookieValue() {
  deleteCookie(SESSION_COOKIE, { path: "/" });
}

export function getSessionId(): string | null {
  return getCookie(SESSION_COOKIE) ?? null;
}

/**
 * Resolve the current user from the session cookie or
 * `Authorization: Token <sid>` header.
 */
export async function getCurrentUser(): Promise<{
  user: ConduitProfile | null;
  sessionId: string | null;
}> {
  let sid: string | null = null;
  const header = getHeader("authorization");
  if (header) {
    const [scheme, value] = header.split(" ");
    if ((scheme === "Token" || scheme === "Bearer") && value) sid = value;
  }
  if (!sid) sid = getSessionId();
  if (!sid) return { user: null, sessionId: null };
  const r = await validateSession(sid);
  if (r._tag === "Failure") return { user: null, sessionId: null };
  const user = getUserById(r.success.session.userId);
  return { user, sessionId: sid };
}
