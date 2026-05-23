import type { Cookies } from "@sveltejs/kit";

export const SESSION_COOKIE = "conduit_session";

export function setSessionCookie(cookies: Cookies, sessionId: string, expiresAt: Date) {
  cookies.set(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: expiresAt,
  });
}

export function clearSessionCookie(cookies: Cookies) {
  cookies.delete(SESSION_COOKIE, { path: "/" });
}

export function getSessionId(cookies: Cookies): string | null {
  return cookies.get(SESSION_COOKIE) ?? null;
}
