import { redirect } from "react-router";
import { validateSession } from "./runtime";
import { getUserById } from "../services/users";
import type { ConduitProfile } from "../types";

// The cookie stores the RAW session id (no JSON/base64 encoding) so the
// effect-auth web handler mounted at /api/auth (see webHandler.ts) reads the
// same session as these server helpers.
const COOKIE_NAME = "conduit_session";
const MAX_AGE = 60 * 60 * 24 * 30;
const secure = process.env.NODE_ENV === "production";

const cookieAttributes = `Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;

export async function setSessionHeader(sessionId: string): Promise<HeadersInit> {
  return { "Set-Cookie": `${COOKIE_NAME}=${sessionId}; ${cookieAttributes}; Max-Age=${MAX_AGE}` };
}

export async function clearSessionHeader(): Promise<HeadersInit> {
  return { "Set-Cookie": `${COOKIE_NAME}=; ${cookieAttributes}; Max-Age=0` };
}

export async function getSessionId(request: Request): Promise<string | null> {
  const header = request.headers.get("Cookie") ?? "";
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === COOKIE_NAME) {
      const value = part.slice(eq + 1).trim();
      return value === "" ? null : value;
    }
  }
  return null;
}

export async function getCurrentUser(
  request: Request,
): Promise<{ user: ConduitProfile | null; sessionId: string | null }> {
  let sid: string | null = null;
  const header = request.headers.get("authorization");
  if (header) {
    const [scheme, value] = header.split(" ");
    if ((scheme === "Token" || scheme === "Bearer") && value) sid = value;
  }
  if (!sid) sid = await getSessionId(request);
  if (!sid) return { user: null, sessionId: null };
  const r = await validateSession(sid);
  if (r._tag === "Failure") return { user: null, sessionId: null };
  const user = getUserById(r.success.session.userId);
  return { user, sessionId: sid };
}

export async function requireUser(request: Request): Promise<ConduitProfile> {
  const { user } = await getCurrentUser(request);
  if (!user) throw redirect("/login");
  return user;
}
