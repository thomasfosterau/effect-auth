import { defineEventHandler } from "h3";
import { clearSessionCookie } from "../../auth/session";
import { invalidateSession } from "../../auth/runtime";

export default defineEventHandler(async (event) => {
  if (event.context.sessionId) await invalidateSession(event.context.sessionId);
  clearSessionCookie(event);
  return { ok: true };
});
