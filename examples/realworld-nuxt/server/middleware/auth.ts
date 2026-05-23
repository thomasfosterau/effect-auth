import { defineEventHandler } from "h3";
import { resolveCurrentUser } from "../auth/session";

declare module "h3" {
  interface H3EventContext {
    user: import("../types").ConduitProfile | null;
    sessionId: string | null;
  }
}

export default defineEventHandler(async (event) => {
  const { user, sessionId } = await resolveCurrentUser(event);
  event.context.user = user;
  event.context.sessionId = sessionId;
});
