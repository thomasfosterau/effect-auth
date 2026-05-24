import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { apiRouter } from "./routes/api";
import { uiRouter } from "./routes/ui";
import { resolveCurrentUser } from "./auth/session";
import type { ConduitProfile } from "./types";

declare module "hono" {
  interface ContextVariableMap {
    user: ConduitProfile | null;
    sessionId: string | null;
  }
}

const app = new Hono();

// Session middleware — runs on every request, populates c.var.user
app.use("*", async (c, next) => {
  const { user, sessionId } = await resolveCurrentUser(c);
  c.set("user", user);
  c.set("sessionId", sessionId);
  await next();
});

app.route("/api", apiRouter);
app.route("/", uiRouter);

const port = Number(process.env.PORT ?? 3004);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`Conduit (effect-auth × Hono) listening on http://localhost:${info.port}`);
});
