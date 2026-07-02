import { createAuthClient } from "@effect-auth/client";

/** Browser client over the effect-auth handler mounted at /api/auth. */
export const authClient = createAuthClient({ baseUrl: "/api/auth" });
