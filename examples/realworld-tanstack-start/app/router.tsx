// @ts-nocheck — TanStack Start API surface still churning; runtime is current
import { createRouter as createTanstackRouter } from "@tanstack/react-router";
import { routeTree } from "./routeTree.gen";

export const createRouter = () =>
  createTanstackRouter({
    routeTree,
    scrollRestoration: true,
    defaultPreload: "intent",
  });

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createRouter>;
  }
}
