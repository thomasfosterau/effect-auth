// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import ecTwoSlash from "expressive-code-twoslash";

// COOP/COEP headers are required for StackBlitz WebContainers (used by
// <RunnableExample>). Mirrored for production in `public/_headers`.
const crossOriginIsolationHeaders = {
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Opener-Policy": "same-origin",
};

export default defineConfig({
  vite: {
    server: { headers: crossOriginIsolationHeaders },
    preview: { headers: crossOriginIsolationHeaders },
  },
  integrations: [
    starlight({
      title: "Effect Auth",
      description: "Authentication and authorization primitives for the Effect ecosystem.",
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/thomasfosterau/effect-auth",
        },
      ],
      expressiveCode: {
        plugins: [ecTwoSlash()],
        themes: ["github-dark", "github-light"],
      },
      sidebar: [
        {
          label: "Guides",
          items: [
            { label: "Getting Started", slug: "guides/getting-started" },
            { label: "Sessions", slug: "guides/sessions" },
          ],
        },
        { label: "Playground", slug: "playground" },
        {
          label: "API Reference",
          autogenerate: { directory: "reference/api" },
          collapsed: true,
        },
      ],
    }),
  ],
});
