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
  // Update this once a custom domain is connected in the Cloudflare Pages dashboard.
  site: "https://effect-auth-docs.pages.dev",
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
            { label: "HTTP & Framework Mounting", slug: "guides/http" },
            { label: "Storage Backends", slug: "guides/storage" },
            { label: "Multi-Algorithm Hashing", slug: "guides/multi-algorithm" },
          ],
        },
        {
          label: "Features",
          items: [
            { label: "Magic Link", slug: "guides/magic-link" },
            { label: "Email OTP", slug: "guides/email-otp" },
            { label: "Two-Factor Auth", slug: "guides/two-factor" },
            { label: "Organizations", slug: "guides/organizations" },
            { label: "Admin", slug: "guides/admin" },
            { label: "API Keys", slug: "guides/api-keys" },
            { label: "JWT & JWKS", slug: "guides/jwt" },
            { label: "OIDC Provider", slug: "guides/oidc-provider" },
          ],
        },
        {
          label: "Migration",
          items: [
            { label: "User Model v2", slug: "guides/migration-v2" },
            { label: "Coming from better-auth", slug: "guides/better-auth" },
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
