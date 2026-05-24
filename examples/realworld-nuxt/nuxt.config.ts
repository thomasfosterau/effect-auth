export default defineNuxtConfig({
  compatibilityDate: "2026-05-01",
  devtools: { enabled: false },
  nitro: {
    externals: { external: ["better-sqlite3", "effect-auth"] },
    moduleSideEffects: ["effect-auth"],
  },
  app: {
    head: {
      title: "Conduit — effect-auth × Nuxt",
      link: [
        { rel: "stylesheet", href: "//demo.productionready.io/main.css" },
        {
          rel: "stylesheet",
          href: "//code.ionicframework.com/ionicons/2.0.1/css/ionicons.min.css",
        },
        {
          rel: "stylesheet",
          href: "//fonts.googleapis.com/css?family=Titillium+Web:700|Source+Serif+Pro:400,700|Merriweather+Sans:400,700|Source+Sans+Pro:400,300,600,700,300italic,400italic,600italic,700italic",
        },
      ],
    },
  },
  typescript: { strict: true, typeCheck: false },
});
