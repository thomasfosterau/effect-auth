// Consumed by `svelte-package` and `@sveltejs/vite-plugin-svelte`. `script:
// true` is what strips the `lang="ts"` blocks: without it `vitePreprocess`
// only touches styles, and the packaged components would ship TypeScript that
// every consumer then has to preprocess themselves.
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

export default {
  preprocess: vitePreprocess({ script: true }),
};
