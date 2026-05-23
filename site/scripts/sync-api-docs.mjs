#!/usr/bin/env node
// Sync @effect/docgen output into the Starlight content collection.
//
//   src:  packages/effect-auth/docs/modules/*.md   (Jekyll-style frontmatter)
//   dst:  site/src/content/docs/reference/api/*.md (Starlight frontmatter)
//
// Run after `nx docs effect-auth`. The Astro sidebar autogenerates entries
// for everything under `reference/api/`.

import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(here, "../../packages/effect-auth/docs/modules");
const DST = resolve(here, "../src/content/docs/reference/api");

const titleFromName = (file) => file.replace(/\.ts\.md$/, "").replace(/\.md$/, "");

const rewrite = (raw, title) => {
  const fmMatch = raw.match(/^---\n([\s\S]*?)\n---\n?/);
  const body = fmMatch ? raw.slice(fmMatch[0].length) : raw;
  const description = `API reference for the ${title} module.`;
  const frontmatter = `---\ntitle: ${JSON.stringify(title)}\ndescription: ${JSON.stringify(description)}\n---\n\n`;
  return frontmatter + body;
};

const main = async () => {
  let entries;
  try {
    entries = await readdir(SRC);
  } catch (err) {
    if (err && err.code === "ENOENT") {
      console.error(`No docgen output at ${SRC}. Run \`nx docs effect-auth\` first.`);
      process.exit(1);
    }
    throw err;
  }

  await rm(DST, { recursive: true, force: true });
  await mkdir(DST, { recursive: true });

  let count = 0;
  for (const name of entries) {
    if (!name.endsWith(".md")) continue;
    const title = titleFromName(name);
    const raw = await readFile(join(SRC, name), "utf8");
    const out = rewrite(raw, title);
    // Strip the `.ts` from the slug so URLs read /reference/api/session/
    const outName = name.replace(/\.ts\.md$/, ".md");
    await writeFile(join(DST, outName), out);
    count += 1;
  }
  console.log(`Synced ${count} module(s) → ${DST}`);
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
